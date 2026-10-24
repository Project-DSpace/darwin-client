//! Fleet health: an extensible, always-available indicator of node-fleet health.
//!
//! The model is deliberately generic — [`FleetHealth`] is a list of [`HealthCheck`]s plus an
//! `overall` level — so future signals (connectivity, sync lag, reward health, …) can be added as
//! new [`HealthCheckKind`]s without changing the API surface the CLI and GUI consume.
//!
//! The first and only check today is **disk space**, per partition that holds node data (measured
//! by [`super::disk`]): green while there is room, a warning at 1 GiB free or less, critical at
//! 500 MiB or less. It only reports. The node manager deletes no node's data at any level, and
//! names no node to delete: upstream's evicted a node at the critical level, deleting its data
//! directory, and that eviction is removed.

use serde::{Deserialize, Serialize};

use super::disk::PartitionState;

/// One mebibyte, in bytes.
pub const MIB: u64 = 1024 * 1024;

/// Free space at or below which a partition's disk health is critical: 500 MiB, the level at which
/// upstream's manager evicted a node, and the reserve at which nodes then refused new data.
/// Internal constant — deliberately not user-configurable.
const CRITICAL_THRESHOLD_MB: u64 = 500;

/// Free space at or below which a partition's disk health turns to a warning. Internal constant —
/// deliberately not user-configurable.
const WARNING_THRESHOLD_MB: u64 = 1024;

/// What every disk-space finding below green tells the operator to do: the manager won't make
/// room itself.
const NOTHING_DELETED: &str =
    "The node manager deletes no node's data: free up disk space or run fewer nodes.";

/// Severity level for a single check or the fleet as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthLevel {
    /// Everything is comfortable.
    Green,
    /// Action may be needed soon (e.g. disk space is running low).
    Warning,
    /// At or past a hard limit right now (e.g. disk space is nearly exhausted).
    Critical,
}

impl HealthLevel {
    fn rank(self) -> u8 {
        match self {
            HealthLevel::Green => 0,
            HealthLevel::Warning => 1,
            HealthLevel::Critical => 2,
        }
    }

    /// The more severe of two levels.
    pub fn worst(self, other: HealthLevel) -> HealthLevel {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Which signal produced a [`HealthCheck`]. Extensible: new variants slot in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    /// Free disk space at node data directories.
    DiskSpace,
}

/// A single health finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HealthCheck {
    pub kind: HealthCheckKind,
    pub level: HealthLevel,
    /// Human-readable, user-facing one-liner.
    pub summary: String,
    /// Partition this finding concerns (disk checks only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,
    /// Free bytes on the partition (disk checks only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_bytes: Option<u64>,
    /// Free-space level at or below which the check is critical (disk checks only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_threshold_bytes: Option<u64>,
}

/// Fleet-wide health snapshot: the worst level across all checks, plus the individual findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FleetHealth {
    pub overall: HealthLevel,
    pub checks: Vec<HealthCheck>,
}

impl FleetHealth {
    /// A green snapshot with no findings (e.g. no nodes registered).
    pub fn healthy() -> Self {
        FleetHealth {
            overall: HealthLevel::Green,
            checks: Vec::new(),
        }
    }

    /// Build the fleet health from measured partition states and the configured disk thresholds.
    pub fn from_partitions(partitions: &[PartitionState], thresholds: &DiskThresholds) -> Self {
        let checks: Vec<HealthCheck> = partitions
            .iter()
            .map(|p| disk_space_check(p, thresholds))
            .collect();
        let overall = checks
            .iter()
            .fold(HealthLevel::Green, |acc, c| acc.worst(c.level));
        FleetHealth { overall, checks }
    }
}

/// Configured free-space thresholds for the disk-space check.
#[derive(Debug, Clone, Copy)]
pub struct DiskThresholds {
    /// The check is critical once free space falls to/below this many bytes.
    pub critical_bytes: u64,
    /// The check is a warning once free space falls to/below this many bytes.
    pub warning_bytes: u64,
}

impl Default for DiskThresholds {
    fn default() -> Self {
        DiskThresholds {
            critical_bytes: CRITICAL_THRESHOLD_MB * MIB,
            warning_bytes: WARNING_THRESHOLD_MB * MIB,
        }
    }
}

/// Evaluate the disk-space health of a single partition. A report only: whatever the level, no
/// node is named for deletion and none is deleted.
fn disk_space_check(p: &PartitionState, thresholds: &DiskThresholds) -> HealthCheck {
    let available = p.available_bytes;

    let (level, summary) = if available <= thresholds.critical_bytes {
        (
            HealthLevel::Critical,
            format!(
                "Disk space critical on {}: {} free (at or below {}). {NOTHING_DELETED}",
                p.partition,
                fmt_bytes(available),
                fmt_bytes(thresholds.critical_bytes),
            ),
        )
    } else if available <= thresholds.warning_bytes {
        (
            HealthLevel::Warning,
            format!(
                "Disk space low on {}: {} free (at or below {}). {NOTHING_DELETED}",
                p.partition,
                fmt_bytes(available),
                fmt_bytes(thresholds.warning_bytes),
            ),
        )
    } else {
        (
            HealthLevel::Green,
            format!(
                "Disk space healthy on {}: {} free.",
                p.partition,
                fmt_bytes(available)
            ),
        )
    };

    HealthCheck {
        kind: HealthCheckKind::DiskSpace,
        level,
        summary,
        partition: Some(p.partition.to_string()),
        available_bytes: Some(available),
        critical_threshold_bytes: Some(thresholds.critical_bytes),
    }
}

/// Format a byte count as a human-friendly string (GiB/MiB).
fn fmt_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{:.0} MiB", bytes as f64 / MIB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::daemon::disk::{PartitionKey, PartitionState};

    fn partition(available_bytes: u64) -> PartitionState {
        PartitionState {
            partition: PartitionKey::for_test("p0"),
            available_bytes,
        }
    }

    fn thresholds() -> DiskThresholds {
        DiskThresholds {
            critical_bytes: 500 * MIB,
            warning_bytes: 1024 * MIB,
        }
    }

    /// No finding, at any level, says a node is or would be evicted, or names one to delete.
    fn assert_names_no_eviction(health: &FleetHealth) {
        for check in &health.checks {
            let summary = check.summary.to_lowercase();
            assert!(!summary.contains("evict"), "{}", check.summary);
            assert!(!summary.contains("would be"), "{}", check.summary);
        }
        let json = serde_json::to_string(health).unwrap();
        assert!(!json.contains("candidate"), "{json}");
        assert!(!json.contains("evict"), "{json}");
    }

    #[test]
    fn the_defaults_are_the_levels_the_manager_always_had() {
        let defaults = DiskThresholds::default();
        assert_eq!(defaults.critical_bytes, 500 * MIB);
        assert_eq!(defaults.warning_bytes, 1024 * MIB);
    }

    #[test]
    fn green_when_space_comfortable() {
        let health = FleetHealth::from_partitions(&[partition(4 * 1024 * MIB)], &thresholds());
        assert_eq!(health.overall, HealthLevel::Green);
        assert!(health.checks[0].summary.contains("healthy"));
        assert_names_no_eviction(&health);
    }

    #[test]
    fn warning_between_thresholds_only_reports() {
        // 800 MiB free: below warning (1024) but above critical (500).
        let health = FleetHealth::from_partitions(&[partition(800 * MIB)], &thresholds());
        assert_eq!(health.overall, HealthLevel::Warning);
        assert!(health.checks[0].summary.contains("800 MiB free"));
        assert!(health.checks[0].summary.contains(NOTHING_DELETED));
        assert_names_no_eviction(&health);
    }

    #[test]
    fn critical_at_or_below_the_critical_level_only_reports() {
        for available in [500 * MIB, 400 * MIB, 0] {
            let health = FleetHealth::from_partitions(&[partition(available)], &thresholds());
            assert_eq!(health.overall, HealthLevel::Critical);
            assert!(health.checks[0].summary.contains(NOTHING_DELETED));
            assert_eq!(health.checks[0].critical_threshold_bytes, Some(500 * MIB));
            assert_names_no_eviction(&health);
        }
    }

    #[test]
    fn overall_is_worst_across_partitions() {
        let health = FleetHealth::from_partitions(
            &[partition(4 * 1024 * MIB), partition(800 * MIB)],
            &thresholds(),
        );
        assert_eq!(health.overall, HealthLevel::Warning);
        assert_eq!(health.checks.len(), 2);
    }

    #[test]
    fn empty_fleet_is_green() {
        let health = FleetHealth::from_partitions(&[], &thresholds());
        assert_eq!(health.overall, HealthLevel::Green);
        assert!(health.checks.is_empty());
    }

    /// What the storage-deploy watchdog reads from `GET /api/v1/health`: `overall`, and each
    /// check's `level`, `partition` and `summary`, in these names.
    #[test]
    fn the_fields_the_watchdog_reads_keep_their_names() {
        let health = FleetHealth::from_partitions(&[partition(400 * MIB)], &thresholds());
        let json = serde_json::to_value(&health).unwrap();
        assert_eq!(json["overall"], "critical");
        assert_eq!(json["checks"][0]["level"], "critical");
        assert_eq!(json["checks"][0]["partition"], "p0");
        assert!(json["checks"][0]["summary"]
            .as_str()
            .unwrap()
            .starts_with("Disk space critical on p0"));
    }
}
