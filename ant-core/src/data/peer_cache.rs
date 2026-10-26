//! Persistent client bootstrap peer cache.
//!
//! Client peer IDs are ephemeral, so this cache is not keyed by distance from
//! the local client. It remembers authenticated node peers that we have already
//! connected to directly during client runs, stores their dialable channel
//! addresses, and prefers retaining peers that are spread across the peer-id
//! keyspace.

use crate::config;
use ant_protocol::transport::{IPDiversityConfig, MultiAddr, P2PNode, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

pub const CLIENT_PEER_CACHE_MAX_PEERS: usize = 50;

/// Address families allowed when materializing cached startup candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapAddressFilter {
    /// Allow every dialable cached address.
    All,
    /// Allow only IPv4 cached addresses.
    Ipv4Only,
}

const CLIENT_PEER_CACHE_SCHEMA_VERSION: u32 = 1;
/// darwin's own cache file in the data directory. Autonomi's `ant` keeps its
/// cache, peers of its network, as `client_peer_cache.json` in the same
/// directory; that file is never read, since cached peers are dialled before
/// the seeds.
const CLIENT_PEER_CACHE_FILE_NAME: &str = "darwin_client_peer_cache.json";
const CLIENT_PEER_CACHE_TEMP_SUFFIX: &str = "tmp";
const DEFAULT_MAX_PER_EXACT_IP: usize = 2;
const SUBNET_LIMIT_K_DIVISOR: usize = 4;
const IPV4_SUBNET_PREFIX_OCTETS: usize = 3;
const IPV6_SUBNET_PREFIX_SEGMENTS: usize = 3;
const BITS_PER_BYTE: u8 = 8;
const PEER_ID_SECTOR_BITS: u8 = 4;
const PEER_ID_SECTOR_COUNT: usize = 1 << PEER_ID_SECTOR_BITS;
const PEER_ID_XOR_DISTANCE_BYTES: usize = 32;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClientPeerCacheFile {
    schema_version: u32,
    peers: Vec<CachedPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CachedPeer {
    peer_id: PeerId,
    direct_addresses: Vec<MultiAddr>,
    first_connected_epoch_secs: u64,
    last_connected_epoch_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubnetKey {
    V4([u8; IPV4_SUBNET_PREFIX_OCTETS]),
    V6([u16; IPV6_SUBNET_PREFIX_SEGMENTS]),
}

struct DiversityTracker {
    exact_ip_counts: HashMap<IpAddr, usize>,
    subnet_counts: HashMap<SubnetKey, usize>,
    max_per_ip: usize,
    max_per_subnet: usize,
}

/// Build the on-disk cache path for the client peer cache.
#[must_use]
pub fn cache_path() -> Option<PathBuf> {
    match config::data_dir() {
        Ok(data_dir) => Some(cache_path_in(&data_dir)),
        Err(err) => {
            warn!("client peer cache disabled: failed to resolve data dir: {err}");
            None
        }
    }
}

/// The client peer cache's path in the data directory `data_dir`.
fn cache_path_in(data_dir: &Path) -> PathBuf {
    data_dir.join(CLIENT_PEER_CACHE_FILE_NAME)
}

/// Load cache addresses to try before configured bootstrap peers.
///
/// Returns at most one direct address per cached peer. saorsa-core stops client
/// bootstrap after the client bootstrap target is reached, so every usable
/// cached peer is ordered before the configured fallback peers without forcing
/// all cached peers to be dialed on a healthy warm start.
#[must_use]
pub fn cached_bootstrap_peers(cache_path: &Path, k_value: usize) -> Vec<MultiAddr> {
    cached_bootstrap_peers_with_filter(cache_path, k_value, BootstrapAddressFilter::All)
}

/// Load cache addresses to try before configured bootstrap peers, applying an
/// address-family filter before choosing the first address for each peer.
#[must_use]
pub fn cached_bootstrap_peers_with_filter(
    cache_path: &Path,
    k_value: usize,
    address_filter: BootstrapAddressFilter,
) -> Vec<MultiAddr> {
    let Some(mut cache) = ClientPeerCacheFile::load_existing(cache_path) else {
        return Vec::new();
    };
    let loaded_peer_count = cache.peers.len();
    let loaded_direct_address_count = cache.direct_address_count();
    let diversity_config = cache_diversity_config();
    let normalized = cache.normalize(&diversity_config, k_value);
    if normalized {
        cache.save(cache_path);
    }
    let bootstrap_addresses =
        cache.bootstrap_addresses(CLIENT_PEER_CACHE_MAX_PEERS, address_filter);
    info!(
        path = %cache_path.display(),
        cached_peers = loaded_peer_count,
        direct_addresses = loaded_direct_address_count,
        usable_cached_peers = cache.peers.len(),
        bootstrap_candidates = bootstrap_addresses.len(),
        "client peer bootstrap cache file found and loaded; cached peers available",
    );
    bootstrap_addresses
}

/// Select startup bootstrap peers.
///
/// Cached peers are ordered first and configured bootstrap peers are appended
/// behind them, in a random order ([`crate::data::network::in_random_order`]).
/// saorsa-core stops client bootstrap after the client bootstrap target is
/// reached, so configured peers are only reached when the cached candidates do
/// not produce enough successful connections, and then not always the same
/// first few.
#[must_use]
pub fn select_bootstrap_peers(
    cached: impl IntoIterator<Item = MultiAddr>,
    configured: impl IntoIterator<Item = MultiAddr>,
) -> Vec<MultiAddr> {
    let configured = crate::data::network::in_random_order(
        configured.into_iter().collect(),
        &mut rand::thread_rng(),
    );
    dedupe_bootstrap_peers(cached.into_iter().chain(configured))
}

fn dedupe_bootstrap_peers(addrs: impl IntoIterator<Item = MultiAddr>) -> Vec<MultiAddr> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for addr in addrs {
        if seen.insert(bootstrap_address_key(&addr)) {
            deduped.push(addr);
        }
    }

    deduped
}

/// Persist authenticated peers reached directly during this client run.
///
/// A DHT Direct tag is not required here. The cache records dialable addresses
/// from currently live peer connections so the next client run can try peers it
/// actually reached.
pub async fn promote_connected_direct_peers(node: &P2PNode, cache_path: &Path, k_value: usize) {
    let connected_peers = node.connected_peers().await;
    if connected_peers.is_empty() {
        return;
    }

    let connected_peer_count = connected_peers.len();
    let mut cache = ClientPeerCacheFile::load(cache_path);
    let diversity_config = cache_diversity_config();
    let now = now_epoch_secs();
    let mut changed = false;
    let mut cacheable_peer_count = 0usize;
    let mut cacheable_address_count = 0usize;

    for peer_id in connected_peers {
        let Some(peer_info) = node.peer_info(&peer_id).await else {
            continue;
        };

        let channel_addresses = peer_info
            .addresses
            .into_iter()
            .filter(|addr| addr.dialable_socket_addr().is_some())
            .collect::<Vec<_>>();
        if channel_addresses.is_empty() {
            continue;
        }

        cacheable_peer_count += 1;
        cacheable_address_count += channel_addresses.len();

        changed |= cache.upsert_connected_peer(
            peer_id,
            channel_addresses,
            now,
            &diversity_config,
            k_value,
        );
    }

    if changed {
        info!(
            path = %cache_path.display(),
            connected_peers = connected_peer_count,
            cacheable_peers = cacheable_peer_count,
            cacheable_addresses = cacheable_address_count,
            cached_peers = cache.peers.len(),
            direct_addresses = cache.direct_address_count(),
            "client peer bootstrap cache updated from live connected peers",
        );
        cache.save(cache_path);
    }
}

/// The cache applies the default k-bucket IP diversity policy rather than the
/// client's permissive routing-table setting. This keeps the persisted
/// bootstrap surface from collapsing onto one IP or subnet.
#[must_use]
fn cache_diversity_config() -> IPDiversityConfig {
    IPDiversityConfig::default()
}

impl BootstrapAddressFilter {
    fn allows(self, addr: &MultiAddr) -> bool {
        match self {
            Self::All => addr.dialable_socket_addr().is_some(),
            Self::Ipv4Only => addr
                .dialable_socket_addr()
                .is_some_and(|socket| socket.is_ipv4()),
        }
    }
}

impl ClientPeerCacheFile {
    fn empty() -> Self {
        Self {
            schema_version: CLIENT_PEER_CACHE_SCHEMA_VERSION,
            peers: Vec::new(),
        }
    }

    fn load(path: &Path) -> Self {
        Self::load_existing(path).unwrap_or_else(Self::empty)
    }

    fn load_existing(path: &Path) -> Option<Self> {
        let Ok(data) = std::fs::read_to_string(path) else {
            return None;
        };

        match serde_json::from_str::<Self>(&data) {
            Ok(cache) if cache.schema_version == CLIENT_PEER_CACHE_SCHEMA_VERSION => Some(cache),
            Ok(cache) => {
                debug!(
                    path = %path.display(),
                    schema_version = cache.schema_version,
                    "ignoring client peer cache with unsupported schema version",
                );
                None
            }
            Err(err) => {
                warn!(
                    path = %path.display(),
                    "ignoring unreadable client peer cache: {err}",
                );
                None
            }
        }
    }

    fn direct_address_count(&self) -> usize {
        self.peers
            .iter()
            .map(|peer| peer.direct_addresses.len())
            .sum()
    }

    fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                warn!(
                    path = %path.display(),
                    "failed to create client peer cache directory: {err}",
                );
                return;
            }
        }

        let data = match serde_json::to_vec_pretty(self) {
            Ok(data) => data,
            Err(err) => {
                warn!("failed to serialize client peer cache: {err}");
                return;
            }
        };

        let temp_path = temp_path_for(path);
        if let Err(err) = std::fs::write(&temp_path, data) {
            warn!(
                path = %temp_path.display(),
                "failed to write client peer cache temp file: {err}",
            );
            return;
        }

        #[cfg(windows)]
        if path.exists() {
            if let Err(err) = std::fs::remove_file(path) {
                warn!(
                    path = %path.display(),
                    "failed to replace existing client peer cache: {err}",
                );
                let _ = std::fs::remove_file(&temp_path);
                return;
            }
        }

        if let Err(err) = std::fs::rename(&temp_path, path) {
            warn!(
                from = %temp_path.display(),
                to = %path.display(),
                "failed to commit client peer cache: {err}",
            );
            let _ = std::fs::remove_file(temp_path);
        }
    }

    fn upsert_connected_peer(
        &mut self,
        peer_id: PeerId,
        direct_addresses: Vec<MultiAddr>,
        now: u64,
        diversity_config: &IPDiversityConfig,
        k_value: usize,
    ) -> bool {
        let direct_addresses = sanitize_direct_addresses(peer_id, direct_addresses);
        if direct_addresses.is_empty() {
            return false;
        }

        let before = self.peers.clone();
        if let Some(existing) = self.peers.iter_mut().find(|peer| peer.peer_id == peer_id) {
            existing.direct_addresses = direct_addresses;
            existing.last_connected_epoch_secs = now;
        } else {
            self.peers.push(CachedPeer {
                peer_id,
                direct_addresses,
                first_connected_epoch_secs: now,
                last_connected_epoch_secs: now,
            });
        }

        self.normalize(diversity_config, k_value);
        self.peers != before
    }

    fn normalize(&mut self, diversity_config: &IPDiversityConfig, k_value: usize) -> bool {
        let before = self.peers.clone();
        self.peers.retain(|peer| !peer.direct_addresses.is_empty());
        self.peers.sort_by(|left, right| {
            right
                .last_connected_epoch_secs
                .cmp(&left.last_connected_epoch_secs)
                .then_with(|| left.peer_id.to_hex().cmp(&right.peer_id.to_hex()))
        });

        let mut candidates = Vec::with_capacity(self.peers.len());
        let mut seen_peers = HashSet::new();
        for peer in self.peers.drain(..) {
            if seen_peers.insert(peer.peer_id) {
                candidates.push(peer);
            }
        }

        let mut tracker = DiversityTracker::new(diversity_config, k_value);
        let mut normalized = Vec::with_capacity(CLIENT_PEER_CACHE_MAX_PEERS);

        while normalized.len() < CLIENT_PEER_CACHE_MAX_PEERS {
            let Some(best_index) =
                select_peer_id_diverse_candidate(&candidates, &normalized, &tracker)
            else {
                break;
            };
            let peer = candidates.swap_remove(best_index);
            tracker.record_peer(&peer);
            normalized.push(peer);
        }

        self.peers = normalized;
        self.peers != before
    }

    fn bootstrap_addresses(
        &self,
        limit: usize,
        address_filter: BootstrapAddressFilter,
    ) -> Vec<MultiAddr> {
        let mut sectors = (0..PEER_ID_SECTOR_COUNT)
            .map(|_| Vec::new())
            .collect::<Vec<Vec<&CachedPeer>>>();

        for peer in &self.peers {
            sectors[peer_id_sector(peer.peer_id)].push(peer);
        }

        let mut positions = [0usize; PEER_ID_SECTOR_COUNT];
        let mut addresses = Vec::with_capacity(self.peers.len().min(limit));

        loop {
            let mut advanced_this_round = false;
            for sector in 0..PEER_ID_SECTOR_COUNT {
                let position = positions[sector];
                let Some(peer) = sectors[sector].get(position) else {
                    continue;
                };
                positions[sector] += 1;
                advanced_this_round = true;
                if let Some(addr) = peer
                    .direct_addresses
                    .iter()
                    .find(|addr| address_filter.allows(addr))
                {
                    addresses.push(addr.clone());
                }
                if addresses.len() >= limit {
                    return addresses;
                }
            }
            if !advanced_this_round {
                return addresses;
            }
        }
    }
}

fn select_peer_id_diverse_candidate(
    candidates: &[CachedPeer],
    selected: &[CachedPeer],
    tracker: &DiversityTracker,
) -> Option<usize> {
    let mut best_index = None;

    for (candidate_index, candidate) in candidates.iter().enumerate() {
        if !tracker.can_admit_peer(candidate) {
            continue;
        }
        let Some(current_best_index) = best_index else {
            best_index = Some(candidate_index);
            continue;
        };
        let current_best = &candidates[current_best_index];
        if prefer_peer_id_candidate(candidate, current_best, selected) {
            best_index = Some(candidate_index);
        }
    }

    best_index
}

fn prefer_peer_id_candidate(
    candidate: &CachedPeer,
    current_best: &CachedPeer,
    selected: &[CachedPeer],
) -> bool {
    peer_id_spread_score(candidate, selected)
        .cmp(&peer_id_spread_score(current_best, selected))
        .then_with(|| {
            candidate
                .last_connected_epoch_secs
                .cmp(&current_best.last_connected_epoch_secs)
        })
        .then_with(|| {
            current_best
                .peer_id
                .to_hex()
                .cmp(&candidate.peer_id.to_hex())
        })
        .is_gt()
}

fn peer_id_spread_score(
    candidate: &CachedPeer,
    selected: &[CachedPeer],
) -> Option<[u8; PEER_ID_XOR_DISTANCE_BYTES]> {
    selected
        .iter()
        .map(|peer| peer_id_xor_distance(candidate.peer_id, peer.peer_id))
        .min()
}

fn peer_id_xor_distance(left: PeerId, right: PeerId) -> [u8; PEER_ID_XOR_DISTANCE_BYTES] {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let mut distance = [0u8; PEER_ID_XOR_DISTANCE_BYTES];
    for (index, byte) in distance.iter_mut().enumerate() {
        *byte = left_bytes[index] ^ right_bytes[index];
    }
    distance
}

impl DiversityTracker {
    fn new(config: &IPDiversityConfig, k_value: usize) -> Self {
        Self {
            exact_ip_counts: HashMap::new(),
            subnet_counts: HashMap::new(),
            max_per_ip: config.max_per_ip.unwrap_or(DEFAULT_MAX_PER_EXACT_IP),
            max_per_subnet: config
                .max_per_subnet
                .unwrap_or_else(|| default_subnet_limit(k_value)),
        }
    }

    fn can_admit_peer(&self, peer: &CachedPeer) -> bool {
        let Some((ip_set, subnet_set)) = peer_diversity_sets(peer) else {
            return false;
        };

        for ip in &ip_set {
            if self.exact_ip_counts.get(ip).copied().unwrap_or_default() >= self.max_per_ip {
                return false;
            }
        }

        for subnet in &subnet_set {
            if self.subnet_counts.get(subnet).copied().unwrap_or_default() >= self.max_per_subnet {
                return false;
            }
        }

        true
    }

    fn record_peer(&mut self, peer: &CachedPeer) {
        let Some((ip_set, subnet_set)) = peer_diversity_sets(peer) else {
            return;
        };

        for ip in ip_set {
            *self.exact_ip_counts.entry(ip).or_default() += 1;
        }
        for subnet in subnet_set {
            *self.subnet_counts.entry(subnet).or_default() += 1;
        }
    }
}

fn peer_diversity_sets(peer: &CachedPeer) -> Option<(HashSet<IpAddr>, HashSet<SubnetKey>)> {
    let ip_set = peer
        .direct_addresses
        .iter()
        .filter_map(|addr| {
            addr.dialable_socket_addr()
                .map(|socket| canonical_ip(socket.ip()))
        })
        .collect::<HashSet<_>>();

    if ip_set.is_empty() {
        return None;
    }

    let subnet_set = ip_set
        .iter()
        .map(|ip| subnet_key(*ip))
        .collect::<HashSet<_>>();

    Some((ip_set, subnet_set))
}

fn sanitize_direct_addresses(peer_id: PeerId, direct_addresses: Vec<MultiAddr>) -> Vec<MultiAddr> {
    let mut seen = HashSet::new();
    let mut sanitized = Vec::new();

    for addr in direct_addresses {
        if addr.dialable_socket_addr().is_none() {
            continue;
        }
        let addr = addr.with_peer_id(peer_id);
        if seen.insert(addr.to_string()) {
            sanitized.push(addr);
        }
    }

    sanitized
}

fn bootstrap_address_key(addr: &MultiAddr) -> String {
    addr.dialable_socket_addr()
        .map(|socket| socket.to_string())
        .unwrap_or_else(|| addr.to_string())
}

fn default_subnet_limit(k_value: usize) -> usize {
    std::cmp::max(k_value / SUBNET_LIMIT_K_DIVISOR, 1)
}

fn subnet_key(ip: IpAddr) -> SubnetKey {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            SubnetKey::V4([octets[0], octets[1], octets[IPV4_SUBNET_PREFIX_OCTETS - 1]])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            SubnetKey::V6([
                segments[0],
                segments[1],
                segments[IPV6_SUBNET_PREFIX_SEGMENTS - 1],
            ])
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
    }
}

fn peer_id_sector(peer_id: PeerId) -> usize {
    let sector_shift = BITS_PER_BYTE - PEER_ID_SECTOR_BITS;
    usize::from(peer_id.as_bytes()[0] >> sector_shift)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(CLIENT_PEER_CACHE_FILE_NAME);
    path.with_file_name(format!(
        ".{file_name}.{process_id}.{counter}.{CLIENT_PEER_CACHE_TEMP_SUFFIX}"
    ))
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    const TEST_PEER_ID_LEN: usize = 32;
    const TEST_K_VALUE: usize = 20;
    const FIRST_PORT: u16 = 10_000;
    const TEST_NOW: u64 = 1_000_000;
    const EXACT_IP_ATTEMPTS: u8 = 3;
    const SUBNET_ATTEMPTS: u8 = 6;
    const BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT: usize = 6;

    fn peer_id(byte: u8) -> PeerId {
        peer_id_with_prefix(byte, 0)
    }

    fn peer_id_with_prefix(first_byte: u8, second_byte: u8) -> PeerId {
        let mut bytes = [0u8; TEST_PEER_ID_LEN];
        bytes[0] = first_byte;
        bytes[1] = second_byte;
        PeerId::from_bytes(bytes)
    }

    fn direct_addr(ip: IpAddr, port: u16) -> MultiAddr {
        MultiAddr::quic(SocketAddr::new(ip, port))
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(first_segment: u16, host: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(first_segment, 0, 0, 0, 0, 0, 0, host))
    }

    #[test]
    fn cache_prefers_peer_id_spread_over_recency_when_full() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        let old_distant_peer = peer_id_with_prefix(u8::MAX, 0);
        cache.peers.push(CachedPeer {
            peer_id: old_distant_peer,
            direct_addresses: vec![direct_addr(v4(203, 0, 113, 1), FIRST_PORT)],
            first_connected_epoch_secs: TEST_NOW,
            last_connected_epoch_secs: TEST_NOW,
        });

        for idx in 0..CLIENT_PEER_CACHE_MAX_PEERS {
            let peer = peer_id_with_prefix(0, idx as u8);
            let addr = direct_addr(
                v4(1, 0, idx as u8, 1),
                FIRST_PORT + u16::try_from(idx).unwrap(),
            );
            let connected_epoch_secs = TEST_NOW + u64::try_from(idx).unwrap() + 1;
            cache.peers.push(CachedPeer {
                peer_id: peer,
                direct_addresses: vec![addr.with_peer_id(peer)],
                first_connected_epoch_secs: connected_epoch_secs,
                last_connected_epoch_secs: connected_epoch_secs,
            });
        }

        cache.normalize(&diversity, TEST_K_VALUE);

        assert_eq!(cache.peers.len(), CLIENT_PEER_CACHE_MAX_PEERS);
        assert!(
            cache
                .peers
                .iter()
                .any(|peer| peer.peer_id == old_distant_peer),
            "old distant peer must be retained ahead of one newer clustered peer"
        );
        assert_eq!(
            cache
                .peers
                .iter()
                .filter(|peer| peer.peer_id.as_bytes()[0] == 0)
                .count(),
            CLIENT_PEER_CACHE_MAX_PEERS - 1
        );
    }

    #[test]
    fn cache_applies_exact_ip_limit() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::default();

        for idx in 0..EXACT_IP_ATTEMPTS {
            cache.upsert_connected_peer(
                peer_id(idx),
                vec![direct_addr(v4(203, 0, 113, 1), FIRST_PORT + u16::from(idx))],
                TEST_NOW + u64::from(idx),
                &diversity,
                TEST_K_VALUE,
            );
        }

        assert_eq!(cache.peers.len(), DEFAULT_MAX_PER_EXACT_IP);
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(2)));
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(1)));
        assert!(!cache.peers.iter().any(|peer| peer.peer_id == peer_id(0)));
    }

    #[test]
    fn cache_applies_subnet_limit() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::default();

        for idx in 0..SUBNET_ATTEMPTS {
            cache.upsert_connected_peer(
                peer_id(idx),
                vec![direct_addr(
                    v4(198, 51, 100, idx),
                    FIRST_PORT + u16::from(idx),
                )],
                TEST_NOW + u64::from(idx),
                &diversity,
                TEST_K_VALUE,
            );
        }

        assert_eq!(cache.peers.len(), default_subnet_limit(TEST_K_VALUE));
        assert!(cache.peers.iter().any(|peer| peer.peer_id == peer_id(5)));
        assert!(!cache.peers.iter().any(|peer| peer.peer_id == peer_id(0)));
    }

    #[test]
    fn cache_rejects_peers_without_dialable_direct_addresses() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        let changed =
            cache.upsert_connected_peer(peer_id(1), Vec::new(), TEST_NOW, &diversity, TEST_K_VALUE);

        assert!(!changed);
        assert!(cache.peers.is_empty());
    }

    #[test]
    fn cached_bootstrap_addresses_round_robin_peer_id_sectors() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        cache.upsert_connected_peer(
            peer_id(0x01),
            vec![direct_addr(v4(1, 0, 0, 1), FIRST_PORT)],
            TEST_NOW,
            &diversity,
            TEST_K_VALUE,
        );
        cache.upsert_connected_peer(
            peer_id(0x02),
            vec![direct_addr(v4(1, 0, 0, 2), FIRST_PORT + 1)],
            TEST_NOW + 1,
            &diversity,
            TEST_K_VALUE,
        );
        cache.upsert_connected_peer(
            peer_id(0xf0),
            vec![direct_addr(v6(0x2001, 1), FIRST_PORT + 2)],
            TEST_NOW + 2,
            &diversity,
            TEST_K_VALUE,
        );

        let addresses = cache.bootstrap_addresses(
            BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT,
            BootstrapAddressFilter::All,
        );

        assert_eq!(addresses.len(), 3);
        assert_eq!(
            addresses[0].dialable_socket_addr().unwrap().ip(),
            v4(1, 0, 0, 2)
        );
        assert_eq!(
            addresses[1].dialable_socket_addr().unwrap().ip(),
            v6(0x2001, 1)
        );
        assert_eq!(
            addresses[2].dialable_socket_addr().unwrap().ip(),
            v4(1, 0, 0, 1)
        );
    }

    #[test]
    fn cached_addresses_are_stored_with_peer_id_suffix() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        cache.upsert_connected_peer(
            peer_id(1),
            vec![direct_addr(v4(203, 0, 113, 10), FIRST_PORT)],
            TEST_NOW,
            &diversity,
            TEST_K_VALUE,
        );

        let addr = cache.peers[0].direct_addresses[0].clone();
        assert_eq!(addr.peer_id(), Some(&peer_id(1)));
    }

    #[test]
    fn cached_bootstrap_addresses_respect_ipv4_only_filter() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        let peer = peer_id(1);
        let ipv6_addr = direct_addr(v6(0x2001, 1), FIRST_PORT);
        let ipv4_addr = direct_addr(v4(203, 0, 113, 10), FIRST_PORT + 1);
        cache.upsert_connected_peer(
            peer,
            vec![ipv6_addr.clone(), ipv4_addr.clone()],
            TEST_NOW,
            &diversity,
            TEST_K_VALUE,
        );

        let all_addresses =
            cache.bootstrap_addresses(CLIENT_PEER_CACHE_MAX_PEERS, BootstrapAddressFilter::All);
        assert_eq!(all_addresses, vec![ipv6_addr.with_peer_id(peer)]);

        let ipv4_addresses = cache.bootstrap_addresses(
            CLIENT_PEER_CACHE_MAX_PEERS,
            BootstrapAddressFilter::Ipv4Only,
        );
        assert_eq!(ipv4_addresses, vec![ipv4_addr.with_peer_id(peer)]);
    }

    #[test]
    fn select_bootstrap_peers_orders_configured_after_cached_fallback() {
        let first_cached = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 20), FIRST_PORT))
            .with_peer_id(peer_id(1));
        let second_cached = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 21), FIRST_PORT))
            .with_peer_id(peer_id(2));
        let configured = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 22), FIRST_PORT));

        let selected = select_bootstrap_peers(
            vec![first_cached.clone(), second_cached.clone()],
            vec![configured.clone()],
        );

        assert_eq!(selected, vec![first_cached, second_cached, configured]);
    }

    #[test]
    fn select_bootstrap_peers_tries_the_configured_seeds_in_a_random_order() {
        let cached = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 20), FIRST_PORT))
            .with_peer_id(peer_id(1));
        let configured: Vec<MultiAddr> = (0..16u8)
            .map(|n| MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 100 + n), FIRST_PORT)))
            .collect();
        let mut firsts = HashSet::new();
        for _ in 0..200 {
            let selected = select_bootstrap_peers(vec![cached.clone()], configured.clone());
            // The cached peer still goes first, and every seed is there once.
            assert_eq!(selected[0], cached);
            let mut seeds = selected[1..].to_vec();
            seeds.sort_by_key(ToString::to_string);
            let mut expected = configured.clone();
            expected.sort_by_key(ToString::to_string);
            assert_eq!(seeds, expected);
            firsts.insert(selected[1].to_string());
        }
        // Not the same seed first every time.
        assert!(firsts.len() > 1, "{firsts:?}");
    }

    #[test]
    fn select_bootstrap_peers_uses_configured_when_cache_empty() {
        let configured = MultiAddr::quic(SocketAddr::new(v4(203, 0, 113, 21), FIRST_PORT));

        let selected = select_bootstrap_peers(Vec::new(), vec![configured.clone()]);

        assert_eq!(selected, vec![configured]);
    }

    /// A peer cache Autonomi's `ant` left in the data directory, whose peers
    /// would be dialled before darwin's seeds, is not read: darwin's cache is
    /// its own file.
    #[test]
    fn a_peer_cache_left_by_autonomis_ant_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = ClientPeerCacheFile::empty();
        cache.upsert_connected_peer(
            peer_id(1),
            vec![direct_addr(v4(203, 0, 113, 10), FIRST_PORT)],
            TEST_NOW,
            &IPDiversityConfig::permissive(),
            TEST_K_VALUE,
        );
        cache.save(&dir.path().join("client_peer_cache.json"));

        let path = cache_path_in(dir.path());
        assert_eq!(path.file_name().unwrap(), "darwin_client_peer_cache.json");
        assert!(cached_bootstrap_peers(&path, TEST_K_VALUE).is_empty());

        // The same cache under darwin's name is read.
        cache.save(&path);
        assert_eq!(cached_bootstrap_peers(&path, TEST_K_VALUE).len(), 1);
        if let Some(path) = cache_path() {
            assert_eq!(path.file_name().unwrap(), "darwin_client_peer_cache.json");
        }
    }

    #[test]
    fn cached_bootstrap_peers_include_all_usable_cached_peers() {
        let mut cache = ClientPeerCacheFile::empty();
        let diversity = IPDiversityConfig::permissive();

        for idx in 0..BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT + 1 {
            cache.upsert_connected_peer(
                peer_id(idx as u8),
                vec![direct_addr(
                    v4(1, 0, idx as u8, 1),
                    FIRST_PORT + u16::try_from(idx).unwrap(),
                )],
                TEST_NOW + u64::try_from(idx).unwrap(),
                &diversity,
                TEST_K_VALUE,
            );
        }

        let addresses =
            cache.bootstrap_addresses(CLIENT_PEER_CACHE_MAX_PEERS, BootstrapAddressFilter::All);

        assert_eq!(addresses.len(), BOOTSTRAP_ROUND_ROBIN_TEST_LIMIT + 1);
    }
}
