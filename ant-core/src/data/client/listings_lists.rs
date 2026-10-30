//! The lists an operator may give the listings producer
//! (`darwin listings serve`), and the file of the entries it holds.
//!
//! - **A hide list** (`--hide-list`): addresses the producer publishes
//!   nothing of. A hidden address has no entry, support, row or feed record
//!   in any published file. The network keeps the file and its listing
//!   whatever the list says: it changes only what this producer publishes.
//! - **A cleared list** (`--hold-until-cleared`): with it, a readable entry
//!   the producer hasn't published yet is held, published in no file, until
//!   its address is on the cleared list; then it is published at its own
//!   key, keeping its listing time. Entries published before are kept.
//!   Unreadable entries are never held. An address on both lists is hidden.
//! - **The held file** (`--held-file`): the entries held, each as its
//!   address's shard would hold it, with its data map and when it was first
//!   held, written whole at every cycle for whatever decides what to clear.
//!   It is never in the output directory.
//!
//! Both lists are in the same format: one address per line, as 64 hex digits
//! in any case, with or without `0x`, `#` starting a comment, blank lines
//! ignored ([`AddressList::parse`]). A line that isn't an address is skipped,
//! and only its number is logged. Each list's file is looked at again at the
//! start of each cycle and before each publication between cycles, and read
//! again when its modification time or length changed. The last list read is
//! kept in the producer's store: a file that is missing or can't be read keeps
//! it, across restarts too, with one warning for as long as it stays so.

use std::collections::HashSet;
use std::fs::Metadata;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use ant_protocol::XorName;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::listings_v1::ShardEntry;
use crate::data::error::{Error, Result};

/// The format of the hide list and the cleared list.
#[derive(Debug, Clone, Copy)]
pub struct AddressList;

impl AddressList {
    /// The addresses in `text`, a list, and the numbers (from 1) of its lines
    /// that aren't one. Anything after a `#` is a comment, and blank lines
    /// are ignored. An address is 64 hex digits, in any case, after any
    /// leading `0x`, with nothing else on its line but spaces and a comment.
    #[must_use]
    pub fn parse(text: &str) -> (HashSet<XorName>, Vec<usize>) {
        let mut addresses = HashSet::new();
        let mut skipped = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let entry = line.split_once('#').map_or(line, |(entry, _)| entry).trim();
            if entry.is_empty() {
                continue;
            }
            match hex::decode(entry.trim_start_matches("0x"))
                .ok()
                .and_then(|bytes| XorName::try_from(bytes).ok())
            {
                Some(address) => {
                    addresses.insert(address);
                }
                None => skipped.push(index + 1),
            }
        }
        (addresses, skipped)
    }
}

/// What the lists say of the entries the producer publishes, as last read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// The hide list's addresses: none if there is no hide list.
    pub hidden: HashSet<XorName>,
    /// The cleared list's addresses, when readable entries are held until
    /// cleared; `None` when they aren't.
    pub cleared: Option<HashSet<XorName>>,
}

impl Rules {
    /// Whether `address` is hidden: published in no file.
    #[must_use]
    pub fn hides(&self, address: &XorName) -> bool {
        self.hidden.contains(address)
    }

    /// Whether the entry at `address` is held, published in no file until
    /// cleared: it is `readable`, not `published` already, not hidden, and
    /// entries are held until cleared but its address isn't cleared.
    #[must_use]
    pub fn holds(&self, address: &XorName, readable: bool, published: bool) -> bool {
        readable
            && !published
            && !self.hides(address)
            && self
                .cleared
                .as_ref()
                .is_some_and(|cleared| !cleared.contains(address))
    }

    /// Whether entries are held until cleared.
    #[must_use]
    pub fn holding(&self) -> bool {
        self.cleared.is_some()
    }
}

/// An entry held, as the held file and the producer's store keep it: as its
/// address's shard would hold it, and when it was first held, in Unix
/// seconds (when the publication that first held it began).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldEntry {
    /// The entry, with its data map.
    #[serde(flatten)]
    pub entry: ShardEntry,
    /// When it was first held.
    pub held_since: u64,
}

/// The held file.
#[derive(Debug, Serialize)]
struct HeldFile<'a> {
    /// When it was written, in Unix seconds.
    generated_at: u64,
    /// The start of the latest cycle in which both lists were looked at and
    /// could be read (changed or not), in Unix seconds; 0 if none was.
    lists_read_at: u64,
    /// The entries held, in address order.
    held: &'a [HeldEntry],
}

/// A list's file, as the producer follows it.
#[derive(Debug)]
pub(crate) struct ListFile {
    /// What the list is, for the log: `hide list` or `cleared list`.
    name: &'static str,
    path: PathBuf,
    /// The file's modification time and length when it was last read.
    stamp: Option<(Option<SystemTime>, u64)>,
    /// Whether it couldn't be read when last looked at: warned of once.
    failing: bool,
}

/// What looking at a list's file found ([`ListFile::look`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Looked {
    /// It is as when it was last read.
    Unchanged,
    /// It changed, and holds these addresses.
    Read(HashSet<XorName>),
    /// It is missing or can't be read: the last list read stays.
    Failed,
}

impl ListFile {
    /// The list `name` in the file at `path`, not read yet.
    pub(crate) fn new(name: &'static str, path: PathBuf) -> Self {
        Self {
            name,
            path,
            stamp: None,
            failing: false,
        }
    }

    /// Look at the file: read it again if its modification time or length
    /// changed since it was last read, or it couldn't be read then. A file
    /// missing or unreadable is warned of once for as long as it stays so,
    /// with the number of addresses of the last list read, `kept`, which
    /// stays.
    pub(crate) fn look(&mut self, kept: usize) -> Looked {
        let read = std::fs::metadata(&self.path).and_then(|meta| {
            let stamp = stamp_of(&meta);
            if self.stamp == Some(stamp) && !self.failing {
                return Ok(None);
            }
            let bytes = std::fs::read(&self.path)?;
            Ok(Some((stamp, bytes)))
        });
        match read {
            Ok(None) => Looked::Unchanged,
            Ok(Some((stamp, bytes))) => {
                let (addresses, skipped) = AddressList::parse(&String::from_utf8_lossy(&bytes));
                if self.failing {
                    info!(
                        "The {} {} can be read again",
                        self.name,
                        self.path.display()
                    );
                }
                info!(
                    "Read the {} {}: {} addresses",
                    self.name,
                    self.path.display(),
                    addresses.len()
                );
                if !skipped.is_empty() {
                    let lines: Vec<String> = skipped.iter().map(ToString::to_string).collect();
                    warn!(
                        "The {} {}: lines {} aren't addresses, and are skipped",
                        self.name,
                        self.path.display(),
                        lines.join(", ")
                    );
                }
                self.stamp = Some(stamp);
                self.failing = false;
                Looked::Read(addresses)
            }
            Err(e) => {
                if !self.failing {
                    warn!(
                        "The {} {} can't be read ({e}): the last one read stays, with {kept} \
                         addresses",
                        self.name,
                        self.path.display()
                    );
                }
                self.failing = true;
                Looked::Failed
            }
        }
    }
}

/// A file's modification time and length.
fn stamp_of(meta: &Metadata) -> (Option<SystemTime>, u64) {
    (meta.modified().ok(), meta.len())
}

/// Write the held file at `path`, whole: `held` at `generated_at`, with
/// `lists_read_at` ([`HeldFile`]), readable by its owner and group only.
///
/// # Errors
///
/// If it can't be written.
pub(crate) fn write_held_file(
    path: &Path,
    generated_at: u64,
    lists_read_at: u64,
    held: &[HeldEntry],
) -> Result<()> {
    let file = HeldFile {
        generated_at,
        lists_read_at,
        held,
    };
    let bytes = serde_json::to_vec(&file)
        .map_err(|e| Error::Serialization(format!("the held file: {e}")))?;
    write_atomic(path, &bytes)
}

/// Write `bytes` to `path` whole: to a file beside it, flushed to disk, then
/// renamed over it, so a reader never sees part of it. On Unix the file is
/// readable by its owner and group only (mode 0640).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let failed = |e: std::io::Error| {
        Error::Storage(format!(
            "could not write the held file {}: {e}",
            path.display()
        ))
    };
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(failed)?;
    file.write_all(bytes).map_err(failed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))
            .map_err(failed)?;
    }
    file.as_file().sync_all().map_err(failed)?;
    file.persist(path).map_err(|e| failed(e.error))?;
    Ok(())
}

/// `path` made absolute, with `.` and `..` taken out, and the part of it that
/// exists resolved (links followed): so two paths to the same place compare
/// equal, and one inside a directory starts with it, whether or not they
/// exist yet.
///
/// # Errors
///
/// If the current directory can't be read.
pub(crate) fn resolved(path: &Path) -> Result<PathBuf> {
    let mut lexical = PathBuf::new();
    for component in std::path::absolute(path)?.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            other => lexical.push(other),
        }
    }
    let mut rest = Vec::new();
    let mut base = lexical.clone();
    loop {
        if let Ok(mut found) = base.canonicalize() {
            for name in rest.iter().rev() {
                found.push(name);
            }
            return Ok(found);
        }
        match base.file_name() {
            Some(name) => {
                rest.push(name.to_os_string());
                base.pop();
            }
            None => return Ok(lexical),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_format_matches_the_gateway() {
        let (a, b, c) = ([0xab; 32], [0x0c; 32], [0x5e; 32]);
        let text = format!(
            "# A list\n\n{}\n  0x{}  # a reason\r\n{}\nnot an address\n{}\n{} {}\n# {}\n0X{}\n",
            hex::encode(a),
            hex::encode(b),
            // Any case.
            hex::encode(c).to_uppercase(),
            // Too short.
            &hex::encode(a)[..62],
            // Two on one line.
            hex::encode(a),
            hex::encode(b),
            // Commented out.
            hex::encode([0x77; 32]),
            // Only a lowercase `0x` is a prefix.
            hex::encode([0x66; 32]),
        );
        let (addresses, skipped) = AddressList::parse(&text);
        assert_eq!(addresses, HashSet::from([a, b, c]));
        assert_eq!(skipped, vec![6, 7, 8, 10]);
        assert_eq!(AddressList::parse(""), (HashSet::new(), Vec::new()));
        // A lone `0x` and a comment alone are a bad line and nothing.
        assert_eq!(
            AddressList::parse("0x\n   # only a comment\n"),
            (HashSet::new(), vec![1])
        );
    }

    #[test]
    fn an_address_on_both_lists_is_hidden() {
        let x: XorName = [0x42; 32];
        let rules = Rules {
            hidden: HashSet::from([x]),
            cleared: Some(HashSet::from([x])),
        };
        assert!(rules.hides(&x));
        assert!(!rules.holds(&x, true, false), "hidden, not held");
        // Cleared alone, it is published; on neither, held.
        let cleared = Rules {
            hidden: HashSet::new(),
            cleared: Some(HashSet::from([x])),
        };
        assert!(!cleared.hides(&x) && !cleared.holds(&x, true, false));
        let neither = Rules {
            hidden: HashSet::new(),
            cleared: Some(HashSet::new()),
        };
        assert!(neither.holds(&x, true, false));
        // Never one published already, nor one unreadable, nor without a
        // cleared list.
        assert!(!neither.holds(&x, true, true));
        assert!(!neither.holds(&x, false, false));
        assert!(!Rules::default().holds(&x, true, false));
    }

    #[test]
    fn a_list_file_is_read_again_only_when_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("list.txt");
        let mut file = ListFile::new("hide list", path.clone());
        assert_eq!(file.look(0), Looked::Failed, "missing");
        std::fs::write(&path, format!("{}\n", hex::encode([1u8; 32]))).unwrap();
        assert_eq!(file.look(0), Looked::Read(HashSet::from([[1u8; 32]])));
        assert_eq!(file.look(1), Looked::Unchanged);
        std::fs::write(
            &path,
            format!("{}\n{}\n", hex::encode([1u8; 32]), hex::encode([2u8; 32])),
        )
        .unwrap();
        assert_eq!(
            file.look(1),
            Looked::Read(HashSet::from([[1u8; 32], [2u8; 32]]))
        );
        std::fs::remove_file(&path).unwrap();
        assert_eq!(file.look(2), Looked::Failed);
        assert_eq!(file.look(2), Looked::Failed);
    }

    #[test]
    fn a_path_inside_a_directory_resolves_inside_it_whether_or_not_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let inside = out.join("sub").join("..").join("held.json");
        assert!(resolved(&inside)
            .unwrap()
            .starts_with(resolved(&out).unwrap()));
        std::fs::create_dir_all(out.join("sub")).unwrap();
        assert!(resolved(&inside)
            .unwrap()
            .starts_with(resolved(&out).unwrap()));
        let beside = dir.path().join("out-held.json");
        assert!(!resolved(&beside)
            .unwrap()
            .starts_with(resolved(&out).unwrap()));
    }
}
