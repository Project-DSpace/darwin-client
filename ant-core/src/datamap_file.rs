//! Persisted DataMap file format.
//!
//! A `.datamap` file is the on-disk form of a `self_encryption::DataMap` that
//! private uploads need in order to be downloaded later. Every callsite that
//! writes one (today: `ant-cli` and `ant-gui`) routes through this module so
//! the wire format and naming convention stay consistent.
//!
//! # Wire format
//!
//! Canonical: msgpack (`rmp_serde`). The file contains the bare serialized
//! `DataMap` — no header, no envelope. This matches the format `ant-cli` has
//! always written; `ant-gui` adopts it here.
//!
//! For backwards compatibility, [`read_datamap`] also accepts the legacy JSON
//! format that older `ant-gui` versions wrote. Format detection is by sniffing
//! the first byte of the file:
//!   - `0x7B` (`{`) → JSON (legacy ant-gui)
//!   - else        → msgpack (canonical)
//!
//! A future envelope format wrapping the DataMap with metadata (e.g. original
//! filename, version) would be signalled by a magic byte that is neither `{`
//! nor a valid msgpack initial byte. The reserved byte for that purpose is
//! `0xC1`, which is unused in the msgpack spec.
//!
//! # Naming convention
//!
//! The original filename is preserved verbatim with `.datamap` appended:
//! `holiday.jpg` → `holiday.jpg.datamap`, `Makefile` → `Makefile.datamap`,
//! `archive.tar.gz` → `archive.tar.gz.datamap`. Files without an extension
//! are handled naturally because we append rather than replace.
//!
//! On collision under [`CollisionPolicy::NumericSuffix`], a `-N` (starting at
//! 2) is inserted before the `.datamap` extension: `holiday.jpg-2.datamap`,
//! `holiday.jpg-3.datamap`, …

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use self_encryption::DataMap;
use tempfile::NamedTempFile;

use crate::data::error::{Error, Result};

/// Extension appended to every persisted datamap file.
pub const DATAMAP_EXTENSION: &str = "datamap";

/// Cap on collision-suffix attempts before [`write_datamap`] gives up.
///
/// In normal use a directory will see at most a handful of repeated
/// uploads; this bound just protects against pathological state (e.g.
/// thousands of stale entries) so we fail fast instead of looping.
/// Set generously (1000) so legitimate users with many backups of the
/// same file don't hit a confusing error before pathological state does.
const MAX_COLLISION_ATTEMPTS: u32 = 1000;

/// Behaviour when a target datamap filename already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionPolicy {
    /// Replace the existing file. Used by `ant-cli` when invoked with
    /// `--overwrite` to preserve its pre-`feat/datamap-fs-helper` behaviour.
    Overwrite,
    /// Insert `-N` (starting at 2) between the filename and `.datamap`.
    /// `holiday.jpg.datamap` → `holiday.jpg-2.datamap` → `-3` → … capped at
    /// `MAX_COLLISION_ATTEMPTS` (1000).
    NumericSuffix,
}

/// Construct the canonical datamap filename for an arbitrary input filename.
///
/// Appends `.datamap` without replacing any existing extension, then runs
/// the result through filename sanitization (alphanumerics + a small set
/// of punctuation kept; everything else replaced with `_`) so platform-
/// illegal characters don't reach the filesystem. Falls back to
/// `datamap.datamap` when the input sanitizes to an empty string.
///
/// Pure function: takes only the basename, never a path with separators.
pub fn datamap_filename_for(original_name: &str) -> String {
    let sanitized = sanitize_filename(original_name);
    if sanitized.is_empty() {
        format!("datamap.{DATAMAP_EXTENSION}")
    } else {
        format!("{sanitized}.{DATAMAP_EXTENSION}")
    }
}

/// Inverse of [`datamap_filename_for`] for download UX. Strips a single
/// trailing `.datamap` from the basename of `path`.
///
/// Returns `None` when `path` has no UTF-8 basename, doesn't end in
/// `.datamap`, or would produce an empty result. Does *not* attempt to undo
/// `-N` collision suffixes — `holiday.jpg-2.datamap` returns `holiday.jpg-2`
/// rather than `holiday.jpg`. The collision suffix is a write-side artifact;
/// callers can offer the literal stem as a default and let users edit.
pub fn original_name_from_datamap(path: &Path) -> Option<OsString> {
    let basename = path.file_name()?.to_str()?;
    let stripped = basename.strip_suffix(&format!(".{DATAMAP_EXTENSION}"))?;
    if stripped.is_empty() {
        None
    } else {
        Some(OsString::from(stripped))
    }
}

/// Write `dm` to `dir` using the canonical naming and the given collision
/// policy. Returns the absolute path to the written file.
///
/// Atomicity: writes to a tempfile in `dir`, fsyncs the file, renames into
/// place, then (on Unix) best-effort-fsyncs the parent directory. A crash
/// at any point cannot leave a half-serialized datamap at the target
/// path, and on Unix the rename itself is durable across power loss
/// because the directory entry is flushed. The tempfile is created on
/// the same filesystem as `dir` to keep the rename atomic. Windows
/// relies on NTFS metadata journaling for rename durability — we do not
/// fsync the directory there because Windows does not expose that
/// operation through `std::fs`.
pub fn write_datamap(
    dir: &Path,
    original_name: &str,
    dm: &DataMap,
    policy: CollisionPolicy,
) -> Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let bytes = rmp_serde::to_vec(dm)
        .map_err(|e| Error::Serialization(format!("DataMap msgpack encode failed: {e}")))?;
    let base_filename = datamap_filename_for(original_name);
    let target = reserve_target_path(dir, &base_filename, policy)?;
    write_atomic(dir, &target, &bytes)?;
    Ok(target)
}

/// Read a persisted datamap, auto-detecting msgpack vs legacy JSON.
pub fn read_datamap(path: &Path) -> Result<DataMap> {
    let bytes = fs::read(path)?;
    if bytes.first() == Some(&b'{') {
        // Legacy JSON written by ant-gui versions prior to the shared helper.
        serde_json::from_slice::<DataMap>(&bytes)
            .map_err(|e| Error::Serialization(format!("DataMap JSON decode failed: {e}")))
    } else {
        rmp_serde::from_slice::<DataMap>(&bytes)
            .map_err(|e| Error::Serialization(format!("DataMap msgpack decode failed: {e}")))
    }
}

/// Reduce an arbitrary filename to one safe to place on disk: keep
/// alphanumerics and a small set of common punctuation, replace every other
/// character with `_`, then trim surrounding whitespace. Leading/trailing
/// dots are intentionally preserved so dotfiles like `.bashrc` survive.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '(' | ')') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn reserve_target_path(
    dir: &Path,
    base_filename: &str,
    policy: CollisionPolicy,
) -> Result<PathBuf> {
    match policy {
        CollisionPolicy::Overwrite => Ok(dir.join(base_filename)),
        CollisionPolicy::NumericSuffix => {
            // base_filename is e.g. `photo.jpg.datamap`. The collision suffix
            // sits between the trailing `.datamap` and the rest of the name:
            // `photo.jpg-2.datamap`, never `photo-2.jpg.datamap`.
            let stem = base_filename
                .strip_suffix(&format!(".{DATAMAP_EXTENSION}"))
                .unwrap_or(base_filename);
            for attempt in 0..MAX_COLLISION_ATTEMPTS {
                let candidate = if attempt == 0 {
                    base_filename.to_string()
                } else {
                    format!("{stem}-{}.{DATAMAP_EXTENSION}", attempt + 1)
                };
                let path = dir.join(&candidate);
                if !path.exists() {
                    return Ok(path);
                }
            }
            Err(Error::Storage(format!(
                "Unable to reserve a free datamap filename after {MAX_COLLISION_ATTEMPTS} attempts in {}",
                dir.display()
            )))
        }
    }
}

fn write_atomic(dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(target).map_err(|e| Error::Io(e.error))?;
    // On Unix, fsync the parent directory so the rename itself survives
    // a crash. On ext4 (default mount opts) and btrfs the rename can
    // otherwise be lost if the directory entry hasn't reached disk. This
    // is best-effort — a failure here means we wrote a valid datamap but
    // can't prove the rename is durable, which is no worse than where we
    // were before the call. Windows has no portable directory-fsync, so
    // we skip it there and lean on NTFS metadata journaling.
    #[cfg(unix)]
    {
        if let Ok(dir_handle) = fs::File::open(dir) {
            let _ = dir_handle.sync_all();
        }
    }
    Ok(())
}

/// Extension of the envelope record saved with an upload that stored an
/// envelope: `holiday.jpg.record`, next to `holiday.jpg.datamap` for a
/// private upload.
///
/// The record is an [`ant_listings::EnvelopeProof`] as text
/// ([`ant_listings::EnvelopeProof::to_hex`]) and a newline: the envelope, its
/// payment's tx hash and paid quote, and for a private file the data map and
/// the salt of the envelope's salted hash. It proves the upload from the
/// chain alone, so keep it as safe as the data map.
pub const RECORD_EXTENSION: &str = "record";

/// Paths of the files [`write_upload_files`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadFiles {
    /// The `.datamap` file, if a data map was written.
    pub datamap: Option<PathBuf>,
    /// The `.record` file, if a record was written.
    pub record: Option<PathBuf>,
}

/// Write an upload's local files in `dir` under one name: its data map
/// (`holiday.jpg.datamap`) and its envelope record (`holiday.jpg.record`),
/// either of which may be absent. Under [`CollisionPolicy::NumericSuffix`]
/// both get the same `-N` suffix, the first free for both, so a record is
/// never written over an older one. The record is written first.
pub fn write_upload_files(
    dir: &Path,
    original_name: &str,
    data_map: Option<&DataMap>,
    record: Option<&ant_listings::EnvelopeProof>,
    policy: CollisionPolicy,
) -> Result<UploadFiles> {
    fs::create_dir_all(dir)?;
    let base = datamap_filename_for(original_name);
    let base = base
        .strip_suffix(&format!(".{DATAMAP_EXTENSION}"))
        .unwrap_or(&base);
    let mut extensions = Vec::new();
    if data_map.is_some() {
        extensions.push(DATAMAP_EXTENSION);
    }
    if record.is_some() {
        extensions.push(RECORD_EXTENSION);
    }
    let stem = reserve_stem(dir, base, &extensions, policy)?;
    let record = record
        .map(|record| -> Result<PathBuf> {
            let path = dir.join(format!("{stem}.{RECORD_EXTENSION}"));
            write_atomic(dir, &path, &record_text(record)?)?;
            Ok(path)
        })
        .transpose()?;
    let datamap = data_map
        .map(|dm| -> Result<PathBuf> {
            let bytes = rmp_serde::to_vec(dm)
                .map_err(|e| Error::Serialization(format!("DataMap msgpack encode failed: {e}")))?;
            let path = dir.join(format!("{stem}.{DATAMAP_EXTENSION}"));
            write_atomic(dir, &path, &bytes)?;
            Ok(path)
        })
        .transpose()?;
    Ok(UploadFiles { datamap, record })
}

/// The record path that goes with a datamap path: `holiday.jpg-2.datamap`
/// gives `holiday.jpg-2.record`.
pub fn record_path_for(datamap: &Path) -> PathBuf {
    let name = datamap
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name
        .strip_suffix(&format!(".{DATAMAP_EXTENSION}"))
        .unwrap_or(&name);
    datamap.with_file_name(format!("{stem}.{RECORD_EXTENSION}"))
}

/// Write `record` to `path` as text, atomically, replacing any file there.
pub fn write_record(path: &Path, record: &ant_listings::EnvelopeProof) -> Result<()> {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    write_atomic(dir, path, &record_text(record)?)
}

/// Read a record or proof written by [`write_upload_files`] or
/// [`write_record`] (or the text of one pasted into a file). Doesn't check
/// it: [`ant_listings::check_proof`] does.
pub fn read_record(path: &Path) -> Result<ant_listings::EnvelopeProof> {
    let text = fs::read_to_string(path)?;
    ant_listings::EnvelopeProof::from_hex(&text)
        .map_err(|e| Error::Serialization(format!("record decode failed: {e}")))
}

fn record_text(record: &ant_listings::EnvelopeProof) -> Result<Vec<u8>> {
    let mut text = record
        .to_hex()
        .map_err(|e| Error::Serialization(format!("record encode failed: {e}")))?;
    text.push('\n');
    Ok(text.into_bytes())
}

/// The first stem free for every one of `extensions` in `dir`.
fn reserve_stem(
    dir: &Path,
    base: &str,
    extensions: &[&str],
    policy: CollisionPolicy,
) -> Result<String> {
    if policy == CollisionPolicy::Overwrite {
        return Ok(base.to_string());
    }
    for attempt in 0..MAX_COLLISION_ATTEMPTS {
        let candidate = if attempt == 0 {
            base.to_string()
        } else {
            format!("{base}-{}", attempt + 1)
        };
        if extensions
            .iter()
            .all(|extension| !dir.join(format!("{candidate}.{extension}")).exists())
        {
            return Ok(candidate);
        }
    }
    Err(Error::Storage(format!(
        "Unable to reserve a free upload filename after {MAX_COLLISION_ATTEMPTS} attempts in {}",
        dir.display()
    )))
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use ant_listings::{Envelope, EnvelopeProof, Metadata, ShownFields};
    use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
    use ant_protocol::transport::NodeIdentity;

    fn data_map() -> DataMap {
        let (map, _) =
            self_encryption::encrypt(bytes::Bytes::from(vec![3u8; 5000])).expect("encrypt");
        map
    }

    /// A private upload's record: a withheld envelope, a signed quote for it,
    /// and the reveal.
    fn record(map: &DataMap) -> EnvelopeProof {
        let salt = [4u8; 32];
        let envelope = Envelope::withheld(map, &salt, Metadata::default(), ShownFields::ALL, false)
            .expect("envelope");
        let identity = NodeIdentity::generate().expect("identity");
        let mut quote = PaymentQuote {
            content: xor_name::XorName(envelope.address()),
            timestamp: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
            price: Amount::from(10),
            rewards_address: RewardsAddress::new([1; 20]),
            pub_key: identity.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
            committed_key_count: 0,
            commitment_pin: None,
        };
        quote.signature = identity
            .sign(&quote.bytes_for_sig())
            .expect("sign")
            .as_bytes()
            .to_vec();
        EnvelopeProof::new(&envelope, [8; 32], &quote)
            .expect("proof")
            .with_reveal(ant_listings::encode_data_map(map).expect("map"), salt)
            .expect("reveal")
    }

    #[test]
    fn records_round_trip_next_to_their_datamap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let map = data_map();
        let record = record(&map);
        let files = write_upload_files(
            dir.path(),
            "notes.txt",
            Some(&map),
            Some(&record),
            CollisionPolicy::NumericSuffix,
        )
        .expect("write");
        let datamap = files.datamap.expect("datamap");
        let saved = files.record.expect("record");
        assert_eq!(datamap, dir.path().join("notes.txt.datamap"));
        assert_eq!(saved, dir.path().join("notes.txt.record"));
        assert_eq!(record_path_for(&datamap), saved);
        // The datamap format is unchanged, and the record reads back exactly.
        assert!(read_datamap(&datamap).expect("datamap reads") == map);
        assert_eq!(read_record(&saved).expect("record reads"), record);
        let text = fs::read_to_string(&saved).expect("text");
        assert!(text.ends_with('\n'));
        assert_eq!(text.trim(), record.to_hex().expect("hex"));
    }

    /// A data map or a private file's record can read the file. They are
    /// written through tempfile, which creates files owner-only (0600) on
    /// Unix; this pins that, with no chmod that could fail a write made after
    /// the upload was paid.
    #[cfg(unix)]
    #[test]
    fn datamaps_and_records_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let map = data_map();
        let record = record(&map);
        let files = write_upload_files(
            dir.path(),
            "notes.txt",
            Some(&map),
            Some(&record),
            CollisionPolicy::NumericSuffix,
        )
        .expect("write");
        let copy = dir.path().join("copy.record");
        write_record(&copy, &record).expect("record copy");
        for path in [
            files.datamap.expect("datamap"),
            files.record.expect("record"),
            copy,
        ] {
            let mode = fs::metadata(&path).expect("metadata").permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} is {mode:o}", path.display());
        }
    }

    #[test]
    fn a_suffix_is_shared_and_never_overwrites_a_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let map = data_map();
        let record = record(&map);
        // An old record without its datamap still holds a salt: keep it.
        fs::write(dir.path().join("notes.txt.record"), "old").expect("old record");
        let files = write_upload_files(
            dir.path(),
            "notes.txt",
            Some(&map),
            Some(&record),
            CollisionPolicy::NumericSuffix,
        )
        .expect("write");
        assert_eq!(files.datamap, Some(dir.path().join("notes.txt-2.datamap")));
        assert_eq!(files.record, Some(dir.path().join("notes.txt-2.record")));
        assert_eq!(
            fs::read_to_string(dir.path().join("notes.txt.record")).expect("old"),
            "old"
        );
        // A record alone, for a readable upload.
        let files = write_upload_files(
            dir.path(),
            "notes.txt",
            None,
            Some(&record),
            CollisionPolicy::NumericSuffix,
        )
        .expect("write");
        assert_eq!(files.datamap, None);
        assert_eq!(files.record, Some(dir.path().join("notes.txt-3.record")));
        // A datamap alone, as before.
        let files = write_upload_files(
            dir.path(),
            "other.bin",
            Some(&map),
            None,
            CollisionPolicy::NumericSuffix,
        )
        .expect("write");
        assert_eq!(files.datamap, Some(dir.path().join("other.bin.datamap")));
        assert_eq!(files.record, None);
    }

    #[test]
    fn a_record_written_anywhere_reads_back_and_garbage_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let map = data_map();
        let record = record(&map);
        let path = dir.path().join("handed-over.proof");
        write_record(&path, &record).expect("write");
        assert_eq!(read_record(&path).expect("read"), record);
        fs::write(&path, "not hex").expect("garbage");
        assert!(read_record(&path).is_err());
    }
}
