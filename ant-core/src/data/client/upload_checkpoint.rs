// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An upload's checkpoint on disk: the files the upload engine keeps for an
//! upload, or for a record paid on its own, until it is stored.
//!
//! Each checkpoint has a 64-hex stem, and up to four files
//! ([`UPLOAD_CHECKPOINT_EXTENSIONS`]):
//!
//! - `<stem>.msgpack`, the checkpoint without its proofs, in the format
//!   [`UploadState::checkpoint`] describes ([`CHECKPOINT_MAGIC`] first). It
//!   is small, and rewritten whole, through a temporary file, at each step;
//! - `<stem>.proofs`, the paid proofs, appended one record at a time, so a
//!   proof is written once, not again at every step: [`PROOF_FILE_MAGIC`],
//!   then records of a 32-byte address, a 4-byte little-endian length, the
//!   proof, and the first 8 bytes of a BLAKE3 hash of the three. A length of
//!   0 forgets the address's proof. A torn last record, from a crash while
//!   it was written, is left out when the file is read, and cut off before
//!   the next record is appended;
//! - `<stem>.salt`, a private upload's envelope salt;
//! - `<stem>.lock`, held while the checkpoint is in use.
//!
//! A checkpoint written before the magic, one msgpack file holding every
//! proof, is migrated when it is opened: its proofs are written to a new
//! proof file first, then the new `.msgpack` replaces the old one by
//! rename, so the old file stays until the new one is complete.
//!
//! What can't be restored is never deleted: the error names the file and
//! says to keep it, since it may hold a payment that is still to be settled.

use super::upload_state::{UploadState, CHECKPOINT_MAGIC, UNRESUMED_PROOFS_BACKSTOP};
use crate::data::error::{Error, Result};
use ant_protocol::XorName;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::{info, warn};

/// The extension of a checkpoint's main file.
pub const CHECKPOINT_EXTENSION: &str = "msgpack";

/// The extension of a checkpoint's proof file.
pub const PROOFS_EXTENSION: &str = "proofs";

/// The extensions of every file a checkpoint may have, beside its 64-hex
/// stem: the checkpoint, its proofs, a private upload's salt, and its lock.
/// A server that removes what ended uploads left (dspace-gateway's
/// `remove_ended`) removes these, the lock last.
pub const UPLOAD_CHECKPOINT_EXTENSIONS: [&str; 4] =
    [CHECKPOINT_EXTENSION, PROOFS_EXTENSION, "salt", "lock"];

/// What a proof file starts with: "DSPF" and its format version.
pub const PROOF_FILE_MAGIC: [u8; 5] = *b"DSPF\x01";

/// The files a checkpoint whose main file is `checkpoint` may have, in the
/// order of [`UPLOAD_CHECKPOINT_EXTENSIONS`].
#[must_use]
pub fn upload_checkpoint_files(checkpoint: &Path) -> Vec<PathBuf> {
    UPLOAD_CHECKPOINT_EXTENSIONS
        .iter()
        .map(|extension| checkpoint.with_extension(extension))
        .collect()
}

/// What a checkpoint's files hold of its proofs, as last written.
#[derive(Default)]
struct Written {
    /// The serial of each proof the proof file holds.
    proofs: HashMap<XorName, u64>,
    /// How long the proof file is, up to its last whole record; `None` when
    /// it is to be written anew at the next save.
    length: Option<u64>,
}

/// A checkpoint's files (see the module docs). The caller holds its lock.
pub struct UploadCheckpointFiles {
    path: PathBuf,
    written: Mutex<Written>,
}

impl std::fmt::Debug for UploadCheckpointFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadCheckpointFiles")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// The error for a checkpoint at `path` that can't be restored.
fn unrestorable(path: &Path, error: &Error) -> Error {
    Error::InvalidData(format!(
        "the upload checkpoint {} can't be restored ({error}). Don't delete it: it may hold a \
         payment still to be settled. Finish the upload with the client that saved it",
        path.display()
    ))
}

impl UploadCheckpointFiles {
    /// The checkpoint whose main file is `path`, with what it holds (`None`
    /// if there is none): checked, and migrated if it was in the format
    /// before [`CHECKPOINT_MAGIC`].
    ///
    /// # Errors
    ///
    /// Returns an error if it can't be read, or can't be restored: the
    /// error names the file and says to keep it.
    pub fn open(path: PathBuf) -> Result<(Self, Option<UploadState>)> {
        let files = Self {
            path,
            written: Mutex::new(Written::default()),
        };
        let bytes = match std::fs::read(&files.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((files, None));
            }
            Err(error) => return Err(Error::Io(error)),
        };
        let state = files
            .read(&bytes)
            .map_err(|error| unrestorable(&files.path, &error))?;
        Ok((files, Some(state)))
    }

    /// Read the checkpoint from its main file's `bytes` and its proof file.
    fn read(&self, bytes: &[u8]) -> Result<UploadState> {
        let parsed = UploadState::parse(bytes)?;
        if parsed.legacy {
            let state = parsed.state.validated()?;
            info!(
                "Migrating the upload checkpoint {} to the current format",
                self.path.display()
            );
            self.lock_written().length = None;
            self.save(&state)?;
            return Ok(state);
        }
        let mut state = parsed.state;
        let (proofs, length) = read_proofs(&self.proofs_path())?;
        state.add_parsed_proofs(proofs);
        let state = state.validated()?;
        let mut written = self.lock_written();
        written.proofs = state
            .proof_entries()
            .map(|(address, _, serial)| (*address, serial))
            .collect();
        written.length = length;
        Ok(state)
    }

    fn lock_written(&self) -> std::sync::MutexGuard<'_, Written> {
        self.written
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The main file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The proof file's path.
    #[must_use]
    pub fn proofs_path(&self) -> PathBuf {
        self.path.with_extension(PROOFS_EXTENSION)
    }

    /// Save `state`: the proofs it has that the proof file doesn't, then
    /// the rest, whole or not at all.
    ///
    /// # Errors
    ///
    /// Returns an error if a file can't be written.
    pub fn save(&self, state: &UploadState) -> Result<()> {
        let directory = self
            .path
            .parent()
            .ok_or_else(|| Error::Config("missing checkpoint directory".into()))?;
        std::fs::create_dir_all(directory)?;
        {
            let mut written = self.lock_written();
            match written.length {
                None => {
                    // Written anew: the first save, or a migration.
                    let mut bytes = PROOF_FILE_MAGIC.to_vec();
                    let mut proofs = HashMap::new();
                    for (address, proof, serial) in state.proof_entries() {
                        append_record(&mut bytes, address, proof);
                        proofs.insert(*address, serial);
                    }
                    write_whole(&self.proofs_path(), &bytes)?;
                    *written = Written {
                        proofs,
                        length: Some(bytes.len() as u64),
                    };
                }
                Some(length) => {
                    let mut records = Vec::new();
                    let mut changed = Vec::new();
                    for (address, proof, serial) in state.proof_entries() {
                        if written.proofs.get(address) != Some(&serial) {
                            append_record(&mut records, address, proof);
                            changed.push((*address, Some(serial)));
                        }
                    }
                    for address in written.proofs.keys() {
                        if state.proof(address).is_none() {
                            append_record(&mut records, address, &[]);
                            changed.push((*address, None));
                        }
                    }
                    if !records.is_empty() {
                        let mut file = std::fs::OpenOptions::new()
                            .create(true)
                            .truncate(false)
                            .write(true)
                            .open(self.proofs_path())?;
                        // Anything past the last whole record is a torn
                        // record: cut it off.
                        file.set_len(length)?;
                        file.seek(SeekFrom::Start(length))?;
                        file.write_all(&records)?;
                        file.sync_all()?;
                        written.length = Some(length + records.len() as u64);
                        for (address, serial) in changed {
                            match serial {
                                Some(serial) => written.proofs.insert(address, serial),
                                None => written.proofs.remove(&address),
                            };
                        }
                    }
                }
            }
        }
        write_whole(&self.path, &state.checkpoint_without_proofs()?)
    }

    /// Remove the checkpoint and its proofs, once its records are stored:
    /// the main file first, so a crash between the two leaves a proof file
    /// without a checkpoint, which the next checkpoint at this path writes
    /// anew. A file left behind is only logged.
    pub fn remove(&self) {
        for path in [self.path.clone(), self.proofs_path()] {
            if let Err(e) = std::fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("Could not remove {}: {e}", path.display());
                }
            }
        }
        *self.lock_written() = Written::default();
    }
}

/// Append one proof record to `bytes`: `proof` for `address`, or its
/// removal if `proof` is empty.
fn append_record(bytes: &mut Vec<u8>, address: &XorName, proof: &[u8]) {
    let start = bytes.len();
    bytes.extend_from_slice(address);
    bytes.extend_from_slice(&u32::try_from(proof.len()).unwrap_or(u32::MAX).to_le_bytes());
    bytes.extend_from_slice(proof);
    let check = blake3::hash(&bytes[start..]);
    bytes.extend_from_slice(&check.as_bytes()[..8]);
}

/// What a proof file holds: its proofs, and how long it is up to its last
/// whole record (`None` if there is no file, so the next save writes it
/// anew).
type ProofFile = (HashMap<XorName, Vec<u8>>, Option<u64>);

/// The proofs a proof file at `path` holds ([`ProofFile`]).
fn read_proofs(path: &Path) -> Result<ProofFile> {
    let mut bytes = Vec::new();
    match std::fs::File::open(path) {
        Ok(mut file) => {
            file.read_to_end(&mut bytes)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), None));
        }
        Err(error) => return Err(Error::Io(error)),
    }
    let Some(mut rest) = bytes.strip_prefix(&PROOF_FILE_MAGIC) else {
        return Err(Error::InvalidData(format!(
            "{} is not a proof file this client reads",
            path.display()
        )));
    };
    let mut proofs = HashMap::new();
    let mut length = PROOF_FILE_MAGIC.len();
    loop {
        if rest.len() < 36 {
            break;
        }
        let mut address = [0u8; 32];
        address.copy_from_slice(&rest[..32]);
        let mut len = [0u8; 4];
        len.copy_from_slice(&rest[32..36]);
        let len = u32::from_le_bytes(len) as usize;
        let Some(record) = rest.get(..36 + len + 8) else {
            break;
        };
        let check = blake3::hash(&record[..36 + len]);
        if record[36 + len..] != check.as_bytes()[..8] {
            break;
        }
        if len == 0 {
            proofs.remove(&address);
        } else {
            proofs.insert(address, record[36..36 + len].to_vec());
        }
        length += record.len();
        rest = &rest[record.len()..];
    }
    if length < bytes.len() {
        warn!(
            "Leaving out a torn last record of {} ({} bytes)",
            path.display(),
            bytes.len() - length
        );
    }
    Ok((proofs, Some(length as u64)))
}

/// Write `bytes` to `path`, whole or not at all.
fn write_whole(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| Error::Config("missing checkpoint directory".into()))?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| Error::Io(e.error))?;
    Ok(())
}

/// How often a process looks through a directory of checkpoints for those
/// [`remove_unresumed`] removes: at most once an hour, so a server opening
/// many uploads doesn't read the whole directory for each.
const UNRESUMED_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Remove the checkpoints in `directory` that no upload has touched for
/// [`UNRESUMED_PROOFS_BACKSTOP`]: the proofs of uploads never resumed. One
/// holding a pending payment is kept whatever its age, as is one whose lock
/// is held, or one this client can't read. Its lock file stays, as the
/// engine leaves locks. A process does this for a directory at most once
/// every [`UNRESUMED_SWEEP_INTERVAL`]. Returns how many checkpoints were
/// removed.
pub(crate) fn remove_unresumed(directory: &Path) -> usize {
    static SWEPT: Mutex<Option<HashMap<PathBuf, std::time::Instant>>> = Mutex::new(None);
    {
        let mut swept = SWEPT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let swept = swept.get_or_insert_with(HashMap::new);
        let now = std::time::Instant::now();
        if swept
            .get(directory)
            .is_some_and(|at| now.duration_since(*at) < UNRESUMED_SWEEP_INTERVAL)
        {
            return 0;
        }
        swept.insert(directory.to_path_buf(), now);
    }
    remove_unresumed_before(directory, SystemTime::now() - UNRESUMED_PROOFS_BACKSTOP)
}

/// [`remove_unresumed`], for checkpoints last written before `before`.
pub(crate) fn remove_unresumed_before(directory: &Path, before: SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_checkpoint = path.extension().is_some_and(|e| e == CHECKPOINT_EXTENSION)
            && path.file_stem().is_some_and(|stem| {
                let stem = stem.to_string_lossy();
                stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit())
            });
        if !is_checkpoint {
            continue;
        }
        let files = [
            path.clone(),
            path.with_extension(PROOFS_EXTENSION),
            path.with_extension("salt"),
        ];
        let untouched = files.iter().all(|file| match std::fs::metadata(file) {
            Ok(metadata) => metadata.modified().is_ok_and(|at| at < before),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        });
        if !untouched {
            continue;
        }
        let Ok(lock) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))
        else {
            continue;
        };
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
            continue;
        }
        let pending = std::fs::read(&path)
            .map_err(Error::Io)
            .and_then(|bytes| UploadState::parse(&bytes))
            .map(|parsed| parsed.state.pending_payment.is_some());
        match pending {
            Ok(false) => {
                info!(
                    "Removing the upload checkpoint {}, untouched for {} days",
                    path.display(),
                    UNRESUMED_PROOFS_BACKSTOP.as_secs() / 86_400
                );
                for file in files {
                    let _ = std::fs::remove_file(file);
                }
                removed += 1;
            }
            Ok(true) => {}
            Err(error) => warn!(
                "Keeping the old upload checkpoint {}, which can't be read: {error}",
                path.display()
            ),
        }
        drop(lock);
    }
    removed
}

/// Whether `bytes` start as a checkpoint in the current format.
#[must_use]
pub fn is_current_format(bytes: &[u8]) -> bool {
    bytes.starts_with(&CHECKPOINT_MAGIC)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::upload_state::test_state::{plan, plan_priced, transactions, weighted};
    use super::*;
    use std::time::Duration;

    fn now() -> SystemTime {
        crate::runtime::system_time()
    }

    /// A state with `paid` records paid and one plan pending payment.
    fn state_with(paid: &[&[u8]], pending: Option<&[u8]>) -> UploadState {
        let mut state = UploadState::default();
        for content in paid {
            let p = plan(content, now());
            state.prepare(p.clone());
            state
                .confirm(&[p.address], &transactions(&p), now())
                .unwrap();
        }
        if let Some(content) = pending {
            let p = plan(content, now());
            state.prepare(p.clone());
            state.start_payment(false, vec![p.address]).unwrap();
        }
        state
    }

    fn checkpoint_in(dir: &Path) -> PathBuf {
        dir.join(format!("{}.msgpack", "ab".repeat(32)))
    }

    /// The proofs go to the proof file, one record each, and the
    /// checkpoint holds none; both read back.
    #[test]
    fn proofs_are_kept_apart_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let (files, none) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        assert!(none.is_none());
        let state = state_with(&[b"one", b"two"], Some(b"three"));
        files.save(&state).unwrap();
        let main = std::fs::read(files.path()).unwrap();
        assert!(is_current_format(&main));
        assert!(
            UploadState::restore(&main)
                .unwrap()
                .proof_addresses()
                .is_empty(),
            "the checkpoint holds no proofs"
        );
        let (_, restored) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        let restored = restored.unwrap();
        assert_eq!(restored.proof_addresses(), state.proof_addresses());
        assert_eq!(
            restored.pending_plans().unwrap()[0].address,
            state.pending_plans().unwrap()[0].address
        );
    }

    /// A proof is appended once, not written again at every save; a
    /// dropped one is forgotten by a record of its own.
    #[test]
    fn a_proof_is_appended_once_and_a_dropped_one_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (files, _) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        let mut state = state_with(&[b"one"], None);
        files.save(&state).unwrap();
        let first = std::fs::metadata(files.proofs_path()).unwrap().len();
        files.save(&state).unwrap();
        files.save(&state).unwrap();
        assert_eq!(std::fs::metadata(files.proofs_path()).unwrap().len(), first);
        let p = plan(b"two", now());
        state.prepare(p.clone());
        state
            .confirm(&[p.address], &transactions(&p), now())
            .unwrap();
        files.save(&state).unwrap();
        let second = std::fs::metadata(files.proofs_path()).unwrap().len();
        assert!(second > first);
        let one = plan(b"one", now()).address;
        state.drop_proof(&one);
        files.save(&state).unwrap();
        assert_eq!(
            std::fs::metadata(files.proofs_path()).unwrap().len(),
            second + 32 + 4 + 8
        );
        let (_, restored) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        assert_eq!(restored.unwrap().proof_addresses(), state.proof_addresses());
    }

    /// A torn last record is left out on reading and cut off before the
    /// next record is appended.
    #[test]
    fn a_torn_last_record_is_left_out_and_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let (files, _) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        let mut state = state_with(&[b"one"], None);
        files.save(&state).unwrap();
        let mut torn = std::fs::OpenOptions::new()
            .append(true)
            .open(files.proofs_path())
            .unwrap();
        torn.write_all(&[7; 50]).unwrap();
        drop(torn);
        let (files, restored) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        assert_eq!(restored.unwrap().proof_addresses(), state.proof_addresses());
        let p = plan(b"two", now());
        state.prepare(p.clone());
        state
            .confirm(&[p.address], &transactions(&p), now())
            .unwrap();
        files.save(&state).unwrap();
        let (_, restored) = UploadCheckpointFiles::open(checkpoint_in(dir.path())).unwrap();
        assert_eq!(restored.unwrap().proof_addresses(), state.proof_addresses());
    }

    /// A checkpoint in the format before the magic, native, is read and
    /// migrated: its proofs go to a proof file, and the new checkpoint
    /// replaces the old one. A crash before that rename leaves the old file,
    /// which migrates again.
    #[test]
    fn an_old_format_checkpoint_is_migrated_keeping_the_old_until_the_new_is_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = checkpoint_in(dir.path());
        let state = state_with(&[b"one", b"two"], Some(b"three"));
        std::fs::write(&path, state.legacy_checkpoint()).unwrap();
        // A crash part way through an earlier migration left a proof file.
        std::fs::write(path.with_extension(PROOFS_EXTENSION), b"DSPF\x01partial").unwrap();
        let (_, restored) = UploadCheckpointFiles::open(path.clone()).unwrap();
        let restored = restored.unwrap();
        assert_eq!(restored.proof_addresses(), state.proof_addresses());
        assert!(restored.pending_payment.is_some());
        assert!(is_current_format(&std::fs::read(&path).unwrap()));
        let (_, again) = UploadCheckpointFiles::open(path).unwrap();
        assert_eq!(again.unwrap().proof_addresses(), state.proof_addresses());
    }

    /// One that can't be restored is never deleted, and the error names it
    /// and says to keep it.
    #[test]
    fn an_unrestorable_checkpoint_is_kept_and_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = checkpoint_in(dir.path());
        let mut state = state_with(&[], None);
        let mut bad = plan(b"pending", now());
        bad.payment.quotes[0].amount += ant_protocol::evm::Amount::from(1);
        state.prepare(bad.clone());
        state.start_payment(false, vec![bad.address]).unwrap();
        std::fs::write(&path, state.legacy_checkpoint()).unwrap();
        let error = UploadCheckpointFiles::open(path.clone())
            .unwrap_err()
            .to_string();
        assert!(error.contains(&path.display().to_string()), "{error}");
        assert!(error.contains("Don't delete it"), "{error}");
        assert_eq!(std::fs::read(&path).unwrap(), state.legacy_checkpoint());
    }

    /// A checkpoint saved before the switch with a journaled payment of a
    /// plan under 4 MiB (full amount) opens in a client that pays the
    /// weighted amount, and the reverse: the plan is settled as recorded.
    #[test]
    fn a_journaled_payment_restores_across_the_switch_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        for (i, saved) in [
            plan_priced(&[1; 3000], now(), &[10_000_000, 20_000_000]),
            weighted(plan_priced(&[2; 3000], now(), &[10_000_000, 20_000_000])),
        ]
        .into_iter()
        .enumerate()
        {
            let path = dir
                .path()
                .join(format!("{}.msgpack", hex::encode([i as u8; 32])));
            let mut state = UploadState::default();
            state.prepare(saved.clone());
            state.start_payment(false, vec![saved.address]).unwrap();
            let (files, _) = UploadCheckpointFiles::open(path.clone()).unwrap();
            files.save(&state).unwrap();
            let (_, restored) = UploadCheckpointFiles::open(path).unwrap();
            let plans = restored.unwrap().pending_plans().unwrap();
            assert_eq!(
                plans[0].payment.total_amount(),
                saved.payment.total_amount()
            );
        }
    }

    /// The backstop removes checkpoints untouched for 30 days, but never
    /// one with a pending payment, one in use, or one it can't read.
    #[test]
    fn the_backstop_removes_only_old_unpending_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let write = |fill: u8, state: &UploadState| {
            let path = dir
                .path()
                .join(format!("{}.msgpack", hex::encode([fill; 32])));
            let (files, _) = UploadCheckpointFiles::open(path.clone()).unwrap();
            files.save(state).unwrap();
            path
        };
        let old_paid = write(1, &state_with(&[b"a"], None));
        let old_pending = write(2, &state_with(&[b"b"], Some(b"c")));
        let in_use = write(3, &state_with(&[b"d"], None));
        let unreadable = dir.path().join(format!("{}.msgpack", hex::encode([4; 32])));
        std::fs::write(&unreadable, b"DSCK\x09").unwrap();
        let held = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(in_use.with_extension("lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&held).unwrap();
        // Nothing is old enough yet.
        assert_eq!(remove_unresumed(dir.path()), 0);
        let later = SystemTime::now() + Duration::from_secs(60);
        assert_eq!(remove_unresumed_before(dir.path(), later), 1);
        assert!(!old_paid.exists() && !old_paid.with_extension(PROOFS_EXTENSION).exists());
        assert!(old_pending.exists() && old_pending.with_extension(PROOFS_EXTENSION).exists());
        assert!(in_use.exists() && unreadable.exists());
    }

    /// The files of a checkpoint, as a server removing ended uploads lists
    /// them.
    #[test]
    fn a_checkpoints_files_are_listed() {
        let path = Path::new("x").join(format!("{}.msgpack", "c".repeat(64)));
        let names = upload_checkpoint_files(&path)
            .into_iter()
            .map(|file| file.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let stem = "c".repeat(64);
        assert_eq!(
            names,
            ["msgpack", "proofs", "salt", "lock"].map(|extension| format!("{stem}.{extension}"))
        );
    }
}
