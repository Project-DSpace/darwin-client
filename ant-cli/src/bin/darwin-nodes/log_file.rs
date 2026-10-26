//! The manager's own log file, capped in size.
//!
//! Its log shares the data partition with the nodes, so it is held to a cap whatever the
//! traffic:
//!
//! - a new file every [`Limits::segment_bytes`] or every [`Limits::segment_age`], whichever comes
//!   first, and on every start;
//! - after each new file, the oldest closed files of the family are deleted until the family,
//!   the new file included, can fill that file and still hold at most [`Limits::cap_bytes`], and
//!   closed files older than [`Limits::max_age`] are deleted;
//! - at or below the full line, [`Limits::full_line_bytes`] free on the log's partition, it first
//!   deletes its own closed files, then writes only warnings and errors, counting the lines it
//!   leaves out, and writes one line saying how many once space returns.
//!
//! The family is every file in the log's folder named `<prefix>.<anything>.log`, which includes
//! the daily files the manager wrote before. The files it writes are named
//! `<prefix>.<UTC time it was opened>.log`, such as `manager.2026-10-25T09-30-00.log`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

/// One mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;

/// How often the writer reads the partition's free space at most, so a flood of lines costs no
/// more than one reading a second.
const FREE_SPACE_READ_INTERVAL: Duration = Duration::from_secs(1);

/// How large the family may grow, and when the writer gives way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most the family's files hold, the file being written included.
    pub cap_bytes: u64,
    /// A new file once the one being written holds this much.
    pub segment_bytes: u64,
    /// A new file once the one being written has been open this long.
    pub segment_age: Duration,
    /// Closed files last written longer ago than this are deleted.
    pub max_age: Duration,
    /// At or below this much free space on the log's partition, the writer gives way.
    pub full_line_bytes: u64,
}

impl Limits {
    /// The manager's: 50 MiB in all, in files of 10 MiB or an hour, a month at most (as long as
    /// the daily files before), giving way at the nodes' full line, 1 GiB free, which is also the
    /// manager's own low-disk warning level.
    pub fn manager() -> Self {
        Self {
            cap_bytes: 50 * MIB,
            segment_bytes: 10 * MIB,
            segment_age: Duration::from_secs(60 * 60),
            max_age: Duration::from_secs(30 * 24 * 60 * 60),
            full_line_bytes: ant_core::node::daemon::health::DiskThresholds::default()
                .warning_bytes,
        }
    }
}

/// Reads the free bytes on the partition holding a folder, or `None` when it can't.
type FreeSpace = Box<dyn Fn(&Path) -> Option<u64> + Send>;

/// The log file family, as a `tracing` writer: each event is written whole, as one line.
#[derive(Clone)]
pub struct LogFile {
    inner: Arc<Mutex<Family>>,
}

impl LogFile {
    /// Write to files named `<prefix>.<time>.log` in `dir`, which is created if missing, within
    /// the manager's limits.
    pub fn open(dir: &Path, prefix: &str) -> io::Result<Self> {
        Self::with(
            dir,
            prefix,
            Limits::manager(),
            Box::new(ant_core::node::daemon::disk::available_space),
        )
    }

    fn with(dir: &Path, prefix: &str, limits: Limits, free_space: FreeSpace) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let mut family = Family {
            dir: dir.to_path_buf(),
            prefix: prefix.to_string(),
            limits,
            free_space,
            current: None,
            free: None,
            free_read: None,
            at_line: false,
            left_out: 0,
        };
        family.start_file()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(family)),
        })
    }

    fn family(&self) -> MutexGuard<'_, Family> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = Line<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        Line {
            log: self,
            level: None,
        }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        Line {
            log: self,
            level: Some(*meta.level()),
        }
    }
}

/// One event's line, written whole to the family's current file.
pub struct Line<'a> {
    log: &'a LogFile,
    /// The event's level: a line with none is kept as a warning is.
    level: Option<Level>,
}

impl Write for Line<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.log.family().write_line(buf, self.level)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The file being written.
struct Current {
    file: File,
    path: PathBuf,
    written: u64,
    opened: Instant,
}

struct Family {
    dir: PathBuf,
    prefix: String,
    limits: Limits,
    free_space: FreeSpace,
    current: Option<Current>,
    /// The partition's free bytes when last read.
    free: Option<u64>,
    free_read: Option<Instant>,
    /// At or below the full line when last read.
    at_line: bool,
    /// Lines left out at the full line, since it was reached.
    left_out: u64,
}

impl Family {
    fn write_line(&mut self, line: &[u8], level: Option<Level>) -> io::Result<()> {
        self.read_free_space();
        let at_line = self
            .free
            .is_some_and(|free| free <= self.limits.full_line_bytes);
        if at_line && !self.at_line {
            self.at_line = true;
            self.delete_closed_files(|_| true);
        } else if !at_line && self.at_line {
            self.at_line = false;
            if self.left_out > 0 {
                let summary = format!(
                    "{} log line(s) below warning level were left out while the disk was at \
                     {} MiB free or less\n",
                    self.left_out,
                    self.limits.full_line_bytes / MIB
                );
                self.left_out = 0;
                self.append(summary.as_bytes())?;
            }
        }
        if self.at_line && !matches!(level, None | Some(Level::WARN) | Some(Level::ERROR)) {
            self.left_out += 1;
            return Ok(());
        }
        self.append(line)
    }

    fn read_free_space(&mut self) {
        if self
            .free_read
            .is_some_and(|read| read.elapsed() < FREE_SPACE_READ_INTERVAL)
        {
            return;
        }
        self.free = (self.free_space)(&self.dir);
        self.free_read = Some(Instant::now());
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        let due = match &self.current {
            None => true,
            Some(current) => {
                (current.written > 0
                    && current.written + line.len() as u64 > self.limits.segment_bytes)
                    || current.opened.elapsed() >= self.limits.segment_age
            }
        };
        if due {
            self.start_file()?;
        }
        let Some(current) = self.current.as_mut() else {
            return Err(io::Error::other("no log file open"));
        };
        current.file.write_all(line)?;
        current.written += line.len() as u64;
        Ok(())
    }

    /// Close the file being written, if any, open a new one, and keep the family within its
    /// limits.
    fn start_file(&mut self) -> io::Result<()> {
        self.current = None;
        let stamp = utc_stamp(SystemTime::now());
        let mut path = self.dir.join(format!("{}.{stamp}.log", self.prefix));
        // A second file within the same second: numbered so names still sort as they were
        // opened ('_' sorts after '.').
        let mut n = 0;
        while path.exists() {
            n += 1;
            path = self.dir.join(format!("{}.{stamp}_{n:04}.log", self.prefix));
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.current = Some(Current {
            file,
            path,
            written: 0,
            opened: Instant::now(),
        });
        self.prune();
        Ok(())
    }

    /// Delete closed files past their age, then the oldest until the new file can fill without
    /// the family passing its cap.
    fn prune(&mut self) {
        let max_age = self.limits.max_age;
        self.delete_closed_files(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .is_ok_and(|age| age > max_age)
        });
        let room = self
            .limits
            .cap_bytes
            .saturating_sub(self.limits.segment_bytes);
        let mut closed = self.closed_files();
        let mut total: u64 = closed.iter().map(|file| file.size).sum();
        // Oldest first.
        closed.sort_by(|a, b| (a.modified, &a.path).cmp(&(b.modified, &b.path)));
        for file in closed {
            if total <= room {
                break;
            }
            if fs::remove_file(&file.path).is_ok() {
                total = total.saturating_sub(file.size);
            }
        }
    }

    /// Delete the closed files whose last write time `delete` picks.
    fn delete_closed_files(&self, delete: impl Fn(SystemTime) -> bool) {
        for file in self.closed_files() {
            if delete(file.modified) {
                let _ = fs::remove_file(&file.path);
            }
        }
    }

    /// The family's files other than the one being written.
    fn closed_files(&self) -> Vec<FamilyFile> {
        let current = self.current.as_ref().map(|current| current.path.clone());
        let head = format!("{}.", self.prefix);
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with(&head) && name.ends_with(".log") && name.len() > head.len() + 4
                })
            })
            .filter(|entry| current.as_deref() != Some(entry.path().as_path()))
            .filter_map(|entry| {
                let metadata = entry.metadata().ok().filter(fs::Metadata::is_file)?;
                Some(FamilyFile {
                    path: entry.path(),
                    size: metadata.len(),
                    modified: metadata.modified().unwrap_or(UNIX_EPOCH),
                })
            })
            .collect()
    }
}

struct FamilyFile {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

/// `time` in UTC as `YYYY-MM-DDTHH-MM-SS`, which sorts as time does.
fn utc_stamp(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX);
    let of_day = secs % 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}-{:02}-{:02}",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const KIB: u64 = 1024;

    /// Small limits, so a few lines fill a file: files of 1 KiB, 4 KiB in all.
    fn limits() -> Limits {
        Limits {
            cap_bytes: 4 * KIB,
            segment_bytes: KIB,
            segment_age: Duration::from_secs(3_600),
            max_age: Duration::from_secs(30 * 24 * 3_600),
            full_line_bytes: 1_000,
        }
    }

    /// A family in a new folder whose free space the test sets.
    fn family(limits: Limits) -> (tempfile::TempDir, LogFile, Arc<AtomicU64>) {
        let dir = tempfile::tempdir().unwrap();
        let free = Arc::new(AtomicU64::new(u64::MAX));
        let probe = Arc::clone(&free);
        let log = LogFile::with(
            dir.path(),
            "manager",
            limits,
            Box::new(move |_| Some(probe.load(Ordering::SeqCst))),
        )
        .unwrap();
        (dir, log, free)
    }

    fn write(log: &LogFile, level: Level, line: &str) {
        log.family()
            .write_line(format!("{line}\n").as_bytes(), Some(level))
            .unwrap();
    }

    /// The family's files, oldest first, with what each holds.
    fn files(dir: &Path) -> Vec<(String, String)> {
        let mut files: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap())
            .map(|entry| {
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read_to_string(entry.path()).unwrap(),
                )
            })
            .collect();
        files.sort();
        files
    }

    fn total(dir: &Path) -> u64 {
        files(dir).iter().map(|(_, text)| text.len() as u64).sum()
    }

    /// The free-space reading is kept for a second; tests that change it read again at once.
    fn read_free_space_now(log: &LogFile) {
        log.family().free_read = None;
    }

    #[test]
    fn the_managers_limits_are_50_mib_in_files_of_10_mib_or_an_hour() {
        let limits = Limits::manager();
        assert_eq!(limits.cap_bytes, 50 * MIB);
        assert_eq!(limits.segment_bytes, 10 * MIB);
        assert_eq!(limits.segment_age, Duration::from_secs(3_600));
        assert_eq!(limits.max_age, Duration::from_secs(30 * 86_400));
        // The nodes' full line, and the manager's own low-disk warning level.
        assert_eq!(limits.full_line_bytes, 1024 * MIB);
        assert!(limits.segment_bytes < limits.cap_bytes);
    }

    #[test]
    fn the_family_never_holds_more_than_its_cap() {
        let (dir, log, _) = family(limits());
        let line = "x".repeat(99);
        for _ in 0..500 {
            write(&log, Level::INFO, &line);
            assert!(
                total(dir.path()) <= limits().cap_bytes,
                "{}",
                total(dir.path())
            );
        }
        let files = files(dir.path());
        // Full files are rotated: none holds more than a segment.
        assert!(files.iter().all(|(_, text)| text.len() as u64 <= KIB));
        // What's kept is the newest: the cap less one segment of closed files, and the file
        // being written.
        assert!(files.len() >= 4, "{files:?}");
        assert!(files
            .iter()
            .all(|(name, _)| name.starts_with("manager.") && name.ends_with(".log")));
    }

    #[test]
    fn an_hour_old_file_is_closed_for_a_new_one() {
        let (dir, log, _) = family(Limits {
            segment_age: Duration::ZERO,
            ..limits()
        });
        write(&log, Level::INFO, "first");
        write(&log, Level::INFO, "second");
        let files = files(dir.path());
        assert_eq!(files.len(), 3, "{files:?}");
        assert_eq!(files[0].1, "");
        assert_eq!(files[1].1, "first\n");
        assert_eq!(files[2].1, "second\n");
    }

    #[test]
    fn closed_files_older_than_the_age_limit_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("manager.2026-09-01.log");
        fs::write(&old, "a daily file from before\n").unwrap();
        File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(31 * 86_400))
            .unwrap();
        let recent = dir.path().join("manager.2026-10-24.log");
        fs::write(&recent, "yesterday's daily file\n").unwrap();
        let other = dir.path().join("node-1");
        fs::create_dir(&other).unwrap();
        let unrelated = dir.path().join("managerial.log");
        fs::write(&unrelated, "not the family\n").unwrap();

        let _log = LogFile::with(dir.path(), "manager", limits(), Box::new(|_| None)).unwrap();
        assert!(!old.exists());
        assert!(recent.exists());
        assert!(other.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn earlier_files_count_towards_the_cap_and_go_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let day = |name: &str, age_days: u64| {
            let path = dir.path().join(name);
            fs::write(&path, "y".repeat(KIB as usize)).unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(age_days * 86_400))
                .unwrap();
            path
        };
        let oldest = day("manager.2026-10-20.log", 5);
        let older = day("manager.2026-10-21.log", 4);
        let kept: Vec<_> = (22..=24u64)
            .map(|d| day(&format!("manager.2026-10-{d}.log"), 25 - d))
            .collect();
        let _log = LogFile::with(dir.path(), "manager", limits(), Box::new(|_| None)).unwrap();
        // 5 KiB of earlier files: the two oldest go, leaving room for the new file to fill.
        assert!(!oldest.exists());
        assert!(!older.exists());
        assert!(kept.iter().all(|path| path.exists()));
    }

    #[test]
    fn at_the_full_line_only_warnings_and_errors_are_written_and_closed_files_go() {
        let (dir, log, free) = family(limits());
        let line = "z".repeat(300);
        for _ in 0..10 {
            write(&log, Level::INFO, &line);
        }
        assert!(files(dir.path()).len() > 1);

        free.store(limits().full_line_bytes, Ordering::SeqCst);
        read_free_space_now(&log);
        write(&log, Level::INFO, "left out");
        write(&log, Level::DEBUG, "left out too");
        write(&log, Level::WARN, "a warning is kept");
        write(&log, Level::ERROR, "an error is kept");
        let at_line = files(dir.path());
        // Only the file being written is left.
        assert_eq!(at_line.len(), 1, "{at_line:?}");
        let text = &at_line[0].1;
        assert!(!text.contains("left out"), "{text}");
        assert!(
            text.contains("a warning is kept\nan error is kept\n"),
            "{text}"
        );

        free.store(limits().full_line_bytes + 1, Ordering::SeqCst);
        read_free_space_now(&log);
        write(&log, Level::INFO, "back");
        let text = files(dir.path()).concat_text();
        assert!(
            text.contains(
                "2 log line(s) below warning level were left out while the disk was at 0 MiB \
                 free or less\nback\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn an_unreadable_free_space_never_holds_lines_back() {
        let (dir, log, _) = {
            let dir = tempfile::tempdir().unwrap();
            let log = LogFile::with(dir.path(), "manager", limits(), Box::new(|_| None)).unwrap();
            (dir, log, ())
        };
        write(&log, Level::INFO, "kept");
        assert!(files(dir.path()).concat_text().contains("kept\n"));
    }

    #[test]
    fn utc_stamps_sort_as_time_does() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "1970-01-01T00-00-00");
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(1_761_384_645)),
            "2025-10-25T09-30-45"
        );
        assert_eq!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29T00-00-00"
        );
        assert!(
            utc_stamp(UNIX_EPOCH + Duration::from_secs(1_761_384_645))
                < utc_stamp(UNIX_EPOCH + Duration::from_secs(1_761_384_646))
        );
    }

    trait ConcatText {
        fn concat_text(&self) -> String;
    }

    impl ConcatText for Vec<(String, String)> {
        fn concat_text(&self) -> String {
            self.iter().map(|(_, text)| text.as_str()).collect()
        }
    }
}
