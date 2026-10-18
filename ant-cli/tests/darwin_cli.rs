//! The `darwin` binary as users run it: commands this build holds back are
//! refused before they read a key, touch the data or config directories, or
//! reach a network.
//!
//! Each run gets home, data and config directories of its own, which must
//! still be empty afterwards; `SECRET_KEY` is unset; and every proxy variable
//! points at a closed local port, so a build that lost a refusal can't
//! download anything.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The binary under test, built by cargo for this test run.
const DARWIN: &str = env!("CARGO_BIN_EXE_darwin");

/// How long one run may take. A refusal takes a fraction of a second; a run
/// still going after this has done more than refuse, and is stopped.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// How long a run's output may take to arrive once it has ended. Longer only
/// if a process it started holds its stdout or stderr open.
const OUTPUT_GRACE: Duration = Duration::from_secs(10);

/// What `darwin chunk put` says while raw chunks are off.
const CHUNK_PUT_OFF: &str = "`darwin chunk put` is off in this build: a raw chunk can't carry an \
     envelope, so it would be stored without the payment record, listing and .record every upload \
     carries. Use `darwin file upload <FILE>`: private by default, every payment field shown.";

/// How a run of `darwin` ended and what it printed and left behind.
#[derive(Debug)]
struct Run {
    /// The exit code: `None` if the run was stopped at [`RUN_LIMIT`] or
    /// ended by a signal.
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// What the run left in its home, data and config directories.
    left_behind: Vec<PathBuf>,
}

/// A local port nothing listens on: bound, then let go.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free local port")
        .port()
}

/// Read `pipe` to its end on a thread of its own.
fn read_all(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        let _ = sender.send(String::from_utf8_lossy(&bytes).into_owned());
    });
    receiver
}

/// Run `darwin` with `args` and `stdin` written to it, isolated as the
/// module documentation describes.
fn darwin(args: &[&str], stdin: &[u8]) -> Run {
    let home = tempfile::tempdir().expect("a temporary home");
    let proxy = format!("http://127.0.0.1:{}", closed_port());
    let mut command = Command::new(DARWIN);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("SECRET_KEY")
        .env_remove("RUST_LOG")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for variable in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
    ] {
        command.env(variable, home.path());
    }
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env(variable, &proxy);
    }

    let mut child = command.spawn().expect("darwin starts");
    let mut input = child.stdin.take().expect("darwin's stdin");
    let stdin = stdin.to_vec();
    // darwin may end without reading its input, so a failed write is no error.
    std::thread::spawn(move || {
        let _ = input.write_all(&stdin);
    });
    let stdout = read_all(child.stdout.take().expect("darwin's stdout"));
    let stderr = read_all(child.stderr.take().expect("darwin's stderr"));

    let deadline = Instant::now() + RUN_LIMIT;
    let code = loop {
        match child.try_wait().expect("darwin's exit status") {
            Some(status) => break status.code(),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let held_open = |_| "<held open by a process darwin started>".to_string();
    let stdout = stdout.recv_timeout(OUTPUT_GRACE).unwrap_or_else(held_open);
    let stderr = stderr.recv_timeout(OUTPUT_GRACE).unwrap_or_else(held_open);
    let left_behind = std::fs::read_dir(home.path())
        .expect("the temporary home")
        .map(|entry| entry.expect("an entry of the temporary home").path())
        .collect();
    Run {
        code,
        stdout,
        stderr,
        left_behind,
    }
}

/// `run` of `darwin args` failed with `message` and did nothing else: exit
/// code 1, nothing on stdout, nothing left in its directories.
fn assert_refused(args: &[&str], run: &Run, message: &str) {
    assert_eq!(run.code, Some(1), "darwin {args:?}: {run:#?}");
    assert!(
        run.stderr.contains(message),
        "darwin {args:?} should say {message:?}: {run:#?}"
    );
    assert!(run.stdout.is_empty(), "darwin {args:?}: {run:#?}");
    assert!(run.left_behind.is_empty(), "darwin {args:?}: {run:#?}");
}

/// `darwin chunk put` is off: refused from a file and from stdin, before
/// `SECRET_KEY` is asked for or the network is joined.
#[test]
fn chunk_put_is_refused() {
    let input = tempfile::tempdir().expect("a temporary folder");
    let file = input.path().join("chunk.bin");
    std::fs::write(&file, b"hello darwin").expect("a chunk to store");
    let file = file.to_str().expect("a UTF-8 path");
    for args in [
        &["chunk", "put", file][..],
        &["chunk", "put"],
        &["--json", "chunk", "put", file],
    ] {
        let run = darwin(args, b"hello darwin");
        assert_refused(args, &run, CHUNK_PUT_OFF);
    }
}

/// `darwin chunk get` stays.
#[test]
fn chunk_get_still_parses() {
    let args = ["chunk", "get", "--help"];
    let run = darwin(&args, b"");
    assert_eq!(run.code, Some(0), "darwin {args:?}: {run:#?}");
    assert!(
        run.stdout.contains("Retrieve a single chunk"),
        "darwin {args:?}: {run:#?}"
    );
    assert!(run.left_behind.is_empty(), "darwin {args:?}: {run:#?}");
}
