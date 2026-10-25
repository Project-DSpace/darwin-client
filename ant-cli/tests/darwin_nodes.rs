//! `darwin-nodes`, the storage-node image's node manager, as the image runs it.
//!
//! The pins the image's manager is held to: the binary has no eviction, no reset and no download
//! or log-forwarding path, and carries neither Autonomi's download repository ("WithAutonomi") nor
//! its log endpoint ("logs.autonomi.com"); nodes are registered as `ant` 0.3.9 registered them and
//! start with the same arguments, `--evm-network` included; and the data folder, which holds the
//! registry the image reads in place, is still `$XDG_DATA_HOME/ant`.
//!
//! Each run gets home, data and config folders of its own, and every proxy variable points at a
//! closed local port (loopback excepted, for the manager's own daemon), so a build that reached
//! for a download would fail rather than fetch anything.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use ant_core::node::daemon::supervisor::build_node_args;
use ant_core::node::registry::NodeRegistry;

/// The binary under test, built by cargo for this test run.
const DARWIN_NODES: &str = env!("CARGO_BIN_EXE_darwin-nodes");

/// The wallet the image's smoke test uses: test nodes earn nothing.
const WALLET: &str = "0x000000000000000000000000000000000000dEaD";

/// How long the daemon may take to answer once started.
const DAEMON_START_LIMIT: Duration = Duration::from_secs(60);

/// The folders one run of `darwin-nodes` gets, each empty to begin with.
struct Homes {
    root: tempfile::TempDir,
}

impl Homes {
    fn new() -> Self {
        let homes = Self {
            root: tempfile::tempdir().expect("a temporary folder"),
        };
        for dir in ["home", "appdata", "localappdata", "xdg-data", "xdg-config"] {
            std::fs::create_dir(homes.path(dir)).expect("a home folder");
        }
        homes
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Where `darwin-nodes` keeps its registry here: `$XDG_DATA_HOME/ant` on Linux, the image's
    /// platform, and the platform's own data folder elsewhere.
    fn data_folder(&self) -> PathBuf {
        if cfg!(target_os = "windows") {
            self.path("appdata").join("ant")
        } else if cfg!(target_os = "macos") {
            self.path("home")
                .join("Library")
                .join("Application Support")
                .join("ant")
        } else {
            self.path("xdg-data").join("ant")
        }
    }

    /// `darwin-nodes` with `args`, isolated as the module documentation describes.
    fn command(&self, args: &[&str]) -> Command {
        let proxy = format!("http://127.0.0.1:{}", free_port());
        let mut command = Command::new(DARWIN_NODES);
        command
            .args(args)
            .stdin(Stdio::null())
            .env_remove("RUST_LOG")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env("NO_COLOR", "1");
        for (variable, dir) in [
            ("HOME", "home"),
            ("USERPROFILE", "home"),
            ("APPDATA", "appdata"),
            ("LOCALAPPDATA", "localappdata"),
            ("XDG_DATA_HOME", "xdg-data"),
            ("XDG_CONFIG_HOME", "xdg-config"),
            ("XDG_CACHE_HOME", "home"),
            ("XDG_STATE_HOME", "home"),
        ] {
            command.env(variable, self.path(dir));
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
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("darwin-nodes runs")
    }

    /// A stand-in node binary that answers `--version` as ant-node does.
    fn node_binary(&self) -> PathBuf {
        let dir = self.path("opt");
        std::fs::create_dir_all(&dir).expect("a folder for the node binary");
        if cfg!(windows) {
            let path = dir.join("ant-node.cmd");
            std::fs::write(&path, "@echo off\r\necho ant-node 0.11.2\r\n").unwrap();
            path
        } else {
            let path = dir.join("ant-node");
            std::fs::write(&path, "#!/bin/sh\necho \"ant-node 0.11.2\"\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            path
        }
    }

    /// The image's add (docker/entrypoint.sh): one node on `port`, its data under `nodes/` and
    /// its logs under `logs/`, with the image's per-node settings and two bootstrap peers.
    fn add_as_the_image_does(&self, port: u16) -> Output {
        let binary = self.node_binary();
        let nodes = self.path("nodes");
        let logs = self.path("logs");
        let port = port.to_string();
        let env = format!(
            "ANT_WEBRTC_DIRECT_PORT={},ANT_EVM_RPC_URL=https://rpc.mainnet.chain.robinhood.com",
            11000 + (port.parse::<u16>().unwrap() - 10000)
        );
        self.run(&[
            "add",
            "--count",
            "1",
            "--rewards-address",
            WALLET,
            "--node-port",
            &port,
            "--path",
            binary.to_str().unwrap(),
            "--data-dir-path",
            nodes.to_str().unwrap(),
            "--log-dir-path",
            logs.to_str().unwrap(),
            "--env",
            &env,
            "--bootstrap",
            "142.93.32.90:10000,165.22.193.90:10000",
        ])
    }
}

/// A local port nothing listens on: bound, then let go.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free local port")
        .port()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether `haystack` holds `needle`.
fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Every file under `dir` with its contents, by path relative to `dir`.
fn files_under(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let contents = std::fs::read(&path).unwrap();
                found.push((path.strip_prefix(dir).unwrap().to_path_buf(), contents));
            }
        }
    }
    found.sort();
    found
}

/// The binary carries no Autonomi download repository and no Autonomi log endpoint, and none of
/// the reset and log-forwarding routes of the darwin CLI's daemon: the code that would use them
/// isn't in it. The routes it serves are, so the scan reads what the binary holds.
///
/// This is the test build. `scripts/check-darwin-nodes.sh` checks the same strings in a release
/// build, the kind the image ships: build.yml runs it on the one it makes, and darwin-node's image
/// build can run it on its own. Keep the two lists alike.
#[test]
fn the_binary_has_no_autonomi_download_or_log_address_and_no_reset_or_forwarding() {
    let binary = std::fs::read(DARWIN_NODES).expect("the darwin-nodes binary");
    for needle in [
        "WithAutonomi",
        "logs.autonomi.com",
        "/api/v1/reset",
        "/api/v1/logs/forward",
    ] {
        assert!(
            !contains(&binary, needle),
            "{DARWIN_NODES} contains {needle:?}"
        );
    }
    for needle in [
        "/api/v1/nodes/status",
        "/api/v1/health",
        "node_registry.json",
    ] {
        assert!(contains(&binary, needle), "{DARWIN_NODES} lacks {needle:?}");
    }
}

/// `darwin-nodes --version`: its name and the package version, then the commit it was built
/// from, as darwin's.
#[test]
fn the_version_names_darwin_nodes_and_the_commit() {
    let homes = Homes::new();
    let output = homes.run(&["--version"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = text(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert_eq!(
        lines[0],
        concat!("darwin-nodes ", env!("CARGO_PKG_VERSION"))
    );
    let commit = lines[1].strip_prefix("commit ").expect("a commit line");
    assert!(
        commit == "unknown"
            || (!commit.is_empty() && commit.chars().all(|c| c.is_ascii_hexdigit())),
        "{commit:?}"
    );
}

/// There is no reset and no log forwarding to run, and no self-update.
#[test]
fn there_is_no_reset_log_forwarding_or_update_command() {
    let homes = Homes::new();
    for args in [
        &["reset", "--force"][..],
        &["logs", "forward", "enable", "--token", "token"],
        &["logs", "forward", "status"],
        &["update"],
        &["daemon", "reset"],
    ] {
        let output = homes.run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(
            text(&output.stderr).contains("unrecognized subcommand"),
            "{args:?}: {output:?}"
        );
    }
    assert!(files_under(homes.root.path()).is_empty());
}

/// `add` downloads nothing: without `--path` it is refused, and it has no download source to
/// name. Nothing is written either way.
#[test]
fn add_takes_a_local_binary_and_no_download_source() {
    let homes = Homes::new();
    let binary = homes.node_binary();
    let binary = binary.to_str().unwrap();
    for (args, says) in [
        (&["add", "--rewards-address", WALLET][..], "--path"),
        (
            &[
                "add",
                "--rewards-address",
                WALLET,
                "--url",
                "https://github.com/x/y.tar.gz",
            ],
            "--url",
        ),
        (
            &["add", "--rewards-address", WALLET, "--version", "0.11.2"],
            "--version",
        ),
        (
            &[
                "add",
                "--rewards-address",
                WALLET,
                "--path",
                binary,
                "--upgrade-channel",
                "beta",
            ],
            "--upgrade-channel",
        ),
        (
            &[
                "add",
                "--rewards-address",
                WALLET,
                "--path",
                binary,
                "--evm-network",
                "arbitrum-sepolia",
            ],
            "--evm-network",
        ),
    ] {
        let output = homes.run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(text(&output.stderr).contains(says), "{args:?}: {output:?}");
    }
    assert!(!homes.data_folder().exists());
    assert!(!homes.path("nodes").exists());
}

/// The image's add registers the node `ant` 0.3.9 registered, in the registry in the data folder
/// `ant` 0.3.9 used (`$XDG_DATA_HOME/ant` on Linux: the image's
/// `/data/manager/ant/node_registry.json`), and the node starts with the arguments `ant` 0.3.9
/// gave it, `--evm-network arbitrum-one` included (the image's payment settings override it in
/// the node). `status` reads it back from there.
#[test]
fn add_registers_what_ant_0_3_9_did_where_it_did() {
    let homes = Homes::new();
    let output = homes.add_as_the_image_does(10000);
    assert!(output.status.success(), "{output:?}");

    let registry_path = homes.data_folder().join("node_registry.json");
    assert!(registry_path.is_file(), "{}", registry_path.display());
    let registry = NodeRegistry::load(&registry_path).unwrap();
    assert_eq!(registry.len(), 1);
    let node = registry.get(1).unwrap();
    assert_eq!(node.service_name, "node1");
    assert_eq!(node.version, "0.11.2");
    assert_eq!(node.env_variables.len(), 2);
    assert_eq!(node.env_variables["ANT_WEBRTC_DIRECT_PORT"], "11000");
    assert!(node.binary_path.is_file());
    assert!(node.eviction.is_none());

    let data_dir = homes.path("nodes").join("node-1");
    let log_dir = homes.path("logs").join("node-1").join("logs");
    assert_eq!(node.data_dir, data_dir);
    assert_eq!(node.log_dir.as_deref(), Some(log_dir.as_path()));
    let data_dir = data_dir.display().to_string();
    let log_dir = log_dir.display().to_string();
    assert_eq!(
        build_node_args(node),
        [
            "--rewards-address",
            WALLET,
            "--root-dir",
            &data_dir,
            "--enable-logging",
            "--log-dir",
            &log_dir,
            "--port",
            "10000",
            "--bootstrap",
            "142.93.32.90:10000",
            "--bootstrap",
            "165.22.193.90:10000",
            "--stop-on-upgrade",
            "--evm-network",
            "arbitrum-one",
        ]
    );

    // As `ant` 0.3.9's registry entry reads in JSON: no upgrade channel, Arbitrum One's name.
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).unwrap()).unwrap();
    assert_eq!(json["nodes"]["1"]["evm_network"], "arbitrum-one");
    assert!(json["nodes"]["1"]["upgrade_channel"].is_null());
    assert!(json["nodes"]["1"]["eviction"].is_null());

    let output = homes.run(&["--json", "status"]);
    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["nodes"][0]["name"], "node1");
    assert_eq!(status["nodes"][0]["status"], "stopped");
}

/// `dismiss` takes a node out of the registry and leaves its data folder as it was.
#[test]
fn dismiss_leaves_the_data_folder_in_place() {
    let homes = Homes::new();
    assert!(homes.add_as_the_image_does(10000).status.success());
    let data_dir = homes.path("nodes").join("node-1");
    std::fs::write(data_dir.join("record"), b"a stored record").unwrap();
    let before = files_under(&data_dir);

    let output = homes.run(&["dismiss", "1"]);
    assert!(output.status.success(), "{output:?}");

    let registry = NodeRegistry::load(&homes.data_folder().join("node_registry.json")).unwrap();
    assert!(registry.is_empty());
    assert_eq!(files_under(&data_dir), before);
}

/// A running `darwin-nodes daemon run`, killed when dropped.
struct Daemon {
    child: Child,
    port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP/1.1 request to the daemon: its status code and body.
fn request(port: u16, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon's port");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("an HTTP response: {response}"));
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

fn start_daemon(homes: &Homes) -> Daemon {
    let port = free_port();
    let child = homes
        .command(&[
            "daemon",
            "run",
            "--listen-addr",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("darwin-nodes daemon run starts");
    let mut daemon = Daemon { child, port };
    let deadline = Instant::now() + DAEMON_START_LIMIT;
    loop {
        if let Ok(Some(status)) = daemon.child.try_wait() {
            panic!("the daemon exited: {status}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok()
            && homes.data_folder().join("daemon.port").is_file()
        {
            return daemon;
        }
        assert!(Instant::now() < deadline, "the daemon did not answer");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The daemon the image runs serves the node manager's core, with the shapes the image, stats.sh
/// and the watchdog read, and no reset, no log forwarding and no download; adding from a
/// download source is refused; and with the disk in any state, it leaves a node's data as it was.
#[test]
fn the_daemon_serves_no_reset_forwarding_or_download_and_deletes_nothing() {
    let homes = Homes::new();
    assert!(homes.add_as_the_image_does(10000).status.success());
    let data_dir = homes.path("nodes").join("node-1");
    std::fs::write(data_dir.join("record"), b"a stored record").unwrap();
    let before = files_under(&data_dir);

    let daemon = start_daemon(&homes);
    let port = daemon.port;

    let (code, body) = request(port, "GET", "/api/v1/status", None);
    assert_eq!(code, 200, "{body}");
    let status: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(status["running"], true);
    assert_eq!(status["nodes_total"], 1);
    for field in [
        "nodes_running",
        "nodes_stopped",
        "nodes_errored",
        "uptime_secs",
    ] {
        assert!(status[field].is_u64(), "{field}: {body}");
    }

    let (code, body) = request(port, "GET", "/api/v1/nodes/status", None);
    assert_eq!(code, 200, "{body}");
    let nodes: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(nodes["nodes"][0]["node_id"], 1);
    assert_eq!(nodes["nodes"][0]["status"], "stopped");

    let (code, body) = request(port, "GET", "/api/v1/health", None);
    assert_eq!(code, 200, "{body}");
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(health["overall"].is_string(), "{body}");
    assert!(!body.to_lowercase().contains("evict"), "{body}");

    for (method, path) in [
        ("POST", "/api/v1/reset"),
        ("GET", "/api/v1/logs/forward"),
        ("POST", "/api/v1/logs/forward/enable"),
        ("POST", "/api/v1/logs/forward/disable"),
    ] {
        let (code, body) = request(port, method, path, Some("{}"));
        assert_eq!(code, 404, "{method} {path}: {body}");
    }

    let (code, body) = request(port, "GET", "/api/v1/openapi.json", None);
    assert_eq!(code, 200, "{body}");
    let spec: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(spec["info"]["title"], "darwin-nodes API");
    let paths: Vec<&String> = spec["paths"].as_object().unwrap().keys().collect();
    assert!(
        paths
            .iter()
            .all(|path| !path.contains("reset") && !path.contains("logs")),
        "{paths:?}"
    );

    // A download source is refused, before anything is written.
    let add = format!(
        r#"{{"count":1,"rewards_address":"{WALLET}","node_port":10001,"data_dir_path":null,
            "log_dir_path":null,"binary_source":{{"type":"url","value":"https://github.com/x/y.tar.gz"}},
            "bootstrap_peers":[],"env_variables":[],"upgrade_channel":null}}"#
    );
    let (code, body) = request(port, "POST", "/api/v1/nodes", Some(&add));
    assert_eq!(code, 400, "{body}");
    assert!(body.contains("downloads no node binary"), "{body}");

    // The CLI reads the same daemon: two nodes' worth of status would mean the refused add
    // registered one.
    let output = homes.run(&["--json", "status"]);
    assert!(output.status.success(), "{output:?}");
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["nodes"].as_array().unwrap().len(), 1, "{status}");
    assert!(status["health"]["overall"].is_string(), "{status}");

    drop(daemon);
    assert_eq!(
        files_under(&data_dir),
        before,
        "the node's data is as it was"
    );
}
