use std::net::IpAddr;

use ant_core::node::binary::NoopProgress;
use ant_core::node::daemon::server;
use ant_core::node::registry::NodeRegistry;
use ant_core::node::types::{AddNodeOpts, BinarySource, DaemonConfig, DaemonStatus, NodeInfo};

fn test_config(dir: &tempfile::TempDir) -> DaemonConfig {
    DaemonConfig {
        listen_addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port: Some(0), // random available port
        registry_path: dir.path().join("registry.json"),
        log_path: None,
        port_file_path: dir.path().join("daemon.port"),
        pid_file_path: dir.path().join("daemon.pid"),
    }
}

#[tokio::test]
async fn start_daemon_get_status_stop() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();

    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();

    // Hit the status endpoint
    let url = format!("http://{addr}/api/v1/status");
    let resp = reqwest::get(&url).await.unwrap();
    assert!(resp.status().is_success());

    let status: DaemonStatus = resp.json().await.unwrap();
    assert!(status.running);
    assert!(status.pid.is_some());
    assert_eq!(status.nodes_total, 0);
    assert_eq!(status.nodes_running, 0);
    assert_eq!(status.nodes_stopped, 0);
    assert_eq!(status.nodes_errored, 0);

    // Verify uptime is reasonable (should be very small)
    assert!(status.uptime_secs.unwrap() < 5);

    // Stop the daemon
    shutdown.cancel();
    // Give server time to shut down
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn openapi_spec_is_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();

    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();

    let url = format!("http://{addr}/api/v1/openapi.json");
    let resp = reqwest::get(&url).await.unwrap();
    assert!(resp.status().is_success());

    let spec: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["info"]["title"], "Darwin Daemon API");
    assert!(spec["paths"]["/api/v1/status"].is_object());

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[tokio::test]
async fn port_and_pid_files_written() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let port_file = config.port_file_path.clone();
    let pid_file = config.pid_file_path.clone();
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();

    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();

    // Verify port file
    let port_contents = std::fs::read_to_string(&port_file).unwrap();
    let port: u16 = port_contents.trim().parse().unwrap();
    assert_eq!(port, addr.port());

    // Verify PID file
    let pid_contents = std::fs::read_to_string(&pid_file).unwrap();
    let pid: u32 = pid_contents.trim().parse().unwrap();
    assert_eq!(pid, std::process::id());

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // After shutdown, files should be cleaned up
    assert!(
        !port_file.exists(),
        "Port file should be removed after shutdown"
    );
    assert!(
        !pid_file.exists(),
        "PID file should be removed after shutdown"
    );
}

#[tokio::test]
async fn server_binds_to_pinned_port() {
    // Reserve a free port by binding to 0, then drop the listener so the
    // server can claim it. Another test binding port 0 in that gap can take
    // the port first, so a port found in use is replaced by a fresh one.
    let dir = tempfile::tempdir().unwrap();
    let mut attempts = 0;
    let (addr, pinned_port, port_file, shutdown) = loop {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let pinned_port = probe.local_addr().unwrap().port();
        drop(probe);

        let config = DaemonConfig {
            port: Some(pinned_port),
            ..test_config(&dir)
        };
        let port_file = config.port_file_path.clone();
        let registry = NodeRegistry::load(&config.registry_path).unwrap();
        let shutdown = tokio_util::sync::CancellationToken::new();

        match server::start(config, registry, shutdown.clone()).await {
            Ok(addr) => break (addr, pinned_port, port_file, shutdown),
            Err(e) if attempts < 10 && e.to_string().contains("in use") => attempts += 1,
            Err(e) => panic!("server failed to bind the pinned port: {e:?}"),
        }
    };

    assert_eq!(addr.port(), pinned_port, "server bound to the wrong port");

    let port_contents = std::fs::read_to_string(&port_file).unwrap();
    let written_port: u16 = port_contents.trim().parse().unwrap();
    assert_eq!(written_port, pinned_port);

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn console_returns_html() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();

    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();

    let url = format!("http://{addr}/console");
    let resp = reqwest::get(&url).await.unwrap();
    assert!(resp.status().is_success());

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/html"),
        "Expected text/html, got {content_type}"
    );

    let body = resp.text().await.unwrap();
    assert!(body.contains("Node Console"));
    assert!(body.contains("/api/v1"));

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Create a fake binary that responds to `--version`.
fn create_fake_binary(dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        let binary_path = dir.join("fake-antnode");
        std::fs::write(&binary_path, "#!/bin/sh\necho \"antnode 0.1.0-test\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Another test thread forking at the same moment can briefly hold a copy of
        // the write descriptor, which makes executing the file fail with ETXTBSY
        // ("Text file busy"). Wait until the file can be run before handing it out.
        let mut attempts = 0;
        loop {
            match std::process::Command::new(&binary_path)
                .arg("--version")
                .output()
            {
                Err(e) if e.raw_os_error() == Some(26) && attempts < 500 => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        binary_path
    }
    #[cfg(windows)]
    {
        let binary_path = dir.join("fake-antnode.cmd");
        std::fs::write(&binary_path, "@echo off\r\necho antnode 0.1.0-test\r\n").unwrap();
        binary_path
    }
}

#[tokio::test]
async fn get_node_detail_returns_full_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let reg_path = config.registry_path.clone();

    // Add a node to the registry
    let binary = create_fake_binary(dir.path());
    let opts = AddNodeOpts {
        count: 1,
        rewards_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        data_dir_path: Some(dir.path().join("data")),
        log_dir_path: Some(dir.path().join("logs")),
        binary_source: BinarySource::LocalPath(binary),
        ..Default::default()
    };
    ant_core::node::add_nodes(opts, &reg_path, &NoopProgress)
        .await
        .unwrap();

    // Start the daemon
    let registry = NodeRegistry::load(&reg_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();

    // GET /api/v1/nodes/1 — should return full config + runtime state
    let url = format!("http://{addr}/api/v1/nodes/1");
    let resp = reqwest::get(&url).await.unwrap();
    assert!(resp.status().is_success());

    let detail: NodeInfo = resp.json().await.unwrap();
    assert_eq!(detail.config.id, 1);
    assert_eq!(detail.config.service_name, "node1");
    assert_eq!(
        detail.config.rewards_address,
        "0x1234567890abcdef1234567890abcdef12345678"
    );
    assert!(detail.config.data_dir.exists());
    assert_eq!(detail.status, ant_core::node::types::NodeStatus::Stopped);
    assert!(detail.pid.is_none());
    assert!(detail.uptime_secs.is_none());

    // Verify JSON includes flattened config fields (serde flatten)
    let raw: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    assert!(raw.get("id").is_some(), "should have flattened id");
    assert!(
        raw.get("service_name").is_some(),
        "should have flattened service_name"
    );
    assert!(
        raw.get("data_dir").is_some(),
        "should have flattened data_dir"
    );
    assert!(
        raw.get("rewards_address").is_some(),
        "should have flattened rewards_address"
    );
    assert!(raw.get("status").is_some());

    // GET /api/v1/nodes/999 — should 404
    let resp_404 = reqwest::get(format!("http://{addr}/api/v1/nodes/999"))
        .await
        .unwrap();
    assert_eq!(resp_404.status(), 404);

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// The daemon of the storage-node image's manager (`darwin-nodes daemon run`) serves the node
/// manager's core, with the shapes the image's entrypoint and the servers' monitoring read, and no
/// reset and no log forwarding. The darwin CLI's daemon still documents both.
#[tokio::test]
async fn the_image_managers_daemon_serves_the_core_and_no_reset_or_log_forwarding() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let addr = server::start_image_manager(config, registry, shutdown.clone())
        .await
        .unwrap();
    let client = reqwest::Client::new();

    for path in [
        "/api/v1/status",
        "/api/v1/health",
        "/api/v1/nodes/status",
        "/console",
    ] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "GET {path}: {}", resp.status());
    }
    let status: DaemonStatus = client
        .get(format!("http://{addr}/api/v1/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status.running);

    for (method, path) in [
        (reqwest::Method::POST, "/api/v1/reset"),
        (reqwest::Method::GET, "/api/v1/logs/forward"),
        (reqwest::Method::POST, "/api/v1/logs/forward/enable"),
        (reqwest::Method::POST, "/api/v1/logs/forward/disable"),
    ] {
        let resp = client
            .request(method.clone(), format!("http://{addr}{path}"))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{method} {path}");
    }

    let spec: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/openapi.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(spec["info"]["title"], "darwin-nodes API");
    let paths: Vec<&String> = spec["paths"].as_object().unwrap().keys().collect();
    assert!(paths.iter().any(|path| *path == "/api/v1/nodes"));
    assert!(
        paths
            .iter()
            .all(|path| !path.contains("reset") && !path.contains("logs")),
        "{paths:?}"
    );
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    assert!(schemas.keys().all(|name| !name.contains("LogForward")));
    shutdown.cancel();

    // The darwin CLI's daemon (off in the CLI) is unchanged: it documents both.
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let registry = NodeRegistry::load(&config.registry_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let addr = server::start(config, registry, shutdown.clone())
        .await
        .unwrap();
    let spec: serde_json::Value = reqwest::get(format!("http://{addr}/api/v1/openapi.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for path in [
        "/api/v1/reset",
        "/api/v1/logs/forward",
        "/api/v1/logs/forward/enable",
        "/api/v1/logs/forward/disable",
        "/api/v1/nodes",
        "/api/v1/status",
    ] {
        assert!(spec["paths"][path].is_object(), "{path}");
    }
    assert!(spec["components"]["schemas"]["LogForwardResult"].is_object());
    assert!(spec["components"]["schemas"]["DaemonStatus"].is_object());

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// The image manager's daemon adds nodes from a node binary already on the machine, and refuses
/// every download source before anything is written.
#[tokio::test]
async fn the_image_managers_daemon_adds_from_a_local_binary_only() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir);
    let reg_path = config.registry_path.clone();
    let registry = NodeRegistry::load(&reg_path).unwrap();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let addr = server::start_image_manager(config, registry, shutdown.clone())
        .await
        .unwrap();
    let client = reqwest::Client::new();

    for source in [
        BinarySource::Latest,
        BinarySource::Version("0.11.2".to_string()),
        BinarySource::Url("https://github.com/x/y.tar.gz".to_string()),
    ] {
        let opts = AddNodeOpts {
            count: 1,
            rewards_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            data_dir_path: Some(dir.path().join("data")),
            binary_source: source,
            ..Default::default()
        };
        let resp = client
            .post(format!("http://{addr}/api/v1/nodes"))
            .json(&opts)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("downloads no node binary"),
            "{body}"
        );
        assert!(!reg_path.exists(), "the registry was not written");
        assert!(!dir.path().join("data").exists());
    }

    let opts = AddNodeOpts {
        count: 1,
        rewards_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
        data_dir_path: Some(dir.path().join("data")),
        binary_source: BinarySource::LocalPath(create_fake_binary(dir.path())),
        ..Default::default()
    };
    let resp = client
        .post(format!("http://{addr}/api/v1/nodes"))
        .json(&opts)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let detail: NodeInfo = client
        .get(format!("http://{addr}/api/v1/nodes/1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail.config.service_name, "node1");
    assert!(detail.config.data_dir.is_dir());

    shutdown.cancel();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// A node an earlier manager evicted stays refused, and each daemon names its own command for
/// dismissing it.
#[tokio::test]
async fn each_daemon_names_its_own_command_for_a_node_an_earlier_manager_evicted() {
    for (image_manager, command) in [
        (true, "darwin-nodes dismiss 1"),
        (false, "darwin node dismiss 1"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(&dir);
        let reg_path = config.registry_path.clone();
        let opts = AddNodeOpts {
            count: 1,
            rewards_address: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            data_dir_path: Some(dir.path().join("data")),
            binary_source: BinarySource::LocalPath(create_fake_binary(dir.path())),
            ..Default::default()
        };
        ant_core::node::add_nodes(opts, &reg_path, &NoopProgress)
            .await
            .unwrap();
        let mut registry = NodeRegistry::load(&reg_path).unwrap();
        registry.get_mut(1).unwrap().eviction = Some(ant_core::node::types::EvictionRecord {
            reason: "Automatically evicted to reclaim disk space".to_string(),
            evicted_at: 1_760_000_000,
            reclaimed_bytes: 1_000_000,
        });
        registry.save().unwrap();

        let shutdown = tokio_util::sync::CancellationToken::new();
        let addr = if image_manager {
            server::start_image_manager(config, registry, shutdown.clone()).await
        } else {
            server::start(config, registry, shutdown.clone()).await
        }
        .unwrap();

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/api/v1/nodes/1/start"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 409);
        let body: serde_json::Value = resp.json().await.unwrap();
        let error = body["error"].as_str().unwrap();
        assert!(error.contains(command), "{error}");
        assert!(error.contains("earlier node manager"), "{error}");
        assert_eq!(body["current_state"]["status"], "evicted");

        shutdown.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
