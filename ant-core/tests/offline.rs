//! Client checks that fail before any network call, on a client whose node
//! has no peers, and the DARWIN vault fixture the e2e testnets deploy. No
//! storage nodes and no chain: build.yml runs this target.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ant_core::data::client::merkle::PaymentMode;
use ant_core::data::{Client, Error};
use ant_protocol::transport::{CoreNodeConfig, P2PNode};
use bytes::Bytes;
use std::sync::Arc;
use tempfile::TempDir;

/// A client on a node bound to a free loopback port and never started: it
/// knows no peer, so anything that reached the network would fail there.
async fn offline_client() -> Client {
    let config = CoreNodeConfig::builder()
        .port(0)
        .local(true)
        .build()
        .expect("node config");
    let node = P2PNode::new(config).await.expect("create node");
    Client::from_node(Arc::new(node), Default::default())
}

/// An estimate refuses a file below self-encryption's minimum of 3 bytes.
#[tokio::test]
async fn an_estimate_refuses_a_file_too_small_to_encrypt() {
    let client = offline_client().await;
    let work_dir = TempDir::new().expect("create work dir");
    let tiny_path = work_dir.path().join("tiny.bin");
    std::fs::write(&tiny_path, b"ab").expect("write tiny file");

    let result = client
        .estimate_upload_cost(&tiny_path, PaymentMode::Auto, None)
        .await;
    assert!(
        matches!(&result, Err(Error::InvalidData(m)) if m.contains("too small")),
        "Estimate should fail for files < 3 bytes, got {result:?}"
    );
}

/// An upload of in-memory data below self-encryption's minimum fails.
#[tokio::test]
async fn a_data_upload_too_small_to_encrypt_fails() {
    let client = offline_client().await;
    // MIN_ENCRYPTABLE_BYTES = 3 (3 * MIN_CHUNK_SIZE where MIN_CHUNK_SIZE=1),
    // so only 0, 1, or 2 bytes fail.
    let result = client.data_upload(Bytes::from(vec![0x42u8; 2])).await;
    assert!(
        matches!(&result, Err(Error::Encryption(_))),
        "data smaller than MIN_ENCRYPTABLE_BYTES (3) should fail to encrypt, got {:?}",
        result.err()
    );
}

/// An upload of a file that does not exist fails.
#[tokio::test]
async fn a_file_upload_of_a_missing_path_fails() {
    let client = offline_client().await;
    let work_dir = TempDir::new().expect("create work dir");
    let missing = work_dir.path().join("missing.bin");
    let result = client.file_upload(&missing).await;
    assert!(
        result.is_err(),
        "file_upload on non-existent path should fail"
    );
}

/// The fixture is the deployed DARWIN vault's creation code: with the DARWIN
/// token and batch limit 512 as arguments, it hashes to the recorded
/// deployment's creation code (payment-vault's deployment.json).
#[test]
fn the_vault_fixture_is_the_deployed_vaults_code() {
    use alloy::primitives::{address, keccak256, U256};
    use alloy::sol_types::SolValue;
    let mut code =
        hex::decode(include_str!("fixtures/darwin-vault-creation-code.hex").trim()).unwrap();
    code.extend(
        (
            address!("511f76A3De41F000EC11EA4fD212fb3587c6cef3"),
            U256::from(512u64),
        )
            .abi_encode_params(),
    );
    assert_eq!(
        hex::encode(keccak256(&code)),
        "ee232ab3534f8cab41744a6bf26f862d6e72dc28529f218db5e94c386f8dcac1"
    );
}
