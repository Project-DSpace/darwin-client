# ant-protocol

Wire protocol types and helpers for the Autonomi decentralized network.

`ant-protocol` defines the on-wire contract between clients and nodes on
the Autonomi network: chunk request/response messages, content
addressing, payment proof formats, and the pure-verification half of the
ML-DSA-65 signing scheme.

## Modules

| Module | Contents |
|---|---|
| `chunk` | Chunk protocol messages (`ChunkMessage`, PUT/GET/Quote/MerkleCandidateQuote request+response), protocol constants (`CHUNK_PROTOCOL_ID`, `MAX_CHUNK_SIZE`, `MAX_WIRE_MESSAGE_SIZE`, `CLOSE_GROUP_SIZE`, `CLOSE_GROUP_MAJORITY`), `ProtocolError`, proof type tags |
| `data_types` | Address helpers — `compute_address` (BLAKE3), `xor_distance`, `peer_id_to_xor_name` — and `DataChunk` |
| `chunk_protocol` | `send_and_await_chunk_response`: the subscribe/send/poll helper used to exchange chunk messages on a `P2PNode` |
| `payment` | On-wire payment artifacts: `PaymentProof`, `SingleNodePayment` (with `pay` and `verify`), and ML-DSA-65 signature verification for quotes and merkle candidates |
| `devnet_manifest` | `DevnetManifest` / `DevnetEvmInfo` — the on-disk handoff document written by a devnet launcher and read by clients connecting to it |

### Transitive re-exports

`evmlib`, `saorsa-core`, and `saorsa-pqc` are re-exported under three
modules so downstream crates can pin them through `ant-protocol`:

| Module | Wraps |
|---|---|
| `ant_protocol::evm` | `evmlib` (`Wallet`, `PaymentQuote`, `ProofOfPayment`, `RewardsAddress`, `Network`, merkle payment types, Anvil `Testnet`) |
| `ant_protocol::transport` | `saorsa-core` (`P2PNode`, `PeerId`, `MultiAddr`, `P2PEvent`, `NodeIdentity`, `MlDsa65`) |
| `ant_protocol::pqc` | `saorsa-pqc` (ML-DSA-65 types and operations, both the `pqc::*` and `api::sig::*` API paths) |

## Install

```toml
[dependencies]
ant-protocol = "2"
```

## Features

| Feature | Default | Description |
|---|---|---|
| `logging` | yes | Re-exports the `tracing` macros. Disable with `--no-default-features` for minimum-overhead builds; the macros then expand to no-ops. |

## Compatibility

- Requires Rust 1.75 or later.
- The `2.x` series is the current release line. It is not wire-compatible
  with `1.x` releases of the same crate name previously published from a
  different repository.
- `ChunkMessageBody`, `ChunkPutResponse`, `ChunkGetResponse`,
  `ChunkQuoteResponse`, `MerkleCandidateQuoteResponse`, `ProofType`,
  `ProtocolError`, and `Error` are marked `#[non_exhaustive]`, so new
  variants can be added in a minor release without breaking downstream
  exhaustive-match compilation.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Native and browser features

The default `native` feature retains the native node transport, wallet, and
local testnet API. With `default-features = false`, the same chunk wire types,
quotes, proof serialization, pricing, commitments, signature verification,
saorsa-core identities/peer records, and lookup APIs compile for browser WASM.
Enable `rpc` for HTTP wallet/contract operations using browser Fetch. Native
socket event handling and local process management require `native`.

```sh
cargo check --lib --no-default-features --target wasm32-unknown-unknown
cargo check --lib --no-default-features --features rpc --target wasm32-unknown-unknown
```

Pre-release dependency revisions are pinned to the coordinated web-support
branches. The earlier experimental browser crypto/session surface on this
branch is superseded by shared saorsa-pqc and saorsa_transport::webrtc APIs; application
messages use the ordinary ant-protocol types on both targets.
