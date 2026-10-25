// Copyright 2026 Saorsa Labs Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native wallet journal: persist a signed payment before any storage broadcast.
use super::{
    batch::ChunkPaymentPlan,
    merkle::PreparedMerkleBatch,
    upload::{MerkleUploadPayment, UploadAdapter, UploadPayment, UploadRecord},
    upload_state::{PaymentAttempt, UploadState},
    Client,
};
use crate::data::error::{Error, Result};
use ant_protocol::evm::journal::{PaymentReceipt, PaymentRequest, PaymentStatus, SignedPayment};
use ant_protocol::evm::Network;
use ant_protocol::XorName;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// How long a payment whose outcome is unknown waits before it is
/// reconciled, so the RPC has caught up with the transaction.
pub(super) const PAYMENT_RECHECK_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `state` holds a payment whose outcome is unknown: a transaction
/// was signed and sent, and neither confirmed nor shown to have failed.
pub(super) fn payment_outcome_unknown(state: &UploadState) -> bool {
    state
        .pending_payment
        .as_ref()
        .is_some_and(|attempt| !attempt.submissions.is_empty())
}

/// Where the checkpoints of records paid one at a time are kept, under the
/// data directory ([`RecordCheckpoint`]).
pub(super) const RECORD_CHECKPOINTS: &str = "payments/record";

/// The checkpoint of one record paid for by this client's wallet: a chunk, or
/// a pointer's state.
///
/// It holds the payment's journal from before the transaction is signed until
/// it is confirmed, and then the paid proof until the record is stored. So a
/// payment the RPC answered with an error, or a record that failed to store
/// after it was paid, is found by the next attempt to store the same record
/// with the same wallet on the same network, which reconciles the journaled
/// transaction from the chain, or reuses the proof, instead of paying again.
/// It is named by the payment network, the payer and the record's address (a
/// pointer's `state_id`), and its lock is held while the record is paid for
/// and stored.
pub(super) struct RecordCheckpoint {
    files: super::upload_checkpoint::UploadCheckpointFiles,
    _lock: std::fs::File,
}

impl RecordCheckpoint {
    /// Open the checkpoint of `payer`'s payment for the record at `address`
    /// on `network`, in `directory`: wait for its lock, and read the state an
    /// earlier attempt saved (an empty one if there was none). Once the lock
    /// is held, other records' checkpoints untouched for 30 days with no
    /// pending payment are removed
    /// ([`remove_unresumed`](super::upload_checkpoint::remove_unresumed)).
    pub(super) async fn open(
        directory: &Path,
        network: &Network,
        payer: &[u8],
        address: &XorName,
    ) -> Result<(Self, UploadState)> {
        let scope = rmp_serde::to_vec(&(network, payer, address))
            .map_err(|e| Error::Serialization(e.to_string()))?;
        std::fs::create_dir_all(directory)?;
        let directory = super::file::long_path_safe(directory.to_path_buf());
        let path = directory.join(format!(
            "{}.msgpack",
            hex::encode(blake3::hash(&scope).as_bytes())
        ));
        let lock_path = path.with_extension("lock");
        let lock = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(lock_path)?;
            fs2::FileExt::lock_exclusive(&file)?;
            Ok(file)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))??;
        super::upload_checkpoint::remove_unresumed(&directory);
        let (files, state) = super::upload_checkpoint::UploadCheckpointFiles::open(path)?;
        Ok((Self { files, _lock: lock }, state.unwrap_or_default()))
    }

    /// Save `state`: its new proofs appended, the rest whole or not at all.
    pub(super) fn save(&self, state: &UploadState) -> Result<()> {
        self.files.save(state)
    }

    /// Remove the checkpoint, once the record is stored or its proof is in
    /// the caller's hands. Never fails: a checkpoint left behind is only
    /// logged, and the next attempt for the record finds its proof stored or
    /// still usable.
    pub(super) fn finish(self) {
        self.files.remove();
    }
}

/// The journal's persistence: [`pay`] saves the payment's state here before
/// the transaction is signed, before it is sent and once it is confirmed.
#[async_trait::async_trait]
impl UploadAdapter for RecordCheckpoint {
    async fn load(&self, _: UploadRecord) -> Result<bytes::Bytes> {
        Err(Error::InvalidData(
            "a record's payment checkpoint holds no bytes".into(),
        ))
    }
    async fn pay(&self, _: &[ChunkPaymentPlan]) -> Result<UploadPayment> {
        Err(Error::Payment(
            "a record's payment goes through the journal".into(),
        ))
    }
    async fn checkpoint(&self, state: &UploadState, _: Option<&UploadPayment>) -> Result<()> {
        self.save(state)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "native_payment_v1",
    content = "transaction",
    rename_all = "snake_case"
)]
enum Journal {
    Preparing,
    Signed(SignedPayment),
}

pub(super) fn initialize(attempt: &mut PaymentAttempt) {
    // This synchronous marker is persisted with the attempt, before wallet I/O.
    attempt.submissions = vec![serde_json::json!({ "native_payment_v1": "preparing" })];
}

pub(super) async fn pay<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    plans: &[ChunkPaymentPlan],
    state: &mut UploadState,
) -> Result<UploadPayment> {
    let quotes = plans
        .iter()
        .flat_map(|p| p.payment.quotes.iter())
        .filter(|q| q.amount != ant_protocol::evm::Amount::ZERO)
        .map(|q| (q.quote_hash, q.rewards_address, q.amount))
        .collect::<Vec<_>>();
    let hashes = quotes.iter().map(|q| q.0).collect::<Vec<_>>();
    let fresh = |state: &UploadState| {
        plans.iter().all(|p| {
            state
                .retained_plan(&p.address, p.data_size, crate::runtime::system_time())
                .is_some()
        })
    };
    let receipt = execute(
        client,
        adapter,
        &PaymentRequest::Quotes(quotes),
        state,
        fresh,
    )
    .await?;
    Ok(UploadPayment {
        transactions: hashes
            .into_iter()
            .map(|h| (h, receipt.transaction_hash))
            .collect(),
        amount: receipt.amount,
        gas: receipt.gas_cost_wei,
    })
}

pub(super) async fn pay_merkle<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    batch: &PreparedMerkleBatch,
    state: &mut UploadState,
) -> Result<MerkleUploadPayment> {
    let request = PaymentRequest::Merkle {
        depth: batch.depth,
        pools: batch.pool_commitments.clone(),
        timestamp: batch.merkle_payment_timestamp,
    };
    let fresh = |_: &UploadState| {
        super::upload_state::merkle_fresh(
            batch.merkle_payment_timestamp,
            crate::runtime::system_time(),
        )
    };
    let receipt = execute(client, adapter, &request, state, fresh).await?;
    Ok(MerkleUploadPayment {
        winner_pool: receipt
            .winner_pool
            .ok_or_else(|| Error::Payment("missing confirmed Merkle winner".into()))?,
        amount: receipt.amount,
        gas: receipt.gas_cost_wei,
    })
}

/// The network refused the nonce of a payment signed in this call. Those bytes
/// never left the process, so nothing was paid and preparing again is safe.
const STALE_UNSENT_NONCE: &str = "stale nonce on an unsent payment; preparing again";

/// A definitive nonce rejection from the endpoint, as opposed to a transport
/// failure (which `broadcast_payment` has already retried).
fn is_stale_nonce(message: &str) -> bool {
    message.to_ascii_lowercase().contains("nonce too low")
}

async fn execute<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    adapter: &A,
    request: &PaymentRequest,
    state: &mut UploadState,
    fresh: F,
) -> Result<PaymentReceipt> {
    // A nonce is read from a public endpoint whose replicas lag each other, so
    // a freshly signed payment can carry a nonce the chain already consumed
    // (measured 1 in 150 reads on Arbitrum Sepolia, DEV-03 run 589). Such bytes
    // can never be mined and were never sent, so one re-preparation is the fix.
    match execute_once(client, adapter, request, state, &fresh).await {
        Err(Error::Payment(message)) if message == STALE_UNSENT_NONCE => {
            execute_once(client, adapter, request, state, &fresh).await
        }
        outcome => outcome,
    }
}

async fn execute_once<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    adapter: &A,
    request: &PaymentRequest,
    state: &mut UploadState,
    fresh: &F,
) -> Result<PaymentReceipt> {
    let attempt = state
        .pending_payment
        .as_ref()
        .ok_or_else(|| Error::Payment("missing native payment attempt".into()))?;
    let journal: Journal =
        match attempt.submissions.as_slice() {
            [value] => serde_json::from_value(value.clone()).map_err(|_| {
                Error::Payment(
                    "unknown native payment journal; reconciliation evidence is required".into(),
                )
            })?,
            _ => return Err(Error::Payment(
                "legacy pending payment has no transaction identity; reconcile it before retrying"
                    .into(),
            )),
        };
    let wallet = client.require_wallet()?;
    let _wallet_lock = wallet.lock().await;
    // True only for bytes signed below, in this call: they have never been
    // broadcast, so there is nothing on chain to observe before sending them.
    let mut unsent = false;
    let signed = match journal {
        Journal::Signed(signed) => signed,
        Journal::Preparing => {
            // This marker proves no storage payment was broadcast by this implementation.
            let prepared = if let Some(refusal) = client.corroborated_settlement_refusal() {
                Err(Error::ClientUpdateRequired(refusal))
            } else if !fresh(state) {
                Err(Error::Payment(
                    "unsubmitted payment quotes expired; retry to prepare fresh quotes".into(),
                ))
            } else {
                wallet
                    .prepare_payment(request)
                    .await
                    .map_err(Error::Payment)
            };
            let signed = match prepared {
                Ok(signed) => signed,
                Err(error) => {
                    state.pending_payment = None;
                    adapter.checkpoint(state, None).await?;
                    return Err(error);
                }
            };
            let value = serde_json::to_value(Journal::Signed(signed.clone()))
                .map_err(|e| Error::Serialization(e.to_string()))?;
            if let Some(attempt) = &mut state.pending_payment {
                attempt.submissions = vec![value];
            }
            adapter.checkpoint(state, None).await?;
            unsent = true;
            signed
        }
    };
    let mut broadcast = false;
    let observation = async {
        loop {
            if unsent && !broadcast {
                // Freshness and settlement refusal were checked moments ago,
                // before signing. A rejected nonce here can only be a stale
                // nonce read: discard the journal and let `execute` prepare
                // again. Any other rejection is final for this attempt.
                match wallet.broadcast_payment(&signed, request).await {
                    Ok(_) => broadcast = true,
                    Err(message) if is_stale_nonce(&message) => {
                        if let Some(attempt) = &mut state.pending_payment {
                            initialize(attempt);
                        }
                        adapter.checkpoint(state, None).await?;
                        return Err(Error::Payment(STALE_UNSENT_NONCE.into()));
                    }
                    Err(message) => return Err(Error::Payment(message)),
                }
            }
            match wallet
                .observe_payment(&signed, request)
                .await
                .map_err(Error::Payment)?
            {
                PaymentStatus::Confirmed(receipt) => {
                    if let Some(attempt) = &mut state.pending_payment {
                        attempt.receipt = Some(
                            serde_json::to_value(&receipt)
                                .map_err(|e| Error::Serialization(e.to_string()))?,
                        );
                    }
                    adapter.checkpoint(state, None).await?;
                    return Ok(receipt);
                }
                PaymentStatus::Reverted => {
                    state.pending_payment = None;
                    adapter.checkpoint(state, None).await?;
                    return Err(Error::Payment(
                        "payment reverted on-chain; retry is safe".into(),
                    ));
                }
                PaymentStatus::Finalizing => {
                    return Err(Error::Payment(
                        "payment outcome is awaiting chain finality; retain its journal and retry later"
                            .into(),
                    ));
                }
                PaymentStatus::Replaced { transaction_hash } => {
                    state.pending_payment = None;
                    adapter.checkpoint(state, None).await?;
                    return Err(Error::Payment(format!(
                        "payment nonce was finalized by transaction {transaction_hash}; retry is safe"
                    )));
                }
                PaymentStatus::Pending => {
                    if !broadcast {
                        if let Some(refusal) = client.corroborated_settlement_refusal() {
                            return Err(Error::ClientUpdateRequired(refusal));
                        }
                        if !fresh(state) {
                            return Err(Error::Payment("pending payment has expired quotes; retain its transaction journal for reconciliation".into()));
                        }
                        // An ambiguous send only ever retries these exact signed bytes.
                        // A nonce rejection means the nonce is used: by these bytes,
                        // whose receipt a lagging replica doesn't show yet (seen live on
                        // a load-balanced endpoint), or by another transaction, which
                        // finality turns into `Replaced`. Either way, keep observing
                        // until the timeout below rather than fail at once.
                        match wallet.broadcast_payment(&signed, request).await {
                            Ok(_) => {}
                            Err(message) if is_stale_nonce(&message) => {
                                tracing::debug!(
                                    "re-sent payment's nonce is already used ({message}); observing"
                                );
                            }
                            Err(message) => return Err(Error::Payment(message)),
                        }
                        broadcast = true;
                    }
                    crate::runtime::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    };
    crate::runtime::timeout(std::time::Duration::from_secs(30), observation)
        .await
        .map_err(|_| {
            Error::Payment(
                "payment outcome pending; retry will reconcile the journaled transaction".into(),
            )
        })?
}

#[cfg(feature = "test-utils")]
impl Client {
    /// Exercise the native payment journal with an injected persistence adapter.
    /// Available only to integration tests built with `test-utils`.
    pub async fn test_execute_native_payment<A: UploadAdapter>(
        &self,
        adapter: &A,
        request: &PaymentRequest,
        state: &mut UploadState,
        fresh: bool,
    ) -> Result<PaymentReceipt> {
        if state.pending_payment.is_none() {
            state.start_payment(false, Vec::new())?;
            initialize(state.pending_payment.as_mut().expect("just initialized"));
            adapter.checkpoint(state, None).await?;
        }
        execute(self, adapter, request, state, |_| fresh).await
    }
}

/// Plans and payments of records for the tests of the record checkpoint and
/// of the payments that use it.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(super) mod test_plans {
    use super::*;
    use crate::data::client::batch::SingleNodeQuotePayment;
    use ant_protocol::evm::{Amount, CustomNetwork, EncodedPeerId, PaymentQuote, QuoteHash};
    use ant_protocol::evm::{RewardsAddress, TxHash};
    use ant_protocol::transport::NodeIdentity;
    use std::collections::HashMap;
    use std::path::PathBuf;

    /// The plan of a record of `data_size` bytes at `address`: one quote,
    /// signed by a fresh node at `timestamp`.
    pub(crate) fn signed_plan(
        address: XorName,
        data_size: u64,
        timestamp: std::time::SystemTime,
    ) -> ChunkPaymentPlan {
        let identity = NodeIdentity::generate().unwrap();
        let mut quote = PaymentQuote {
            content: xor_name::XorName(address),
            timestamp,
            price: Amount::from(10),
            rewards_address: RewardsAddress::new([1; 20]),
            pub_key: identity.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
            committed_key_count: 0,
            commitment_pin: None,
        };
        quote.signature = identity
            .sign(&quote.bytes_for_sig())
            .unwrap()
            .as_bytes()
            .to_vec();
        ChunkPaymentPlan {
            address,
            data_size,
            quoted_peers: Vec::new(),
            payment: SingleNodeQuotePayment::from_quotes(vec![quote.clone()]).unwrap(),
            peer_quotes: vec![(
                EncodedPeerId::new(*blake3::hash(&quote.pub_key).as_bytes()),
                quote,
            )],
            commitment_sidecars: Vec::new(),
        }
    }

    /// A transaction for each paid quote of `plan`.
    pub(crate) fn transactions(plan: &ChunkPaymentPlan) -> HashMap<QuoteHash, TxHash> {
        plan.payment
            .quotes
            .iter()
            .filter(|quote| !quote.amount.is_zero())
            .map(|quote| (quote.quote_hash, TxHash::from([7; 32])))
            .collect()
    }

    /// A payment network whose RPC is at `port` on this machine.
    pub(crate) fn network(port: u16) -> Network {
        Network::Custom(CustomNetwork {
            rpc_url_http: format!("http://127.0.0.1:{port}").parse().unwrap(),
            payment_token_address: [0x11; 20].into(),
            payment_vault_address: [0x22; 20].into(),
        })
    }

    /// The checkpoints saved in `directory`.
    pub(crate) fn checkpoints(directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "msgpack"))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::test_plans::{checkpoints, network, signed_plan, transactions};
    use super::*;
    use std::time::Duration;

    #[test]
    fn only_a_sent_payment_without_an_outcome_is_rechecked() {
        let mut state = UploadState::default();
        // Nothing pending.
        assert!(!payment_outcome_unknown(&state));
        // Pending, but no transaction sent yet: nothing on the chain to find.
        state.start_payment(false, vec![[1; 32]]).unwrap();
        assert!(!payment_outcome_unknown(&state));
        // A transaction sent and no outcome: the chain may hold the payment.
        state
            .pending_payment
            .as_mut()
            .unwrap()
            .submissions
            .push(serde_json::json!({ "native_payment_v1": {} }));
        assert!(payment_outcome_unknown(&state));
        // Settled either way (confirmed, or shown to have failed): nothing to reconcile.
        state.pending_payment = None;
        assert!(!payment_outcome_unknown(&state));
    }

    /// A record's checkpoint is its own for each payment network, payer and
    /// record: none of them reads another's payment.
    #[tokio::test]
    async fn a_records_checkpoint_is_named_by_network_payer_and_address() {
        let directory = tempfile::tempdir().unwrap();
        let mut paths = std::collections::HashSet::new();
        for (port, payer, address) in [
            (1, [1u8; 20], [1u8; 32]),
            (2, [1; 20], [1; 32]),
            (1, [2; 20], [1; 32]),
            (1, [1; 20], [2; 32]),
        ] {
            let (checkpoint, state) =
                RecordCheckpoint::open(directory.path(), &network(port), &payer, &address)
                    .await
                    .unwrap();
            assert!(state.pending_payment.is_none() && state.proof(&address).is_none());
            checkpoint.save(&state).unwrap();
            paths.insert(checkpoint.files.path().to_path_buf());
        }
        assert_eq!(paths.len(), 4);
        assert_eq!(checkpoints(directory.path()).len(), 4);
    }

    /// The journal of a payment, then its proof, are read back by the next
    /// attempt for the same record, until the checkpoint is finished.
    #[tokio::test]
    async fn a_records_checkpoint_keeps_the_journal_then_the_proof_until_finished() {
        let directory = tempfile::tempdir().unwrap();
        let (net, payer, address) = (network(1), [3u8; 20], [3u8; 32]);
        let now = crate::runtime::system_time();
        let plan = signed_plan(address, 1024, now);
        let open = || RecordCheckpoint::open(directory.path(), &net, &payer, &address);

        let (checkpoint, mut state) = open().await.unwrap();
        state.prepare(plan.clone());
        state.start_payment(false, vec![address]).unwrap();
        initialize(state.pending_payment.as_mut().unwrap());
        checkpoint.save(&state).unwrap();
        drop(checkpoint);

        let (checkpoint, mut state) = open().await.unwrap();
        assert!(payment_outcome_unknown(&state), "the journal is read back");
        assert_eq!(state.pending_plans().unwrap()[0].address, address);
        state
            .confirm(&[address], &transactions(&plan), now)
            .unwrap();
        let proof = state.proof(&address).cloned().unwrap();
        checkpoint.save(&state).unwrap();
        drop(checkpoint);

        let (checkpoint, state) = open().await.unwrap();
        assert!(state.pending_payment.is_none());
        assert!(state.is_paid(&address, now), "the proof is read back");
        assert_eq!(state.proof(&address), Some(&proof));
        checkpoint.finish();
        assert!(checkpoints(directory.path()).is_empty());

        let (_, state) = open().await.unwrap();
        assert!(state.pending_payment.is_none() && state.proof(&address).is_none());
    }

    /// A second attempt at the same record waits for the first to let go of
    /// its checkpoint, so two never pay for one record at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_records_checkpoint_waits_for_the_attempt_holding_it() {
        let directory = tempfile::tempdir().unwrap();
        let (net, payer, address) = (network(1), [4u8; 20], [4u8; 32]);
        let (first, _) = RecordCheckpoint::open(directory.path(), &net, &payer, &address)
            .await
            .unwrap();
        let second = {
            let directory = directory.path().to_path_buf();
            let net = net.clone();
            tokio::spawn(async move {
                RecordCheckpoint::open(&directory, &net, &payer, &address)
                    .await
                    .map(|(checkpoint, _)| checkpoint.files.path().to_path_buf())
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!second.is_finished(), "the second attempt must wait");
        let path = first.files.path().to_path_buf();
        first.finish();
        let opened = tokio::time::timeout(Duration::from_secs(10), second)
            .await
            .expect("opened once the first let go")
            .unwrap()
            .unwrap();
        assert_eq!(opened, path);
    }
}
