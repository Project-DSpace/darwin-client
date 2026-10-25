//! Payment orchestration for the Autonomi client.
//!
//! Connects quote collection, on-chain EVM payment, and proof serialization.
//! Every PUT to the network requires a valid payment proof.

use crate::data::client::batch::ChunkPaymentPlan;
#[cfg(not(feature = "native"))]
use crate::data::client::batch::SingleNodeQuotePayment;
#[cfg(feature = "native")]
use crate::data::client::native_payment::{
    payment_outcome_unknown, RecordCheckpoint, PAYMENT_RECHECK_DELAY, RECORD_CHECKPOINTS,
};
#[cfg(feature = "native")]
use crate::data::client::occupied::OccupiedQuote;
use crate::data::client::occupied::{occupied_error, MAX_OCCUPIED_REQUOTES};
#[cfg(not(feature = "native"))]
use crate::data::client::quote::median_paid_quote_issuer;
#[cfg(feature = "native")]
use crate::data::client::upload::{paid_outside_width, validate_payment_total, UploadPayment};
#[cfg(feature = "native")]
use crate::data::client::upload_state::{reusable_proof, UploadState};
use crate::data::client::Client;
use crate::data::error::{Error, Result};
#[cfg(not(feature = "native"))]
use ant_protocol::evm::ProofOfPayment;
use ant_protocol::evm::{EncodedPeerId, Wallet};
#[cfg(not(feature = "native"))]
use ant_protocol::payment::{serialize_single_node_proof, PaymentProof};
use ant_protocol::transport::{MultiAddr, PeerId};
#[cfg(feature = "native")]
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub(crate) use crate::payment_policy::SINGLE_NODE_PAYMENT_MULTIPLIER;

/// A record paid for by this client's wallet and not stored yet
/// ([`Client::pay_for_record`]): its proof, where to store it, and its
/// checkpoint, which keeps the proof, and holds the record's lock, until
/// [`Self::stored`].
#[cfg(feature = "native")]
pub(crate) struct PaidRecord {
    /// The serialized payment proof.
    pub(crate) proof: Vec<u8>,
    /// The ordered PUT targets: those of this payment's quotes, or of a
    /// fresh quote for a chunk an earlier attempt paid for. None for a
    /// pointer state an earlier attempt paid for: its write looks up the
    /// close group itself.
    pub(crate) put_peers: Vec<(PeerId, Vec<MultiAddr>)>,
    /// Whether the proof is one an earlier attempt paid, kept in the
    /// checkpoint: if every storer refuses it, the record is paid again
    /// ([`Self::refused`]).
    pub(crate) reused: bool,
    checkpoint: RecordCheckpoint,
}

#[cfg(feature = "native")]
impl PaidRecord {
    /// The record is stored: its checkpoint, and the proof kept in it, go.
    pub(crate) fn stored(self) {
        self.checkpoint.finish();
    }

    /// Every storer that failed to store the record refused its proof, one
    /// an earlier attempt paid ([`Self::reused`]): forget the proof, so the
    /// next payment for the record pays again rather than reuse it.
    ///
    /// # Errors
    ///
    /// If the checkpoint can't be written.
    pub(crate) fn refused(self) -> Result<()> {
        self.checkpoint.save(&UploadState::default())
    }

    /// Hand the proof and the PUT targets to a caller that stores the record
    /// itself, out of this client's sight: the checkpoint goes.
    fn handed_over(self) -> (Vec<u8>, Vec<(PeerId, Vec<MultiAddr>)>) {
        self.checkpoint.finish();
        (self.proof, self.put_peers)
    }
}

impl Client {
    /// Get the wallet, returning an error if not configured.
    pub(crate) fn require_wallet(&self) -> Result<&Arc<Wallet>> {
        self.wallet().ok_or_else(|| {
            Error::Payment("Wallet not configured — call with_wallet() first".to_string())
        })
    }

    /// Pay for storage and return the serialized payment proof bytes.
    ///
    /// This orchestrates the full payment flow:
    /// 1. Collect at least one witnessed quote plus ordered PUT targets
    /// 2. Build single-node payment using node-reported prices (median 3x, others 0)
    /// 3. Pay on-chain via the wallet
    /// 4. Serialize `PaymentProof` with transaction hashes
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet is not set, quotes cannot be collected,
    /// on-chain payment fails, or serialization fails.
    /// Returns `(proof_bytes, put_targets)`. The peer list is the ordered PUT
    /// target set from quote planning: it starts with peers expected to accept
    /// the paid proof and can include non-quoted fallback peers beyond the
    /// quoted close group.
    ///
    /// A raw building block: it pays for one record, reading the paid quote
    /// back ([`Self::pay_for_storage_split`]), and stores nothing; the caller
    /// stores the record with the proof, with no envelope unless it adds one.
    /// Upload files with `Client::file_upload`.
    pub async fn pay_for_storage(
        &self,
        address: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<(Vec<u8>, Vec<(PeerId, Vec<MultiAddr>)>)> {
        self.pay_for_storage_split(address, address, data_size, data_type)
            .await
    }

    /// As [`Self::pay_for_storage`], quoting at `content` while collecting from
    /// the close group around `routing`.
    ///
    /// The two are one address for a chunk and two for a pointer, whose address
    /// is stable for its life: paying against it would buy every future update
    /// at once.
    ///
    /// After paying, the paid quote's vault record is read back. If it isn't
    /// the payment (someone recorded the quote first, and the vault skipped
    /// the payment), the record is quoted and paid again, up to
    /// [`MAX_OCCUPIED_REQUOTES`] times.
    ///
    /// The payment is journaled, as an upload's is: the signed transaction is
    /// saved before it is sent, in a checkpoint under the data directory
    /// (`payments/record/`) named by the payment network, the wallet and
    /// `content`. When the RPC answers the payment with an error and its
    /// outcome is unknown, the chain is checked again after 10 seconds; if
    /// the outcome is still unknown, the call fails and the journal stays,
    /// and the next call for the same record with the same wallet reconciles
    /// the transaction from the chain instead of paying again. The checkpoint
    /// goes once the proof is returned, since the caller stores the record;
    /// `Client::chunk_put` and `Client::pointer_put` keep it until the record
    /// is stored. Browser builds journal nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::pay_for_storage`], and an error starting with
    /// [`QUOTES_OCCUPIED`](crate::data::QUOTES_OCCUPIED) when every quote was occupied.
    pub async fn pay_for_storage_split(
        &self,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<(Vec<u8>, Vec<(PeerId, Vec<MultiAddr>)>)> {
        #[cfg(feature = "native")]
        {
            self.pay_for_record(routing, content, data_size, data_type)
                .await
                .map(PaidRecord::handed_over)
        }
        #[cfg(not(feature = "native"))]
        {
            let mut history = Vec::new();
            for requote in 0..=MAX_OCCUPIED_REQUOTES {
                let (proof, put_peers, plan) = self
                    .pay_for_storage_once(routing, content, data_size, data_type)
                    .await?;
                let occupied = self.occupied_quotes(std::slice::from_ref(&plan)).await;
                if occupied.is_empty() {
                    return Ok((proof, put_peers));
                }
                history.extend(occupied);
                if requote < MAX_OCCUPIED_REQUOTES {
                    warn!(
                        "the vault already held another payment's record for the quote paid for \
                         {}; quoting it again ({} of {MAX_OCCUPIED_REQUOTES})",
                        hex::encode(content),
                        requote + 1
                    );
                }
            }
            Err(occupied_error(&history))
        }
    }

    /// Pay for the record at `content` with this client's wallet, or find its
    /// payment, as [`Self::pay_for_storage_split`] does, keeping the record's
    /// checkpoint, and its lock, until the caller has stored the record
    /// ([`PaidRecord::stored`]). If the record is not stored, its proof stays
    /// in the checkpoint, and the next attempt to store the same record with
    /// the same wallet reuses it instead of paying again.
    ///
    /// # Errors
    ///
    /// As [`Self::pay_for_storage_split`], and [`Error::AlreadyStored`] when
    /// the quotes show a chunk the network already holds: nothing is paid,
    /// and its checkpoint goes.
    #[cfg(feature = "native")]
    pub(crate) async fn pay_for_record(
        &self,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<PaidRecord> {
        let directory = crate::config::data_dir()
            .map_err(|e| Error::Config(e.to_string()))?
            .join(RECORD_CHECKPOINTS);
        self.pay_for_record_in(&directory, routing, content, data_size, data_type)
            .await
    }

    /// [`Self::pay_for_record`], with the record's checkpoint in `directory`.
    #[cfg(feature = "native")]
    async fn pay_for_record_in(
        &self,
        directory: &Path,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<PaidRecord> {
        // Checked before the checkpoint is opened, so a client without a
        // wallet neither waits for a lock nor collects quotes.
        let wallet = self.require_wallet()?;
        let (checkpoint, mut state) = RecordCheckpoint::open(
            directory,
            wallet.network(),
            wallet.address().as_slice(),
            content,
        )
        .await?;
        // A payment this wallet sent may have gone through although the RPC
        // answered with an error. Its signed transaction is in the journal,
        // and settling the record again reconciles it from the chain before
        // anything is paid, so do that once here, as an upload does, rather
        // than leave it to the caller.
        let mut rechecked = false;
        loop {
            // Boxed, like the quote's chunk reads, so the journal and the
            // reconciliation don't deepen the type of every future that
            // pays for a record.
            let settled = Box::pin(self.settle_record(
                routing,
                content,
                data_size,
                data_type,
                &mut state,
                &checkpoint,
            ))
            .await;
            match settled {
                Ok((proof, put_peers, reused)) => {
                    return Ok(PaidRecord {
                        proof,
                        put_peers,
                        reused,
                        checkpoint,
                    })
                }
                Err(Error::AlreadyStored) => {
                    // Stored already: neither a payment nor a proof kept
                    // for it is needed any more.
                    checkpoint.finish();
                    return Err(Error::AlreadyStored);
                }
                Err(error) if !rechecked && payment_outcome_unknown(&state) => {
                    rechecked = true;
                    warn!(
                        "Payment outcome unknown ({error}); checking the chain in {}s before giving up",
                        PAYMENT_RECHECK_DELAY.as_secs()
                    );
                    crate::runtime::sleep(PAYMENT_RECHECK_DELAY).await;
                }
                Err(error) => {
                    // With neither a journal to reconcile nor a proof, as
                    // when the payment failed before anything was sent or
                    // failed for good, nothing is left to keep.
                    if state.pending_payment.is_none() && state.proof(content).is_none() {
                        checkpoint.finish();
                    }
                    return Err(error);
                }
            }
        }
    }

    /// One attempt of [`Self::pay_for_record`], from the state the record's
    /// checkpoint holds. A payment an earlier attempt sent is reconciled from
    /// the chain, never paid again; a proof still fresh enough to store is
    /// reused; otherwise the record is quoted and paid, and the paid quote is
    /// read back and the record quoted and paid again if someone recorded it
    /// first, up to [`MAX_OCCUPIED_REQUOTES`] times. Returns the proof, the
    /// PUT targets, and whether the proof is one an earlier attempt paid.
    ///
    /// A kept proof has no age limit: a chunk's is reused while its paid
    /// node is among the [`PUT_TARGET_WIDTH`](crate::quote_policy::PUT_TARGET_WIDTH)
    /// nearest storers a fresh quote names, and paid again otherwise.
    #[cfg(feature = "native")]
    async fn settle_record(
        &self,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
        state: &mut UploadState,
        checkpoint: &RecordCheckpoint,
    ) -> Result<(Vec<u8>, Vec<(PeerId, Vec<MultiAddr>)>, bool)> {
        let mut history = Vec::new();
        if state.pending_payment.is_some() {
            history = self
                .reconcile_record_payment(content, state, checkpoint)
                .await?;
        }
        let now = crate::runtime::system_time();
        if let Some(proof) = state
            .proof(content)
            .filter(|bytes| reusable_proof(content, bytes, now))
            .cloned()
        {
            debug!(
                "Reusing the paid proof kept for {} instead of paying again",
                hex::encode(content)
            );
            // A chunk goes to the PUT targets a fresh quote names, as the
            // upload engine stores a chunk it paid for earlier, and one the
            // network holds already needs nothing more. A pointer's write
            // looks up its own close group.
            let put_peers = if data_type == ant_protocol::DATA_TYPE_CHUNK {
                self.get_store_quote_plan_split(routing, content, data_size, data_type)
                    .await?
                    .put_peers
            } else {
                Vec::new()
            };
            let paid_outside = data_type == ant_protocol::DATA_TYPE_CHUNK
                && paid_outside_width(&proof, &put_peers);
            if !paid_outside {
                return Ok((proof, put_peers, true));
            }
            info!(
                "the node an earlier attempt paid for {} is no longer among its {} nearest \
                 storers; paying for it again",
                hex::encode(content),
                crate::quote_policy::PUT_TARGET_WIDTH
            );
            state.drop_proof(content);
            checkpoint.save(state)?;
        }
        for requote in 0..=MAX_OCCUPIED_REQUOTES {
            let (plan, payment) = self
                .pay_for_storage_once(routing, content, data_size, data_type, state, checkpoint)
                .await?;
            let occupied = self.occupied_quotes(std::slice::from_ref(&plan)).await;
            if let Some(proof) = confirm_record(&plan, &payment, &occupied, state, checkpoint)? {
                return Ok((proof, plan.quoted_peers, false));
            }
            history.extend(occupied);
            if requote < MAX_OCCUPIED_REQUOTES {
                warn!(
                    "the vault already held another payment's record for the quote paid for \
                     {}; quoting it again ({} of {MAX_OCCUPIED_REQUOTES})",
                    hex::encode(content),
                    requote + 1
                );
            }
        }
        Err(occupied_error(&history))
    }

    /// Reconcile the payment an earlier attempt journaled for the record at
    /// `content`, as an upload reconciles its own: from the chain, sending
    /// at most the journaled transaction again, never a new one. Once
    /// confirmed, its paid quote is read back: the payment becomes the
    /// record's proof, or, if someone recorded the quote first, it is
    /// dropped and the occupied quotes returned, so the record is quoted
    /// again.
    ///
    /// # Errors
    ///
    /// Why the outcome is still unknown, with the journal kept, or how the
    /// payment ended if it failed or was replaced, with the journal gone.
    #[cfg(feature = "native")]
    async fn reconcile_record_payment(
        &self,
        content: &[u8; 32],
        state: &mut UploadState,
        checkpoint: &RecordCheckpoint,
    ) -> Result<Vec<OccupiedQuote>> {
        let plan = match state.pending_plans()?.as_slice() {
            [plan] if plan.address == *content => plan.clone(),
            _ => {
                return Err(Error::InvalidData(format!(
                    "the payment checkpoint of {} holds another record's payment",
                    hex::encode(content)
                )))
            }
        };
        debug!(
            "Reconciling the journaled payment for {} from the chain",
            hex::encode(content)
        );
        let payment =
            super::native_payment::pay(self, checkpoint, std::slice::from_ref(&plan), state)
                .await?;
        validate_payment_total(std::slice::from_ref(&plan), &payment)?;
        let occupied = self.occupied_quotes(std::slice::from_ref(&plan)).await;
        confirm_record(&plan, &payment, &occupied, state, checkpoint)?;
        Ok(occupied)
    }

    /// One quote and payment of [`Self::pay_for_storage_split`], journaled in
    /// `state`, which is saved to `checkpoint` before the transaction is
    /// signed, before it is sent and once it is confirmed. Returns the plan
    /// paid and what the wallet paid, for its paid quote to be read back.
    #[cfg(feature = "native")]
    async fn pay_for_storage_once(
        &self,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
        state: &mut UploadState,
        checkpoint: &RecordCheckpoint,
    ) -> Result<(ChunkPaymentPlan, UploadPayment)> {
        debug!("Collecting quotes for address {}", hex::encode(content));
        // Refused before quoting if an earlier upload on this client
        // established a settlement refusal; quotes over the price ceiling
        // are left out.
        let plan = self
            .prepare_payment_plan_split(routing, content, data_size, data_type)
            .await?;
        info!(
            "Paying {} atto for address {}",
            plan.payment.total_amount(),
            hex::encode(content)
        );
        state.prepare(plan.clone());
        state.start_payment(false, vec![plan.address])?;
        if let Some(attempt) = state.pending_payment.as_mut() {
            super::native_payment::initialize(attempt);
        }
        // On disk before the wallet is asked to sign anything.
        checkpoint.save(state)?;
        let payment =
            super::native_payment::pay(self, checkpoint, std::slice::from_ref(&plan), state)
                .await?;
        validate_payment_total(std::slice::from_ref(&plan), &payment)?;
        info!(
            "On-chain payment succeeded for address {}",
            hex::encode(content)
        );
        Ok((plan, payment))
    }

    /// One quote and payment of [`Self::pay_for_storage_split`]. Also returns
    /// the payment as a plan, to read its vault record back.
    #[cfg(not(feature = "native"))]
    async fn pay_for_storage_once(
        &self,
        routing: &[u8; 32],
        content: &[u8; 32],
        data_size: u64,
        data_type: u32,
    ) -> Result<(Vec<u8>, Vec<(PeerId, Vec<MultiAddr>)>, ChunkPaymentPlan)> {
        let address = content;
        // A refusal established by any earlier upload on this client stops
        // this one before it spends. The verdict is about this build, not
        // about one operation.
        if let Some(refusal) = self.corroborated_settlement_refusal() {
            return Err(Error::ClientUpdateRequired(refusal));
        }

        // Wallet is required for the on-chain payment step (step 4 below).
        // Check early so we don't waste time collecting quotes for a misconfigured client.
        let wallet = self.require_wallet()?;

        debug!("Collecting quotes for address {}", hex::encode(address));

        // 1. Collect at least one witnessed quote from the network
        let quote_plan = self
            .get_store_quote_plan_split(routing, content, data_size, data_type)
            .await?;
        let quotes_with_peers = quote_plan.quotes;
        let median_quote_issuer =
            median_paid_quote_issuer(&quotes_with_peers).ok_or_else(|| {
                Error::Payment(
                    "Failed to select median quote issuer from witnessed quotes".to_string(),
                )
            })?;

        // Capture the ordered PUT target set for replication by the caller.
        // This can be wider than the peers that supplied the paid quotes.
        let quoted_peers = quote_plan.put_peers;

        // 2. Build peer_quotes for ProofOfPayment + quotes for single-node payment.
        // Use node-reported prices directly — no contract price fetch needed.
        let mut peer_quotes = Vec::with_capacity(quotes_with_peers.len());
        let mut quotes_for_payment = Vec::with_capacity(quotes_with_peers.len());
        // ADR-0004: forward the signed commitment each bound quote shipped, so
        // the storers can cross-check the quote's count against the original
        // commitment synchronously ("the commitment arrived with the quote").
        // A baseline quote ships none. `get_store_quotes` already verified each
        // quote's forced-price binding, so anything here is payable.
        let mut commitment_sidecars = Vec::new();

        for (peer_id, _addrs, quote, _price, commitment) in quotes_with_peers {
            let encoded = peer_id_to_encoded(&peer_id)?;
            peer_quotes.push((encoded, quote.clone()));
            quotes_for_payment.push(quote);
            if let Some(sidecar) = commitment {
                commitment_sidecars.push(sidecar);
            }
        }

        // 3. Create single-node payment (sorts by price, selects median)
        let payment = SingleNodeQuotePayment::from_quotes_within(
            quotes_for_payment,
            self.config().max_chunk_price,
        )
        .map_err(|e| Error::Payment(format!("Failed to create payment: {e}")))?;

        info!(
            "Selected SNP median paid quote issuer {} for address {} (median price: {})",
            median_quote_issuer.0,
            hex::encode(address),
            median_quote_issuer.1
        );
        info!("Payment total: {} atto", payment.total_amount());

        // 4. Pay on-chain
        let tx_hashes = payment
            .pay(wallet)
            .await
            .map_err(|e| Error::Payment(format!("On-chain payment failed: {e}")))?;

        info!(
            "On-chain payment succeeded: {} transactions",
            tx_hashes.len()
        );

        // 5. Build and serialize proof with version tag
        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment {
                peer_quotes: peer_quotes.clone(),
            },
            tx_hashes,
            commitment_sidecars,
        };

        let proof_bytes = serialize_single_node_proof(&proof)
            .map_err(|e| Error::Serialization(format!("Failed to serialize payment proof: {e}")))?;

        let plan = ChunkPaymentPlan {
            address: *address,
            data_size,
            quoted_peers: Vec::new(),
            payment,
            peer_quotes,
            commitment_sidecars: Vec::new(),
        };
        Ok((proof_bytes, quoted_peers, plan))
    }

    /// Approve the wallet to spend tokens on the payment vault contract.
    ///
    /// This must be called once before any payments can be made.
    /// Approves `U256::MAX` (unlimited) spending.
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet is not set or the approval transaction fails.
    pub async fn approve_token_spend(&self) -> Result<()> {
        let wallet = self.require_wallet()?;
        let evm_network = self.require_evm_network()?;

        let vault_address = evm_network.payment_vault_address();
        wallet
            .approve_to_spend_tokens(*vault_address, ant_protocol::evm::U256::MAX)
            .await
            .map_err(|e| Error::Payment(format!("Token approval failed: {e}")))?;
        info!("Token spend approved for payment vault contract");

        Ok(())
    }
}

/// Take the confirmed `payment` of `plan` into `state` and save it: the
/// record's proof, unless the read-back found its paid quote `occupied`,
/// recorded first by someone else, so the vault skipped the payment; then
/// the plan is dropped for the record to be quoted again (`None`).
#[cfg(feature = "native")]
fn confirm_record(
    plan: &ChunkPaymentPlan,
    payment: &UploadPayment,
    occupied: &[OccupiedQuote],
    state: &mut UploadState,
    checkpoint: &RecordCheckpoint,
) -> Result<Option<Vec<u8>>> {
    let released = state.release_occupied(occupied);
    let proof = if released.is_empty() {
        state.confirm(
            &[plan.address],
            &payment.transactions,
            crate::runtime::system_time(),
        )?;
        state.proof(&plan.address).cloned()
    } else {
        None
    };
    checkpoint.save(state)?;
    Ok(proof)
}

/// Convert an ant-node `PeerId` to an `EncodedPeerId` for payment proofs.
pub(crate) fn peer_id_to_encoded(peer_id: &PeerId) -> Result<EncodedPeerId> {
    Ok(EncodedPeerId::new(*peer_id.as_bytes()))
}

#[cfg(all(test, feature = "native"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::data::client::native_payment::test_plans::{
        checkpoints, network, signed_plan, transactions,
    };
    use ant_protocol::pointer::{
        Pointer, PointerTarget, PointerTargetKind, DATA_TYPE_POINTER, POINTER_WIRE_LEN,
    };
    use ant_protocol::pqc::api::ml_dsa_65;
    use std::time::{Duration, SystemTime};

    /// A client whose node never started and whose payment RPC is a closed
    /// port, paying with a fresh wallet: anything it asked of the network or
    /// of the chain would fail.
    async fn offline_client() -> (Client, crate::data::Network) {
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_with_random_wallet(network(closed)));
        (client, node)
    }

    /// A pointer's first state.
    fn pointer() -> Pointer {
        let (owner, secret) = ml_dsa_65().generate_keypair_from_seed(&[8; 32]);
        Pointer::create(
            &secret,
            &owner,
            PointerTarget::new(PointerTargetKind::Chunk, [1; 32]),
        )
        .unwrap()
    }

    /// What an earlier attempt that paid for `record`'s state, with quotes
    /// issued at `issued`, and failed to store it leaves in its checkpoint in
    /// `directory`: the proof, which is returned.
    async fn kept_proof(
        client: &Client,
        directory: &Path,
        record: &Pointer,
        issued: SystemTime,
    ) -> Vec<u8> {
        let wallet = client.require_wallet().unwrap();
        let state_id = record.state_id();
        let plan = signed_plan(state_id, POINTER_WIRE_LEN as u64, issued);
        let (checkpoint, mut state) = RecordCheckpoint::open(
            directory,
            wallet.network(),
            wallet.address().as_slice(),
            &state_id,
        )
        .await
        .unwrap();
        state.prepare(plan.clone());
        state
            .confirm(&[state_id], &transactions(&plan), issued)
            .unwrap();
        checkpoint.save(&state).unwrap();
        state.proof(&state_id).cloned().unwrap()
    }

    /// Pay for `record`'s state, with its checkpoint in `directory`.
    async fn pay(client: &Client, directory: &Path, record: &Pointer) -> Result<PaidRecord> {
        client
            .pay_for_record_in(
                directory,
                &record.address(),
                &record.state_id(),
                POINTER_WIRE_LEN as u64,
                DATA_TYPE_POINTER,
            )
            .await
    }

    /// The proof an earlier attempt paid for and didn't store is used again,
    /// with no quote and no payment, and kept until the state is stored; then
    /// the next payment for the state is a new one.
    #[tokio::test]
    async fn a_kept_proof_is_reused_until_the_record_is_stored() {
        let directory = tempfile::tempdir().unwrap();
        let (client, _node) = offline_client().await;
        let record = pointer();
        let now = crate::runtime::system_time();
        let kept = kept_proof(&client, directory.path(), &record, now).await;

        let paid = pay(&client, directory.path(), &record)
            .await
            .expect("the kept proof, with nothing asked of the network or the chain");
        assert_eq!(paid.proof, kept);
        assert!(
            paid.put_peers.is_empty(),
            "a pointer's write looks up its group"
        );
        // The write fails again: the proof stays.
        drop(paid);
        assert_eq!(checkpoints(directory.path()).len(), 1);

        let paid = pay(&client, directory.path(), &record)
            .await
            .expect("the kept proof again");
        assert_eq!(paid.proof, kept);
        paid.stored();
        assert!(checkpoints(directory.path()).is_empty());

        // Stored, the state is quoted and paid afresh, which this client
        // can't do.
        assert!(pay(&client, directory.path(), &record).await.is_err());
        assert!(checkpoints(directory.path()).is_empty());
    }

    /// A proof handed to a caller that stores the record itself leaves no
    /// checkpoint behind.
    #[tokio::test]
    async fn a_proof_handed_to_the_caller_leaves_no_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let (client, _node) = offline_client().await;
        let record = pointer();
        let now = crate::runtime::system_time();
        let kept = kept_proof(&client, directory.path(), &record, now).await;
        let paid = pay(&client, directory.path(), &record).await.unwrap();
        let (proof, put_peers) = paid.handed_over();
        assert_eq!(proof, kept);
        assert!(put_peers.is_empty());
        assert!(checkpoints(directory.path()).is_empty());
    }

    /// A kept proof has no age limit: one paid 25 hours ago is reused, with
    /// nothing asked of the network or the chain, as darwin-node takes it
    /// (its `test_old_quote_uses_storage_delta_not_timestamp`). Refused by
    /// every storer, it is forgotten, and the state quoted and paid again,
    /// which this client can't do.
    #[tokio::test]
    async fn a_kept_proof_is_reused_whatever_its_age_until_refused() {
        let directory = tempfile::tempdir().unwrap();
        let (client, _node) = offline_client().await;
        let record = pointer();
        let issued = crate::runtime::system_time() - Duration::from_secs(25 * 60 * 60);
        let kept = kept_proof(&client, directory.path(), &record, issued).await;
        let paid = pay(&client, directory.path(), &record)
            .await
            .expect("the 25-hour-old proof, with no new quote and no payment");
        assert_eq!(paid.proof, kept);
        assert!(paid.reused);
        paid.refused().unwrap();
        assert!(pay(&client, directory.path(), &record).await.is_err());
    }

    /// An attempt that fails holding neither a journal nor a proof, such as
    /// one whose payment was refused before anything was sent, removes its
    /// checkpoint: nothing in it is worth keeping.
    #[tokio::test]
    async fn a_failed_attempt_with_nothing_to_keep_leaves_no_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let (client, _node) = offline_client().await;
        let record = pointer();
        let wallet = client.require_wallet().unwrap();
        let state_id = record.state_id();
        let (checkpoint, mut state) = RecordCheckpoint::open(
            directory.path(),
            wallet.network(),
            wallet.address().as_slice(),
            &state_id,
        )
        .await
        .unwrap();
        // What a payment refused before signing leaves: the plan, no journal.
        state.prepare(signed_plan(
            state_id,
            POINTER_WIRE_LEN as u64,
            crate::runtime::system_time(),
        ));
        checkpoint.save(&state).unwrap();
        drop(checkpoint);
        assert_eq!(checkpoints(directory.path()).len(), 1);

        assert!(pay(&client, directory.path(), &record).await.is_err());
        assert!(checkpoints(directory.path()).is_empty());
    }
}
