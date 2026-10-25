// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Upload coordination shared by native and browser storage/wallet adapters.

use super::batch::{ChunkPaymentPlan, PaidChunk, WaveAggregateStats, WaveResult};
use super::merkle::PaymentMode;
use super::occupied::{
    occupied_error, skipped_amount, KeptPayment, OccupiedQuote, MAX_OCCUPIED_REQUOTES,
};
use super::upload_state::{paid_node, UploadState};
use super::{adaptive::observe_op, classify_error, Client};
use crate::data::error::{Error, PartialUploadSpend, Result};
use ant_protocol::evm::{Amount, QuoteHash, TxHash};
use bytes::Bytes;
use futures::StreamExt;
use std::collections::{HashMap, HashSet};

/// Content identity and size, independent of where the bytes are staged.
#[derive(Debug, Clone, Copy)]
pub struct UploadRecord {
    /// Canonical content address.
    pub address: [u8; 32],
    /// Expected byte length.
    pub size: u64,
    /// Stable index understood by the byte-source adapter.
    pub index: usize,
}

/// Confirmed wallet result; proof construction remains in Rust.
#[derive(Debug, Default)]
pub struct UploadPayment {
    /// Transactions indexed by quote hash.
    pub transactions: HashMap<QuoteHash, TxHash>,
    /// Actual storage spend for this submission.
    pub amount: Amount,
    /// Gas spend, when the adapter can report it.
    pub gas: u128,
}

/// Confirmed Merkle settlement; Rust constructs all record proofs.
#[derive(Debug)]
pub struct MerkleUploadPayment {
    /// Winning pool reported by the confirmed vault event.
    pub winner_pool: [u8; 32],
    /// Actual amount from that event.
    pub amount: Amount,
    /// Gas spend if known.
    pub gas: u128,
}

#[cfg(feature = "native")]
/// Native adapters permit futures to move between executor threads.
pub trait AdapterBounds: Sync {}
#[cfg(feature = "native")]
impl<T: Sync> AdapterBounds for T {}
#[cfg(not(feature = "native"))]
/// Browser adapters run on the local browser executor.
pub trait AdapterBounds {}
#[cfg(not(feature = "native"))]
impl<T> AdapterBounds for T {}

/// Only byte loading, wallet submission, endpoint admission, and persistence vary by platform.
// async-trait marks each method `#[must_use]`, and Clippy now treats the boxed
// future it returns as must-use already.
#[allow(clippy::double_must_use)]
#[cfg_attr(not(feature = "native"), async_trait::async_trait(?Send))]
#[cfg_attr(feature = "native", async_trait::async_trait)]
pub trait UploadAdapter: AdapterBounds {
    /// Load one previously described record.
    async fn load(&self, record: UploadRecord) -> Result<Bytes>;
    /// Submit the native single-node payment plans and await confirmation.
    async fn pay(&self, plans: &[ChunkPaymentPlan]) -> Result<UploadPayment>;
    /// Submit a prepared Merkle batch and await its confirmed winner.
    async fn pay_merkle(
        &self,
        _batch: &super::merkle::PreparedMerkleBatch,
    ) -> Result<MerkleUploadPayment> {
        Err(Error::Payment(
            "wallet adapter does not support Merkle payments".into(),
        ))
    }
    /// Submit with a durable attempt already recorded; adapters can journal broadcast evidence.
    async fn pay_tracked(
        &self,
        plans: &[ChunkPaymentPlan],
        _state: &UploadState,
    ) -> Result<UploadPayment> {
        self.pay(plans).await
    }
    /// Observe an existing attempt without broadcasting another transaction.
    async fn recover_payment(
        &self,
        _plans: &[ChunkPaymentPlan],
        _state: &UploadState,
    ) -> Result<UploadPayment> {
        Err(Error::Payment(
            "payment outcome unknown; wallet reconciliation is required".into(),
        ))
    }
    /// Submit a Merkle payment with the prepared attempt already persisted.
    async fn pay_merkle_tracked(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
        _state: &UploadState,
    ) -> Result<MerkleUploadPayment> {
        self.pay_merkle(batch).await
    }
    /// Observe an existing Merkle attempt without broadcasting.
    async fn recover_merkle(
        &self,
        _batch: &super::merkle::PreparedMerkleBatch,
        _state: &UploadState,
    ) -> Result<MerkleUploadPayment> {
        Err(Error::Payment(
            "Merkle payment outcome unknown; wallet reconciliation is required".into(),
        ))
    }
    /// Initialize adapter-owned recovery evidence before persisting an attempt.
    fn initialize_payment_attempt(&self, _attempt: &mut super::upload_state::PaymentAttempt) {}
    /// Submit while updating the shared journal. Existing adapters may keep their callback journal.
    async fn submit_payment(
        &self,
        plans: &[ChunkPaymentPlan],
        state: &mut UploadState,
    ) -> Result<UploadPayment> {
        self.pay_tracked(plans, state).await
    }
    /// Reconcile a previous submission while updating its journal.
    async fn reconcile_payment(
        &self,
        plans: &[ChunkPaymentPlan],
        state: &mut UploadState,
    ) -> Result<UploadPayment> {
        self.recover_payment(plans, state).await
    }
    /// Submit a Merkle payment with mutable recovery evidence.
    async fn submit_merkle_payment(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
        state: &mut UploadState,
    ) -> Result<MerkleUploadPayment> {
        self.pay_merkle_tracked(batch, state).await
    }
    /// Reconcile a Merkle payment without creating a new transaction.
    async fn reconcile_merkle_payment(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
        state: &mut UploadState,
    ) -> Result<MerkleUploadPayment> {
        self.recover_merkle(batch, state).await
    }
    /// Check transport-specific endpoint capabilities before payment.
    async fn admit(&self, _plan: &mut ChunkPaymentPlan) -> Result<()> {
        Ok(())
    }
    /// Persist before submission and again before any paid data is loaded/stored.
    async fn checkpoint(
        &self,
        _state: &UploadState,
        _payment: Option<&UploadPayment>,
    ) -> Result<()> {
        Ok(())
    }
    /// Persist the marks that records are being paid again
    /// ([`UploadState::mark_paid_again`]), their refused proofs still in
    /// `state`, before those proofs are dropped and anything is paid. An
    /// adapter whose other checkpoints are best effort must fail here when
    /// the marks can't be saved, so the payment stops.
    async fn checkpoint_paid_again(&self, state: &UploadState) -> Result<()> {
        self.checkpoint(state, None).await
    }
    /// Adapter resource ceiling; the adaptive controller still controls scheduling.
    fn quote_limit(&self) -> usize {
        usize::MAX
    }
    /// Report a completed store or an already-present record.
    fn stored(&self, _stored: usize, _total: usize) {}
    /// Report a successful write in this attempt, identified by stable index + 1.
    fn record_stored(&self, _index: usize, _total: usize) {}
    /// Report a completed quote (the first argument is the stable record index + 1).
    fn quoted(&self, _quoted: usize, _total: usize) {}
    /// Report existing-storage checks, which do not complete payment quotes.
    fn checked(&self, _checked: usize, _total: usize) {}
    /// Report a record confirmed already present, identified by stable index + 1.
    fn already_stored(&self, _index: usize, _total: usize) {}
    /// Report validated Merkle candidate pools for the current payment batch.
    fn payment_quotes(&self, _completed: usize, _total: usize) {}
    /// Describe a preparation boundary that has no meaningful completion fraction.
    fn preparing(&self, _message: &str) {}
}

/// Completed upload accounting.
#[derive(Debug, Default)]
pub struct UploadOutcome {
    /// Successfully stored or already-present addresses, including repeated input records.
    pub addresses: Vec<[u8; 32]>,
    /// New storage spend during this invocation.
    pub amount: Amount,
    /// New gas spend during this invocation.
    pub gas: u128,
    /// Shared per-record retry statistics.
    pub stats: WaveAggregateStats,
    /// Effective payment mode.
    pub mode: PaymentMode,
}

impl Client {
    fn ensure_upload_payment_allowed(&self) -> Result<()> {
        match self.corroborated_settlement_refusal() {
            Some(refusal) => Err(Error::ClientUpdateRequired(refusal)),
            None => Ok(()),
        }
    }

    /// Drive record uploads using platform adapters and portable recovery state.
    ///
    /// A raw building block: it quotes, pays for and stores exactly the
    /// records it is given, reading each paid quote back, so an upload has an
    /// envelope only if the caller adds one, as the `last` record of
    /// [`Client::upload_records_then`]. Upload files with
    /// `Client::file_upload`, which builds the envelope.
    pub async fn upload_records<A: UploadAdapter>(
        &self,
        records: Vec<UploadRecord>,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
    ) -> Result<UploadOutcome> {
        self.upload_records_and_last(records, None, state, adapter, mode)
            .await
    }

    /// As [`Client::upload_records`], with `last` stored after every other
    /// record, as an envelope is: the file upload paths build one and pass it
    /// here. `last` is always paid per chunk: in the same payment as the
    /// records paid per chunk (all of them below the Merkle threshold, else
    /// those left after the Merkle batches), or alone if there are none. It
    /// is stored only once every other record is stored, so a listing
    /// envelope never points at missing content; if any record fails, it is
    /// left unstored (its payment stays in `state` for a retry).
    pub async fn upload_records_then<A: UploadAdapter>(
        &self,
        records: Vec<UploadRecord>,
        last: UploadRecord,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
    ) -> Result<UploadOutcome> {
        self.upload_records_and_last(records, Some(last), state, adapter, mode)
            .await
    }

    async fn upload_records_and_last<A: UploadAdapter>(
        &self,
        records: Vec<UploadRecord>,
        last: Option<UploadRecord>,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
    ) -> Result<UploadOutcome> {
        // Counted while it runs, so a shared wave knows whom to wait for.
        #[cfg(feature = "native")]
        let _upload = self.shared_waves().upload();
        let mut original = records.iter().map(|r| r.address).collect::<Vec<_>>();
        let mut sizes = HashMap::new();
        let mut unique = Vec::new();
        for record in records {
            match sizes.insert(record.address, record.size) {
                Some(size) if size != record.size => {
                    return Err(Error::InvalidData(
                        "one content address has conflicting sizes".into(),
                    ))
                }
                Some(_) => {}
                None => unique.push(record),
            }
        }
        if let Some(last) = last {
            if sizes.contains_key(&last.address) {
                return Err(Error::InvalidData(
                    "the record stored last is also among the others".into(),
                ));
            }
            original.push(last.address);
        }
        match self
            .upload_unique_records(unique, last, state, adapter, mode)
            .await
        {
            Ok(mut result) => {
                let stored = result.addresses.into_iter().collect::<HashSet<_>>();
                result.addresses = original
                    .iter()
                    .copied()
                    .filter(|address| stored.contains(address))
                    .collect();
                adapter.stored(result.addresses.len(), original.len());
                Ok(result)
            }
            Err(Error::PartialUpload {
                stored,
                failed,
                spend,
                reason,
                ..
            }) => {
                let stored_set = stored.into_iter().collect::<HashSet<_>>();
                let failures = failed.into_iter().collect::<HashMap<_, _>>();
                let stored = original
                    .iter()
                    .filter(|a| stored_set.contains(*a))
                    .copied()
                    .collect::<Vec<_>>();
                let failed = original
                    .iter()
                    .filter(|a| !stored_set.contains(*a))
                    .map(|a| {
                        (
                            *a,
                            failures
                                .get(a)
                                .cloned()
                                .unwrap_or_else(|| "upload interrupted before storage".into()),
                        )
                    })
                    .collect::<Vec<_>>();
                Err(Error::PartialUpload {
                    stored_count: stored.len(),
                    stored,
                    failed_count: failed.len(),
                    failed,
                    total_chunks: original.len(),
                    spend,
                    reason,
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn upload_unique_records<A: UploadAdapter>(
        &self,
        mut records: Vec<UploadRecord>,
        last: Option<UploadRecord>,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
    ) -> Result<UploadOutcome> {
        let mut outcome = UploadOutcome {
            mode: PaymentMode::Single,
            ..Default::default()
        };
        let result = self
            .upload_unique_records_inner(&records, last, state, adapter, mode, &mut outcome)
            .await;
        records.extend(last);
        match result {
            Err(error @ Error::PartialUpload { .. }) => Err(error),
            Err(error)
                if outcome.amount != Amount::ZERO
                    || outcome.gas != 0
                    || !outcome.addresses.is_empty() =>
            {
                let reason = match error {
                    Error::ClientUpdateRequired(reason) => format!(
                        "Further payment refused; reported spend covers earlier settled batches. {reason}"
                    ),
                    error => error.to_string(),
                };
                let stored = outcome.addresses.iter().copied().collect::<HashSet<_>>();
                let failed = records
                    .iter()
                    .filter(|r| !stored.contains(&r.address))
                    .map(|r| (r.address, reason.clone()))
                    .collect::<Vec<_>>();
                Err(Error::PartialUpload {
                    stored_count: outcome.addresses.len(),
                    stored: outcome.addresses,
                    failed_count: failed.len(),
                    failed,
                    total_chunks: records.len(),
                    spend: Box::new(PartialUploadSpend {
                        storage_cost_atto: outcome.amount.to_string(),
                        gas_cost_wei: outcome.gas,
                    }),
                    reason,
                })
            }
            result => result,
        }
    }

    async fn upload_unique_records_inner<A: UploadAdapter>(
        &self,
        records: &[UploadRecord],
        last: Option<UploadRecord>,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
        outcome: &mut UploadOutcome,
    ) -> Result<UploadOutcome> {
        // Preflight every byte source before any payment, including Merkle batches.
        // Read one record at a time so files remain bounded by record size, not file size.
        // The adapter retains its staging session for the lifetime of this operation.
        for record in records.iter().chain(last.iter()) {
            let bytes = adapter.load(*record).await?;
            if bytes.len() as u64 != record.size {
                return Err(Error::InvalidData(
                    "staged record size changed before payment".into(),
                ));
            }
            crate::record::verify(&record.address, &bytes).map_err(Error::InvalidData)?;
        }
        let total = records.len() + usize::from(last.is_some());
        let mut unique = records.to_vec();
        // The records this run paid for, at once, again, or by settling a
        // payment an earlier run journaled, are kept in `state` for every
        // pass a command makes over it ([`UploadState::paid_this_run`]): a
        // proof among them that storers refuse is a failure, never paid for
        // again.
        let preparation = async {
            let settled = self.reconcile_upload_payment(state, adapter).await?;
            state.add_paid_this_run(settled);
            self.prepare_upload_merkle(&mut unique, state, adapter, mode, outcome)
                .await
        }
        .await;
        // A later payment (including its recovery) must not strand earlier paid
        // batches. Preflight above and proof freshness checks still gate every PUT.
        if let Err(Error::InvalidData(reason)) = &preparation {
            return Err(Error::InvalidData(reason.clone()));
        }
        let storage = self
            .store_upload_merkle(&mut unique, state, adapter, outcome, total)
            .await;
        match (preparation, storage) {
            (
                Err(payment_error),
                Err(Error::PartialUpload {
                    stored,
                    stored_count,
                    failed,
                    failed_count,
                    total_chunks,
                    spend,
                    reason,
                }),
            ) => {
                return Err(Error::PartialUpload {
                    stored,
                    stored_count,
                    failed,
                    failed_count,
                    total_chunks,
                    spend,
                    reason: format!("{payment_error}; {reason}"),
                });
            }
            (Err(payment_error), Err(storage_error)) => {
                return Err(Error::Payment(format!("{payment_error}; {storage_error}")));
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
        // `last` is never in a Merkle batch: always paid per chunk, in the
        // final wave, and stored after every other record.
        let per_chunk = PerChunkWaves::new(&unique, last);
        let waves = &per_chunk.waves;
        let mut prefetched = None;
        let mut failed = Vec::new();
        let mut held = None;
        for (wave_index, wave) in waves.iter().enumerate() {
            let mut plans = match prefetched.take() {
                Some(plans) => plans?,
                None => {
                    self.prepare_upload_wave(wave, state, adapter, total)
                        .await?
                }
            };
            let mut payable = Vec::new();
            for (record, plan) in &plans {
                if let Some(plan) = plan {
                    drop_proof_paid_outside(state, plan);
                    if !state.is_paid(&plan.address, crate::runtime::system_time()) {
                        state.prepare(plan.clone());
                        payable.push(plan.clone());
                    }
                } else {
                    outcome.addresses.push(record.address);
                    adapter.stored(outcome.addresses.len(), total);
                }
            }
            if last.is_some() {
                // The envelope's log must not be the last of its payment.
                order_by_quote_hash(&mut payable);
            }
            adapter.checkpoint(state, None).await?;
            state.add_paid_this_run(payable.iter().map(|plan| plan.address));
            let (payment, found_stored, unpaid) = self
                .pay_wave(payable, &mut plans, state, adapter, last.is_some(), total)
                .await?;
            failed.extend(unpaid);
            outcome.amount = outcome
                .amount
                .checked_add(payment.amount)
                .ok_or_else(|| Error::Payment("payment total overflow".into()))?;
            outcome.gas = outcome.gas.saturating_add(payment.gas);
            for address in found_stored {
                outcome.addresses.push(address);
                adapter.stored(outcome.addresses.len(), total);
            }
            let (to_store, held_here) = per_chunk.hold_back(plans);
            if held_here.is_some() {
                held = held_here;
            }
            let stored = outcome.addresses.len();
            let (results, next) = futures::join!(
                self.store_planned(to_store, state, adapter, total, stored),
                async {
                    match waves.get(wave_index + 1) {
                        Some(next) => {
                            Some(self.prepare_upload_wave(next, state, adapter, total).await)
                        }
                        None => None,
                    }
                }
            );
            prefetched = next;
            let mut fatal = false;
            let refused = absorb_stores(results, state, outcome, &mut failed, &mut fatal);
            if fatal {
                break;
            }
            let refused = self.payable_again(refused, state, &mut failed).await;
            if refused.is_empty() {
                continue;
            }
            // Every storer refused the proof an earlier run paid: pay once
            // more, at once, so the upload doesn't stall on an old proof.
            let records = wave
                .iter()
                .filter(|record| refused.contains(&record.address))
                .copied()
                .collect::<Vec<_>>();
            state.add_paid_this_run(refused);
            let plans = self
                .pay_again(
                    &records,
                    state,
                    adapter,
                    last.is_some(),
                    total,
                    outcome,
                    &mut failed,
                )
                .await?;
            let stored = outcome.addresses.len();
            let results = self
                .store_planned(plans, state, adapter, total, stored)
                .await;
            absorb_stores(results, state, outcome, &mut failed, &mut fatal);
            if fatal {
                break;
            }
        }
        // Sent only once every other record is stored.
        if let Some((record, plan)) = release_last(held, |(record, _)| record.address, &mut failed)
        {
            let mut fatal = false;
            let stored = outcome.addresses.len();
            let results = self
                .store_planned(vec![(record, plan)], state, adapter, total, stored)
                .await;
            let refused = absorb_stores(results, state, outcome, &mut failed, &mut fatal);
            let refused = self.payable_again(refused, state, &mut failed).await;
            if !refused.is_empty() {
                state.add_paid_this_run(refused);
                let plans = self
                    .pay_again(&[record], state, adapter, true, total, outcome, &mut failed)
                    .await?;
                let stored = outcome.addresses.len();
                let results = self
                    .store_planned(plans, state, adapter, total, stored)
                    .await;
                absorb_stores(results, state, outcome, &mut failed, &mut fatal);
            }
        }
        if !failed.is_empty() {
            return Err(Error::PartialUpload {
                stored_count: outcome.addresses.len(),
                stored: outcome.addresses.clone(),
                failed_count: failed.len(),
                reason: failed
                    .iter()
                    .map(|(_, error)| error.as_str())
                    .collect::<Vec<_>>()
                    .join("; "),
                failed,
                total_chunks: total,
                spend: Box::new(PartialUploadSpend {
                    storage_cost_atto: outcome.amount.to_string(),
                    gas_cost_wei: outcome.gas,
                }),
            });
        }
        Ok(std::mem::take(outcome))
    }
    /// Store each of `to_store` with the proof `recovery` holds for it, at
    /// the PUT targets its plan names, as many at once as the store
    /// controller allows. `stored` is how many of the upload's records are
    /// stored already, for progress. Each record's result is its store's, or
    /// why it couldn't be sent (its bytes or its proof), which stops the
    /// upload before it pays again.
    async fn store_planned<A: UploadAdapter>(
        &self,
        to_store: Vec<(UploadRecord, ChunkPaymentPlan)>,
        recovery: &UploadState,
        adapter: &A,
        total: usize,
        stored: usize,
    ) -> Vec<([u8; 32], Result<WaveResult>)> {
        let max_size = to_store
            .iter()
            .map(|(record, _)| record.size as usize)
            .max()
            .unwrap_or(1);
        let live_stored = std::sync::atomic::AtomicUsize::new(stored);
        crate::client_engine::rolling_unordered(
            to_store,
            |(record, plan)| {
                let live_stored = &live_stored;
                async move {
                    let result = async {
                        let bytes = adapter.load(record).await?;
                        let prepared = plan.with_content(bytes)?;
                        let paid: PaidChunk = recovery
                            .reuse_prepared(&prepared, crate::runtime::system_time())
                            .ok_or_else(|| {
                                Error::Payment("paid proof expired before storage".into())
                            })?;
                        Ok::<_, Error>(
                            self.store_paid_chunks_with_events(vec![paid], None, 0, total)
                                .await,
                        )
                    }
                    .await;
                    if let Ok(stored) = &result {
                        if stored.stored.contains(&record.address) {
                            adapter.record_stored(record.index + 1, total);
                        }
                        let completed = live_stored
                            .fetch_add(stored.stored.len(), std::sync::atomic::Ordering::Relaxed)
                            + stored.stored.len();
                        adapter.stored(completed, total);
                    }
                    (record.address, result)
                }
            },
            || {
                self.controller()
                    .store
                    .current()
                    .min(crate::client_engine::store_byte_bound(max_size))
            },
        )
        .collect::<Vec<_>>()
        .await
    }

    /// Pay again, once, for `records`, whose proofs an earlier run paid and
    /// storers refused ([`absorb_stores`]): their proofs are dropped, and
    /// they are quoted afresh and paid together, as a wave is. Returns those
    /// to store. One found stored meanwhile counts as stored, and one whose
    /// quotes were occupied every time as failed.
    #[allow(clippy::too_many_arguments)]
    async fn pay_again<A: UploadAdapter>(
        &self,
        records: &[UploadRecord],
        state: &mut UploadState,
        adapter: &A,
        envelope: bool,
        total: usize,
        outcome: &mut UploadOutcome,
        failed: &mut Vec<([u8; 32], String)>,
    ) -> Result<Vec<(UploadRecord, ChunkPaymentPlan)>> {
        for record in records {
            tracing::warn!(
                "every storer that failed to store {} refused the proof an earlier run \
                 paid for it; paying for it again, once",
                hex::encode(record.address)
            );
            state.mark_paid_again(record.address);
        }
        // The marks are saved first, the refused proofs still kept, so a
        // crash before the proofs are dropped leaves them marked, never
        // dropped unmarked; a mark that can't be saved stops the payment.
        adapter.checkpoint_paid_again(state).await?;
        for record in records {
            state.drop_proof(&record.address);
        }
        // Saved before anything is paid, so no later run pays again.
        adapter.checkpoint(state, None).await?;
        let mut plans = self
            .prepare_upload_wave(records, state, adapter, total)
            .await?;
        let mut payable = Vec::new();
        for (record, plan) in &plans {
            match plan {
                Some(plan) => {
                    state.prepare(plan.clone());
                    payable.push(plan.clone());
                }
                None => {
                    outcome.addresses.push(record.address);
                    adapter.stored(outcome.addresses.len(), total);
                }
            }
        }
        if envelope {
            order_by_quote_hash(&mut payable);
        }
        adapter.checkpoint(state, None).await?;
        let (payment, found_stored, unpaid) = self
            .pay_wave(payable, &mut plans, state, adapter, envelope, total)
            .await?;
        failed.extend(unpaid);
        outcome.amount = outcome
            .amount
            .checked_add(payment.amount)
            .ok_or_else(|| Error::Payment("payment total overflow".into()))?;
        outcome.gas = outcome.gas.saturating_add(payment.gas);
        for address in found_stored {
            outcome.addresses.push(address);
            adapter.stored(outcome.addresses.len(), total);
        }
        Ok(plans
            .into_iter()
            .filter_map(|(record, plan)| plan.map(|plan| (record, plan)))
            .collect())
    }

    /// Settle the payment an earlier run journaled, from the chain. Returns
    /// the records it paid for (none for a Merkle batch): their proofs are
    /// this run's, so a refusal of them is a failure, never paid for again.
    async fn reconcile_upload_payment<A: UploadAdapter>(
        &self,
        state: &mut UploadState,
        adapter: &A,
    ) -> Result<Vec<[u8; 32]>> {
        let mut confirmed = Vec::new();
        if let Some(attempt) = state.pending_payment.clone() {
            if attempt.merkle {
                let batch = state
                    .pending_merkle
                    .clone()
                    .ok_or_else(|| Error::Payment("missing pending Merkle intent".into()))?;
                let payment = adapter.reconcile_merkle_payment(&batch, state).await?;
                let paid = super::merkle::finalize_merkle_batch(batch, payment.winner_pool)?;
                state.insert_merkle(paid);
            } else {
                let plans = state.pending_plans()?;
                let payment = adapter.reconcile_payment(&plans, state).await?;
                validate_payment_total(&plans, &payment)?;
                // Records whose quote was occupied stay unpaid: the waves
                // below quote them again.
                let occupied = self.occupied_quotes(&plans).await;
                let released = state.release_occupied(&occupied);
                confirmed = attempt
                    .addresses
                    .iter()
                    .copied()
                    .filter(|address| !released.contains(address))
                    .collect::<Vec<_>>();
                state.confirm(
                    &confirmed,
                    &payment.transactions,
                    crate::runtime::system_time(),
                )?;
            }
            // Recovered receipts are previous spend, not new payments by this invocation.
            adapter.checkpoint(state, None).await?;
        }
        Ok(confirmed)
    }

    /// Of the records `refused` names ([`absorb_stores`]: an earlier run's
    /// proof every failing storer refused, with the store's error), those to
    /// pay for again. The vault's record of each proof's payment is read
    /// back first ([`Client::kept_payment`]): a record whose payment can't
    /// be read, as when the chain's RPCs fail the nodes and this client
    /// alike, is a failure, its proof kept, so an outage never pays again.
    async fn payable_again(
        &self,
        refused: HashMap<[u8; 32], String>,
        state: &UploadState,
        failed: &mut Vec<([u8; 32], String)>,
    ) -> HashSet<[u8; 32]> {
        let mut payable = HashSet::new();
        for (address, error) in refused {
            let Some(proof) = state.proof(&address) else {
                // No kept proof to protect.
                payable.insert(address);
                continue;
            };
            let kept = self.kept_payment(proof).await;
            match kept_proof_failure(kept, &error) {
                Some(failure) => {
                    tracing::warn!(
                        "every storer refused the proof kept for {}, and its payment wasn't \
                         read from the chain ({kept:?}); keeping the proof rather than paying \
                         again",
                        hex::encode(address)
                    );
                    failed.push((address, failure));
                }
                None => {
                    tracing::info!(
                        "the vault's record of the refused proof of {}: {kept:?}",
                        hex::encode(address)
                    );
                    payable.insert(address);
                }
            }
        }
        payable
    }

    /// Pay a wave's `payable` plans, then read every paid quote's vault record
    /// back. A record that isn't the payment means someone recorded the quote
    /// first and the vault skipped the payment: that record is quoted again,
    /// its plan in `plans` replaced, and paid again, up to
    /// [`MAX_OCCUPIED_REQUOTES`] times. Returns the spend (without the skipped
    /// payments, which moved no tokens), the records found already stored when
    /// quoted again, and the records left unpaid because their quotes were
    /// occupied every time, with why (their plans in `plans` become `None`).
    async fn pay_wave<A: UploadAdapter>(
        &self,
        mut payable: Vec<ChunkPaymentPlan>,
        plans: &mut [(UploadRecord, Option<ChunkPaymentPlan>)],
        state: &mut UploadState,
        adapter: &A,
        envelope: bool,
        total: usize,
    ) -> Result<(UploadPayment, Vec<[u8; 32]>, Vec<([u8; 32], String)>)> {
        let mut spent = UploadPayment::default();
        let mut found_stored = Vec::new();
        let mut history: Vec<OccupiedQuote> = Vec::new();
        if payable.is_empty() {
            adapter.checkpoint(state, Some(&spent)).await?;
        }
        for requote in 0..=MAX_OCCUPIED_REQUOTES {
            if payable.is_empty() {
                break;
            }
            self.ensure_upload_payment_allowed()?;
            state.start_payment(false, payable.iter().map(|plan| plan.address).collect())?;
            if let Some(attempt) = &mut state.pending_payment {
                adapter.initialize_payment_attempt(attempt);
            }
            adapter.checkpoint(state, None).await?;
            if let Err(error) = self.ensure_upload_payment_allowed() {
                state.pending_payment = None;
                adapter.checkpoint(state, None).await?;
                return Err(error);
            }
            let payment = adapter.submit_payment(&payable, state).await?;
            validate_payment_total(&payable, &payment)?;
            let occupied = self.occupied_quotes(&payable).await;
            let released = state.release_occupied(&occupied);
            state.confirm(
                &payable
                    .iter()
                    .map(|plan| plan.address)
                    .filter(|address| !released.contains(address))
                    .collect::<Vec<_>>(),
                &payment.transactions,
                crate::runtime::system_time(),
            )?;
            let paid = UploadPayment {
                amount: payment
                    .amount
                    .checked_sub(skipped_amount(&occupied))
                    .ok_or_else(|| Error::Payment("payment total underflow".into()))?,
                gas: payment.gas,
                transactions: payment.transactions,
            };
            adapter.checkpoint(state, Some(&paid)).await?;
            spent.amount = spent
                .amount
                .checked_add(paid.amount)
                .ok_or_else(|| Error::Payment("payment total overflow".into()))?;
            spent.gas = spent.gas.saturating_add(paid.gas);
            spent.transactions.extend(paid.transactions);
            if occupied.is_empty() {
                break;
            }
            history.extend(occupied);
            if requote == MAX_OCCUPIED_REQUOTES {
                let unpaid_history = history
                    .iter()
                    .filter(|quote| released.contains(&quote.address))
                    .cloned()
                    .collect::<Vec<_>>();
                let reason = occupied_error(&unpaid_history).to_string();
                tracing::warn!("{reason}");
                let mut unpaid = Vec::new();
                for (record, plan) in plans.iter_mut() {
                    if released.contains(&record.address) {
                        *plan = None;
                        unpaid.push((record.address, reason.clone()));
                    }
                }
                return Ok((spent, found_stored, unpaid));
            }
            tracing::warn!(
                "the vault already held another payment's record for {} paid quote(s); \
                 quoting those records again ({} of {MAX_OCCUPIED_REQUOTES})",
                released.len(),
                requote + 1
            );
            payable.clear();
            for (record, plan) in plans
                .iter_mut()
                .filter(|(record, _)| released.contains(&record.address))
            {
                let mut fresh = observe_op(
                    &self.controller().quote,
                    || self.prepare_chunk_payment_plan(record.address, record.size),
                    classify_error,
                )
                .await?;
                match fresh.as_mut() {
                    Some(fresh) => {
                        adapter.admit(fresh).await?;
                        adapter.quoted(record.index + 1, total);
                        state.prepare(fresh.clone());
                        payable.push(fresh.clone());
                    }
                    None => {
                        adapter.already_stored(record.index + 1, total);
                        found_stored.push(record.address);
                    }
                }
                *plan = fresh;
            }
            if envelope {
                order_by_quote_hash(&mut payable);
            }
            adapter.checkpoint(state, None).await?;
        }
        Ok((spent, found_stored, Vec::new()))
    }

    async fn prepare_upload_wave<A: UploadAdapter>(
        &self,
        wave: &[UploadRecord],
        state: &UploadState,
        adapter: &A,
        total: usize,
    ) -> Result<Vec<(UploadRecord, Option<ChunkPaymentPlan>)>> {
        adapter.preparing("Collecting record payment quotes and checking storage peers");
        let recovery = state;
        let plans = crate::client_engine::rolling_unordered(
            wave.iter().copied(),
            |record| async move {
                let cached_merkle = recovery.proof(&record.address).is_some_and(|bytes| {
                    ant_protocol::payment::deserialize_merkle_proof(bytes).is_ok()
                }) && recovery
                    .is_paid(&record.address, crate::runtime::system_time());
                let mut plan = if cached_merkle {
                    Some(ChunkPaymentPlan {
                        address: record.address,
                        data_size: record.size,
                        quoted_peers: self.put_target_peers(&record.address).await?,
                        payment: super::batch::SingleNodeQuotePayment { quotes: Vec::new() },
                        peer_quotes: Vec::new(),
                        commitment_sidecars: Vec::new(),
                    })
                } else {
                    match recovery.retained_plan(
                        &record.address,
                        record.size,
                        crate::runtime::system_time(),
                    ) {
                        Some(plan) => Some(plan),
                        None => {
                            observe_op(
                                &self.controller().quote,
                                || self.prepare_chunk_payment_plan(record.address, record.size),
                                classify_error,
                            )
                            .await?
                        }
                    }
                };
                if let Some(plan) = plan.as_mut() {
                    adapter.admit(plan).await?;
                }
                if plan.is_some() {
                    adapter.quoted(record.index + 1, total);
                } else {
                    adapter.already_stored(record.index + 1, total);
                }
                Ok::<_, Error>((record, plan))
            },
            || self.controller().quote.current().min(adapter.quote_limit()),
        )
        .collect::<Vec<_>>()
        .await;
        let mut plans = plans.into_iter().collect::<Result<Vec<_>>>()?;
        plans.sort_by_key(|(record, _)| record.index);
        Ok(plans)
    }

    async fn store_upload_merkle<A: UploadAdapter>(
        &self,
        records: &mut Vec<UploadRecord>,
        state: &UploadState,
        adapter: &A,
        outcome: &mut UploadOutcome,
        total: usize,
    ) -> Result<()> {
        use super::merkle::{
            merkle_deferred_retry, merkle_store_with_retry, DEFERRED_ROUND_DELAYS_SECS,
        };
        let merkle = records
            .iter()
            .filter(|r| {
                state.is_paid(&r.address, crate::runtime::system_time())
                    && state
                        .proof(&r.address)
                        .is_some_and(|p| ant_protocol::payment::deserialize_merkle_proof(p).is_ok())
            })
            .map(|r| (r.address, *r))
            .collect::<HashMap<_, _>>();
        if merkle.is_empty() {
            return Ok(());
        }
        outcome.mode = PaymentMode::Merkle;
        let max_size = merkle.values().map(|r| r.size as usize).max().unwrap_or(1);
        let cap = || {
            self.controller()
                .store
                .current()
                .min(crate::client_engine::store_byte_bound(max_size))
        };
        let live_stored = std::sync::atomic::AtomicUsize::new(outcome.addresses.len());
        let store_one = |address: [u8; 32]| {
            let merkle = &merkle;
            let live_stored = &live_stored;
            async move {
                let started = web_time::Instant::now();
                let record = *merkle
                    .get(&address)
                    .ok_or_else(|| Error::InvalidData("missing Merkle record".into()))?;
                let bytes = adapter.load(record).await?;
                if bytes.len() as u64 != record.size {
                    return Err(Error::InvalidData("staged record size changed".into()));
                }
                crate::record::verify(&address, &bytes).map_err(Error::InvalidData)?;
                let proof = state
                    .proof(&address)
                    .cloned()
                    .ok_or_else(|| Error::Payment("missing Merkle proof".into()))?;
                let peers = self.put_target_peers(&address).await?;
                observe_op(
                    &self.controller().store,
                    || self.chunk_put_to_close_group(bytes, proof, &peers),
                    classify_error,
                )
                .await?;
                adapter.record_stored(record.index + 1, total);
                let completed = live_stored.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                adapter.stored(completed, total);
                Ok(started)
            }
        };
        let result = merkle_store_with_retry(
            merkle.keys().copied().collect(),
            cap,
            1,
            std::time::Duration::ZERO,
            None,
            outcome.addresses.len(),
            total,
            &store_one,
        )
        .await?;
        outcome.addresses.extend(result.stored_addresses);
        merge_stats(&mut outcome.stats, result.stats);
        let mut fatal = result.fatal.map(|e| e.to_string());
        let mut failed = result.failed_addresses;
        if fatal.is_none() && !failed.is_empty() {
            let result = merkle_deferred_retry(
                failed,
                &DEFERRED_ROUND_DELAYS_SECS,
                |_| cap(),
                None,
                outcome.addresses.len(),
                total,
                &store_one,
            )
            .await?;
            outcome.addresses.extend(result.stored_addresses);
            merge_stats(&mut outcome.stats, result.stats);
            failed = result.failed_addresses;
            fatal = result.fatal;
        }
        adapter.stored(outcome.addresses.len(), total);
        if fatal.is_some() || !failed.is_empty() {
            let landed = outcome.addresses.iter().copied().collect::<HashSet<_>>();
            let messages = failed.into_iter().collect::<HashMap<_, _>>();
            let failed = records
                .iter()
                .filter(|r| !landed.contains(&r.address))
                .map(|r| {
                    (
                        r.address,
                        messages.get(&r.address).cloned().unwrap_or_else(|| {
                            fatal
                                .clone()
                                .unwrap_or_else(|| "upload interrupted before storage".into())
                        }),
                    )
                })
                .collect::<Vec<_>>();
            return Err(Error::PartialUpload {
                stored: outcome.addresses.clone(),
                stored_count: outcome.addresses.len(),
                failed_count: failed.len(),
                failed,
                total_chunks: total,
                spend: Box::new(PartialUploadSpend {
                    storage_cost_atto: outcome.amount.to_string(),
                    gas_cost_wei: outcome.gas,
                }),
                reason: fatal.unwrap_or_else(|| {
                    "Merkle storage short of quorum after deferred retries".into()
                }),
            });
        }
        records.retain(|r| !merkle.contains_key(&r.address));
        Ok(())
    }

    async fn prepare_upload_merkle<A: UploadAdapter>(
        &self,
        records: &mut Vec<UploadRecord>,
        state: &mut UploadState,
        adapter: &A,
        mode: PaymentMode,
        outcome: &mut UploadOutcome,
    ) -> Result<()> {
        use super::merkle::{
            finalize_merkle_batch, merkle_upload_partitions, merkle_upload_split, should_use_merkle,
        };
        if state.pending_merkle.as_ref().is_some_and(|batch| {
            !super::upload_state::merkle_fresh(
                batch.merkle_payment_timestamp,
                crate::runtime::system_time(),
            )
        }) {
            state.pending_merkle = None;
        }
        if let Some(batch) = state.pending_merkle.take() {
            if batch
                .addresses()
                .iter()
                .any(|address| !records.iter().any(|r| r.address == *address))
            {
                state.pending_merkle = Some(batch);
                return Err(Error::InvalidData(
                    "pending Merkle batch belongs to different records".into(),
                ));
            }
            state.pending_merkle = Some(batch);
            self.ensure_upload_payment_allowed()?;
            state.start_payment(true, Vec::new())?;
            if let Some(attempt) = &mut state.pending_payment {
                adapter.initialize_payment_attempt(attempt);
            }
            adapter.checkpoint(state, None).await?;
            if let Err(error) = self.ensure_upload_payment_allowed() {
                state.pending_payment = None;
                adapter.checkpoint(state, None).await?;
                return Err(error);
            }
            let batch = state
                .pending_merkle
                .clone()
                .ok_or_else(|| Error::Payment("missing pending Merkle batch".into()))?;
            let payment = adapter.submit_merkle_payment(&batch, state).await?;
            let paid = finalize_merkle_batch(batch, payment.winner_pool)?;
            state.insert_merkle(paid);
            let receipt = UploadPayment {
                amount: payment.amount,
                gas: payment.gas,
                ..Default::default()
            };
            outcome.amount += receipt.amount;
            outcome.gas = outcome.gas.saturating_add(receipt.gas);
            outcome.mode = PaymentMode::Merkle;
            adapter.checkpoint(state, Some(&receipt)).await?;
        }
        let quote_total = records.len();
        let unpaid = records
            .iter()
            .filter(|r| !state.is_paid(&r.address, crate::runtime::system_time()))
            .copied()
            .collect::<Vec<_>>();
        if !should_use_merkle(unpaid.len(), mode) {
            return Ok(());
        }
        // Only the remainder paid per chunk is left, as when an upload resumes
        // after its batches were paid; the per-chunk waves pay it.
        if merkle_upload_split(quote_total, unpaid.len())
            .batches
            .is_empty()
        {
            return Ok(());
        }
        let entries = unpaid.iter().map(|r| (r.address, r.size)).collect();
        adapter.checked(0, unpaid.len());
        let plan = match self
            .plan_merkle_upload_observed(
                entries,
                ant_protocol::DATA_TYPE_CHUNK,
                None,
                &|address, checked, total, present| {
                    if present {
                        if let Some(record) =
                            records.iter().find(|record| record.address == address)
                        {
                            adapter.already_stored(record.index + 1, quote_total);
                        }
                    }
                    adapter.checked(checked, total);
                },
            )
            .await
        {
            Ok(plan) => plan,
            Err(Error::InsufficientPeers(_)) if mode == PaymentMode::Auto => return Ok(()),
            Err(error) => return Err(error),
        };
        let present = plan.already_stored.iter().copied().collect::<HashSet<_>>();
        records.retain(|r| !present.contains(&r.address));
        outcome
            .addresses
            .extend(plan.already_stored.iter().copied());
        if plan.to_upload.is_empty() {
            outcome.mode = PaymentMode::Merkle;
            return Ok(());
        }
        if !should_use_merkle(plan.to_upload.len(), mode) {
            return Ok(());
        }
        // Exact power-of-two batches. The chunks after them stay unpaid here
        // and are paid per chunk once the batches are stored.
        let batches = merkle_upload_partitions(quote_total, &plan.to_upload);
        for (batch_index, addresses) in batches.iter().enumerate() {
            adapter.preparing(&format!(
                "Preparing Merkle payment batch {}/{}: collecting candidate quotes",
                batch_index + 1,
                batches.len()
            ));
            let batch = match self
                .prepare_merkle_batch_external_observed(
                    addresses,
                    ant_protocol::DATA_TYPE_CHUNK,
                    plan.to_upload_avg_size(),
                    &|completed, total| adapter.payment_quotes(completed, total),
                )
                .await
            {
                Ok(batch) => batch,
                // A network too small for a batch, or one whose nodes refuse
                // batches (darwin-node's): `Auto` pays per chunk instead.
                Err(Error::InsufficientPeers(_) | Error::BatchPaymentsRefused(_))
                    if mode == PaymentMode::Auto =>
                {
                    return Ok(())
                }
                Err(error) => return Err(error),
            };
            for record in records
                .iter()
                .filter(|record| addresses.contains(&record.address))
            {
                adapter.quoted(record.index + 1, quote_total);
            }
            adapter.preparing(
                "Payment quotes ready; saving recovery checkpoint before payment review",
            );
            state.pending_merkle = Some(batch);
            adapter.checkpoint(state, None).await?;
            self.ensure_upload_payment_allowed()?;
            state.start_payment(true, Vec::new())?;
            if let Some(attempt) = &mut state.pending_payment {
                adapter.initialize_payment_attempt(attempt);
            }
            adapter.checkpoint(state, None).await?;
            if let Err(error) = self.ensure_upload_payment_allowed() {
                state.pending_payment = None;
                adapter.checkpoint(state, None).await?;
                return Err(error);
            }
            let batch = state
                .pending_merkle
                .clone()
                .ok_or_else(|| Error::Payment("missing prepared Merkle batch".into()))?;
            let payment = adapter.submit_merkle_payment(&batch, state).await?;
            let paid = finalize_merkle_batch(batch, payment.winner_pool)?;
            state.insert_merkle(paid);
            let receipt = UploadPayment {
                amount: payment.amount,
                gas: payment.gas,
                ..Default::default()
            };
            outcome.amount = outcome
                .amount
                .checked_add(receipt.amount)
                .ok_or_else(|| Error::Payment("payment total overflow".into()))?;
            outcome.gas = outcome.gas.saturating_add(receipt.gas);
            outcome.mode = PaymentMode::Merkle;
            adapter.checkpoint(state, Some(&receipt)).await?;
        }
        Ok(())
    }
}

/// What an upload pays per chunk once its Merkle batches are stored, and the
/// order it stores it in: the records no batch paid, in their order, then
/// `last` (an envelope), in payment waves of
/// [`PAYMENT_WAVE_SIZE`](super::batch::PAYMENT_WAVE_SIZE).
///
/// `last` is never in a batch, since the batches are planned from the other
/// records alone. It rides in the final wave: with the remainder the batches
/// left (fewer than `MERKLE_EXACT_MIN_BATCH` records, as
/// `merkle_upload_split` leaves them), or alone when they left none, so its
/// payment is always per chunk. Each wave's stores leave it out
/// ([`PerChunkWaves::hold_back`]), and it is sent only once every other
/// record is stored ([`release_last`]). With no batch paid (per-chunk
/// payment, or `Auto` falling back to it), the waves are every record's.
#[derive(Debug)]
pub(crate) struct PerChunkWaves {
    /// The payment waves, in the order paid.
    pub(crate) waves: Vec<Vec<UploadRecord>>,
    /// The address of the record stored last, if there is one.
    pub(crate) last: Option<[u8; 32]>,
}

/// A record with the paid plan it is stored by.
pub(crate) type Planned<P> = (UploadRecord, P);

impl PerChunkWaves {
    /// The waves for `remaining`, the records left after the Merkle batches
    /// (all of them when there were none), and `last`.
    pub(crate) fn new(remaining: &[UploadRecord], last: Option<UploadRecord>) -> Self {
        let records = remaining.iter().copied().chain(last).collect::<Vec<_>>();
        Self {
            waves: records
                .chunks(super::batch::PAYMENT_WAVE_SIZE)
                .map(<[UploadRecord]>::to_vec)
                .collect(),
            last: last.map(|record| record.address),
        }
    }

    /// One paid wave's plans split into the records to store now, and the
    /// record held back to be stored last (`last`, when this wave pays it).
    /// A record with no plan is already stored, and is in neither.
    pub(crate) fn hold_back<P>(
        &self,
        plans: Vec<(UploadRecord, Option<P>)>,
    ) -> (Vec<Planned<P>>, Option<Planned<P>>) {
        let mut to_store = Vec::with_capacity(plans.len());
        let mut held = None;
        for (record, plan) in plans {
            match plan {
                Some(plan) if Some(record.address) == self.last => held = Some((record, plan)),
                Some(plan) => to_store.push((record, plan)),
                None => {}
            }
        }
        (to_store, held)
    }
}

/// Drop the proof `state` holds for `plan`'s record if an earlier run paid
/// it and `plan`, a fresh lookup's, puts the paid node outside the record's
/// [`PUT_TARGET_WIDTH`](crate::quote_policy::PUT_TARGET_WIDTH) nearest
/// storers, the width within which storers take a proof: the record is then
/// paid again with `plan`. A proof this run paid
/// ([`UploadState::paid_this_run`]) or a Merkle one is kept. Returns whether
/// it dropped one.
pub(crate) fn drop_proof_paid_outside(state: &mut UploadState, plan: &ChunkPaymentPlan) -> bool {
    if state.paid_this_run().contains(&plan.address)
        || !state
            .proof(&plan.address)
            .is_some_and(|proof| paid_outside_width(proof, &plan.quoted_peers))
    {
        return false;
    }
    tracing::info!(
        "the node an earlier run paid for {} is no longer among its {} nearest storers; \
         paying for it again",
        hex::encode(plan.address),
        crate::quote_policy::PUT_TARGET_WIDTH
    );
    state.drop_proof(&plan.address);
    true
}

/// Whether `peers`, a fresh lookup's PUT targets, put the node `proof` paid
/// (a single-node proof's) outside the record's
/// [`PUT_TARGET_WIDTH`](crate::quote_policy::PUT_TARGET_WIDTH) nearest
/// storers. Only a list that holds the whole width can: a shorter one, as a
/// lookup that fell back to the close group gives, leaves storers in the
/// width it doesn't name, which still take the proof, so the storers decide.
pub(crate) fn paid_outside_width(
    proof: &[u8],
    peers: &[(
        ant_protocol::transport::PeerId,
        Vec<ant_protocol::transport::MultiAddr>,
    )],
) -> bool {
    let width = crate::quote_policy::PUT_TARGET_WIDTH;
    peers.len() >= width
        && paid_node(proof).is_some_and(|paid| {
            !peers
                .iter()
                .take(width)
                .any(|(peer, _)| *peer.as_bytes() == paid)
        })
}

/// Take in the stores of `results` ([`Client::store_planned`]): stored
/// records into `outcome`, failed ones into `failed`, and `fatal` set if a
/// record couldn't be sent at all. Returns the records to pay for again,
/// with their store's error: those whose single-node proof an earlier run
/// paid (not in [`UploadState::paid_this_run`]) and every storer that failed
/// the store refused
/// ([`proof_refused`](super::chunk::proof_refused)), left out of `failed`,
/// unless they were paid again once already
/// ([`UploadState::was_paid_again`]): those are failures.
pub(crate) fn absorb_stores(
    results: Vec<([u8; 32], Result<WaveResult>)>,
    state: &mut UploadState,
    outcome: &mut UploadOutcome,
    failed: &mut Vec<([u8; 32], String)>,
    fatal: &mut bool,
) -> HashMap<[u8; 32], String> {
    let mut refused = HashMap::new();
    for (address, result) in results {
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                // Preserve this wave's settled spend and completed stores,
                // but do not pay another wave after a local byte/proof failure.
                *fatal = true;
                failed.push((address, error.to_string()));
                continue;
            }
        };
        outcome.stats.absorb(&result);
        for address in &result.stored {
            state.clear_paid_again(address);
        }
        outcome.addresses.extend(result.stored);
        let again = result
            .refused
            .into_iter()
            .filter(|address| {
                !state.paid_this_run().contains(address)
                    && !state.was_paid_again(address)
                    && state
                        .proof(address)
                        .is_some_and(|bytes| paid_node(bytes).is_some())
            })
            .collect::<HashSet<_>>();
        for (address, error) in result.failed {
            if again.contains(&address) {
                refused.insert(address, error);
            } else {
                failed.push((address, error));
            }
        }
    }
    refused
}

/// Why the record stored last (an envelope) was not sent.
pub(crate) const HELD_BACK: &str = "not stored, since other records failed to store";

/// Decide whether the record held back to be stored last (an envelope) may
/// be sent: only once every other record is stored, so it never points at
/// missing content. If any failed (`failed` is not empty), it is reported
/// failed with [`HELD_BACK`], its payment kept for a resume, and never sent.
pub(crate) fn release_last<T>(
    held: Option<T>,
    address: impl Fn(&T) -> [u8; 32],
    failed: &mut Vec<([u8; 32], String)>,
) -> Option<T> {
    let held = held?;
    if failed.is_empty() {
        Some(held)
    } else {
        failed.push((address(&held), HELD_BACK.into()));
        None
    }
}

/// Put a payment's plans in the order of the quote hashes they pay. The
/// vault emits one `DataPaymentMade` log per paid quote, in the order paid,
/// so a record always paid last (an envelope) would have the last log of its
/// transaction, and anyone reading the transaction would know its log index.
/// In quote-hash order its log is one of the payment's, told apart only by
/// its quote, which an envelope can hide.
pub(crate) fn order_by_quote_hash(plans: &mut [ChunkPaymentPlan]) {
    plans.sort_by_key(|plan| {
        plan.payment
            .quotes
            .iter()
            .filter(|quote| !quote.amount.is_zero())
            .map(|quote| quote.quote_hash)
            .min()
    });
}

pub(super) fn validate_payment_total(
    plans: &[ChunkPaymentPlan],
    payment: &UploadPayment,
) -> Result<()> {
    let expected = plans.iter().try_fold(Amount::ZERO, |sum, plan| {
        sum.checked_add(plan.payment.total_amount())
            .ok_or_else(|| Error::Payment("payment total overflow".into()))
    })?;
    if expected != payment.amount {
        return Err(Error::Payment(
            "wallet reported a different payment total".into(),
        ));
    }
    Ok(())
}

/// Why a record whose kept proof every storer refused (with `error`) is not
/// paid again, given what the vault's record of its payment showed
/// ([`Client::kept_payment`]): its record unread, whether no RPC answered or
/// this client reads no records (a browser build, or no payment network).
/// `None` when the record was read, and it is paid again.
fn kept_proof_failure(kept: KeptPayment, error: &str) -> Option<String> {
    match kept {
        KeptPayment::Recorded | KeptPayment::NotRecorded => None,
        KeptPayment::Unreadable => Some(format!(
            "{error}; the payment record couldn't be read, so the proof is kept and the record \
             not paid for again"
        )),
        KeptPayment::NotChecked => Some(format!(
            "{error}; the payment record couldn't be checked, since this client reads no payment \
             records (a browser build, or no payment network configured), so the proof is kept \
             and the record not paid for again"
        )),
    }
}

/// Native wallet and in-memory byte source for the shared upload coordinator.
pub(crate) struct MemoryUploadAdapter<'a> {
    pub client: &'a Client,
    pub chunks: &'a [Bytes],
    pub progress: Option<&'a tokio::sync::mpsc::Sender<super::file::UploadEvent>>,
    pub stored_offset: usize,
    pub file_total: usize,
    pub resume_key: Option<&'a str>,
}

#[cfg_attr(not(feature = "native"), async_trait::async_trait(?Send))]
#[cfg_attr(feature = "native", async_trait::async_trait)]
impl UploadAdapter for MemoryUploadAdapter<'_> {
    #[cfg(feature = "native")]
    fn initialize_payment_attempt(&self, attempt: &mut super::upload_state::PaymentAttempt) {
        super::native_payment::initialize(attempt);
    }
    #[cfg(feature = "native")]
    async fn submit_payment(
        &self,
        plans: &[ChunkPaymentPlan],
        state: &mut UploadState,
    ) -> Result<UploadPayment> {
        super::native_payment::pay_shared(self.client, self, plans, state).await
    }
    #[cfg(feature = "native")]
    async fn reconcile_payment(
        &self,
        plans: &[ChunkPaymentPlan],
        state: &mut UploadState,
    ) -> Result<UploadPayment> {
        super::native_payment::pay_shared(self.client, self, plans, state).await
    }
    #[cfg(feature = "native")]
    async fn submit_merkle_payment(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
        state: &mut UploadState,
    ) -> Result<MerkleUploadPayment> {
        super::native_payment::pay_merkle(self.client, self, batch, state).await
    }
    #[cfg(feature = "native")]
    async fn reconcile_merkle_payment(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
        state: &mut UploadState,
    ) -> Result<MerkleUploadPayment> {
        super::native_payment::pay_merkle(self.client, self, batch, state).await
    }
    async fn load(&self, record: UploadRecord) -> Result<Bytes> {
        self.chunks
            .get(record.index)
            .cloned()
            .ok_or_else(|| Error::InvalidData("missing staged record".into()))
    }
    async fn pay(&self, plans: &[ChunkPaymentPlan]) -> Result<UploadPayment> {
        let wallet = self.client.require_wallet()?;
        let payments = plans
            .iter()
            .flat_map(|plan| {
                plan.payment
                    .quotes
                    .iter()
                    .map(|q| (q.quote_hash, q.rewards_address, q.amount))
            })
            .collect::<Vec<_>>();
        let (transactions, gas) = wallet.pay_for_quotes(payments).await.map_err(
            |ant_protocol::evm::PayForQuotesError(error, _)| Error::Payment(error.to_string()),
        )?;
        let amount = plans.iter().try_fold(Amount::ZERO, |sum, plan| {
            sum.checked_add(plan.payment.total_amount())
                .ok_or_else(|| Error::Payment("payment total overflow".into()))
        })?;
        Ok(UploadPayment {
            transactions: transactions.into_iter().collect(),
            amount,
            gas: gas.gas_cost_wei,
        })
    }
    async fn pay_merkle(
        &self,
        batch: &super::merkle::PreparedMerkleBatch,
    ) -> Result<MerkleUploadPayment> {
        let (winner_pool, amount, gas) = self
            .client
            .require_wallet()?
            .pay_for_merkle_tree(
                batch.depth,
                batch.pool_commitments.clone(),
                batch.merkle_payment_timestamp,
            )
            .await
            .map_err(|e| Error::Payment(e.to_string()))?;
        Ok(MerkleUploadPayment {
            winner_pool,
            amount,
            gas: gas.gas_cost_wei,
        })
    }
    async fn checkpoint(&self, state: &UploadState, payment: Option<&UploadPayment>) -> Result<()> {
        #[cfg(feature = "native")]
        if let Some(key) = self.resume_key {
            // A wave's payment, or the mark that records are paid again
            // (saved before that payment is sent).
            let (amount, gas) = match payment {
                Some(payment) => (payment.amount.to_string(), payment.gas),
                None if !state.paid_again().is_empty() => ("0".to_string(), 0),
                None => return Ok(()),
            };
            super::cached_single::try_append_wave_marked(
                key,
                state.proofs().clone(),
                state.paid_again(),
                &amount,
                gas,
            );
        }
        #[cfg(not(feature = "native"))]
        let _ = (state, payment, self.resume_key);
        Ok(())
    }
    /// The marks, in the cached receipt, or the error that stops the
    /// payment: unlike the other checkpoints, never best effort.
    async fn checkpoint_paid_again(&self, state: &UploadState) -> Result<()> {
        #[cfg(feature = "native")]
        if let Some(key) = self.resume_key {
            super::cached_single::append_wave_marked(
                key,
                state.proofs().clone(),
                state.paid_again(),
                "0",
                0,
            )
            .map_err(|e| {
                Error::Payment(format!(
                    "the mark that records are paid again couldn't be saved in the cached \
                     receipt ({e}); nothing is paid again"
                ))
            })?;
        }
        #[cfg(not(feature = "native"))]
        let _ = (state, self.resume_key);
        Ok(())
    }
    fn stored(&self, stored: usize, total: usize) {
        if let Some(progress) = self.progress {
            let _ = progress.try_send(super::file::UploadEvent::ChunkStored {
                stored: self.stored_offset + stored,
                total: self.file_total.max(total),
            });
        }
    }
    fn quoted(&self, quoted: usize, total: usize) {
        if let Some(progress) = self.progress {
            let _ = progress.try_send(super::file::UploadEvent::ChunkQuoted {
                quoted: self.stored_offset + quoted,
                total: self.file_total.max(total),
            });
        }
    }
}

fn merge_stats(total: &mut WaveAggregateStats, next: WaveAggregateStats) {
    total.chunk_attempts_total = total
        .chunk_attempts_total
        .saturating_add(next.chunk_attempts_total);
    total.store_durations_ms.extend(next.store_durations_ms);
    for (total, next) in total
        .retries_histogram
        .iter_mut()
        .zip(next.retries_histogram)
    {
        *total = total.saturating_add(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan for `address` paying one quote, with `hash`, and two unpaid
    /// ones.
    fn plan(address: u8, hash: u8) -> ChunkPaymentPlan {
        use ant_protocol::evm::RewardsAddress;
        use ant_protocol::payment::QuotePaymentInfo;
        let quote = |hash: u8, amount: u64| QuotePaymentInfo {
            quote_hash: QuoteHash::from([hash; 32]),
            rewards_address: RewardsAddress::ZERO,
            amount: Amount::from(amount),
            price: Amount::from(1u64),
        };
        ChunkPaymentPlan {
            address: [address; 32],
            data_size: 1,
            quoted_peers: Vec::new(),
            payment: super::super::batch::SingleNodeQuotePayment {
                quotes: vec![quote(0x00, 0), quote(hash, 3), quote(0xff, 0)],
            },
            peer_quotes: Vec::new(),
            commitment_sidecars: Vec::new(),
        }
    }

    #[test]
    fn a_payment_is_in_quote_hash_order_so_the_envelope_is_not_always_last() {
        // Content in index order, then the envelope (address 9), as the
        // engine plans a wave.
        let mut plans = vec![plan(1, 0x30), plan(2, 0x10), plan(3, 0x50), plan(9, 0x20)];
        order_by_quote_hash(&mut plans);
        let addresses: Vec<u8> = plans.iter().map(|plan| plan.address[0]).collect();
        assert_eq!(addresses, vec![2, 9, 1, 3]);
        // The vault pays, and logs, the paid quotes in this order: the
        // envelope's log is wherever its quote hash falls, not last.
        let paid: Vec<QuoteHash> = plans
            .iter()
            .flat_map(|plan| plan.payment.quotes.iter())
            .filter(|quote| !quote.amount.is_zero())
            .map(|quote| quote.quote_hash)
            .collect();
        let mut sorted = paid.clone();
        sorted.sort();
        assert_eq!(paid, sorted);
        // The order doesn't depend on the order planned.
        let mut reversed = vec![plan(9, 0x20), plan(3, 0x50), plan(2, 0x10), plan(1, 0x30)];
        order_by_quote_hash(&mut reversed);
        let again: Vec<u8> = reversed.iter().map(|plan| plan.address[0]).collect();
        assert_eq!(again, addresses);
    }

    #[test]
    fn the_last_record_is_sent_only_when_every_other_record_stored() {
        let address = |record: &(u8, &str)| [record.0; 32];
        // Nothing held: nothing to send, nothing reported.
        let mut failed = Vec::new();
        assert_eq!(release_last(None::<(u8, &str)>, address, &mut failed), None);
        assert!(failed.is_empty());
        // Every other record stored: the held one is sent.
        assert_eq!(
            release_last(Some((7, "envelope")), address, &mut failed),
            Some((7, "envelope"))
        );
        assert!(failed.is_empty());
        // A content record failed: the held one is never sent, and is
        // reported failed (its payment kept for a resume), after the others.
        let mut failed = vec![([1; 32], "timed out".to_string())];
        assert_eq!(
            release_last(Some((7, "envelope")), address, &mut failed),
            None
        );
        assert_eq!(
            failed,
            vec![
                ([1; 32], "timed out".to_string()),
                ([7; 32], HELD_BACK.to_string())
            ]
        );
    }

    /// `count` content records, by index, and an envelope after them.
    fn content_and_envelope(count: usize) -> (Vec<UploadRecord>, UploadRecord) {
        let record = |index: usize, tag: u8| {
            let mut address = [tag; 32];
            address[..8].copy_from_slice(&(index as u64).to_be_bytes());
            UploadRecord {
                address,
                size: 1_000,
                index,
            }
        };
        let content = (0..count).map(|index| record(index, 0x00)).collect();
        (content, record(count, 0xee))
    }

    fn addresses_of(records: &[UploadRecord]) -> Vec<[u8; 32]> {
        records.iter().map(|record| record.address).collect()
    }

    /// The order the engine stores an upload in once every payment is made
    /// and every store succeeds: each batch, then each per-chunk wave's
    /// records (`hold_back`), then the record held back (`release_last`).
    fn stored_in_order(batches: &[&[[u8; 32]]], per_chunk: &PerChunkWaves) -> Vec<[u8; 32]> {
        let mut stored = batches.concat();
        let mut held = None;
        for wave in &per_chunk.waves {
            let plans = wave.iter().map(|record| (*record, Some(()))).collect();
            let (to_store, held_here) = per_chunk.hold_back(plans);
            stored.extend(to_store.iter().map(|(record, ())| record.address));
            if held_here.is_some() {
                held = held_here;
            }
        }
        let mut failed = Vec::new();
        if let Some((record, ())) = release_last(held, |(record, ())| record.address, &mut failed) {
            stored.push(record.address);
        }
        assert!(failed.is_empty(), "{failed:?}");
        stored
    }

    /// An envelope joined after paid Merkle batches, as the engine lays it
    /// out on a network that takes batches (darwin-node refuses them, so no
    /// end-to-end test reaches this): for 33, 65 and 4 × `MAX_LEAVES` + 40
    /// content records, and 32 and 64, which the batches use up. The batches
    /// (`merkle_upload_partitions`, as the engine plans them) hold content
    /// only; the envelope rides in the final per-chunk wave with the
    /// remainder they left, or alone when there is none; and it is stored
    /// after everything else.
    #[test]
    fn after_merkle_batches_the_envelope_is_paid_per_chunk_with_the_remainder_and_stored_last() {
        use super::super::merkle::{merkle_upload_partitions, merkle_upload_split};
        use ant_protocol::evm::MAX_LEAVES;

        for (count, remainder) in [(33, 1), (65, 1), (4 * MAX_LEAVES + 40, 8), (32, 0), (64, 0)] {
            let (content, envelope) = content_and_envelope(count);
            let content_addresses = addresses_of(&content);

            // The batches: content only, in order, as the split says.
            let batches = merkle_upload_partitions(count, &content_addresses);
            let batched: usize = batches.iter().map(|batch| batch.len()).sum();
            assert!(!batches.is_empty(), "{count} records: batches are paid");
            assert_eq!(batches.concat(), content_addresses[..batched], "{count}");
            assert!(
                batches
                    .iter()
                    .all(|batch| !batch.contains(&envelope.address)),
                "{count} records: the envelope is never in a batch"
            );
            assert_eq!(merkle_upload_split(count, count).per_chunk, remainder);

            // Left after the batches, as storing them leaves the records.
            let paid_in_batches: HashSet<[u8; 32]> = batches.concat().into_iter().collect();
            let remaining: Vec<UploadRecord> = content
                .iter()
                .copied()
                .filter(|record| !paid_in_batches.contains(&record.address))
                .collect();
            assert_eq!(remaining.len(), remainder, "{count}");

            // The per-chunk waves: the remainder, then the envelope, in one
            // final wave of at most 32 records.
            let per_chunk = PerChunkWaves::new(&remaining, Some(envelope));
            assert_eq!(per_chunk.last, Some(envelope.address));
            assert_eq!(per_chunk.waves.len(), 1, "{count}");
            let wave = addresses_of(&per_chunk.waves[0]);
            let mut expected = addresses_of(&remaining);
            expected.push(envelope.address);
            assert_eq!(wave, expected, "{count} records");
            if remainder == 0 {
                assert_eq!(wave, vec![envelope.address], "{count}: the envelope alone");
            }

            // Stored last, after every content record.
            let stored = stored_in_order(&batches, &per_chunk);
            assert_eq!(stored.len(), count + 1, "{count}");
            assert_eq!(stored.last(), Some(&envelope.address), "{count}");
            let stored_content: HashSet<[u8; 32]> = stored[..count].iter().copied().collect();
            let all_content: HashSet<[u8; 32]> = content_addresses.into_iter().collect();
            assert_eq!(stored_content, all_content, "{count}");
        }
    }

    /// With no batch paid (`Single`, or `Auto` falling back to per-chunk
    /// payment when the nodes refuse batches), the waves are every record's,
    /// 64 a wave, and the envelope joins the last one: 65 content records
    /// pay 64, then the last one with the envelope.
    #[test]
    fn with_no_batch_the_envelope_joins_the_last_wave_of_64() {
        let (content, envelope) = content_and_envelope(65);
        let per_chunk = PerChunkWaves::new(&content, Some(envelope));
        assert_eq!(
            per_chunk.waves.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![super::super::batch::PAYMENT_WAVE_SIZE, 2]
        );
        assert_eq!(
            addresses_of(&per_chunk.waves[1]),
            vec![content[64].address, envelope.address]
        );
        let stored = stored_in_order(&[], &per_chunk);
        assert_eq!(stored.last(), Some(&envelope.address));
        assert_eq!(stored.len(), 66);
    }

    /// A wave's stores leave out the record held back, and a record with no
    /// plan (already stored); with no `last`, nothing is held back. If any
    /// other record failed to store, the held record is not sent.
    #[test]
    fn a_wave_holds_back_only_the_record_stored_last() {
        let (content, envelope) = content_and_envelope(3);
        let per_chunk = PerChunkWaves::new(&content, Some(envelope));
        let plans = vec![
            (content[0], Some("a")),
            (content[1], None),
            (envelope, Some("envelope")),
            (content[2], Some("c")),
        ];
        let (to_store, held) = per_chunk.hold_back(plans);
        assert_eq!(
            to_store
                .iter()
                .map(|(record, plan)| (record.address, *plan))
                .collect::<Vec<_>>(),
            vec![(content[0].address, "a"), (content[2].address, "c")]
        );
        assert_eq!(
            held.map(|(record, plan)| (record.address, plan)),
            Some((envelope.address, "envelope"))
        );

        // A content record failed: the envelope is reported held back.
        let mut failed = vec![(content[0].address, "timed out".to_string())];
        assert!(release_last(held, |(record, _)| record.address, &mut failed).is_none());
        assert_eq!(
            failed.last(),
            Some(&(envelope.address, HELD_BACK.to_string()))
        );

        // No record stored last: nothing held back.
        let raw = PerChunkWaves::new(&content, None);
        assert_eq!(raw.last, None);
        let plans = content.iter().map(|record| (*record, Some(()))).collect();
        let (to_store, held) = raw.hold_back(plans);
        assert_eq!(to_store.len(), 3);
        assert!(held.is_none());
    }

    /// An earlier run's paid proof is kept while its paid node is among
    /// the storers' width in a fresh lookup, and dropped, to be paid again,
    /// once it isn't; a proof this run paid is never dropped so.
    #[test]
    fn a_proof_is_paid_again_only_once_its_paid_node_is_outside_the_width() {
        use crate::data::client::upload_state::test_state::{plan_priced, transactions};
        use ant_protocol::transport::PeerId;
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let paid = plan_priced(b"paid earlier", now, &[30, 10, 20]);
        let median = paid
            .peer_quotes
            .iter()
            .find(|(_, quote)| quote.price == ant_protocol::evm::Amount::from(20u64))
            .map(|(peer, _)| PeerId::from_bytes(*peer.as_bytes()))
            .unwrap();
        let with_targets = |targets: Vec<PeerId>| {
            let mut fresh = paid.clone();
            fresh.quoted_peers = targets.into_iter().map(|peer| (peer, Vec::new())).collect();
            fresh
        };
        let others = |count: u8| {
            (0..count)
                .map(|i| PeerId::from_bytes([i + 100; 32]))
                .collect::<Vec<_>>()
        };
        let state_paid = || {
            let mut state = UploadState::default();
            state.prepare(paid.clone());
            state
                .confirm(&[paid.address], &transactions(&paid), now)
                .unwrap();
            state
        };
        // Among the 20 nearest, last of them: kept.
        let mut inside = others(19);
        inside.push(median);
        let mut state = state_paid();
        assert!(!drop_proof_paid_outside(&mut state, &with_targets(inside)));
        assert!(state.proof(&paid.address).is_some());
        // The 21st: dropped.
        let mut outside = others(20);
        outside.push(median);
        assert!(drop_proof_paid_outside(
            &mut state,
            &with_targets(outside.clone())
        ));
        assert!(state.proof(&paid.address).is_none());
        // Paid by this run: kept.
        let mut state = state_paid();
        state.add_paid_this_run([paid.address]);
        assert!(!drop_proof_paid_outside(&mut state, &with_targets(outside)));
        assert!(state.proof(&paid.address).is_some());
        // A lookup that fell back to the close group: 7 targets, the paid
        // node not among them. Storers in places 8 to 20 still take the
        // proof, so it is kept, here and when a record is paid on its own
        // (`settle_record` decides by the same check).
        let mut state = state_paid();
        let close_group = with_targets(others(7));
        assert!(!drop_proof_paid_outside(&mut state, &close_group));
        assert!(state.proof(&paid.address).is_some());
        let proof = state.proof(&paid.address).unwrap();
        assert!(!paid_outside_width(proof, &close_group.quoted_peers));
        assert!(!paid_outside_width(
            proof,
            &with_targets(others(19)).quoted_peers
        ));
        assert!(paid_outside_width(
            proof,
            &with_targets(others(20)).quoted_peers
        ));
    }

    /// A record whose earlier proof every failing storer refused is paid
    /// again, not reported failed; one this run paid, or one whose storers
    /// failed it for another reason, is a failure.
    #[test]
    fn only_an_earlier_runs_refused_proof_is_paid_again() {
        use crate::data::client::upload_state::test_state::{plan, transactions};
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let records = [
            plan(b"earlier", now),
            plan(b"this run", now),
            plan(b"full", now),
            plan(b"paid again", now),
        ];
        let mut state = UploadState::default();
        for record in &records {
            state.prepare(record.clone());
            state
                .confirm(&[record.address], &transactions(record), now)
                .unwrap();
        }
        let [earlier, this_run, full, paid_again] = records.map(|record| record.address);
        // Paid again once already, in this run or an earlier one.
        state.mark_paid_again(paid_again);
        let result = |address: [u8; 32], refused: bool| WaveResult {
            stored: Vec::new(),
            failed: vec![(address, "short of a quorum".into())],
            refused: if refused { vec![address] } else { Vec::new() },
            chunk_attempts_total: 1,
            store_durations_ms: Vec::new(),
            retries_per_chunk: Vec::new(),
        };
        let results = vec![
            (earlier, Ok(result(earlier, true))),
            (this_run, Ok(result(this_run, true))),
            (full, Ok(result(full, false))),
            (paid_again, Ok(result(paid_again, true))),
        ];
        let mut outcome = UploadOutcome::default();
        let mut failed = Vec::new();
        let mut fatal = false;
        state.add_paid_this_run([this_run]);
        let again = absorb_stores(results, &mut state, &mut outcome, &mut failed, &mut fatal);
        assert_eq!(
            again,
            HashMap::from([(earlier, "short of a quorum".to_string())])
        );
        let failed = failed
            .into_iter()
            .map(|(address, _)| address)
            .collect::<HashSet<_>>();
        assert_eq!(failed, HashSet::from([this_run, full, paid_again]));
        assert!(!fatal);

        // Stored, a record paid again is forgotten as such.
        let stored = WaveResult {
            stored: vec![paid_again],
            failed: Vec::new(),
            refused: Vec::new(),
            chunk_attempts_total: 1,
            store_durations_ms: Vec::new(),
            retries_per_chunk: Vec::new(),
        };
        absorb_stores(
            vec![(paid_again, Ok(stored))],
            &mut state,
            &mut outcome,
            &mut Vec::new(),
            &mut fatal,
        );
        assert!(!state.was_paid_again(&paid_again));
    }

    /// A proof the command paid in its first pass over the state, refused
    /// by every storer, is still this run's in the pass the command makes
    /// after a payment whose outcome was unknown: a failure, never paid
    /// again, nor dropped for its paid node's place. Read back from its
    /// checkpoint, as a new process reads it, the proof is an earlier
    /// run's.
    #[test]
    fn a_proof_paid_in_the_first_pass_is_this_runs_in_the_second() {
        use crate::data::client::upload_state::test_state::{plan, transactions};
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let record = plan(b"paid in the first pass", now);
        let address = record.address;
        let mut state = UploadState::default();
        // The first pass pays for the record.
        state.add_paid_this_run([address]);
        state.prepare(record.clone());
        state
            .confirm(&[address], &transactions(&record), now)
            .unwrap();
        let refused = || {
            vec![(
                address,
                Ok(WaveResult {
                    stored: Vec::new(),
                    failed: vec![(address, "refused".into())],
                    refused: vec![address],
                    chunk_attempts_total: 1,
                    store_durations_ms: Vec::new(),
                    retries_per_chunk: Vec::new(),
                }),
            )]
        };
        // Both passes over the same state: a failure each time.
        for pass in 1..=2 {
            let mut failed = Vec::new();
            let again = absorb_stores(
                refused(),
                &mut state,
                &mut UploadOutcome::default(),
                &mut failed,
                &mut false,
            );
            assert!(again.is_empty(), "pass {pass}: not paid again");
            assert_eq!(failed.len(), 1, "pass {pass}: a failure");
        }
        // A fresh lookup that puts the paid node outside the width.
        let mut outside = record.clone();
        outside.quoted_peers = (0..crate::quote_policy::PUT_TARGET_WIDTH)
            .map(|i| {
                let byte = u8::try_from(i + 100).unwrap();
                (
                    ant_protocol::transport::PeerId::from_bytes([byte; 32]),
                    Vec::new(),
                )
            })
            .collect();
        assert!(!drop_proof_paid_outside(&mut state, &outside));
        assert!(state.proof(&address).is_some());

        // A new process: the proof is an earlier run's.
        let mut state = UploadState::parse(&state.checkpoint().unwrap())
            .unwrap()
            .state;
        assert!(state.paid_this_run().is_empty());
        let again = absorb_stores(
            refused(),
            &mut state,
            &mut UploadOutcome::default(),
            &mut Vec::new(),
            &mut false,
        );
        assert!(again.contains_key(&address), "paid again, once");
        assert!(drop_proof_paid_outside(&mut state, &outside));
    }

    /// A kept proof every storer refused is paid again only when the vault's
    /// record of its payment was read; unread, whether no RPC answered or
    /// this client reads none (a browser build, or no payment network), it
    /// is kept and the record fails, each with its own reason.
    #[test]
    fn a_kept_proof_is_paid_again_only_when_its_record_was_read() {
        assert!(kept_proof_failure(KeptPayment::Recorded, "refused").is_none());
        assert!(kept_proof_failure(KeptPayment::NotRecorded, "refused").is_none());
        let unreadable = kept_proof_failure(KeptPayment::Unreadable, "refused").unwrap();
        let unchecked = kept_proof_failure(KeptPayment::NotChecked, "refused").unwrap();
        assert!(unreadable.starts_with("refused; ") && unchecked.starts_with("refused; "));
        assert!(unreadable.contains("couldn't be read"), "{unreadable}");
        assert!(unchecked.contains("couldn't be checked"), "{unchecked}");
        assert_ne!(unreadable, unchecked);
    }

    /// The marks that records are paid again are saved, their refused
    /// proofs still kept, before the proofs are dropped or anything is
    /// paid; a mark that can't be saved stops the payment, as does the
    /// save after the proofs are dropped.
    #[cfg(feature = "native")]
    #[tokio::test]
    async fn the_paid_again_mark_is_saved_before_the_proof_goes_or_anything_is_paid() {
        use crate::data::client::upload_state::test_state::{plan, transactions};
        use std::sync::Mutex;

        /// Records what each save held (which save, marked, proof kept),
        /// and fails the mark's if told to, and every other.
        struct Saves {
            fail_mark: bool,
            saved: Mutex<Vec<(&'static str, bool, bool)>>,
            address: [u8; 32],
        }
        impl Saves {
            fn save(&self, kind: &'static str, state: &UploadState) {
                self.saved.lock().unwrap().push((
                    kind,
                    state.was_paid_again(&self.address),
                    state.proof(&self.address).is_some(),
                ));
            }
        }
        #[async_trait::async_trait]
        impl UploadAdapter for Saves {
            async fn load(&self, _: UploadRecord) -> Result<Bytes> {
                Err(Error::InvalidData("no bytes".into()))
            }
            async fn pay(&self, _: &[ChunkPaymentPlan]) -> Result<UploadPayment> {
                panic!("nothing may be paid")
            }
            async fn checkpoint(
                &self,
                state: &UploadState,
                _: Option<&UploadPayment>,
            ) -> Result<()> {
                self.save("checkpoint", state);
                Err(Error::InvalidData("disk full".into()))
            }
            async fn checkpoint_paid_again(&self, state: &UploadState) -> Result<()> {
                self.save("mark", state);
                if self.fail_mark {
                    return Err(Error::InvalidData("disk full".into()));
                }
                Ok(())
            }
        }

        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let refused = plan(b"refused", now);
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(std::sync::Arc::clone(node.node()), Default::default());
        for (fail_mark, expected) in [
            (true, vec![("mark", true, true)]),
            (
                false,
                vec![("mark", true, true), ("checkpoint", true, false)],
            ),
        ] {
            let mut state = UploadState::default();
            state.prepare(refused.clone());
            state
                .confirm(&[refused.address], &transactions(&refused), now)
                .unwrap();
            let adapter = Saves {
                fail_mark,
                saved: Mutex::new(Vec::new()),
                address: refused.address,
            };
            let record = UploadRecord {
                address: refused.address,
                size: refused.data_size,
                index: 0,
            };
            let result = client
                .pay_again(
                    &[record],
                    &mut state,
                    &adapter,
                    false,
                    1,
                    &mut UploadOutcome::default(),
                    &mut Vec::new(),
                )
                .await;
            assert!(result.is_err());
            assert_eq!(*adapter.saved.lock().unwrap(), expected);
        }
    }

    /// The mark that a record was paid again is saved with the checkpoint
    /// and read back, so a later run never pays for it a third time.
    #[test]
    fn the_paid_again_mark_survives_a_checkpoint() {
        let mut state = UploadState::default();
        state.mark_paid_again([7; 32]);
        let restored = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        assert!(restored.was_paid_again(&[7; 32]));
        assert!(!restored.was_paid_again(&[8; 32]));
        let none = UploadState::restore(&UploadState::default().checkpoint().unwrap()).unwrap();
        assert!(none.paid_again().is_empty());
    }
}
