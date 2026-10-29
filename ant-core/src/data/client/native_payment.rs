// Copyright 2026 Saorsa Labs Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native wallet journal: persist a signed payment before any storage broadcast.
use super::{
    batch::{ChunkPaymentPlan, PAYMENT_WAVE_SIZE},
    merkle::PreparedMerkleBatch,
    occupied::KeptPayment,
    root_payment::{self, PaymentVault, RootWavePayment},
    shared_wave::{Member, QuoteTuple, Step, WaveEnd, WaveSigned},
    upload::{MerkleUploadPayment, UploadAdapter, UploadPayment, UploadRecord},
    upload_state::{PaymentAttempt, UploadState},
    Client,
};
use crate::data::error::{Error, Result};
use ant_protocol::evm::journal::{PaymentReceipt, PaymentRequest, PaymentStatus, SignedPayment};
use ant_protocol::evm::{Network, Wallet};
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
    fn pays_root_waves(&self) -> bool {
        true
    }
    async fn checkpoint(&self, state: &UploadState, _: Option<&UploadPayment>) -> Result<()> {
        self.save(state)
    }
}

/// A payment attempt's journal: the one entry of its `submissions`.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "native_payment_v1",
    content = "transaction",
    rename_all = "snake_case"
)]
enum Journal {
    /// Nothing is signed for the attempt yet.
    Preparing,
    /// The attempt's own transaction, saved before it was sent.
    Signed(SignedPayment),
    /// The attempt joined the shared wave with this id (hex), saved before
    /// anything was signed for the wave. The wave's file
    /// ([`super::shared_wave::read_wave_file`]) says whether anything was.
    Wave(String),
    /// The shared wave's transaction, as the attempt saved it before it was
    /// sent: the wave's file, while it is there, has the latest.
    WaveSigned(WaveSigned),
}

/// The journal of `state`'s pending attempt.
fn journal_of(state: &UploadState) -> Result<Journal> {
    let attempt = state
        .pending_payment
        .as_ref()
        .ok_or_else(|| Error::Payment("missing native payment attempt".into()))?;
    match attempt.submissions.as_slice() {
        [value] => serde_json::from_value(value.clone()).map_err(|_| {
            Error::Payment(
                "unknown native payment journal; reconciliation evidence is required".into(),
            )
        }),
        _ => Err(Error::Payment(
            "legacy pending payment has no transaction identity; reconcile it before retrying"
                .into(),
        )),
    }
}

/// Make `journal` the journal of `state`'s pending attempt.
fn set_journal(state: &mut UploadState, journal: &Journal) -> Result<()> {
    let value = serde_json::to_value(journal).map_err(|e| Error::Serialization(e.to_string()))?;
    if let Some(attempt) = &mut state.pending_payment {
        attempt.submissions = vec![value];
    }
    Ok(())
}

pub(super) fn initialize(attempt: &mut PaymentAttempt) {
    // This synchronous marker is persisted with the attempt, before wallet I/O.
    attempt.submissions = vec![serde_json::json!({ "native_payment_v1": "preparing" })];
}

/// The quotes `plans` pay: each with a non-zero amount, in order.
fn quotes_of(plans: &[ChunkPaymentPlan]) -> Vec<QuoteTuple> {
    plans
        .iter()
        .flat_map(|p| p.payment.quotes.iter())
        .filter(|q| q.amount != ant_protocol::evm::Amount::ZERO)
        .map(|q| (q.quote_hash, q.rewards_address, q.amount))
        .collect()
}

/// Pay for `plans` with the client's wallet, on their own, journaled in
/// `state` ([`pay_shared`] lets them share a wave). An attempt `state`
/// already journals is reconciled, a shared wave's too.
pub(super) async fn pay<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    plans: &[ChunkPaymentPlan],
    state: &mut UploadState,
) -> Result<UploadPayment> {
    pay_with(client, adapter, plans, state, false).await
}

/// [`pay`], in a shared wave ([`super::shared_wave`]) when `plans` are
/// fewer than a wave's [`PAYMENT_WAVE_SIZE`] records: an upload's payments,
/// which small files of one wallet's uploads share.
pub(super) async fn pay_shared<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    plans: &[ChunkPaymentPlan],
    state: &mut UploadState,
) -> Result<UploadPayment> {
    pay_with(
        client,
        adapter,
        plans,
        state,
        plans.len() < PAYMENT_WAVE_SIZE,
    )
    .await
}

async fn pay_with<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    plans: &[ChunkPaymentPlan],
    state: &mut UploadState,
    share: bool,
) -> Result<UploadPayment> {
    // A transaction the attempt journaled is reconciled through the wallet
    // of the vault its `to` names, never sent to the other.
    let vault = match journal_of(state)? {
        Journal::Signed(signed) => journaled_vault(client, &signed, plans)?,
        _ => root_payment::vault_of(plans)?,
    };
    match vault {
        PaymentVault::V2 => {}
        // A root wave is paid on its own: its leaves, and so every
        // record's path, are fixed before anything is signed.
        PaymentVault::Root => return pay_root(client, adapter, plans, state).await,
    }
    let quotes = quotes_of(plans);
    let fresh = |state: &UploadState| {
        plans.iter().all(|p| {
            state
                .retained_plan(&p.address, p.data_size, crate::runtime::system_time())
                .is_some()
        })
    };
    let paid = match journal_of(state)? {
        Journal::Wave(wave) => {
            reconcile_wave(client, adapter, &wave, None, &quotes, state, &fresh).await?
        }
        Journal::WaveSigned(own) => {
            let wave = own.wave.clone();
            reconcile_wave(client, adapter, &wave, Some(own), &quotes, state, &fresh).await?
        }
        Journal::Preparing | Journal::Signed(_) => None,
    };
    let (receipt, wave_quotes) = match paid {
        Some(paid) => paid,
        None => match journal_of(state)? {
            Journal::Preparing if share => {
                pay_in_wave(client, adapter, &quotes, state, &fresh).await?
            }
            _ => {
                let request = PaymentRequest::Quotes(quotes.clone());
                let wallet = client.require_wallet()?;
                let executed =
                    execute(client, wallet, adapter, &request, state, fresh, None).await?;
                (executed.receipt, quotes.len())
            }
        },
    };
    let share = super::shared_wave::share_of(&receipt, &quotes, wave_quotes)?;
    Ok(UploadPayment {
        transactions: quotes
            .iter()
            .map(|q| (q.0, receipt.transaction_hash))
            .collect(),
        amount: share.amount,
        gas: share.gas,
        root: None,
    })
}

/// Pay for `plans`, each of which pays the root vault, as one wave through
/// the client's root wallet, journaled in `state` as any payment is: the
/// wave's leaves in ascending quote-hash order, sent as one `payForQuotes`
/// call, the same calldata the per-quote vault takes. A journaled attempt is
/// reconciled through the root wallet, never sent to the other vault.
///
/// Once the payment is confirmed, the vault's record under the wave's key
/// is read back, again while it reads empty, as the occupied-quote
/// read-back reads; an empty read never pays again, since an RPC can lag
/// the chain. The key binds every leaf's payee and amount, so that one read
/// stands for the read-back of every paid quote.
///
/// The proofs, and so the envelope's payment record, name the transaction
/// that recorded the wave ([`Client::root_wave_transaction`]): the payment's
/// own when its receipt holds the vault's `RootPaid` log naming the key,
/// else the one that sent the same leaves first, found by that log. Storers
/// check an envelope's payment in the transaction its proof names. If it
/// can't be found, the payment fails with its journal kept, and a retry
/// looks again without paying again.
async fn pay_root<A: UploadAdapter>(
    client: &Client,
    adapter: &A,
    plans: &[ChunkPaymentPlan],
    state: &mut UploadState,
) -> Result<UploadPayment> {
    let wave = root_payment::wave_of(plans)?;
    let quotes = root_payment::wave_quotes(&wave);
    if client.root_wallet().is_none() {
        if let Journal::Preparing = journal_of(state)? {
            // Nothing was signed for the attempt, so nothing was sent: it
            // ends, and its records are quoted again for the per-quote vault
            // (`upload::keeps_retained_plan`). A journaled transaction keeps
            // its journal, to be reconciled by a client paying the root vault.
            state.pending_payment = None;
            adapter.checkpoint(state, None).await?;
            return Err(Error::Payment(
                "this payment is to the root vault, and the client has no wallet for it; nothing \
                 was sent for it, so a retry quotes its records for the per-quote vault"
                    .into(),
            ));
        }
    }
    let wallet = client.wallet_paying(PaymentVault::Root)?;
    let vault: [u8; 20] = wallet.network().payment_vault_address().0 .0;
    let key = wave.key(&vault);
    if let Journal::Wave(_) | Journal::WaveSigned(_) = journal_of(state)? {
        return Err(Error::Payment(
            "the checkpoint journals a shared wave for plans that pay the root vault, which is \
             never paid in a shared wave; its journal is kept. Don't delete the upload's \
             checkpoint"
                .into(),
        ));
    }
    let fresh = |state: &UploadState| {
        plans.iter().all(|p| {
            state
                .retained_plan(&p.address, p.data_size, crate::runtime::system_time())
                .is_some()
        })
    };
    let request = PaymentRequest::Quotes(quotes.clone());
    let Executed {
        receipt,
        replaced_by,
    } = execute(
        client,
        wallet,
        adapter,
        &request,
        state,
        fresh,
        Some((vault, key)),
    )
    .await?;
    match client
        .root_wave_recorded(&vault, &key, ROOT_READS_AFTER_PAYMENT)
        .await
    {
        KeptPayment::Recorded => {}
        read => tracing::warn!(
            "the root vault's record of the wave {} read {read:?} after its payment was \
             confirmed; its recording transaction is looked for by its RootPaid log",
            hex::encode(key)
        ),
    }
    // A receipt of no tokens is one whose own transaction reverted or was
    // replaced, with the wave recorded by another (`recorded_elsewhere`).
    let own_confirmed = !receipt.amount.is_zero();
    let own = receipt.transaction_hash;
    let recording = ant_protocol::evm::TxHash::from(
        client
            .root_wave_transaction(
                &vault,
                &key,
                &own.0,
                own_confirmed,
                replaced_by.as_ref().map(|replacement| &replacement.0),
                earliest_quote(plans),
            )
            .await?,
    );
    let share = super::shared_wave::share_of(&receipt, &quotes, quotes.len())?;
    Ok(root_wave_payment(
        &quotes,
        own,
        recording,
        wave,
        share.amount,
        share.gas,
    ))
}

/// A root wave's payment, recorded by transaction `recording`: every
/// record's proof, and so its envelope's payment record, names it. When
/// that isn't the payment's own transaction (`own`), another recorded the
/// same leaves first, and this payment moved no tokens: its `amount` is
/// none, and only its `gas` was spent.
fn root_wave_payment(
    quotes: &[QuoteTuple],
    own: ant_protocol::evm::TxHash,
    recording: ant_protocol::evm::TxHash,
    wave: ant_listings::root::Wave,
    amount: ant_protocol::evm::Amount,
    gas: u128,
) -> UploadPayment {
    let amount = if recording == own {
        amount
    } else {
        tracing::warn!(
            "the root wave was recorded by transaction {recording}, not by this payment's own \
             {own}, which moved no tokens: its records' proofs and its envelope's payment record \
             name the recording transaction"
        );
        ant_protocol::evm::Amount::ZERO
    };
    UploadPayment {
        transactions: quotes.iter().map(|q| (q.0, recording)).collect(),
        amount,
        gas,
        root: Some(RootWavePayment {
            transaction: recording,
            wave,
        }),
    }
}

/// The earliest signed time (Unix seconds) of any quote `plans` carry: a
/// root wave can't be recorded before it, give or take clock skew.
fn earliest_quote(plans: &[ChunkPaymentPlan]) -> u64 {
    plans
        .iter()
        .flat_map(|plan| plan.peer_quotes.iter())
        .filter_map(|(_, quote)| quote.timestamp.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|since| since.as_secs())
        .min()
        .unwrap_or(0)
}

/// Settle an external payer's `payment` of `plans` from the chain, when the
/// plans pay the root vault and the payment names no root wave: a payer
/// that asked for root waves (`UploadPayer::pays_root_waves`) returns only
/// its transactions and total, and the engine finds the wave itself. Any
/// other payment is returned as it is: one of the per-quote vault, or the
/// client's own root payment ([`pay_root`]), which names its wave.
///
/// - **The root vault records the wave** (its record under the wave's key,
///   read again while empty, as after the client's own root payment): the
///   proofs, and so the envelope's payment record, name the transaction
///   that recorded it ([`Client::root_wave_transaction`]), the payer's own
///   when its receipt holds the vault's `RootPaid` log naming the key. When
///   another transaction recorded the same leaves first, the payer's moved
///   no tokens (the vault records a key once and skips a wave it holds):
///   the payment's amount is none, nothing is paid again, and the records
///   are stored with proofs naming the recording transaction.
/// - **The per-quote vault records every quote instead:** the wave's
///   calldata was sent there, which pays each quote as a quotes payment
///   does. Nodes accept a single-node proof for these quotes: a quote
///   carries no settlement version, and one asked at the root vault's
///   version is priced as one asked at the per-quote vault's. So `plans`
///   (and their kept copies in `state`) pay the per-quote vault from here
///   on, and the records are stored with single-node proofs from the
///   payer's transactions, after the occupied-quote read-back as any
///   per-quote payment.
/// - **Neither:** the upload stops with the payment kept pending, and
///   nothing is paid again: the next attempt reconciles it, asking the
///   payer again for the payment it made.
///
/// # Errors
///
/// If no root vault or EVM network is known, the wave can't be built, the
/// recording transaction isn't found, or neither vault shows the payment.
pub(crate) async fn outside_root_payment(
    client: &Client,
    plans: &mut [ChunkPaymentPlan],
    state: &mut UploadState,
    payment: UploadPayment,
) -> Result<UploadPayment> {
    if payment.root.is_some()
        || plans.is_empty()
        || root_payment::vault_of(plans)? != PaymentVault::Root
    {
        return Ok(payment);
    }
    let vault = client.root_vault().ok_or_else(|| {
        Error::Payment(
            "these plans pay the root vault, and the client knows no root vault to find their \
             payment at; the payment stays pending, and nothing is paid again. Don't delete the \
             upload's checkpoint"
                .into(),
        )
    })?;
    let wave = root_payment::wave_of(plans)?;
    let key = wave.key(&vault);
    let read = client
        .root_wave_recorded(&vault, &key, ROOT_READS_AFTER_PAYMENT)
        .await;
    if read == KeptPayment::Recorded {
        // A payer names one transaction for a wave; any other answer leaves
        // the recording transaction to its RootPaid log.
        let mut sent = payment.transactions.values().copied();
        let first = sent.next();
        let own = first.filter(|first| sent.all(|tx| tx == *first));
        let recording = ant_protocol::evm::TxHash::from(
            client
                .root_wave_transaction(
                    &vault,
                    &key,
                    &own.map_or([0; 32], |own| own.0),
                    own.is_some(),
                    None,
                    earliest_quote(plans),
                )
                .await?,
        );
        let quotes = root_payment::wave_quotes(&wave);
        let total = quotes
            .iter()
            .try_fold(ant_protocol::evm::Amount::ZERO, |sum, quote| {
                sum.checked_add(quote.2)
            })
            .ok_or_else(|| Error::Payment("payment total overflow".into()))?;
        // The key binds every leaf's payee and amount, so a wave its own
        // transaction recorded paid exactly the wave's total.
        return Ok(root_wave_payment(
            &quotes,
            own.unwrap_or_default(),
            recording,
            wave,
            total,
            payment.gas,
        ));
    }
    if read == KeptPayment::NotChecked {
        return Err(Error::Payment(
            "these plans pay the root vault, and the client has no EVM network to find their \
             payment on (with_evm_network); the payment stays pending, and nothing is paid \
             again. Don't delete the upload's checkpoint"
                .into(),
        ));
    }
    match client
        .per_quote_vault_records(plans, ROOT_READS_AFTER_PAYMENT)
        .await
    {
        KeptPayment::Recorded => {
            tracing::warn!(
                "the root wave under key {} isn't recorded at the root vault ({read:?}), and the \
                 per-quote vault records each of its quotes: the payer sent it there, and its {} \
                 record(s) are stored with single-node proofs",
                hex::encode(key),
                plans.len()
            );
            for plan in plans.iter_mut() {
                plan.vault = PaymentVault::V2;
                state.prepare(plan.clone());
            }
            Ok(payment)
        }
        per_quote => Err(Error::Payment(format!(
            "the payment of the root wave under key {} wasn't found: the root vault's record \
             read {read:?}, and the per-quote vault's records of its quotes {per_quote:?}. The \
             payment stays pending, and nothing is paid again: the next attempt asks the payer \
             for the payment it made. Don't delete the upload's checkpoint",
            hex::encode(key)
        ))),
    }
}

/// Why a journaled transaction can't be read.
fn journal_unreadable() -> Error {
    Error::Payment(
        "the journaled transaction can't be read; its journal is kept, and nothing is paid \
         again. Don't delete the upload's checkpoint"
            .into(),
    )
}

/// A journaled transaction, decoded.
///
/// # Errors
///
/// If the journaled bytes aren't a transaction.
fn journaled_tx(signed: &SignedPayment) -> Result<alloy::consensus::TxEnvelope> {
    use alloy::eips::eip2718::Decodable2718 as _;
    let raw: Vec<u8> = serde_json::to_value(signed)
        .ok()
        .and_then(|value| serde_json::from_value(value.get("raw")?.clone()).ok())
        .ok_or_else(journal_unreadable)?;
    alloy::consensus::TxEnvelope::decode_2718(&mut raw.as_slice()).map_err(|_| journal_unreadable())
}

/// The `to` of a journaled transaction: the address it pays.
///
/// # Errors
///
/// If the journaled bytes aren't a transaction with a recipient.
fn journaled_to(signed: &SignedPayment) -> Result<ant_protocol::evm::Address> {
    use alloy::consensus::Transaction as _;
    journaled_tx(signed)?.to().ok_or_else(journal_unreadable)
}

/// Which of this client's vaults `to` is: the per-quote vault its wallet
/// pays, or the root vault, as its root wallet pays it or, without one, as
/// the client's network bundles it or the client names it
/// ([`Client::root_vault`]).
fn vault_named(client: &Client, to: &ant_protocol::evm::Address) -> Option<PaymentVault> {
    let v2 = client
        .wallet_paying(PaymentVault::V2)
        .ok()
        .map(|wallet| *wallet.network().payment_vault_address());
    let root = client.root_vault().map(ant_protocol::evm::Address::from);
    if Some(*to) == root {
        Some(PaymentVault::Root)
    } else if Some(*to) == v2 {
        Some(PaymentVault::V2)
    } else {
        None
    }
}

/// The vault a journaled transaction is reconciled through: the one its
/// `to` names, which must be the vault its `plans` recorded.
///
/// # Errors
///
/// If its `to` is neither vault, or names the other vault than its plans
/// recorded: its journal is kept, and nothing is paid again.
fn journaled_vault(
    client: &Client,
    signed: &SignedPayment,
    plans: &[ChunkPaymentPlan],
) -> Result<PaymentVault> {
    let to = journaled_to(signed)?;
    let recorded = root_payment::vault_of(plans)?;
    match vault_named(client, &to) {
        Some(named) if named == recorded => Ok(named),
        Some(named) => Err(Error::Payment(format!(
            "the journaled transaction pays the {named:?} vault, but its plans record the \
             {recorded:?} vault; its journal is kept, and nothing is paid again. Don't delete the \
             upload's checkpoint"
        ))),
        None => Err(Error::Payment(format!(
            "the journaled transaction pays {to}, which is neither vault this client pays; its \
             journal is kept, and nothing is paid again. A client paying the root vault \
             reconciles a root payment (with_root_payments). Don't delete the upload's checkpoint"
        ))),
    }
}

/// How many times the root vault's record of a wave is read after its
/// payment was confirmed, 2 seconds apart, while it reads empty: as many
/// as the occupied-quote read-back reads each paid quote.
const ROOT_READS_AFTER_PAYMENT: usize = 5;

/// How many times the root vault's record of a wave is read, 2 seconds
/// apart, before a root payment whose transaction reverted or was replaced
/// is taken to have paid nothing: a read and a re-read.
const ROOT_READS_BEFORE_PAYING_AGAIN: usize = 2;

/// Pay `quotes` in the shared wave of the client's wallet
/// ([`super::shared_wave`]): join it, save its id in `state`'s journal, and
/// wait for its transaction, sending it if this attempt leads the wave.
/// Returns the receipt and how many quotes the wave paid.
async fn pay_in_wave<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    adapter: &A,
    quotes: &[QuoteTuple],
    state: &mut UploadState,
    fresh: &F,
) -> Result<(PaymentReceipt, usize)> {
    let wallet = client.require_wallet()?;
    if let Some(refusal) = client.corroborated_settlement_refusal() {
        state.pending_payment = None;
        adapter.checkpoint(state, None).await?;
        return Err(Error::ClientUpdateRequired(refusal));
    }
    if !fresh(state) {
        state.pending_payment = None;
        adapter.checkpoint(state, None).await?;
        return Err(Error::Payment(
            "unsubmitted payment quotes expired; retry to prepare fresh quotes".into(),
        ));
    }
    let member = client.shared_waves().join(quotes.len());
    set_journal(state, &Journal::Wave(member.wave_id()))?;
    if let Err(error) = adapter.checkpoint(state, None).await {
        // Nothing of the wave is on disk: the attempt is as it was.
        if let Some(attempt) = &mut state.pending_payment {
            initialize(attempt);
        }
        return Err(error);
    }
    member.ready(quotes.to_vec());
    let steps = async {
        loop {
            match member.next().await {
                Step::Save(round, journal) => {
                    let saved = save_wave_journal(adapter, state, journal).await;
                    member.saved(round, saved);
                }
                Step::Ended(ended) => break ended,
            }
        }
    };
    let ended = if member.leads() {
        let (ended, ()) = futures::join!(steps, lead(client, wallet, &member));
        ended
    } else {
        steps.await
    };
    let receipt = finish_wave(adapter, state, ended.ended).await?;
    Ok((receipt, ended.quotes))
}

/// Save the wave's signed transaction in `state`'s journal before it is
/// sent. Returns whether it was saved.
async fn save_wave_journal<A: UploadAdapter>(
    adapter: &A,
    state: &mut UploadState,
    journal: WaveSigned,
) -> bool {
    set_journal(state, &Journal::WaveSigned(journal)).is_ok()
        && adapter.checkpoint(state, None).await.is_ok()
}

/// Send the wave `member` leads, once it closes
/// ([`super::shared_wave::Member::close`]): sign one transaction paying
/// every member's quotes, write the wave's file, have every member save it,
/// send it, and tell the members how it ended.
async fn lead(client: &Client, wallet: &Wallet, member: &Member) {
    // One transaction in flight per signing key: the wave stays open for
    // others to join while an earlier one is in flight.
    let _signing = root_payment::signing_lock(wallet.address())
        .lock_owned()
        .await;
    // And the wallet's own lock inside it, as in `execute_once`: the lead
    // prepares and sends the wave's payment (`Wallet::prepare_payment`).
    let _wallet_lock = wallet.lock().await;
    let quotes = member.close(client.shared_waves()).await;
    if quotes.is_empty() {
        member.end(WaveEnd::NotSent(Error::Payment(
            "every payment of the shared wave left it".into(),
        )));
        return;
    }
    let request = PaymentRequest::Quotes(quotes.clone());
    for round in 0..2 {
        if let Some(refusal) = client.corroborated_settlement_refusal() {
            member.end(WaveEnd::NotSent(Error::ClientUpdateRequired(refusal)));
            return;
        }
        let signed = match wallet.prepare_payment(&request).await {
            Ok(signed) => signed,
            Err(message) => {
                member.end(WaveEnd::NotSent(Error::Payment(message)));
                return;
            }
        };
        let journal = WaveSigned {
            wave: member.wave_id(),
            transaction: signed.clone(),
            quotes: quotes.clone(),
        };
        // On disk, whole, before any member saves it or anything is sent:
        // the one record of what the wave signed.
        if let Err(error) = super::shared_wave::write_wave_file(&journal) {
            member.end(WaveEnd::NotSent(error));
            return;
        }
        if member.publish(journal).await {
            // Every member saved it: none needs the file.
            super::shared_wave::remove_wave_file(&member.wave_id());
        }
        match settle(client, wallet, &signed, &request, true, || true).await {
            Settled::StaleUnsent if round == 0 => {}
            Settled::StaleUnsent => {
                member.end(WaveEnd::StaleUnsent);
                return;
            }
            settled => {
                member.end(WaveEnd::Settled(settled));
                return;
            }
        }
    }
}

/// Take how the wave ended into `state`'s journal, as [`finish`] does for a
/// payment of its own.
async fn finish_wave<A: UploadAdapter>(
    adapter: &A,
    state: &mut UploadState,
    ended: WaveEnd,
) -> Result<PaymentReceipt> {
    match ended {
        WaveEnd::Settled(settled) => finish(adapter, state, settled).await,
        WaveEnd::StaleUnsent => finish(adapter, state, Settled::StaleUnsent).await,
        WaveEnd::NotSent(error) => {
            // Nothing was sent for the wave: nothing is left to reconcile.
            state.pending_payment = None;
            adapter.checkpoint(state, None).await?;
            Err(error)
        }
        WaveEnd::Stopped => Err(Error::Payment(
            "the shared wave's payment stopped before it ended; retry will reconcile it from \
             its journal"
                .into(),
        )),
    }
}

/// Reconcile the shared wave `wave` that `state`'s attempt joined
/// (`own`, its signed transaction if the attempt saved it): from the
/// wave's file if it is there, which holds the latest transaction the wave
/// signed, else from `own`, sending at most that transaction again. When
/// nothing was signed for the attempt ([`super::shared_wave::wave_payment`]),
/// it starts afresh (`None`), its journal back to preparing. Returns the
/// receipt and how many quotes the wave paid.
///
/// The wave's file is the only record of a later round the attempt didn't
/// save. So when it is gone, and the attempt would start afresh, or its own
/// copy ended reverted or replaced, the vault's records of its quotes are
/// read first ([`wave_quotes_unpaid`]): if any is recorded as paid, or they
/// can't be read, the journal is kept and the payment fails, never paid
/// again.
async fn reconcile_wave<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    adapter: &A,
    wave: &str,
    own: Option<WaveSigned>,
    quotes: &[QuoteTuple],
    state: &mut UploadState,
    fresh: &F,
) -> Result<Option<(PaymentReceipt, usize)>> {
    let wallet = client.require_wallet()?;
    let _signing = client.lock_signing().await?;
    // And the wallet's own lock inside it, as in `execute_once`: the wave's
    // transaction may be sent again below.
    let _wallet_lock = wallet.lock().await;
    let file = super::shared_wave::read_wave_file(wave)?;
    let file_gone = file.is_none();
    let Some(signed) = super::shared_wave::wave_payment(file, own, quotes)? else {
        if file_gone {
            wave_quotes_unpaid(client, wave, quotes).await?;
        }
        if let Some(attempt) = &mut state.pending_payment {
            initialize(attempt);
        }
        adapter.checkpoint(state, None).await?;
        return Ok(None);
    };
    let request = PaymentRequest::Quotes(signed.quotes.clone());
    let settled = settle(client, wallet, &signed.transaction, &request, false, || {
        fresh(state)
    })
    .await;
    if file_gone && matches!(settled, Settled::Reverted | Settled::Replaced(_)) {
        // The attempt's own copy may be of an earlier round than the one
        // the wave sent.
        wave_quotes_unpaid(client, wave, quotes).await?;
    }
    let receipt = finish(adapter, state, settled).await?;
    Ok(Some((receipt, signed.quotes.len())))
}

/// Check, before a shared wave's member whose wave's file is gone is paid
/// afresh, that the vault records none of its `quotes` as paid
/// ([`Client::quotes_recorded`]).
///
/// # Errors
///
/// If any is recorded as paid, or they can't be read: the journal is kept,
/// and the error says not to delete the checkpoint.
async fn wave_quotes_unpaid(client: &Client, wave: &str, quotes: &[QuoteTuple]) -> Result<()> {
    use super::occupied::KeptPayment;
    match client.quotes_recorded(quotes).await {
        KeptPayment::NotRecorded => Ok(()),
        KeptPayment::Recorded => Err(Error::Payment(format!(
            "the shared wave {wave}'s file is gone and the vault records this payment's quotes \
             as paid, so its transaction can't be reconciled from this checkpoint; its journal \
             is kept, and nothing is paid again. Don't delete the upload's checkpoint: it holds \
             a payment that was made"
        ))),
        KeptPayment::Unreadable | KeptPayment::NotChecked => Err(Error::Payment(format!(
            "the shared wave {wave}'s file is gone and the vault's records of this payment's \
             quotes couldn't be read; its journal is kept, and a retry reads them again rather \
             than pay twice. Don't delete the upload's checkpoint"
        ))),
    }
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
    let wallet = client.require_wallet()?;
    let receipt = execute(client, wallet, adapter, &request, state, fresh, None)
        .await?
        .receipt;
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

/// A root wave's vault and key, for a payment through the root vault.
type RootKey = ([u8; 20], [u8; 32]);

/// How [`execute`] ended with a payment made.
struct Executed {
    /// The payment's receipt.
    receipt: PaymentReceipt,
    /// For a root wave whose own transaction was replaced, and which the
    /// vault records by another ([`recorded_elsewhere`]): the transaction
    /// that took its nonce, the first [`pay_root`] reads for the recording.
    replaced_by: Option<ant_protocol::evm::TxHash>,
}

impl From<PaymentReceipt> for Executed {
    fn from(receipt: PaymentReceipt) -> Self {
        Self {
            receipt,
            replaced_by: None,
        }
    }
}

/// Pay `request` through `wallet`, journaled in `state`. For a root wave
/// (`root`: its vault and key), a transaction that reverted or was replaced
/// ends the attempt only once the vault shows no record under the wave's
/// key ([`root_wave_recorded_elsewhere`]), or, if it shows one, ends it as
/// paid by another transaction, moving no tokens ([`recorded_elsewhere`]).
async fn execute<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    wallet: &Wallet,
    adapter: &A,
    request: &PaymentRequest,
    state: &mut UploadState,
    fresh: F,
    root: Option<RootKey>,
) -> Result<Executed> {
    // A nonce is read from a public endpoint whose replicas lag each other, so
    // a freshly signed payment can carry a nonce the chain already consumed
    // (measured 1 in 150 reads on Arbitrum Sepolia, DEV-03 run 589). Such bytes
    // can never be mined and were never sent, so one re-preparation is the fix.
    match execute_once(client, wallet, adapter, request, state, &fresh, root).await {
        Err(Error::Payment(message)) if message == STALE_UNSENT_NONCE => {
            execute_once(client, wallet, adapter, request, state, &fresh, root).await
        }
        outcome => outcome,
    }
}

async fn execute_once<A: UploadAdapter, F: Fn(&UploadState) -> bool + Send + Sync>(
    client: &Client,
    wallet: &Wallet,
    adapter: &A,
    request: &PaymentRequest,
    state: &mut UploadState,
    fresh: &F,
    root: Option<RootKey>,
) -> Result<Executed> {
    let journal = journal_of(state)?;
    // One transaction in flight per signing key, whichever vault it pays.
    let _signing = root_payment::signing_lock(wallet.address())
        .lock_owned()
        .await;
    // And the wallet's own lock inside it, as evmlib asks of a caller that
    // prepares and sends a payment through a wallet it may share
    // (`Wallet::prepare_payment`). Always taken after the signing lock.
    let _wallet_lock = wallet.lock().await;
    // True only for bytes signed below, in this call: they have never been
    // broadcast, so there is nothing on chain to observe before sending them.
    let (signed, unsent) = match journal {
        Journal::Signed(signed) => (signed, false),
        Journal::Wave(_) | Journal::WaveSigned(_) => {
            return Err(Error::Payment(
                "a shared wave's payment is reconciled with its wave".into(),
            ))
        }
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
            set_journal(state, &Journal::Signed(signed.clone()))?;
            adapter.checkpoint(state, None).await?;
            (signed, true)
        }
    };
    let settled = settle(client, wallet, &signed, request, unsent, || fresh(state)).await;
    if let (Some((vault, key)), Settled::Reverted | Settled::Replaced(_)) = (root, &settled) {
        if root_wave_recorded_elsewhere(client, &vault, &key).await? {
            let transaction = journaled_hash(&signed)?;
            tracing::warn!(
                "the root wave's own transaction {transaction} didn't pay it, and the root vault \
                 records the wave under its key {} as paid, by another transaction: its records \
                 are taken as paid, with proofs naming the transaction that recorded it, found \
                 by its RootPaid log; this payment moved no tokens",
                hex::encode(key)
            );
            let replaced_by = match &settled {
                Settled::Replaced(replacement) => Some(*replacement),
                _ => None,
            };
            let receipt = finish(
                adapter,
                state,
                Settled::Confirmed(recorded_elsewhere(transaction)),
            )
            .await?;
            return Ok(Executed {
                receipt,
                replaced_by,
            });
        }
    }
    finish(adapter, state, settled).await.map(Executed::from)
}

/// The receipt a root wave's payment ends with when its own transaction
/// (`transaction`) reverted or was replaced and the root vault records the
/// wave by another ([`root_wave_recorded_elsewhere`]): it moved no tokens
/// and its gas isn't read, and the wave's records are paid. [`pay_root`]
/// builds their proofs from the wave, naming the transaction that recorded
/// it, found by its `RootPaid` log ([`Client::root_wave_transaction`]).
fn recorded_elsewhere(transaction: ant_protocol::evm::TxHash) -> PaymentReceipt {
    PaymentReceipt {
        transaction_hash: transaction,
        amount: ant_protocol::evm::Amount::ZERO,
        winner_pool: None,
        gas_cost_wei: 0,
    }
}

/// The hash of a journaled transaction.
///
/// # Errors
///
/// If the journaled bytes aren't a transaction.
fn journaled_hash(signed: &SignedPayment) -> Result<ant_protocol::evm::TxHash> {
    Ok(*journaled_tx(signed)?.tx_hash())
}

/// Whether the root vault records a wave under `key`, read before a root
/// payment whose transaction reverted or was replaced ends: the same
/// leaves, sent by any wallet in any block, are recorded under the same
/// key, and a recorded key counts as paid. `false`: the vault records none,
/// and the records can be paid again. `true`: the wave is paid, by another
/// transaction, and its records' proofs are built from it, naming that
/// transaction ([`Client::root_wave_transaction`]): storers check a
/// record's payment by the vault's record under the key, and an envelope's
/// in the transaction its proof names.
///
/// # Errors
///
/// If the key's record can't be read: the journal is kept, and nothing is
/// paid again.
async fn root_wave_recorded_elsewhere(
    client: &Client,
    vault: &[u8; 20],
    key: &[u8; 32],
) -> Result<bool> {
    match client
        .root_wave_recorded(vault, key, ROOT_READS_BEFORE_PAYING_AGAIN)
        .await
    {
        KeptPayment::NotRecorded => Ok(false),
        KeptPayment::Recorded => Ok(true),
        KeptPayment::Unreadable | KeptPayment::NotChecked => Err(Error::Payment(format!(
            "the root wave's own transaction didn't pay it, and the root vault's record under its \
             key {} couldn't be read; its journal is kept, and a retry reads it again rather \
             than pay twice. Don't delete the upload's checkpoint",
            hex::encode(key)
        ))),
    }
}

/// How a signed payment ended, as [`settle`] saw it.
pub(crate) enum Settled {
    /// Included in the chain.
    Confirmed(PaymentReceipt),
    /// It reverted in a finalized block: it can't charge anything now.
    Reverted,
    /// Another transaction took its nonce in a finalized block.
    Replaced(ant_protocol::evm::TxHash),
    /// The first send of bytes signed for it was refused for a stale nonce:
    /// they were never sent, and can never be mined.
    StaleUnsent,
    /// Its outcome is unknown, or it was refused for good before it was
    /// sent: its journal stays.
    Kept(Error),
}

/// Send `signed` (if `unsent`, at once; else only if the chain doesn't show
/// it and `fresh` says its quotes are still fresh, the same bytes again) and
/// observe it, for up to 30 seconds. The caller holds the wallet's lock.
async fn settle<F: Fn() -> bool>(
    client: &Client,
    wallet: &Wallet,
    signed: &SignedPayment,
    request: &PaymentRequest,
    unsent: bool,
    fresh: F,
) -> Settled {
    let mut broadcast = false;
    let observation = async {
        loop {
            if unsent && !broadcast {
                // Freshness and settlement refusal were checked moments ago,
                // before signing. A rejected nonce here can only be a stale
                // nonce read: the caller prepares again. Any other rejection
                // is final for this attempt.
                match wallet.broadcast_payment(signed, request).await {
                    Ok(_) => broadcast = true,
                    Err(message) if is_stale_nonce(&message) => return Settled::StaleUnsent,
                    Err(message) => return Settled::Kept(Error::Payment(message)),
                }
            }
            let status = match wallet.observe_payment(signed, request).await {
                Ok(status) => status,
                Err(message) => return Settled::Kept(Error::Payment(message)),
            };
            match status {
                PaymentStatus::Confirmed(receipt) => return Settled::Confirmed(receipt),
                PaymentStatus::Reverted => return Settled::Reverted,
                PaymentStatus::Finalizing => {
                    return Settled::Kept(Error::Payment(
                        "payment outcome is awaiting chain finality; retain its journal and retry later"
                            .into(),
                    ))
                }
                PaymentStatus::Replaced { transaction_hash } => {
                    return Settled::Replaced(transaction_hash)
                }
                PaymentStatus::Pending => {
                    if !broadcast {
                        if let Some(refusal) = client.corroborated_settlement_refusal() {
                            return Settled::Kept(Error::ClientUpdateRequired(refusal));
                        }
                        if !fresh() {
                            return Settled::Kept(Error::Payment("pending payment has expired quotes; retain its transaction journal for reconciliation".into()));
                        }
                        // An ambiguous send only ever retries these exact signed bytes.
                        // A nonce rejection means the nonce is used: by these bytes,
                        // whose receipt a lagging replica doesn't show yet (seen live on
                        // a load-balanced endpoint), or by another transaction, which
                        // finality turns into `Replaced`. Either way, keep observing
                        // until the timeout below rather than fail at once.
                        match wallet.broadcast_payment(signed, request).await {
                            Ok(_) => {}
                            Err(message) if is_stale_nonce(&message) => {
                                tracing::debug!(
                                    "re-sent payment's nonce is already used ({message}); observing"
                                );
                            }
                            Err(message) => return Settled::Kept(Error::Payment(message)),
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
        .unwrap_or_else(|_| {
            Settled::Kept(Error::Payment(
                "payment outcome pending; retry will reconcile the journaled transaction".into(),
            ))
        })
}

/// Take how a payment `settled` into `state`'s journal, saved through
/// `adapter`: a receipt kept with it, an attempt that can't charge anything
/// ended, bytes that were never sent back to preparing, and anything else
/// kept for reconciliation.
async fn finish<A: UploadAdapter>(
    adapter: &A,
    state: &mut UploadState,
    settled: Settled,
) -> Result<PaymentReceipt> {
    match settled {
        Settled::Confirmed(receipt) => {
            if let Some(attempt) = &mut state.pending_payment {
                attempt.receipt = Some(
                    serde_json::to_value(&receipt)
                        .map_err(|e| Error::Serialization(e.to_string()))?,
                );
            }
            adapter.checkpoint(state, None).await?;
            Ok(receipt)
        }
        Settled::Reverted => {
            state.pending_payment = None;
            adapter.checkpoint(state, None).await?;
            Err(Error::Payment(
                "payment reverted on-chain; retry is safe".into(),
            ))
        }
        Settled::Replaced(transaction_hash) => {
            state.pending_payment = None;
            adapter.checkpoint(state, None).await?;
            Err(Error::Payment(format!(
                "payment nonce was finalized by transaction {transaction_hash}; retry is safe"
            )))
        }
        Settled::StaleUnsent => {
            if let Some(attempt) = &mut state.pending_payment {
                initialize(attempt);
            }
            adapter.checkpoint(state, None).await?;
            Err(Error::Payment(STALE_UNSENT_NONCE.into()))
        }
        Settled::Kept(error) => Err(error),
    }
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
        execute(
            self,
            self.require_wallet()?,
            adapter,
            request,
            state,
            |_| fresh,
            None,
        )
        .await
        .map(|executed| executed.receipt)
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
            payment: SingleNodeQuotePayment::from_quotes(
                vec![quote.clone()],
                ant_protocol::payment::pricing::RecordWeight::FULL,
            )
            .unwrap(),
            peer_quotes: vec![(
                EncodedPeerId::new(*blake3::hash(&quote.pub_key).as_bytes()),
                quote,
            )],
            commitment_sidecars: Vec::new(),
            vault: crate::data::client::root_payment::PaymentVault::V2,
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

    /// A signed transaction paying `to`, journaled as a wallet journals it.
    fn journaled_paying(to: ant_protocol::evm::Address) -> SignedPayment {
        use alloy::consensus::{SignableTransaction as _, TxEip1559, TxEnvelope};
        use alloy::eips::eip2718::Encodable2718 as _;
        let tx = TxEip1559 {
            chain_id: 1,
            to: alloy::primitives::TxKind::Call(to),
            ..TxEip1559::default()
        };
        let one = alloy::primitives::U256::from(1u8);
        let signed = tx.into_signed(alloy::primitives::Signature::new(one, one, false));
        let raw = TxEnvelope::from(signed).encoded_2718();
        serde_json::from_value(serde_json::json!({ "raw": raw })).unwrap()
    }

    /// A journaled transaction is reconciled through the wallet of the vault
    /// its `to` names, which must be the vault its plans recorded: one
    /// naming the other vault, or neither, keeps its journal and pays
    /// nothing again, and a root payment needs a client that pays the root
    /// vault to be reconciled.
    #[tokio::test]
    async fn a_journaled_transaction_is_reconciled_through_the_vault_it_pays() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let (v2, root, other) = (
            ant_protocol::evm::Address::from([0x22; 20]),
            ant_protocol::evm::Address::from([0x33; 20]),
            ant_protocol::evm::Address::from([0x44; 20]),
        );
        let net = network(1);
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap());
        let root_wallet =
            Wallet::new_from_private_key(crate::config::network_paying(&net, root), KEY).unwrap();
        let rooted = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_from_private_key(net, KEY).unwrap())
            .with_root_payments(root_wallet)
            .unwrap();
        let now = crate::runtime::system_time();
        let v2_plans = vec![signed_plan([1; 32], 1024, now)];
        let mut root_plans = vec![signed_plan([2; 32], 1024, now)];
        root_plans[0].vault = PaymentVault::Root;

        assert_eq!(journaled_to(&journaled_paying(root)).unwrap(), root);
        let vault = |client: &Client, to, plans: &[ChunkPaymentPlan]| {
            journaled_vault(client, &journaled_paying(to), plans)
        };
        assert_eq!(
            vault(&rooted, root, &root_plans).unwrap(),
            PaymentVault::Root
        );
        assert_eq!(vault(&rooted, v2, &v2_plans).unwrap(), PaymentVault::V2);
        assert_eq!(vault(&client, v2, &v2_plans).unwrap(), PaymentVault::V2);
        for error in [
            vault(&rooted, v2, &root_plans),
            vault(&rooted, root, &v2_plans),
            vault(&rooted, other, &v2_plans),
            vault(&client, root, &root_plans),
        ] {
            let message = error.unwrap_err().to_string();
            assert!(message.contains("journal is kept"), "{message}");
            assert!(message.contains("nothing is paid again"), "{message}");
        }
        let unrooted = vault(&client, root, &root_plans).unwrap_err().to_string();
        assert!(unrooted.contains("with_root_payments"), "{unrooted}");
    }

    /// On the bundled network, a client pays the root vault its
    /// configuration names and no other: a root vault's wallet paying any
    /// other vault is refused, and no approval or payment goes to it.
    #[tokio::test]
    async fn a_bundled_network_client_pays_only_its_root_vault() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let bundled = crate::config::bundled_payment_network().unwrap();
        let root = crate::config::root_vault_address(&bundled).unwrap();
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = || {
            Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
                .with_wallet(Wallet::new_from_private_key(bundled.clone(), KEY).unwrap())
        };
        let paying = |vault| {
            Wallet::new_from_private_key(crate::config::network_paying(&bundled, vault), KEY)
                .unwrap()
        };
        for other in [
            ant_protocol::evm::Address::from([0x33; 20]),
            ant_protocol::evm::Address::from(root.0 .0.map(|byte| byte ^ 1)),
        ] {
            let error = client().with_root_payments(paying(other)).err().unwrap();
            assert!(
                error.to_string().contains("bundled network's root vault"),
                "{error}"
            );
        }
        let rooted = client().with_root_payments(paying(root)).unwrap();
        assert_eq!(rooted.payment_vault(), PaymentVault::Root);
        assert_eq!(
            rooted
                .wallet_paying(PaymentVault::Root)
                .unwrap()
                .network()
                .payment_vault_address(),
            &root
        );
    }

    /// A client may name its network's root vault without a wallet to pay
    /// it (`with_root_vault`): it reads root payments there, and a journaled
    /// root payment to it is reconciled through it. A root vault's wallet
    /// must then pay that vault: one paying another is refused, and one set
    /// earlier is dropped once another vault is named. On the bundled
    /// network its own root vault stays the one read and paid.
    #[tokio::test]
    async fn a_client_names_its_root_vault_without_a_root_wallet() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let other = ant_protocol::evm::Address::from([0x44; 20]);
        let net = network(1);
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = || {
            Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
                .with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap())
        };
        let paying = |vault| {
            Wallet::new_from_private_key(crate::config::network_paying(&net, vault), KEY).unwrap()
        };

        assert_eq!(client().root_vault(), None);
        let named = client().with_root_vault(root);
        assert_eq!(named.root_vault(), Some(root.0 .0));
        assert_eq!(
            named.payment_vault(),
            PaymentVault::V2,
            "it pays nothing by naming"
        );
        assert_eq!(vault_named(&named, &root), Some(PaymentVault::Root));
        let v2 = *net.payment_vault_address();
        assert_eq!(vault_named(&named, &v2), Some(PaymentVault::V2));
        assert_eq!(vault_named(&named, &other), None);
        assert_eq!(vault_named(&client(), &root), None);
        // Reconciling a root payment still needs the root vault's wallet.
        let error = named.wallet_paying(PaymentVault::Root).err().unwrap();
        assert!(error.to_string().contains("with_root_payments"), "{error}");

        // A root vault's wallet must pay the vault named.
        let error = client()
            .with_root_vault(root)
            .with_root_payments(paying(other))
            .err()
            .unwrap();
        assert!(error.to_string().contains("with_root_vault"), "{error}");
        let rooted = client()
            .with_root_vault(root)
            .with_root_payments(paying(root))
            .unwrap();
        assert_eq!(rooted.payment_vault(), PaymentVault::Root);
        assert_eq!(rooted.root_vault(), Some(root.0 .0));
        // Naming the same vault again keeps the wallet; naming another drops
        // it, and the client pays the per-quote vault.
        let kept = rooted.with_root_vault(root);
        assert_eq!(kept.payment_vault(), PaymentVault::Root);
        let moved = kept.with_root_vault(other);
        assert!(moved.root_wallet().is_none());
        assert_eq!(moved.payment_vault(), PaymentVault::V2);
        assert_eq!(moved.root_vault(), Some(other.0 .0));
        // A root vault's wallet set before a vault is named, paying another,
        // is dropped once it is named.
        let later = client()
            .with_root_payments(paying(other))
            .unwrap()
            .with_root_vault(root);
        assert!(later.root_wallet().is_none());

        // On the bundled network, its own root vault is read and paid.
        let bundled = crate::config::bundled_payment_network().unwrap();
        let built_in = crate::config::root_vault_address(&bundled).unwrap();
        let on_bundled = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_from_private_key(bundled.clone(), KEY).unwrap())
            .with_root_vault(root);
        assert_eq!(on_bundled.root_vault(), Some(built_in.0 .0));
        let rooted = on_bundled
            .with_root_payments(
                Wallet::new_from_private_key(
                    crate::config::network_paying(&bundled, built_in),
                    KEY,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(rooted.root_vault(), Some(built_in.0 .0));
    }

    /// A library client opts in to root payments with one key in one call
    /// (`with_root_payments_from_key`): both wallets from that key, the root
    /// vault's paying the bundled network's own, or on another network the
    /// one the client names. With none known, it is refused and nothing is
    /// set; a client that doesn't opt in pays the per-quote vault.
    #[tokio::test]
    async fn one_key_opts_a_client_in_to_root_payments() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let net = network(1);
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = || Client::from_node(std::sync::Arc::clone(node.node()), Default::default());

        let plain = client().with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap());
        assert_eq!(plain.payment_vault(), PaymentVault::V2, "opt-in only");

        let error = client()
            .with_root_payments_from_key(net.clone(), KEY, Some(31337))
            .err()
            .unwrap();
        assert!(error.to_string().contains("with_root_vault"), "{error}");

        let rooted = client()
            .with_root_vault(root)
            .with_root_payments_from_key(net.clone(), KEY, Some(31337))
            .unwrap();
        assert_eq!(rooted.payment_vault(), PaymentVault::Root);
        let wallet = rooted.wallet().unwrap();
        let root_wallet = rooted.root_wallet().unwrap();
        assert_eq!(wallet.address(), root_wallet.address());
        assert_eq!(
            wallet.network().payment_vault_address(),
            net.payment_vault_address()
        );
        assert_eq!(root_wallet.network().payment_vault_address(), &root);

        let bad_key = client()
            .with_root_vault(root)
            .with_root_payments_from_key(net, "not a key", None)
            .err()
            .unwrap();
        assert!(bad_key.to_string().contains("wallet"), "{bad_key}");

        let bundled = crate::config::bundled_payment_network().unwrap();
        let built_in = crate::config::root_vault_address(&bundled).unwrap();
        let on_bundled = client()
            .with_root_payments_from_key(bundled, KEY, None)
            .unwrap();
        assert_eq!(
            on_bundled
                .root_wallet()
                .unwrap()
                .network()
                .payment_vault_address(),
            &built_in
        );
    }

    /// A wallet set after the root vault's keeps the root vault's wallet
    /// only while it passes the same checks: one of another key or network
    /// is dropped, and the client pays the per-quote vault, so root waves
    /// are never signed by another key than the client's wallet.
    #[tokio::test]
    async fn a_later_wallet_keeps_the_root_vaults_only_if_it_matches() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        const OTHER: &str = "0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f";
        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let net = network(1);
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let rooted = || {
            Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
                .with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap())
                .with_root_payments(
                    Wallet::new_from_private_key(crate::config::network_paying(&net, root), KEY)
                        .unwrap(),
                )
                .unwrap()
        };
        let same = rooted().with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap());
        assert_eq!(same.payment_vault(), PaymentVault::Root);
        assert!(same.wallet_paying(PaymentVault::Root).is_ok());
        for wallet in [
            Wallet::new_from_private_key(net.clone(), OTHER).unwrap(),
            Wallet::new_from_private_key(network(2), KEY).unwrap(),
            Wallet::new_from_private_key(crate::config::network_paying(&net, root), KEY).unwrap(),
        ] {
            let moved = rooted().with_wallet(wallet);
            assert!(moved.root_wallet().is_none());
            assert_eq!(moved.payment_vault(), PaymentVault::V2);
            let error = moved.wallet_paying(PaymentVault::Root).err().unwrap();
            assert!(error.to_string().contains("with_root_payments"), "{error}");
        }
    }

    /// A root wave recorded by another transaction than the payment's own
    /// (the own one reverted, was replaced, or found the wave already
    /// recorded) moved no tokens of the payment's, and every record's proof
    /// names the recording transaction, which the envelope's payment record
    /// and storers' listing checks read the envelope leaf's payment log in.
    /// A wave the payment's own transaction recorded names that one, with
    /// the payment's total.
    #[test]
    fn a_root_wave_recorded_by_another_names_the_recording_transaction() {
        use crate::data::client::upload_state::test_state::plan_priced;
        let quoted = std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let plans: Vec<ChunkPaymentPlan> = (0u8..3)
            .map(|n| {
                let at = quoted + Duration::from_secs(u64::from(n) * 60);
                let mut plan = plan_priced(&[n, 0x7e], at, &[10, 20, 30]);
                plan.vault = PaymentVault::Root;
                plan
            })
            .collect();
        assert_eq!(earliest_quote(&plans), 1_800_000_000);
        let wave = root_payment::wave_of(&plans).unwrap();
        let quotes = root_payment::wave_quotes(&wave);
        let total = quotes
            .iter()
            .fold(ant_protocol::evm::Amount::ZERO, |sum, q| sum + q.2);
        let own = ant_protocol::evm::TxHash::from([0x0a; 32]);
        let recording = ant_protocol::evm::TxHash::from([0x0b; 32]);

        let elsewhere = root_wave_payment(&quotes, own, recording, wave.clone(), total, 7);
        assert!(elsewhere.amount.is_zero(), "no tokens of this payment's");
        assert_eq!(elsewhere.gas, 7, "its own transaction's gas was spent");
        assert_eq!(elsewhere.transactions.len(), quotes.len());
        assert!(elsewhere.transactions.values().all(|tx| *tx == recording));
        let root = elsewhere.root.as_ref().unwrap();
        assert_eq!(root.transaction, recording);
        for plan in &plans {
            let proof = ant_protocol::payment::deserialize_root_proof(
                &root_payment::root_proof(plan, root).unwrap(),
            )
            .unwrap();
            assert_eq!(proof.payment.tx_hashes, vec![recording]);
        }
        super::super::upload::validate_payment_total(&plans, &elsewhere).unwrap();

        let own_wave = root_wave_payment(&quotes, own, own, wave, total, 7);
        assert_eq!(own_wave.amount, total);
        assert!(own_wave.transactions.values().all(|tx| *tx == own));
        assert_eq!(own_wave.root.unwrap().transaction, own);
    }

    /// A root wave whose own confirmed transaction found the wave already
    /// recorded, and whose recording transaction can't be looked up, fails
    /// with its journal kept, nothing prepared or sent; the retry settles
    /// the same journaled transaction again, sending and preparing nothing,
    /// and once the lookup answers, its proofs name the recording
    /// transaction and it moved no tokens.
    #[tokio::test]
    async fn a_root_waves_failed_recording_lookup_keeps_its_journal_and_pays_nothing_again() {
        use crate::data::client::listings::test_chain::{serve, MockChain};
        use alloy::consensus::{SignableTransaction as _, TxEip1559, TxEnvelope};
        use alloy::eips::eip2718::Encodable2718 as _;
        use alloy::network::TxSignerSync as _;
        use alloy::sol_types::SolCall as _;
        use ant_listings::{root::ROOT_PAID_TOPIC, PaymentLog};
        use ant_protocol::evm::contract::payment_vault::interface::IPaymentVault;
        use std::sync::{Arc, Mutex};

        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        const CHAIN: u64 = 31_337;
        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let vault: [u8; 20] = root.0 .0;
        // 100 blocks two seconds apart, up to now; quoted at block 50's time.
        let now = crate::runtime::system_time()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = now - 200;
        let mut plan = signed_plan(
            [9; 32],
            1024,
            std::time::UNIX_EPOCH + Duration::from_secs(start + 100),
        );
        plan.vault = PaymentVault::Root;
        let plans = vec![plan];
        let wave = root_payment::wave_of(&plans).unwrap();
        let key = wave.key(&vault);
        let quotes = root_payment::wave_quotes(&wave);

        // The journaled transaction: the wave's payment, signed by the
        // client's key for the root vault.
        let payments: Vec<IPaymentVault::DataPayment> =
            quotes.iter().map(|quote| (*quote).into()).collect();
        let mut tx = TxEip1559 {
            chain_id: CHAIN,
            gas_limit: 100_000,
            max_fee_per_gas: 1,
            to: alloy::primitives::TxKind::Call(root),
            input: IPaymentVault::payForQuotesCall::new((payments,))
                .abi_encode()
                .into(),
            ..TxEip1559::default()
        };
        let signer: alloy::signers::local::PrivateKeySigner = KEY.parse().unwrap();
        let signature = signer.sign_transaction_sync(&mut tx).unwrap();
        let envelope = TxEnvelope::from(tx.into_signed(signature));
        let own = *envelope.tx_hash();
        let signed: SignedPayment =
            serde_json::from_value(serde_json::json!({ "raw": envelope.encoded_2718() })).unwrap();

        // Its own transaction succeeded in block 90 and recorded nothing;
        // another recorded the wave in block 60.
        let recording = ant_protocol::evm::TxHash::from([0x0b; 32]);
        let mut chain = MockChain::with_blocks(100, start);
        chain.chain_id = CHAIN;
        chain.root_records.insert(key);
        chain.add_receipt(ant_listings::PaymentReceipt {
            tx_hash: own.0,
            success: true,
            block_number: 90,
            logs: Vec::new(),
        });
        chain.add_receipt(ant_listings::PaymentReceipt {
            tx_hash: recording.0,
            success: true,
            block_number: 60,
            logs: vec![PaymentLog {
                address: vault,
                topics: vec![ROOT_PAID_TOPIC, key],
                data: vec![0; 96],
                log_index: 0,
            }],
        });
        chain.failing = vec![("eth_getLogs", -32_603)];
        let chain = Arc::new(Mutex::new(chain));
        let url = serve(Arc::clone(&chain)).await;
        let net = Network::Custom(ant_protocol::evm::CustomNetwork {
            rpc_url_http: url.parse().unwrap(),
            payment_token_address: [0x11; 20].into(),
            payment_vault_address: [0x22; 20].into(),
        });
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_from_private_key(net.clone(), KEY).unwrap())
            .with_root_payments(
                Wallet::new_from_private_key(crate::config::network_paying(&net, root), KEY)
                    .unwrap(),
            )
            .unwrap();
        let mut state = UploadState::default();
        state.prepare(plans[0].clone());
        state.start_payment(false, vec![plans[0].address]).unwrap();
        set_journal(&mut state, &Journal::Signed(signed)).unwrap();
        let adapter = Counting::default();
        let nothing_prepared_or_sent = |from: usize| {
            let calls = chain.lock().unwrap().calls[from..].to_vec();
            assert!(
                !calls.iter().any(|method| method.starts_with("eth_send")
                    || method == "eth_getTransactionCount"
                    || method == "eth_estimateGas"),
                "{calls:?}"
            );
            assert!(
                calls
                    .iter()
                    .any(|method| method == "eth_getTransactionReceipt"),
                "{calls:?}"
            );
        };

        let error = pay_root(&client, &adapter, &plans, &mut state)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("search for its RootPaid log failed"),
            "{error}"
        );
        assert!(error.contains("Don't delete"), "{error}");
        let Journal::Signed(kept) = journal_of(&state).unwrap() else {
            panic!("the journal is kept")
        };
        assert_eq!(journaled_hash(&kept).unwrap(), own);
        nothing_prepared_or_sent(0);

        let retried = chain.lock().unwrap().calls.len();
        chain.lock().unwrap().failing.clear();
        let payment = pay_root(&client, &adapter, &plans, &mut state)
            .await
            .unwrap();
        nothing_prepared_or_sent(retried);
        assert!(payment.amount.is_zero(), "no tokens of this payment's");
        assert!(payment.transactions.values().all(|tx| *tx == recording));
        assert_eq!(payment.root.unwrap().transaction, recording);
    }

    /// A root wave whose own transaction reverted or was replaced, and
    /// which the vault records by another, ends as paid: its receipt names
    /// the payment's own transaction and moved no tokens, and [`pay_root`]
    /// then names the recording transaction found by its `RootPaid` log.
    #[test]
    fn a_root_wave_recorded_elsewhere_names_its_own_transaction() {
        use alloy::consensus::TxEnvelope;
        use alloy::eips::eip2718::Decodable2718 as _;
        let signed = journaled_paying(ant_protocol::evm::Address::from([0x33; 20]));
        let raw: Vec<u8> =
            serde_json::from_value(serde_json::to_value(&signed).unwrap()["raw"].clone()).unwrap();
        let expected = *TxEnvelope::decode_2718(&mut raw.as_slice())
            .unwrap()
            .tx_hash();
        let transaction = journaled_hash(&signed).unwrap();
        assert_eq!(transaction, expected);
        let receipt = recorded_elsewhere(transaction);
        assert_eq!(receipt.transaction_hash, transaction);
        assert!(receipt.amount.is_zero());
        assert_eq!(receipt.gas_cost_wei, 0);
        assert!(receipt.winner_pool.is_none());
    }

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

    /// An adapter that keeps nothing, counts its checkpoints, and pays
    /// nothing.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);

    #[async_trait::async_trait]
    impl UploadAdapter for Counting {
        async fn load(&self, _: UploadRecord) -> Result<bytes::Bytes> {
            Err(Error::InvalidData("no bytes".into()))
        }
        async fn pay(&self, _: &[ChunkPaymentPlan]) -> Result<UploadPayment> {
            panic!("nothing may be paid")
        }
        async fn checkpoint(&self, _: &UploadState, _: Option<&UploadPayment>) -> Result<()> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    /// A root payment that sent nothing, on a client without a root vault's
    /// wallet, ends without paying: its records are quoted again for the
    /// per-quote vault. One whose transaction is journaled keeps its
    /// journal, for a client paying the root vault to reconcile.
    #[tokio::test]
    async fn an_unsent_root_payment_ends_on_a_client_without_a_root_wallet() {
        const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_from_private_key(network(1), KEY).unwrap());
        let now = crate::runtime::system_time();
        let mut plan = signed_plan([7; 32], 1024, now);
        plan.vault = PaymentVault::Root;
        let pending = |journal: Option<Journal>| {
            let mut state = UploadState::default();
            state.prepare(plan.clone());
            state.start_payment(false, vec![plan.address]).unwrap();
            match journal {
                Some(journal) => set_journal(&mut state, &journal).unwrap(),
                None => initialize(state.pending_payment.as_mut().unwrap()),
            }
            state
        };

        let mut state = pending(None);
        let adapter = Counting::default();
        let error = pay_shared(&client, &adapter, std::slice::from_ref(&plan), &mut state)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("nothing was sent"), "{error}");
        assert!(state.pending_payment.is_none());
        assert_eq!(adapter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        let kept = state
            .retained_plan(&plan.address, plan.data_size, now)
            .unwrap();
        assert!(!crate::data::client::upload::keeps_retained_plan(
            &state,
            &kept,
            client.payment_vault()
        ));

        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let mut state = pending(Some(Journal::Signed(journaled_paying(root))));
        let error = pay_shared(&client, &adapter, std::slice::from_ref(&plan), &mut state)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("journal is kept"), "{error}");
        assert!(state.pending_payment.is_some());
        let kept = state
            .retained_plan(&plan.address, plan.data_size, now)
            .unwrap();
        assert!(crate::data::client::upload::keeps_retained_plan(
            &state,
            &kept,
            client.payment_vault()
        ));
    }

    /// A member whose journal names only its shared wave, the wave's file
    /// gone (as an aged one once was removed), is never paid afresh while
    /// the vault records its quotes as paid, or can't be read: its journal
    /// is kept and nothing is signed or sent. Only when none is recorded
    /// does it start afresh.
    #[tokio::test]
    async fn a_member_whose_waves_file_is_gone_never_pays_again() {
        use crate::data::client::listings::test_chain::{serve, MockChain, VAULT};
        use ant_protocol::evm::CustomNetwork;
        use std::sync::{Arc, Mutex};

        let address = [6u8; 32];
        // Quoted long ago: a member that starts afresh finds its quotes
        // expired before it joins a wave, so nothing is signed for it.
        let plan = signed_plan(
            address,
            1024,
            std::time::UNIX_EPOCH + Duration::from_secs(1_000_000),
        );
        let quote = plan
            .payment
            .quotes
            .iter()
            .find(|quote| !quote.amount.is_zero())
            .unwrap()
            .clone();
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&quote.rewards_address.as_slice()[..16]);
        let paid = (quote.quote_hash.0, (prefix, quote.amount.to::<u128>()));
        let wave = hex::encode(rand::random::<[u8; 32]>());
        // (the vault's records, whether it refuses reads, whether the
        // journal is kept)
        for (records, refused, kept) in [
            (vec![paid], false, true),
            (Vec::new(), true, true),
            (Vec::new(), false, false),
        ] {
            let chain = MockChain {
                vault_records: records.into_iter().collect(),
                refused: if refused {
                    vec!["eth_call"]
                } else {
                    Vec::new()
                },
                ..MockChain::default()
            };
            let chain = Arc::new(Mutex::new(chain));
            let url = serve(Arc::clone(&chain)).await;
            let node = crate::data::Network::unstarted(&[], true, false)
                .await
                .unwrap();
            let client = Client::from_node(Arc::clone(node.node()), Default::default())
                .with_wallet(Wallet::new_with_random_wallet(Network::Custom(
                    CustomNetwork {
                        rpc_url_http: url.parse().unwrap(),
                        payment_token_address: [0x11; 20].into(),
                        payment_vault_address: VAULT.into(),
                    },
                )));
            let mut state = UploadState::default();
            state.prepare(plan.clone());
            state.start_payment(false, vec![address]).unwrap();
            set_journal(&mut state, &Journal::Wave(wave.clone())).unwrap();
            let adapter = Counting::default();
            let error = pay_shared(&client, &adapter, std::slice::from_ref(&plan), &mut state)
                .await
                .unwrap_err()
                .to_string();
            let calls = chain.lock().unwrap().calls.clone();
            assert!(
                !calls.iter().any(|method| method.starts_with("eth_send")
                    || method == "eth_getTransactionCount"
                    || method == "eth_estimateGas"),
                "{calls:?}"
            );
            if kept {
                assert!(error.contains("Don't delete"), "{error}");
                assert!(
                    matches!(journal_of(&state).unwrap(), Journal::Wave(ref id) if *id == wave),
                    "the journal is kept"
                );
                assert_eq!(adapter.0.load(std::sync::atomic::Ordering::Relaxed), 0);
            } else {
                assert!(error.contains("expired"), "{error}");
                assert!(state.pending_payment.is_none());
            }
        }
    }

    /// While a caller sharing the client's wallet holds its own lock
    /// (`Wallet::lock`), a shared wave's lead waits for it, holding the
    /// key's lock as it waits: the wallet's lock is taken inside the key's,
    /// as in `execute_once`. Once the wallet's lock is free, the lead goes
    /// on (here to end a wave every payment left).
    #[tokio::test]
    async fn a_waves_lead_takes_the_wallets_lock_inside_the_keys() {
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        // A key of its own, so no other test holds its locks.
        let client = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_with_random_wallet(network(1)));
        let wallet = client.require_wallet().unwrap();
        let member = client.shared_waves().join(1);
        member.ready(Vec::new());

        let held = wallet.lock().await;
        let signing = root_payment::signing_lock(wallet.address());
        let (waited, ()) = futures::join!(
            tokio::time::timeout(Duration::from_millis(300), lead(&client, wallet, &member)),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(
                    signing.try_lock().is_err(),
                    "the lead holds the key's lock while it waits for the wallet's"
                );
            }
        );
        assert!(waited.is_err(), "the lead waits for the wallet's lock");
        assert!(
            signing.try_lock().is_ok(),
            "and lets the key's go when stopped"
        );

        drop(held);
        tokio::time::timeout(Duration::from_secs(5), lead(&client, wallet, &member))
            .await
            .expect("the lead goes on once the wallet's lock is free");
        match tokio::time::timeout(Duration::from_secs(5), member.next())
            .await
            .expect("the wave ended")
        {
            Step::Ended(ended) => assert!(matches!(ended.ended, WaveEnd::NotSent(_))),
            Step::Save(..) => panic!("nothing was signed"),
        }
    }

    /// While a caller sharing the client's wallet holds its own lock
    /// (`Wallet::lock`), reconciling a shared wave waits for it, holding the
    /// key's lock as it waits, before it reads the wave or checkpoints: the
    /// wave's transaction may be sent again. Once the wallet's lock is free,
    /// it goes on (here a wave whose file is gone and whose quotes the vault
    /// doesn't record starts afresh).
    #[tokio::test]
    async fn reconciling_a_wave_takes_the_wallets_lock_inside_the_keys() {
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(std::sync::Arc::clone(node.node()), Default::default())
            .with_wallet(Wallet::new_with_random_wallet(network(1)));
        let wallet = client.require_wallet().unwrap();
        let wave = hex::encode(rand::random::<[u8; 32]>());
        let adapter = Counting::default();
        let mut state = UploadState::default();
        let fresh = |_: &UploadState| true;

        let held = wallet.lock().await;
        let signing = root_payment::signing_lock(wallet.address());
        let (waited, ()) = futures::join!(
            tokio::time::timeout(
                Duration::from_millis(300),
                reconcile_wave(&client, &adapter, &wave, None, &[], &mut state, &fresh),
            ),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert!(
                    signing.try_lock().is_err(),
                    "reconciling holds the key's lock while it waits for the wallet's"
                );
            }
        );
        assert!(waited.is_err(), "reconciling waits for the wallet's lock");
        assert_eq!(adapter.0.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(
            signing.try_lock().is_ok(),
            "and lets the key's go when stopped"
        );

        drop(held);
        let reconciled = tokio::time::timeout(
            Duration::from_secs(5),
            reconcile_wave(&client, &adapter, &wave, None, &[], &mut state, &fresh),
        )
        .await
        .expect("reconciling goes on once the wallet's lock is free")
        .unwrap();
        assert!(reconciled.is_none(), "nothing was signed: it starts afresh");
        assert_eq!(adapter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// An external payer's payment of root plans, which names no wave, is
    /// settled from the chain ([`outside_root_payment`]):
    ///
    /// - the wave recorded by the payer's own transaction: every record's
    ///   root proof names it, with the wave's total;
    /// - the wave recorded first by another transaction, the payer's own
    ///   recording nothing: the proofs name the recording transaction, and
    ///   the payment moved no tokens, so nothing is paid twice;
    /// - no wave, and the per-quote vault records every quote (the request
    ///   paid there): the plans pay the per-quote vault from then on, in the
    ///   upload's state too, and get single-node proofs from the payer's
    ///   transactions;
    /// - neither: an error that pays nothing again and keeps the payment
    ///   pending.
    ///
    /// A payment of the per-quote vault's plans, or one naming its wave, is
    /// left as it is, without a read.
    #[tokio::test]
    async fn an_outside_payers_root_wave_is_settled_from_the_chain() {
        use crate::data::client::listings::test_chain::{serve, MockChain, VAULT};
        use ant_listings::{root::ROOT_PAID_TOPIC, PaymentLog};
        use ant_protocol::payment::{detect_proof_type, ProofType};
        use std::sync::{Arc, Mutex};

        /// A client reading `chain` through the per-quote vault [`VAULT`],
        /// naming `root` as its root vault and holding no root vault's
        /// wallet, and an upload's state with `plans` pending in a payment.
        async fn settle(
            node: &crate::data::Network,
            chain: MockChain,
            plans: &[ChunkPaymentPlan],
            root: ant_protocol::evm::Address,
        ) -> (
            Client,
            Vec<ChunkPaymentPlan>,
            UploadState,
            Arc<Mutex<MockChain>>,
        ) {
            let mut chain = chain;
            chain.chain_id = 31_337;
            let chain = Arc::new(Mutex::new(chain));
            let url = serve(Arc::clone(&chain)).await;
            let net = Network::Custom(ant_protocol::evm::CustomNetwork {
                rpc_url_http: url.parse().unwrap(),
                payment_token_address: [0x11; 20].into(),
                payment_vault_address: VAULT.into(),
            });
            let client = Client::from_node(Arc::clone(node.node()), Default::default())
                .with_evm_network(net)
                .with_root_vault(root);
            assert!(client.root_wallet().is_none(), "no root vault's wallet");
            let mut state = UploadState::default();
            for plan in plans {
                state.prepare(plan.clone());
            }
            state
                .start_payment(false, plans.iter().map(|plan| plan.address).collect())
                .unwrap();
            (client, plans.to_vec(), state, chain)
        }

        let root = ant_protocol::evm::Address::from([0x33; 20]);
        let vault: [u8; 20] = root.0 .0;
        let now = crate::runtime::system_time()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = now - 200;
        let quoted = std::time::UNIX_EPOCH + Duration::from_secs(start + 100);
        let plans = (1u8..=3)
            .map(|n| {
                let mut plan = signed_plan([n; 32], 1024, quoted);
                plan.vault = PaymentVault::Root;
                plan
            })
            .collect::<Vec<_>>();
        let wave = root_payment::wave_of(&plans).unwrap();
        let key = wave.key(&vault);
        let total = plans
            .iter()
            .fold(ant_protocol::evm::Amount::ZERO, |sum, plan| {
                sum + plan.payment.total_amount()
            });
        let own = ant_protocol::evm::TxHash::from([0x0a; 32]);
        let recording = ant_protocol::evm::TxHash::from([0x0b; 32]);
        let root_paid = |tx: ant_protocol::evm::TxHash, block| ant_listings::PaymentReceipt {
            tx_hash: tx.0,
            success: true,
            block_number: block,
            logs: vec![PaymentLog {
                address: vault,
                topics: vec![ROOT_PAID_TOPIC, key],
                data: vec![0; 96],
                log_index: 0,
            }],
        };
        let paid_by = |tx| UploadPayment {
            transactions: plans
                .iter()
                .flat_map(|plan| plan.payment.quotes.iter())
                .map(|quote| (quote.quote_hash, tx))
                .collect(),
            amount: total,
            gas: 3,
            root: None,
        };
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let addresses = plans.iter().map(|plan| plan.address).collect::<Vec<_>>();

        // Recorded by the payer's own transaction.
        let mut chain = MockChain::with_blocks(100, start);
        chain.root_records.insert(key);
        chain.add_receipt(root_paid(own, 80));
        let (client, mut paying, mut state, _) = settle(&node, chain, &plans, root).await;
        let payment = outside_root_payment(&client, &mut paying, &mut state, paid_by(own))
            .await
            .unwrap();
        assert_eq!(payment.amount, total);
        assert_eq!(payment.gas, 3);
        assert_eq!(payment.root.as_ref().unwrap().transaction, own);
        super::super::upload::validate_payment_total(&paying, &payment).unwrap();
        state
            .confirm_payment(&addresses, &payment, crate::runtime::system_time())
            .unwrap();
        for address in &addresses {
            let proof = state.proof(address).unwrap();
            assert_eq!(detect_proof_type(proof), Some(ProofType::Root));
            let proof = ant_protocol::payment::deserialize_root_proof(proof).unwrap();
            assert_eq!(proof.payment.tx_hashes, vec![own]);
        }
        assert!(state.pending_payment.is_none());

        // Recorded first by another: the payer's own transaction recorded
        // nothing, and moved nothing.
        let mut chain = MockChain::with_blocks(100, start);
        chain.root_records.insert(key);
        chain.add_receipt(ant_listings::PaymentReceipt {
            tx_hash: own.0,
            success: true,
            block_number: 90,
            logs: Vec::new(),
        });
        chain.add_receipt(root_paid(recording, 60));
        let (client, mut paying, mut state, chain) = settle(&node, chain, &plans, root).await;
        let payment = outside_root_payment(&client, &mut paying, &mut state, paid_by(own))
            .await
            .unwrap();
        assert!(payment.amount.is_zero(), "nothing of this payment's moved");
        assert_eq!(payment.root.as_ref().unwrap().transaction, recording);
        assert!(payment.transactions.values().all(|tx| *tx == recording));
        super::super::upload::validate_payment_total(&paying, &payment).unwrap();
        state
            .confirm_payment(&addresses, &payment, crate::runtime::system_time())
            .unwrap();
        for address in &addresses {
            let proof = state.proof(address).unwrap();
            let proof = ant_protocol::payment::deserialize_root_proof(proof).unwrap();
            assert_eq!(proof.payment.tx_hashes, vec![recording]);
        }
        let calls = chain.lock().unwrap().calls.clone();
        assert!(
            !calls.iter().any(|method| method.starts_with("eth_send")),
            "{calls:?}"
        );

        // Paid at the per-quote vault: single-node proofs.
        let mut chain = MockChain::with_blocks(100, start);
        for plan in &plans {
            for quote in &plan.payment.quotes {
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&quote.rewards_address.as_slice()[..16]);
                let amount = quote.amount.to::<u128>();
                chain
                    .vault_records
                    .insert(quote.quote_hash.0, (prefix, amount));
            }
        }
        let (client, mut paying, mut state, _) = settle(&node, chain, &plans, root).await;
        let payment = outside_root_payment(&client, &mut paying, &mut state, paid_by(own))
            .await
            .unwrap();
        assert!(payment.root.is_none());
        assert_eq!(payment.amount, total);
        assert!(paying.iter().all(|plan| plan.vault.is_v2()));
        super::super::upload::validate_payment_total(&paying, &payment).unwrap();
        state
            .confirm_payment(&addresses, &payment, crate::runtime::system_time())
            .unwrap();
        for address in &addresses {
            let proof = state.proof(address).unwrap();
            assert_eq!(detect_proof_type(proof), Some(ProofType::SingleNode));
        }

        // Neither: nothing is paid again, and the payment stays pending.
        let (client, mut paying, mut state, chain) =
            settle(&node, MockChain::with_blocks(100, start), &plans, root).await;
        let error = outside_root_payment(&client, &mut paying, &mut state, paid_by(own))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("nothing is paid again"), "{error}");
        assert!(error.contains("Don't delete"), "{error}");
        assert!(state.pending_payment.is_some());
        assert!(paying.iter().all(|plan| plan.vault == PaymentVault::Root));
        let calls = chain.lock().unwrap().calls.clone();
        assert!(
            !calls.iter().any(|method| method.starts_with("eth_send")),
            "{calls:?}"
        );

        // A payment of the per-quote vault, or naming its wave, is left
        // alone, read nowhere.
        let (client, mut paying, mut state, chain) =
            settle(&node, MockChain::with_blocks(100, start), &plans, root).await;
        let mut v2 = vec![signed_plan([7; 32], 1024, quoted)];
        let kept = outside_root_payment(&client, &mut v2, &mut state, paid_by(own))
            .await
            .unwrap();
        assert!(kept.root.is_none());
        let mut named = paid_by(own);
        named.root = Some(RootWavePayment {
            transaction: own,
            wave: wave.clone(),
        });
        let kept = outside_root_payment(&client, &mut paying, &mut state, named)
            .await
            .unwrap();
        assert_eq!(kept.root.unwrap().transaction, own);
        assert!(chain.lock().unwrap().calls.is_empty());
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
