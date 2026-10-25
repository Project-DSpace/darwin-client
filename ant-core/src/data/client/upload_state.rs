// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable prepared/paid upload state. Storage and wallet adapters own persistence and I/O.
//!
//! # The checkpoint's format
//!
//! A checkpoint starts with [`CHECKPOINT_MAGIC`] and [`CHECKPOINT_FORMAT`],
//! followed by its body in msgpack. Proofs are kept as byte strings, not as
//! arrays of integers. An older client parses a whole checkpoint as msgpack,
//! where the magic's first byte reads as an integer, so its parse fails and
//! its upload stops with an error instead of paying again.
//!
//! A checkpoint written before the magic, a msgpack [`UploadState`], is still
//! read: native files are migrated to the new format when they are opened
//! (`upload_checkpoint`), and a browser's JSON snapshot is read as it is.
//!
//! # Restoring a saved plan
//!
//! A saved plan's quotes must be signed by the nodes they name. Its amounts
//! must equal one of exactly two recomputations from those signed quotes:
//! the full amount (3 × the median quote), or the weighted amount for the
//! size class of the plan's own `data_size` (`weighted_amount` with
//! `record_weight`; a pointer's plan is sized at its 5,303 bytes, which is in
//! a pointer's own class). Never a range. So a checkpoint saved by a client
//! paying either way restores, on either side of the pricing switch.
//!
//! A plan that matches neither and that no pending payment names is dropped,
//! and its record quoted again. A plan named by a pending payment may have
//! been shown to a payer: it is never dropped, and the whole checkpoint is
//! refused instead. So is a checkpoint with a bad signature or identity.
//!
//! # Paid proofs
//!
//! A paid single-node proof has no age limit: it is kept until its record is
//! stored. The upload decides whether to reuse it by where its paid node
//! stands in a fresh lookup, and by whether storers take it, never by its
//! age. An unpaid plan keeps its age limit ([`UploadState::retained_plan`]),
//! and a Merkle proof its one-week check.

use super::batch::{
    build_plan_proof, proof_is_safely_fresh, ChunkPaymentPlan, PaidChunk, PreparedChunk,
    SingleNodeQuotePayment,
};
use crate::data::error::{Error, Result};
use ant_protocol::{
    evm::{QuoteHash, TxHash},
    payment::deserialize_proof,
    XorName,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

/// What a checkpoint in this format starts with.
pub const CHECKPOINT_MAGIC: [u8; 4] = *b"DSCK";

/// The largest browser snapshot a browser upload saves or reads.
#[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
pub(crate) const MAX_BROWSER_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;

/// A browser snapshot as the page hands it back: text, as this client gives
/// it ([`UploadState::snapshot_text`]) or as the browser client before
/// [`CHECKPOINT_MAGIC`] gave it, or the snapshot's bytes.
#[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum BrowserSnapshot<'a> {
    /// What [`UploadState::snapshot`] gives.
    Bytes(&'a [u8]),
    /// What [`UploadState::snapshot_text`] gives: those bytes as base64, or
    /// as hex in either case; or `{"scope", "state"}`, the state a hex
    /// msgpack [`UploadState`], as the browser client before
    /// [`CHECKPOINT_MAGIC`] gave it.
    Text(&'a str),
}

/// Why a browser snapshot given as text was refused: it is neither the text
/// this client gives nor the JSON the client before it gave.
#[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
pub(crate) const SNAPSHOT_TEXT_REFUSED: &str =
    "an upload checkpoint given as text must be the text on_checkpoint gave (base64), its \
     bytes as hex, or the JSON an earlier client gave; text such as Uint8Array.toString()'s \
     is not accepted: pass the text on_checkpoint gave, or the checkpoint's bytes as a \
     Uint8Array";

/// The format version that follows [`CHECKPOINT_MAGIC`].
pub const CHECKPOINT_FORMAT: u8 = 1;

/// How long the proofs of an upload that is never resumed are kept: a
/// checkpoint, or a cached receipt, untouched for this long, and holding no
/// pending payment, is removed. Claude's proposal (2026-10-24): paid proofs
/// are kept until stored, and this bounds what a client keeps for uploads
/// abandoned for good.
pub const UNRESUMED_PROOFS_BACKSTOP: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A payment may have reached the wallet or chain. Never submit it again merely
/// because receipt parsing or observation failed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAttempt {
    /// True for a prepared Merkle transaction.
    pub merkle: bool,
    /// Records bound to the prepared single-payment intent.
    pub addresses: Vec<XorName>,
    /// Wallet submission evidence retained before awaiting confirmation.
    #[serde(default)]
    pub submissions: Vec<serde_json::Value>,
    /// Unparsed wallet result, retained even if validation later fails.
    pub receipt: Option<serde_json::Value>,
}

/// Evidence retained when an explicit wallet verifier establishes terminal failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FailedPaymentAttempt {
    attempt: PaymentAttempt,
    resolution: serde_json::Value,
}

/// Each proof put into any [`UploadState`] gets the next serial, so a file
/// that keeps proofs apart (`upload_checkpoint`) can tell which it has
/// written without comparing their bytes.
static NEXT_PROOF_SERIAL: AtomicU64 = AtomicU64::new(1);

fn next_proof_serial() -> u64 {
    NEXT_PROOF_SERIAL.fetch_add(1, Ordering::Relaxed)
}

/// Prepared plans and confirmed proofs keyed by content address.
/// Checkpoints contain no file bytes or wallet secrets.
///
/// Its serde form is the checkpoint format before [`CHECKPOINT_MAGIC`],
/// which is only read now: [`UploadState::checkpoint`] writes the new one.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadState {
    plans: HashMap<XorName, ChunkPaymentPlan>,
    proofs: HashMap<XorName, Vec<u8>>,
    /// The serial of each proof ([`next_proof_serial`]); never saved.
    #[serde(skip)]
    proof_serials: HashMap<XorName, u64>,
    #[serde(default)]
    pub(crate) pending_merkle: Option<super::merkle::PreparedMerkleBatch>,
    /// Submission journal; an unresolved attempt must be reconciled before another payment.
    #[serde(default)]
    pub pending_payment: Option<PaymentAttempt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    failed_payments: Vec<FailedPaymentAttempt>,
    /// The records paid again because every storer refused a kept proof
    /// ([`Self::mark_paid_again`]): never more than once each, whatever
    /// the number of runs.
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    paid_again: HashSet<XorName>,
    /// The records this run paid for, at once, again, or by settling a
    /// payment an earlier run journaled ([`Self::paid_this_run`]); never
    /// saved, so a new process starts with none.
    #[serde(skip)]
    paid_this_run: HashSet<XorName>,
}

/// A checkpoint's body, as written after the magic and format.
#[derive(Serialize)]
struct BodyOut<'a> {
    /// What the checkpoint is for: a browser snapshot's file and payment
    /// network. Native files are named by it instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    plans: &'a HashMap<XorName, ChunkPaymentPlan>,
    /// Kept apart in a native file's proof file, so empty there.
    proofs: HashMap<&'a XorName, &'a serde_bytes::Bytes>,
    pending_merkle: &'a Option<super::merkle::PreparedMerkleBatch>,
    pending_payment: &'a Option<PaymentAttempt>,
    failed_payments: &'a [FailedPaymentAttempt],
    #[serde(skip_serializing_if = "no_address")]
    paid_again: &'a HashSet<XorName>,
    /// A native file's proof file's length, up to its last whole record,
    /// when this was written: a proof file found missing or shorter when
    /// the checkpoint is opened lost proofs, and the checkpoint is refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    proofs_len: Option<u64>,
}

fn no_address(addresses: &&HashSet<XorName>) -> bool {
    addresses.is_empty()
}

/// [`BodyOut`], read back.
#[derive(Deserialize)]
struct BodyIn {
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    plans: HashMap<XorName, ChunkPaymentPlan>,
    #[serde(default)]
    proofs: HashMap<XorName, serde_bytes::ByteBuf>,
    #[serde(default)]
    pending_merkle: Option<super::merkle::PreparedMerkleBatch>,
    #[serde(default)]
    pending_payment: Option<PaymentAttempt>,
    #[serde(default)]
    failed_payments: Vec<FailedPaymentAttempt>,
    #[serde(default)]
    paid_again: HashSet<XorName>,
    #[serde(default)]
    proofs_len: Option<u64>,
}

/// A checkpoint as read, before it is checked ([`UploadState::validated`]).
pub(crate) struct Parsed {
    /// What it holds.
    pub(crate) state: UploadState,
    /// A browser snapshot's scope.
    #[cfg_attr(
        not(any(test, all(target_arch = "wasm32", feature = "browser-wasm"))),
        allow(dead_code)
    )]
    pub(crate) scope: Option<String>,
    /// Whether it was in the format before [`CHECKPOINT_MAGIC`].
    pub(crate) legacy: bool,
    /// How long a native file's proof file was, up to its last whole
    /// record, when the checkpoint was written; `None` if unrecorded (a
    /// browser snapshot, or a file written before the length was).
    #[cfg_attr(not(feature = "native"), allow(dead_code))]
    pub(crate) proofs_len: Option<u64>,
}

/// The bytes of a browser snapshot given as text: base64 (what
/// [`UploadState::snapshot_text`] gives) or hex in either case, decoded to
/// bytes that start with [`CHECKPOINT_MAGIC`]. `None` for any other text.
#[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
fn decode_snapshot_text(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()
        .filter(|bytes| bytes.starts_with(&CHECKPOINT_MAGIC))
        .or_else(|| {
            hex::decode(text)
                .ok()
                .filter(|bytes| bytes.starts_with(&CHECKPOINT_MAGIC))
        })
}

/// Native proof expiry, shared by every client adapter.
///
/// A paid single-node proof is reusable whatever its age, as long as it is
/// one for `address`: it is kept until its record is stored. A Merkle proof
/// keeps its one-week check.
pub fn reusable_proof(address: &XorName, bytes: &[u8], now: SystemTime) -> bool {
    if let Ok(proof) = ant_protocol::payment::deserialize_merkle_proof(bytes) {
        return proof.address.0 == *address
            && proof.data_proof.verify()
            && proof.data_proof.root() == proof.winner_pool.midpoint_proof.root()
            && merkle_fresh(
                proof.winner_pool.midpoint_proof.merkle_payment_timestamp,
                now,
            );
    }
    let Ok((proof, _)) = deserialize_proof(bytes) else {
        return false;
    };
    !proof.peer_quotes.is_empty()
        && proof
            .peer_quotes
            .iter()
            .all(|(_, quote)| quote.content.0 == *address)
}

/// The node a single-node proof paid: the issuer of its one quote with a
/// non-zero amount under the single-node rule (the median). `None` for a
/// Merkle proof or one that can't be read.
pub(crate) fn paid_node(bytes: &[u8]) -> Option<[u8; 32]> {
    paid_quote(bytes).map(|(node, _, _)| node)
}

/// The quote a single-node proof paid ([`paid_node`]): its issuer, its hash
/// and its rewards address. `None` for a Merkle proof or one that can't be
/// read.
pub(crate) fn paid_quote(
    bytes: &[u8],
) -> Option<([u8; 32], QuoteHash, ant_protocol::evm::RewardsAddress)> {
    if ant_protocol::payment::deserialize_merkle_proof(bytes).is_ok() {
        return None;
    }
    let (proof, _) = deserialize_proof(bytes).ok()?;
    let payment = SingleNodeQuotePayment::from_quotes(
        proof
            .peer_quotes
            .iter()
            .map(|(_, quote)| quote.clone())
            .collect(),
    )
    .ok()?;
    let paid = payment.quotes.iter().find(|q| !q.amount.is_zero())?;
    proof
        .peer_quotes
        .iter()
        .find(|(_, quote)| quote.hash() == paid.quote_hash)
        .map(|(peer, _)| (*peer.as_bytes(), paid.quote_hash, paid.rewards_address))
}

pub(crate) fn merkle_fresh(timestamp: u64, now: SystemTime) -> bool {
    now.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .is_some_and(|now| {
            timestamp <= now.as_secs()
                && now.as_secs() - timestamp < ant_protocol::evm::MERKLE_PAYMENT_EXPIRATION
        })
}

/// A plan's quote tuples, in order, as compared on restore.
fn quote_tuples(
    quotes: &[ant_protocol::payment::QuotePaymentInfo],
) -> Vec<(
    QuoteHash,
    ant_protocol::evm::RewardsAddress,
    ant_protocol::evm::Amount,
    ant_protocol::evm::Amount,
)> {
    quotes
        .iter()
        .map(|q| (q.quote_hash, q.rewards_address, q.amount, q.price))
        .collect()
}

/// Whether `plan`'s amounts are one of the two recomputations from its
/// signed quotes: the full amount, or the weighted amount for the class of
/// its own `data_size`.
pub(crate) fn plan_amounts_recomputed(plan: &ChunkPaymentPlan) -> bool {
    let Ok(full) = SingleNodeQuotePayment::from_quotes(
        plan.peer_quotes
            .iter()
            .map(|(_, quote)| quote.clone())
            .collect(),
    ) else {
        return false;
    };
    let recorded = quote_tuples(&plan.payment.quotes);
    if recorded == quote_tuples(&full.quotes) {
        return true;
    }
    // A pointer's plan is sized at POINTER_WIRE_LEN, which a chunk of that
    // size shares its class with, so one function covers both.
    let weight = ant_protocol::payment::pricing::record_weight(
        ant_protocol::DATA_TYPE_CHUNK,
        usize::try_from(plan.data_size).unwrap_or(usize::MAX),
    );
    let weighted = full
        .quotes
        .iter()
        .map(|q| {
            let amount = if q.amount.is_zero() {
                Some(q.amount)
            } else {
                ant_protocol::payment::pricing::weighted_amount(q.price, weight)
            };
            amount.map(|amount| (q.quote_hash, q.rewards_address, amount, q.price))
        })
        .collect::<Option<Vec<_>>>();
    weighted.is_some_and(|weighted| weighted == recorded)
}

/// Whether every quote is for `address` and signed by the node its peer id
/// names.
fn quotes_signed_for(
    address: &XorName,
    quotes: &[(
        ant_protocol::evm::EncodedPeerId,
        ant_protocol::evm::PaymentQuote,
    )],
) -> bool {
    quotes.iter().all(|(peer, quote)| {
        quote.content.0 == *address
            && *peer
                == ant_protocol::evm::EncodedPeerId::new(*blake3::hash(&quote.pub_key).as_bytes())
            && ant_protocol::payment::verify_quote_signature(quote)
    })
}

impl UploadState {
    #[cfg(all(target_arch = "wasm32", feature = "browser-wasm"))]
    pub(crate) fn record_failed_payment(&mut self, resolution: serde_json::Value) -> Result<()> {
        let attempt = self
            .pending_payment
            .take()
            .ok_or_else(|| Error::Payment("no pending payment".into()))?;
        self.failed_payments.push(FailedPaymentAttempt {
            attempt,
            resolution,
        });
        Ok(())
    }

    pub(crate) fn start_payment(&mut self, merkle: bool, addresses: Vec<XorName>) -> Result<()> {
        if self.pending_payment.is_some() {
            return Err(Error::Payment(
                "payment outcome unknown; reconcile before submitting again".into(),
            ));
        }
        self.pending_payment = Some(PaymentAttempt {
            merkle,
            addresses,
            submissions: Vec::new(),
            receipt: None,
        });
        Ok(())
    }

    pub(crate) fn pending_plans(&self) -> Result<Vec<ChunkPaymentPlan>> {
        let attempt = self
            .pending_payment
            .as_ref()
            .ok_or_else(|| Error::Payment("no pending payment".into()))?;
        attempt
            .addresses
            .iter()
            .map(|address| {
                self.plans.get(address).cloned().ok_or_else(|| {
                    Error::InvalidData("pending payment is missing its prepared plan".into())
                })
            })
            .collect()
    }

    /// Keep `bytes` as the proof of `address`, replacing any it had.
    fn insert_proof(&mut self, address: XorName, bytes: Vec<u8>) {
        self.proof_serials.insert(address, next_proof_serial());
        self.proofs.insert(address, bytes);
    }

    /// Forget the proof of `address`, so the record is quoted and paid
    /// again: its paid node has left the storers' width, or every storer
    /// refused it. Returns it.
    pub(crate) fn drop_proof(&mut self, address: &XorName) -> Option<Vec<u8>> {
        self.proof_serials.remove(address);
        self.proofs.remove(address)
    }

    /// Record that `address` is being paid again because every storer
    /// refused its kept proof. Saved before the new payment is sent, so a
    /// record is paid again at most once across runs: a refusal of its next
    /// proof is a failure, and the proof is kept.
    pub(crate) fn mark_paid_again(&mut self, address: XorName) {
        self.paid_again.insert(address);
    }

    /// Whether `address` was paid again once already ([`Self::mark_paid_again`]).
    pub(crate) fn was_paid_again(&self, address: &XorName) -> bool {
        self.paid_again.contains(address)
    }

    /// Record that this run paid for `addresses`, at once, again, or by
    /// settling a payment an earlier run journaled: a proof among them that
    /// storers refuse is a failure, never paid for again. Kept for the life
    /// of this state, across every pass an upload makes over it, and never
    /// saved.
    pub(crate) fn add_paid_this_run(&mut self, addresses: impl IntoIterator<Item = XorName>) {
        self.paid_this_run.extend(addresses);
    }

    /// The records this run paid for ([`Self::add_paid_this_run`]).
    pub(crate) fn paid_this_run(&self) -> &HashSet<XorName> {
        &self.paid_this_run
    }

    /// The records paid again once already ([`Self::mark_paid_again`]).
    #[cfg(feature = "native")]
    pub(crate) fn paid_again(&self) -> &HashSet<XorName> {
        &self.paid_again
    }

    /// Mark `addresses` paid again once already, as read from a kept
    /// receipt.
    pub(crate) fn add_paid_again(&mut self, addresses: impl IntoIterator<Item = XorName>) {
        self.paid_again.extend(addresses);
    }

    /// Forget that `address` was paid again: it is stored.
    pub(crate) fn clear_paid_again(&mut self, address: &XorName) {
        self.paid_again.remove(address);
    }

    /// Every proof, with its serial ([`next_proof_serial`]).
    #[cfg(feature = "native")]
    pub(crate) fn proof_entries(&self) -> impl Iterator<Item = (&XorName, &Vec<u8>, u64)> {
        self.proofs.iter().map(|(address, bytes)| {
            (
                address,
                bytes,
                self.proof_serials.get(address).copied().unwrap_or_default(),
            )
        })
    }

    /// The serial of the proof of `address`, if it has one.
    #[cfg(test)]
    pub(crate) fn proof_serial(&self, address: &XorName) -> Option<u64> {
        self.proof_serials.get(address).copied()
    }

    /// The addresses that have a proof.
    #[cfg(test)]
    pub(crate) fn proof_addresses(&self) -> HashSet<XorName> {
        self.proofs.keys().copied().collect()
    }

    /// Give every proof a serial, as after reading them.
    fn renumber(&mut self) {
        self.proof_serials = self
            .proofs
            .keys()
            .map(|address| (*address, next_proof_serial()))
            .collect();
    }

    pub(crate) fn insert_merkle(&mut self, result: super::merkle::MerkleBatchPaymentResult) {
        for (address, bytes) in result.proofs {
            self.insert_proof(address, bytes);
        }
        self.pending_merkle = None;
        self.pending_payment = None;
    }
    pub(crate) fn proof(&self, address: &XorName) -> Option<&Vec<u8>> {
        self.proofs.get(address)
    }

    #[cfg(feature = "native")]
    pub(crate) fn proofs(&self) -> &HashMap<XorName, Vec<u8>> {
        &self.proofs
    }

    /// Confirm a native prepared chunk through the same state transition as browser checkpoints.
    pub(super) fn pay_prepared(
        chunk: PreparedChunk,
        transactions: &HashMap<QuoteHash, TxHash>,
    ) -> Result<PaidChunk> {
        let mut state = Self::default();
        state.prepare(ChunkPaymentPlan {
            address: chunk.address,
            data_size: chunk.content.len() as u64,
            quoted_peers: chunk.quoted_peers.clone(),
            payment: chunk.payment,
            peer_quotes: chunk.peer_quotes,
            commitment_sidecars: chunk.commitment_sidecars,
        });
        state.confirm(
            &[chunk.address],
            transactions,
            crate::runtime::system_time(),
        )?;
        let proof_bytes = state
            .drop_proof(&chunk.address)
            .ok_or_else(|| Error::Payment("confirmed proof missing".into()))?;
        Ok(PaidChunk {
            content: chunk.content,
            address: chunk.address,
            quoted_peers: chunk.quoted_peers,
            proof_bytes,
        })
    }

    /// Import the same per-content proofs used by native disk receipts.
    pub fn from_proofs(proofs: HashMap<XorName, Vec<u8>>) -> Self {
        let mut state = Self {
            plans: HashMap::new(),
            proofs,
            proof_serials: HashMap::new(),
            pending_merkle: None,
            pending_payment: None,
            failed_payments: Vec::new(),
            paid_again: HashSet::new(),
            paid_this_run: HashSet::new(),
        };
        state.renumber();
        state
    }

    /// Reuse a previously prepared plan after a wallet callback was interrupted.
    /// Paid records are re-discovered so current storage targets replace stale ones.
    ///
    /// An unpaid plan keeps its age limit: its quotes are only an offer.
    pub fn retained_plan(
        &self,
        address: &XorName,
        size: u64,
        now: SystemTime,
    ) -> Option<ChunkPaymentPlan> {
        if self.is_paid(address, now) {
            return None;
        }
        let plan = self.plans.get(address)?;
        if plan.data_size != size || plan.peer_quotes.is_empty() {
            return None;
        }
        let proof = ant_protocol::evm::ProofOfPayment {
            peer_quotes: plan.peer_quotes.clone(),
        };
        proof_is_safely_fresh(
            &proof,
            now,
            Duration::from_secs(
                super::batch::CACHED_PROOF_MAX_AGE_SECS
                    - super::batch::CACHED_PROOF_SAFETY_MARGIN_SECS,
            ),
        )
        .then(|| plan.clone())
    }

    /// Retain a verified plan before invoking an external wallet.
    pub fn prepare(&mut self, plan: ChunkPaymentPlan) {
        self.plans.insert(plan.address, plan);
    }

    /// Whether a confirmed proof that is still usable covers this record:
    /// a single-node one whatever its age, a Merkle one within its week.
    pub fn is_paid(&self, address: &XorName, now: SystemTime) -> bool {
        self.proofs
            .get(address)
            .is_some_and(|bytes| reusable_proof(address, bytes, now))
    }

    /// Bind a confirmed payment to all pending plans, before loading or storing bytes.
    /// Missing transactions fail atomically, preserving the prepared plans for recovery.
    pub fn confirm(
        &mut self,
        addresses: &[XorName],
        transactions: &HashMap<QuoteHash, TxHash>,
        now: SystemTime,
    ) -> Result<()> {
        let proofs = addresses
            .iter()
            .filter(|address| !self.is_paid(address, now))
            .map(|address| {
                let plan = self
                    .plans
                    .get(address)
                    .ok_or_else(|| Error::Payment("missing prepared payment plan".into()))?;
                build_plan_proof(plan, transactions).map(|proof| (*address, proof))
            })
            .collect::<Result<Vec<_>>>()?;
        for (address, proof) in proofs {
            self.insert_proof(address, proof);
        }
        if self.pending_payment.as_ref().is_some_and(|attempt| {
            !attempt.merkle
                && attempt
                    .addresses
                    .iter()
                    .all(|address| self.proofs.contains_key(address))
        }) {
            self.pending_payment = None;
        }
        for address in addresses {
            self.plans.remove(address);
        }
        Ok(())
    }

    /// Take the records whose paid quote turned out to be occupied out of the
    /// pending single payment, and forget their plans, so they are quoted and
    /// paid again. Returns their addresses. The attempt ends once none is left.
    pub(crate) fn release_occupied(
        &mut self,
        occupied: &[super::occupied::OccupiedQuote],
    ) -> Vec<XorName> {
        let mut released = occupied.iter().map(|q| q.address).collect::<Vec<_>>();
        released.sort_unstable();
        released.dedup();
        if let Some(attempt) = self.pending_payment.as_mut().filter(|a| !a.merkle) {
            attempt
                .addresses
                .retain(|address| released.binary_search(address).is_err());
            if attempt.addresses.is_empty() {
                self.pending_payment = None;
            }
        }
        for address in &released {
            self.plans.remove(address);
        }
        released
    }

    /// Attach an existing proof to refreshed native or browser PUT targets.
    pub fn reuse_prepared(&self, prepared: &PreparedChunk, now: SystemTime) -> Option<PaidChunk> {
        let proof_bytes = self.proofs.get(&prepared.address)?;
        if !reusable_proof(&prepared.address, proof_bytes, now) {
            return None;
        }
        Some(PaidChunk {
            content: prepared.content.clone(),
            address: prepared.address,
            quoted_peers: prepared.quoted_peers.clone(),
            proof_bytes: proof_bytes.clone(),
        })
    }

    /// Serialize a local recovery checkpoint, proofs included. Treat it like
    /// a native payment receipt.
    pub fn checkpoint(&self) -> Result<Vec<u8>> {
        self.encode(None, true, None)
    }

    /// A browser's snapshot: the whole checkpoint, with `scope` (its file
    /// and payment network) in it, no larger than
    /// [`MAX_BROWSER_SNAPSHOT_BYTES`].
    #[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
    pub(crate) fn snapshot(&self, scope: &str) -> Result<Vec<u8>> {
        let bytes = self.encode(Some(scope), true, None)?;
        if bytes.len() > MAX_BROWSER_SNAPSHOT_BYTES {
            return Err(Error::InvalidData("upload checkpoint too large".into()));
        }
        Ok(bytes)
    }

    /// A browser's snapshot ([`Self::snapshot`]) as the text a page saves:
    /// its bytes as standard base64, padded.
    #[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
    pub(crate) fn snapshot_text(&self, scope: &str) -> Result<String> {
        use base64::Engine as _;
        Ok(base64::engine::general_purpose::STANDARD.encode(self.snapshot(scope)?))
    }

    /// Read a browser's snapshot, in any form a page hands back
    /// ([`BrowserSnapshot`]): the bytes [`Self::snapshot`] gives, as they
    /// are or as the text [`Self::snapshot_text`] gives (or as hex, in either
    /// case), or the JSON text the browser client before
    /// [`CHECKPOINT_MAGIC`] gave (`{"scope", "state"}`, the state a hex
    /// msgpack [`UploadState`]). No more than
    /// [`MAX_BROWSER_SNAPSHOT_BYTES`] of bytes, after any decoding, and of
    /// JSON. Returns its scope and its state, checked.
    #[cfg(any(test, all(target_arch = "wasm32", feature = "browser-wasm")))]
    pub(crate) fn read_snapshot(snapshot: BrowserSnapshot<'_>) -> Result<(String, Self)> {
        let too_large = || Error::InvalidData("upload checkpoint too large".into());
        let decoded;
        let snapshot = match snapshot {
            BrowserSnapshot::Text(text) if !text.trim_start().starts_with('{') => {
                let text = text.trim();
                // Hex is the longest text form: twice the bytes.
                if text.len() > 2 * MAX_BROWSER_SNAPSHOT_BYTES {
                    return Err(too_large());
                }
                decoded = decode_snapshot_text(text)
                    .ok_or_else(|| Error::InvalidData(SNAPSHOT_TEXT_REFUSED.into()))?;
                BrowserSnapshot::Bytes(&decoded)
            }
            snapshot => snapshot,
        };
        let (scope, parsed) = match snapshot {
            BrowserSnapshot::Bytes(bytes) => {
                if bytes.len() > MAX_BROWSER_SNAPSHOT_BYTES {
                    return Err(too_large());
                }
                let parsed = Self::parse(bytes)?;
                if parsed.legacy {
                    return Err(Error::InvalidData(
                        "an upload checkpoint's bytes must start with its format".into(),
                    ));
                }
                let scope = parsed.scope.clone().ok_or_else(|| {
                    Error::InvalidData("the upload checkpoint names no file".into())
                })?;
                (scope, parsed)
            }
            BrowserSnapshot::Text(text) => {
                if text.len() > MAX_BROWSER_SNAPSHOT_BYTES {
                    return Err(too_large());
                }
                #[derive(Deserialize)]
                struct Legacy {
                    scope: String,
                    state: String,
                }
                let legacy: Legacy =
                    serde_json::from_str(text).map_err(|e| Error::Serialization(e.to_string()))?;
                let bytes =
                    hex::decode(&legacy.state).map_err(|e| Error::Serialization(e.to_string()))?;
                (legacy.scope, Self::parse(&bytes)?)
            }
        };
        Ok((scope, parsed.state.validated()?))
    }

    /// The checkpoint without its proofs, which a native file keeps apart,
    /// one appended at a time (`upload_checkpoint`), with the proof file's
    /// length up to its last whole record (`proofs_len`).
    #[cfg(feature = "native")]
    pub(crate) fn checkpoint_without_proofs(&self, proofs_len: u64) -> Result<Vec<u8>> {
        self.encode(None, false, Some(proofs_len))
    }

    fn encode(
        &self,
        scope: Option<&str>,
        with_proofs: bool,
        proofs_len: Option<u64>,
    ) -> Result<Vec<u8>> {
        let body = BodyOut {
            scope,
            plans: &self.plans,
            proofs: if with_proofs {
                self.proofs
                    .iter()
                    .map(|(address, bytes)| (address, serde_bytes::Bytes::new(bytes)))
                    .collect()
            } else {
                HashMap::new()
            },
            pending_merkle: &self.pending_merkle,
            pending_payment: &self.pending_payment,
            failed_payments: &self.failed_payments,
            paid_again: &self.paid_again,
            proofs_len,
        };
        let mut bytes = Vec::with_capacity(5);
        bytes.extend_from_slice(&CHECKPOINT_MAGIC);
        bytes.push(CHECKPOINT_FORMAT);
        rmp_serde::encode::write_named(&mut bytes, &body)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        Ok(bytes)
    }

    /// The checkpoint as the client before [`CHECKPOINT_MAGIC`] wrote it.
    #[cfg(test)]
    pub(crate) fn legacy_checkpoint(&self) -> Vec<u8> {
        rmp_serde::to_vec_named(self).unwrap_or_default()
    }

    /// Read a checkpoint, in either format, without checking it.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Parsed> {
        let Some(rest) = bytes.strip_prefix(&CHECKPOINT_MAGIC) else {
            let mut state: Self =
                rmp_serde::from_slice(bytes).map_err(|e| Error::Serialization(e.to_string()))?;
            state.renumber();
            return Ok(Parsed {
                state,
                scope: None,
                legacy: true,
                proofs_len: None,
            });
        };
        let (&format, body) = rest
            .split_first()
            .ok_or_else(|| Error::InvalidData("checkpoint ends after its magic".into()))?;
        if format != CHECKPOINT_FORMAT {
            return Err(Error::InvalidData(format!(
                "checkpoint format {format} is not one this client reads; \
                 finish the upload with the client that saved it"
            )));
        }
        let body: BodyIn =
            rmp_serde::from_slice(body).map_err(|e| Error::Serialization(e.to_string()))?;
        let mut state = Self {
            plans: body.plans,
            proofs: body
                .proofs
                .into_iter()
                .map(|(address, bytes)| (address, bytes.into_vec()))
                .collect(),
            proof_serials: HashMap::new(),
            pending_merkle: body.pending_merkle,
            pending_payment: body.pending_payment,
            failed_payments: body.failed_payments,
            paid_again: body.paid_again,
            paid_this_run: HashSet::new(),
        };
        state.renumber();
        Ok(Parsed {
            state,
            scope: body.scope,
            legacy: false,
            proofs_len: body.proofs_len,
        })
    }

    /// Add proofs read from a native file's proof file to a parsed
    /// checkpoint, before it is checked.
    #[cfg(feature = "native")]
    pub(crate) fn add_parsed_proofs(&mut self, proofs: HashMap<XorName, Vec<u8>>) {
        for (address, bytes) in proofs {
            self.insert_proof(address, bytes);
        }
    }

    /// Restore a local checkpoint, in either format, validating payment
    /// amounts and signed quote identities.
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        Self::parse(bytes)?.state.validated()
    }

    /// Check a parsed checkpoint (see the module docs): every quote signed
    /// by the node it names; every plan's amounts one of the two
    /// recomputations, or the plan dropped if no pending payment names it;
    /// the journal and every proof well formed.
    pub(crate) fn validated(mut self) -> Result<Self> {
        let pending = self
            .pending_payment
            .as_ref()
            .filter(|attempt| !attempt.merkle)
            .map(|attempt| attempt.addresses.iter().copied().collect::<HashSet<_>>())
            .unwrap_or_default();
        let mut dropped = Vec::new();
        for (address, plan) in &self.plans {
            if address != &plan.address
                || plan.peer_quotes.is_empty()
                || !quotes_signed_for(address, &plan.peer_quotes)
            {
                return Err(Error::InvalidData("invalid checkpoint quote".into()));
            }
            if plan_amounts_recomputed(plan) {
                continue;
            }
            if pending.contains(address) {
                return Err(Error::InvalidData(format!(
                    "the pending payment's plan for {} matches neither the full nor the \
                     weighted amount of its signed quotes",
                    hex::encode(address)
                )));
            }
            dropped.push(*address);
        }
        for address in dropped {
            tracing::warn!(
                "Dropping the saved plan for {}: its amounts are neither the full nor the \
                 weighted amount of its signed quotes; the record is quoted again",
                hex::encode(address)
            );
            self.plans.remove(&address);
        }
        if let Some(prepared) = &self.pending_merkle {
            prepared.validate_checkpoint()?;
        }
        if let Some(attempt) = &self.pending_payment {
            if attempt.submissions.len() > 256 || (attempt.merkle && self.pending_merkle.is_none())
            {
                return Err(Error::InvalidData("invalid payment journal".into()));
            }
            if !attempt.merkle {
                self.pending_plans()?;
            }
        }
        for (address, bytes) in &self.proofs {
            if let Ok(proof) = ant_protocol::payment::deserialize_merkle_proof(bytes) {
                if proof.address.0 != *address
                    || !proof.data_proof.verify()
                    || proof.data_proof.root() != proof.winner_pool.midpoint_proof.root()
                    || proof.winner_pool.candidate_nodes.iter().any(|candidate| {
                        !ant_protocol::payment::verify_merkle_candidate_signature(candidate)
                    })
                {
                    return Err(Error::InvalidData("invalid checkpoint Merkle proof".into()));
                }
                continue;
            }
            let proof = ant_protocol::payment::proof::deserialize_single_node_proof(bytes)
                .map_err(Error::InvalidData)?;
            if proof.tx_hashes.is_empty()
                || proof.proof_of_payment.peer_quotes.is_empty()
                || !quotes_signed_for(address, &proof.proof_of_payment.peer_quotes)
            {
                return Err(Error::InvalidData(
                    "invalid checkpoint payment proof".into(),
                ));
            }
        }
        Ok(self)
    }
}

/// Plans and proofs for the checkpoint's tests, here and in the files that
/// keep checkpoints.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod test_state {
    use super::*;
    use ant_protocol::{
        evm::{Amount, EncodedPeerId, PaymentQuote, RewardsAddress},
        transport::NodeIdentity,
    };

    /// A plan for `content`, with one quote at each of `prices`, each from
    /// a new node, signed at `timestamp`.
    pub(crate) fn plan_priced(
        content: &[u8],
        timestamp: SystemTime,
        prices: &[u64],
    ) -> ChunkPaymentPlan {
        let address = ant_protocol::compute_address(content);
        let peer_quotes = prices
            .iter()
            .map(|price| {
                let identity = NodeIdentity::generate().unwrap();
                let mut quote = PaymentQuote {
                    content: xor_name::XorName(address),
                    timestamp,
                    price: Amount::from(*price),
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
                (
                    EncodedPeerId::new(*blake3::hash(&quote.pub_key).as_bytes()),
                    quote,
                )
            })
            .collect::<Vec<_>>();
        ChunkPaymentPlan {
            address,
            data_size: content.len() as u64,
            quoted_peers: Vec::new(),
            payment: SingleNodeQuotePayment::from_quotes(
                peer_quotes.iter().map(|(_, q)| q.clone()).collect(),
            )
            .unwrap(),
            peer_quotes,
            commitment_sidecars: Vec::new(),
        }
    }

    /// A plan for `content` with one quote, signed at `timestamp`.
    pub(crate) fn plan(content: &[u8], timestamp: SystemTime) -> ChunkPaymentPlan {
        plan_priced(content, timestamp, &[10])
    }

    /// `plan` paid at the weighted amount of its class, as a client past the
    /// pricing switch pays.
    pub(crate) fn weighted(mut plan: ChunkPaymentPlan) -> ChunkPaymentPlan {
        let weight = ant_protocol::payment::pricing::record_weight(
            ant_protocol::DATA_TYPE_CHUNK,
            plan.data_size as usize,
        );
        for quote in &mut plan.payment.quotes {
            if !quote.amount.is_zero() {
                quote.amount =
                    ant_protocol::payment::pricing::weighted_amount(quote.price, weight).unwrap();
            }
        }
        plan
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::batch::finalize_batch_payment;
    use super::test_state::{plan, plan_priced, transactions, weighted};
    use super::*;
    use ant_protocol::evm::Amount;
    use bytes::Bytes;

    #[test]
    fn checkpoint_reuses_original_proof_with_new_quotes_and_matches_native_finalization() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let content = Bytes::from_static(b"retained paid record");
        let original = plan(&content, now);
        let txs = HashMap::from([(original.payment.quotes[0].quote_hash, TxHash::from([7; 32]))]);
        let mut state = UploadState::default();
        state.prepare(original.clone());
        state = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        assert_eq!(
            state
                .retained_plan(&original.address, content.len() as u64, now)
                .unwrap()
                .payment
                .quotes[0]
                .quote_hash,
            original.payment.quotes[0].quote_hash
        );
        state.confirm(&[original.address], &txs, now).unwrap();
        state = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        let refreshed = plan(&content, now + Duration::from_secs(1));
        assert_ne!(
            refreshed.payment.quotes[0].quote_hash,
            original.payment.quotes[0].quote_hash
        );
        let recovered = state
            .reuse_prepared(&refreshed.with_content(content.clone()).unwrap(), now)
            .unwrap();
        let native =
            finalize_batch_payment(vec![original.with_content(content).unwrap()], &txs).unwrap();
        assert_eq!(recovered.proof_bytes, native[0].proof_bytes);
    }

    /// Two plans are confirmed together or not at all, by one transaction
    /// each; a paid proof stays paid whatever its age, and only for its own
    /// record.
    #[test]
    fn confirmation_is_atomic_and_supports_distinct_transactions() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let a = plan(b"first", now);
        let b = plan(b"second", now);
        let mut state = UploadState::default();
        state.prepare(a.clone());
        state.prepare(b.clone());
        let mut txs = HashMap::from([(a.payment.quotes[0].quote_hash, TxHash::from([1; 32]))]);
        assert!(state.confirm(&[a.address, b.address], &txs, now).is_err());
        assert!(!state.is_paid(&a.address, now));
        txs.insert(b.payment.quotes[0].quote_hash, TxHash::from([2; 32]));
        state.confirm(&[a.address, b.address], &txs, now).unwrap();
        assert!(state.is_paid(&a.address, now));
        assert!(state.is_paid(&b.address, now));
        assert!(state.is_paid(&a.address, now + Duration::from_secs(40 * 24 * 60 * 60)));
        assert!(!reusable_proof(&b.address, &state.proofs[&a.address], now));
    }

    #[test]
    fn checkpoint_rejects_modified_payment_amount() {
        let mut state = UploadState::default();
        let mut a = plan(b"first", SystemTime::UNIX_EPOCH);
        a.payment.quotes[0].amount += Amount::from(1);
        state.prepare(a.clone());
        // Unpaid, it is dropped and quoted again.
        let restored = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        assert!(restored.plans.is_empty());
        // Named by a pending payment, the whole checkpoint is refused.
        state.start_payment(false, vec![a.address]).unwrap();
        assert!(UploadState::restore(&state.checkpoint().unwrap()).is_err());
    }

    /// A paid proof is kept and reused whatever its age; an unpaid plan
    /// past its age is quoted again.
    #[test]
    fn a_paid_proof_has_no_age_and_an_unpaid_plan_keeps_its_own() {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let old = plan(b"kept upload", issued);
        let mut state = UploadState::default();
        state.prepare(old.clone());
        state
            .confirm(&[old.address], &transactions(&old), issued)
            .unwrap();
        let evidence = state.proof(&old.address).cloned().unwrap();
        let now = issued + Duration::from_secs(25 * 60 * 60);
        let state = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        assert!(state.is_paid(&old.address, now), "25 hours on, still paid");
        assert_eq!(state.proof(&old.address), Some(&evidence));
        // Stored with it, at the targets a fresh lookup names, with no new
        // payment: the proof sent is the one paid.
        let content = Bytes::from_static(b"kept upload");
        let refreshed = plan(&content, now).with_content(content).unwrap();
        assert_eq!(
            state.reuse_prepared(&refreshed, now).unwrap().proof_bytes,
            evidence
        );
        assert!(state
            .retained_plan(&old.address, old.data_size, now)
            .is_none());

        let unpaid = plan(b"unpaid upload", issued);
        let mut state = UploadState::default();
        state.prepare(unpaid.clone());
        assert!(state
            .retained_plan(&unpaid.address, unpaid.data_size, issued)
            .is_some());
        assert!(state
            .retained_plan(&unpaid.address, unpaid.data_size, now)
            .is_none());
    }

    /// The paid node is the issuer of the median quote.
    #[test]
    fn the_paid_node_is_the_median_quotes_issuer() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let three = plan_priced(b"three quotes", now, &[30, 10, 20]);
        let mut state = UploadState::default();
        state.prepare(three.clone());
        state
            .confirm(&[three.address], &transactions(&three), now)
            .unwrap();
        let median = three
            .peer_quotes
            .iter()
            .find(|(_, quote)| quote.price == Amount::from(20))
            .map(|(peer, _)| *peer.as_bytes())
            .unwrap();
        assert_eq!(
            paid_node(state.proof(&three.address).unwrap()),
            Some(median)
        );
        assert_eq!(paid_node(b"not a proof"), None);
    }

    /// A checkpoint starts with the magic and its format, and the format
    /// before it (a msgpack `UploadState`) can't parse it, so a client that
    /// writes only that one stops with an error rather than paying again.
    #[test]
    fn a_new_checkpoint_stops_the_previous_clients_restore() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let a = plan(b"first", now);
        let mut state = UploadState::default();
        state.prepare(a.clone());
        state.confirm(&[a.address], &transactions(&a), now).unwrap();
        state.prepare(plan(b"second", now));
        let bytes = state.checkpoint().unwrap();
        assert_eq!(&bytes[..4], b"DSCK");
        assert_eq!(bytes[4], CHECKPOINT_FORMAT);
        // How the previous client restores: a msgpack `UploadState`.
        assert!(rmp_serde::from_slice::<UploadState>(&bytes).is_err());
        // A later format is refused here, for the same reason.
        let mut later = bytes.clone();
        later[4] = CHECKPOINT_FORMAT + 1;
        assert!(UploadState::restore(&later).is_err());
    }

    /// A checkpoint in the format before the magic restores, plans, proofs
    /// and journal alike.
    #[test]
    fn an_old_format_checkpoint_restores() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let paid = plan(b"paid", now);
        let pending = plan(b"pending", now);
        let mut state = UploadState::default();
        state.prepare(paid.clone());
        state
            .confirm(&[paid.address], &transactions(&paid), now)
            .unwrap();
        state.prepare(pending.clone());
        state.start_payment(false, vec![pending.address]).unwrap();
        let legacy = state.legacy_checkpoint();
        assert_ne!(&legacy[..4], b"DSCK");
        let parsed = UploadState::parse(&legacy).unwrap();
        assert!(parsed.legacy);
        let restored = parsed.state.validated().unwrap();
        assert_eq!(restored.proof(&paid.address), state.proof(&paid.address));
        assert_eq!(
            restored.pending_plans().unwrap()[0].address,
            pending.address
        );
    }

    /// Proofs are byte strings in the new format, not arrays of integers:
    /// the same state takes less room.
    #[test]
    fn proofs_take_less_room_as_bytes() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut state = UploadState::default();
        for i in 0..8u8 {
            let p = plan_priced(&[i; 64], now, &[10, 20, 30, 40, 50, 60, 70]);
            state.prepare(p.clone());
            state.confirm(&[p.address], &transactions(&p), now).unwrap();
        }
        let new = state.checkpoint().unwrap().len();
        let old = state.legacy_checkpoint().len();
        assert!(new * 4 < old * 3, "new {new} bytes, old {old}");
    }

    /// A plan saved at either amount restores; one at any other amount
    /// doesn't, and is dropped unless a pending payment names it. The full
    /// amount, the weighted amount of a small record, of a pointer at its
    /// 5,303 bytes and of a full chunk (the same as the full amount) are all
    /// recomputed exactly.
    #[test]
    fn a_plan_restores_at_the_full_or_the_weighted_amount_and_nothing_else() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for content in [
            vec![1u8; 1000],
            vec![2u8; 5303],
            vec![3u8; 300 * 1024],
            vec![4u8; ant_protocol::MAX_CHUNK_SIZE],
        ] {
            let full = plan_priced(&content, now, &[10_000_000, 20_000_000, 30_000_000]);
            let weighted = weighted(full.clone());
            assert!(plan_amounts_recomputed(&full));
            assert!(plan_amounts_recomputed(&weighted));
            if content.len() < ant_protocol::MAX_CHUNK_SIZE {
                assert_ne!(
                    full.payment.total_amount(),
                    weighted.payment.total_amount(),
                    "{} bytes",
                    content.len()
                );
            }
            for paid in [full.clone(), weighted.clone()] {
                let mut state = UploadState::default();
                state.prepare(paid.clone());
                state.start_payment(false, vec![paid.address]).unwrap();
                let restored = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
                assert_eq!(
                    quote_tuples(&restored.pending_plans().unwrap()[0].payment.quotes),
                    quote_tuples(&paid.payment.quotes)
                );
            }
            // Between the two: neither form.
            let mut between = full.clone();
            for quote in &mut between.payment.quotes {
                if !quote.amount.is_zero() {
                    quote.amount -= Amount::from(1);
                }
            }
            assert!(!plan_amounts_recomputed(&between));
            // A weighted amount for another class: neither form either. (A
            // full chunk's weighted amount is its full amount.)
            if content.len() < ant_protocol::MAX_CHUNK_SIZE {
                let mut other_class = weighted.clone();
                other_class.data_size = if content.len() > 64 * 1024 {
                    1000
                } else {
                    1_000_000
                };
                assert!(!plan_amounts_recomputed(&other_class));
            }
        }
    }

    /// One bad unpaid plan is dropped; the paid proofs and the good plans
    /// beside it stay.
    #[test]
    fn one_bad_unpaid_plan_doesnt_discard_paid_proofs() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let paid = plan(b"paid", now);
        let good = plan(b"good", now);
        let mut bad = plan(b"bad", now);
        bad.payment.quotes[0].amount += Amount::from(7);
        let mut state = UploadState::default();
        state.prepare(paid.clone());
        state
            .confirm(&[paid.address], &transactions(&paid), now)
            .unwrap();
        state.prepare(good.clone());
        state.prepare(bad.clone());
        let restored = UploadState::restore(&state.checkpoint().unwrap()).unwrap();
        assert!(restored.is_paid(&paid.address, now));
        assert!(restored.plans.contains_key(&good.address));
        assert!(!restored.plans.contains_key(&bad.address));
    }

    /// A bad signature, or a quote whose peer id isn't its key's, refuses
    /// the whole checkpoint.
    #[test]
    fn a_bad_signature_or_identity_refuses_the_whole_checkpoint() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut forged = plan(b"forged", now);
        forged.peer_quotes[0].1.signature[0] ^= 1;
        let mut state = UploadState::default();
        state.prepare(forged);
        assert!(UploadState::restore(&state.checkpoint().unwrap()).is_err());

        let mut renamed = plan(b"renamed", now);
        renamed.peer_quotes[0].0 = ant_protocol::evm::EncodedPeerId::new([9; 32]);
        let mut state = UploadState::default();
        state.prepare(renamed);
        assert!(UploadState::restore(&state.checkpoint().unwrap()).is_err());
    }

    /// A browser's snapshot is binary, and names its file; the JSON
    /// snapshot the browser client saved before reads as it is.
    #[test]
    fn browser_snapshots_old_and_new_restore() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let paid = plan(b"paid", now);
        let pending = plan(b"pending", now);
        let mut state = UploadState::default();
        state.prepare(paid.clone());
        state
            .confirm(&[paid.address], &transactions(&paid), now)
            .unwrap();
        state.prepare(pending.clone());
        state.start_payment(false, vec![pending.address]).unwrap();

        let snapshot = state.snapshot("scope-a").unwrap();
        assert_eq!(&snapshot[..4], b"DSCK");
        let (scope, restored) =
            UploadState::read_snapshot(BrowserSnapshot::Bytes(&snapshot)).unwrap();
        assert_eq!(scope, "scope-a");
        assert_eq!(restored.proof(&paid.address), state.proof(&paid.address));
        assert!(restored.pending_payment.is_some());

        // As the text a page saves: base64, as given, or the bytes as hex
        // in either case, with or without surrounding space.
        let text = state.snapshot_text("scope-a").unwrap();
        for form in [
            text.clone(),
            format!(" {text}\n"),
            hex::encode(&snapshot),
            hex::encode_upper(&snapshot),
        ] {
            let (scope, restored) =
                UploadState::read_snapshot(BrowserSnapshot::Text(&form)).unwrap();
            assert_eq!(scope, "scope-a");
            assert_eq!(restored.proof(&paid.address), state.proof(&paid.address));
        }
        // Text that is neither: the bytes as `Uint8Array.toString()` gives
        // them, or base64 of something else.
        let joined = snapshot
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        for wrong in [joined.as_str(), "aGVsbG8=", ""] {
            let error = UploadState::read_snapshot(BrowserSnapshot::Text(wrong)).unwrap_err();
            assert!(error.to_string().contains("Uint8Array"), "{error}");
        }

        // As the browser client before this one saved it.
        let json = serde_json::json!({
            "scope": "scope-b",
            "state": hex::encode(state.legacy_checkpoint()),
        })
        .to_string();
        let (scope, restored) = UploadState::read_snapshot(BrowserSnapshot::Text(&json)).unwrap();
        assert_eq!(scope, "scope-b");
        assert_eq!(restored.proof(&paid.address), state.proof(&paid.address));
        assert_eq!(
            restored.pending_plans().unwrap()[0].address,
            pending.address
        );
        // A native checkpoint, which names no file, isn't a snapshot.
        assert!(
            UploadState::read_snapshot(BrowserSnapshot::Bytes(&state.checkpoint().unwrap()))
                .is_err()
        );
        assert!(
            UploadState::read_snapshot(BrowserSnapshot::Bytes(&state.legacy_checkpoint())).is_err()
        );
    }

    /// A 1 GB browser upload's snapshot stays under the cap: every record's
    /// paid proof (a 1 GB file is about 240 records of 4 MiB; 260 here) at
    /// 160 KB each, above the 150 KB proofs measured, with a whole wave of
    /// 64 plans of seven quotes still to pay. As hex JSON with proofs as
    /// integer arrays, the format before, the same state took more than
    /// twice the room.
    #[test]
    fn a_one_gigabyte_browser_upload_stays_under_the_cap() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let proofs = (0..260u32)
            .map(|i| {
                let mut address = [0u8; 32];
                address[..4].copy_from_slice(&i.to_le_bytes());
                let proof = (0..160 * 1024u32)
                    .map(|j| (j.wrapping_mul(2_654_435_761).wrapping_add(i) >> 13) as u8)
                    .collect::<Vec<_>>();
                (address, proof)
            })
            .collect::<HashMap<_, _>>();
        let mut state = UploadState::from_proofs(proofs);
        let template = plan_priced(b"wave", now, &[1, 2, 3, 4, 5, 6, 7]);
        for i in 0..64u8 {
            let mut planned = template.clone();
            planned.address = [i; 32];
            state.plans.insert(planned.address, planned);
        }
        let snapshot = state.snapshot("scope").unwrap();
        assert!(
            snapshot.len() <= MAX_BROWSER_SNAPSHOT_BYTES,
            "{} bytes",
            snapshot.len()
        );
        let before = serde_json::json!({
            "scope": "scope",
            "state": hex::encode(state.legacy_checkpoint()),
        })
        .to_string();
        assert!(
            before.len() > 2 * snapshot.len(),
            "before {} bytes, now {}",
            before.len(),
            snapshot.len()
        );
    }

    /// Dropping a proof forgets it, so the record is paid again; serials
    /// tell each proof put in apart.
    #[test]
    fn a_dropped_proof_is_gone_and_serials_change_with_each_proof() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let p = plan(b"serials", now);
        let mut state = UploadState::default();
        state.prepare(p.clone());
        state.confirm(&[p.address], &transactions(&p), now).unwrap();
        let first = state.proof_serial(&p.address).unwrap();
        assert!(state.drop_proof(&p.address).is_some());
        assert!(!state.is_paid(&p.address, now));
        state.prepare(p.clone());
        state.confirm(&[p.address], &transactions(&p), now).unwrap();
        assert_ne!(state.proof_serial(&p.address), Some(first));
    }
}
