// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A carried upload state: the paid state of an upload that another client
//! prepared, given to an upload of the same file so that it stores the paid
//! records without paying for them again.
//!
//! The bytes are what [`UploadState::checkpoint`] writes, taken from the
//! other client's `UploadPayer::state_saved`. An upload is given them by
//! its payer (`UploadPayer::carried_state`) or, paid by the client's wallet,
//! through `Client::file_upload_carried`.
//!
//! # The census
//!
//! [`CarriedPath`] names each way an upload pays for a record once, and
//! [`coverage`] says what a carried state does with it: taken, settled
//! through this upload's payer, quoted and paid afresh, not carried, or
//! refused whole, in words. Proofs map to their path by their
//! [`ProofType`], pending payments by the vault their plans pay
//! ([`PaymentVault`]) and by their wallet journal
//! (`native_payment::carried_journal_path`), each by an exhaustive match,
//! so a new proof type, vault or journal does not build until it is placed
//! here.
//!
//! # What an upload does with a carried state
//!
//! [`starting_state`] reads the state ([`UploadState::parse`], then
//! [`UploadState::validated`]: every quote signed by its node and for its
//! record, every proof well formed), refuses it whole on any failure or on
//! any path the census refuses, and adds to this upload's own state
//! ([`UploadState::take_carried`]) only the proofs of this upload's records
//! that its own state does not prove or hold in a payment not yet
//! confirmed. A saved checkpoint of the upload is never replaced. The
//! upload then runs as a resumed one: a taken proof is stored as an earlier
//! run's proof is, paid again at most once if every storer refuses it and
//! the vault shows its payment, and every new payment goes through the
//! normal quoting, the price ceiling and the occupied-quote read-back.

use super::root_payment::PaymentVault;
use super::upload_state::{paid_quote, PaymentAttempt, TakeReport, UploadState};
use crate::data::client::file::{CarriedOutcome, CARRIED_STATE_REFUSED};
use crate::data::error::{Error, Result};
use ant_protocol::evm::Amount;
use ant_protocol::payment::{detect_proof_type, ProofType};
use ant_protocol::XorName;
use std::collections::{HashMap, HashSet};

/// Why a wallet's payment not yet confirmed, in a shared wave, is refused.
pub(crate) const SHARED_WAVE_PENDING: &str =
    "a wallet's payment not yet confirmed is settled only by that wallet, from the shared \
     wave's file on the machine that made it";

/// Why a wallet's own payment not yet confirmed is refused.
pub(crate) const WALLET_PENDING: &str =
    "a wallet's payment not yet confirmed is settled only by that wallet on the machine that \
     made it; carry the state saved after it was confirmed";

/// Why a payer's payment not yet confirmed is refused to a wallet upload.
pub(crate) const PAYER_PENDING_FOR_WALLET: &str =
    "a payment not yet confirmed that a payer made is settled only through a payer; give the \
     state to an upload with a payer";

/// Why a payer's root payment not yet confirmed is refused to a payer that
/// does not pay root waves.
pub(crate) const ROOT_PENDING_FOR_PER_QUOTE_PAYER: &str =
    "a payment not yet confirmed whose plans pay the root vault is settled only through a payer \
     that pays root waves; give the state to an upload whose payer pays root waves";

/// Why a Merkle batch payment, paid or not yet confirmed, is refused.
pub(crate) const MERKLE_BATCH: &str =
    "a Merkle batch payment is not taken from a carried state: batch payments are refused on \
     this network";

/// Why this machine's own records are not carried.
pub(crate) const LOCAL_RECORDS: &str =
    "this machine's own records, read before a carried state and preferred to it";

/// Why one carried state given to two clients is not covered.
pub(crate) const SAME_STATE_TWICE: &str =
    "uploads on different machines cannot see each other; give a carried state to one client at \
     a time, and carry the newest state_saved state";

/// Why a saved checkpoint's main file is refused.
pub(crate) const MAIN_FILE_WITHOUT_PROOFS: &str =
    "these are a saved checkpoint's main file without its proofs; carry the bytes \
     UploadState::checkpoint writes";

/// Why a payment not yet confirmed that names other records is refused.
pub(crate) const PENDING_OUTSIDE_UPLOAD: &str =
    "its payment not yet confirmed names records that this upload does not have, and a payment \
     is settled whole";

/// Why a state that names none of this upload's records is refused.
pub(crate) const NO_PAYMENT_FOR_UPLOAD: &str =
    "the carried state holds no payment for this upload's records";

/// Why a carried payment not yet confirmed is refused beside a saved one.
pub(crate) const BOTH_PENDING: &str =
    "this upload's saved checkpoint holds a payment not yet confirmed; run it without the \
     carried state to settle it first";

/// Why a carried payment not yet confirmed is refused when this upload
/// already holds some of its records and not the others.
pub(crate) const PENDING_PARTLY_HELD: &str =
    "its payment not yet confirmed names records this upload already holds and records it does \
     not, and a payment is settled whole; carry the state saved after that payment was confirmed";

/// Why a payer's payment not yet confirmed that pays more than this client's
/// price ceiling is refused.
pub(crate) const PENDING_ABOVE_CEILING: &str =
    "its payment not yet confirmed pays a quote above this client's price ceiling";

/// Each way an upload pays for a record, as a carried state meets it.
///
/// Some paths are listed for the census alone: no carried state holds them,
/// so only [`coverage`] and its test name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CarriedPath {
    /// A single-node proof paid at the per-quote vault
    /// ([`PaymentVault::V2`]).
    PerQuoteVault,
    /// A root proof: one leaf of a wave paid at the root vault
    /// ([`PaymentVault::Root`]).
    RootWave,
    /// A wallet's payment not yet confirmed in a shared wave (its journal a
    /// wave's id, or the wave's signed transaction). The wave's confirmed
    /// proofs are single-node proofs: [`Self::PerQuoteVault`].
    SharedWave,
    /// A wallet's own payment not yet confirmed: its journal says nothing
    /// is signed yet, or holds its signed transaction.
    WalletPendingPayment,
    /// A payer's payment not yet confirmed (no wallet journal) whose plans
    /// all pay the per-quote vault.
    PayerPendingPayment,
    /// A payer's payment not yet confirmed whose plans pay the root vault.
    PayerPendingRootPayment,
    /// A Merkle proof.
    MerkleBatch,
    /// A Merkle batch payment not yet confirmed.
    PendingMerkle,
    /// A plan with no proof and no payment not yet confirmed: an offer.
    UnpaidQuote,
    /// This machine's cached receipts of a file's proofs.
    LocalReceipts,
    /// This machine's checkpoints of records paid one at a time.
    RecordCheckpoint,
    /// The marks of records paid again once already.
    PaidAgainMarks,
    /// One carried state given to two clients, or to uploads on two
    /// machines.
    SameStateTwice,
}

impl CarriedPath {
    /// Every path, once.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 13] = [
        Self::PerQuoteVault,
        Self::RootWave,
        Self::SharedWave,
        Self::WalletPendingPayment,
        Self::PayerPendingPayment,
        Self::PayerPendingRootPayment,
        Self::MerkleBatch,
        Self::PendingMerkle,
        Self::UnpaidQuote,
        Self::LocalReceipts,
        Self::RecordCheckpoint,
        Self::PaidAgainMarks,
        Self::SameStateTwice,
    ];
}

/// Who pays for the upload a carried state is given to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CarriedCaller {
    /// The client's own wallet.
    Wallet,
    /// A payer outside the client (`UploadPayer`), whether it pays root
    /// waves (as `UploadPayer::pays_root_waves` says), and the client's
    /// price ceiling.
    Payer {
        /// Whether the payer pays plans for the root vault.
        root_waves: bool,
        /// The client's `ClientConfig::max_chunk_price`, which a carried
        /// payment not yet confirmed is checked against before it is taken.
        ceiling: Option<Amount>,
    },
}

/// What a carried state does with a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coverage {
    /// Taken: stored as a resumed proof is. If every storer refuses it, the
    /// vault's record of its payment is read, and the record is paid again
    /// once.
    Covered,
    /// Settled through this upload's payer, which is asked for exactly the
    /// journaled plans, as on any resume, and must look for that earlier
    /// payment first.
    Reconciled,
    /// Not used: the record is quoted afresh, under the price ceiling, and
    /// paid by this upload's payer or wallet.
    QuotedAgain,
    /// Not part of a carried state, and why.
    NotCarried(&'static str),
    /// The whole carried state is refused, and why.
    Refused(&'static str),
}

/// What a carried state does with `path`, for an upload paid by `caller`.
///
/// A root proof is covered as a single-node proof is: if storers refuse
/// it, its vault record is read under the wave's key; a client that knows
/// no root vault cannot read it, so the proof is kept and the record is not
/// paid again. A payment not yet confirmed with no wallet journal is taken
/// as a payer's: a wallet attempt saved before wallet journals existed
/// looks the same, and the payer, asked for exactly those plans, looks for
/// that earlier payment first. It is taken only if its paid quotes are
/// within this client's price ceiling ([`PENDING_ABOVE_CEILING`]), and not
/// when this upload already holds, proves or has paid again any of its
/// records.
pub(crate) fn coverage(path: CarriedPath, caller: CarriedCaller) -> Coverage {
    match path {
        CarriedPath::PerQuoteVault | CarriedPath::RootWave | CarriedPath::PaidAgainMarks => {
            Coverage::Covered
        }
        CarriedPath::SharedWave => Coverage::Refused(SHARED_WAVE_PENDING),
        CarriedPath::WalletPendingPayment => Coverage::Refused(WALLET_PENDING),
        CarriedPath::PayerPendingPayment => match caller {
            CarriedCaller::Wallet => Coverage::Refused(PAYER_PENDING_FOR_WALLET),
            CarriedCaller::Payer { .. } => Coverage::Reconciled,
        },
        CarriedPath::PayerPendingRootPayment => match caller {
            CarriedCaller::Wallet => Coverage::Refused(PAYER_PENDING_FOR_WALLET),
            CarriedCaller::Payer {
                root_waves: true, ..
            } => Coverage::Reconciled,
            CarriedCaller::Payer {
                root_waves: false, ..
            } => Coverage::Refused(ROOT_PENDING_FOR_PER_QUOTE_PAYER),
        },
        CarriedPath::MerkleBatch | CarriedPath::PendingMerkle => Coverage::Refused(MERKLE_BATCH),
        CarriedPath::UnpaidQuote => Coverage::QuotedAgain,
        CarriedPath::LocalReceipts | CarriedPath::RecordCheckpoint => {
            Coverage::NotCarried(LOCAL_RECORDS)
        }
        CarriedPath::SameStateTwice => Coverage::NotCarried(SAME_STATE_TWICE),
    }
}

/// The path of a proof of `proof_type`.
pub(crate) fn proof_path(proof_type: ProofType) -> CarriedPath {
    match proof_type {
        ProofType::SingleNode => CarriedPath::PerQuoteVault,
        ProofType::Root => CarriedPath::RootWave,
        ProofType::Merkle => CarriedPath::MerkleBatch,
    }
}

/// The path of a payer's payment not yet confirmed of a plan for `vault`.
pub(crate) fn pending_vault_path(vault: PaymentVault) -> CarriedPath {
    match vault {
        PaymentVault::V2 => CarriedPath::PayerPendingPayment,
        PaymentVault::Root => CarriedPath::PayerPendingRootPayment,
    }
}

/// The error that refuses a carried state whole, for `reason`.
pub(crate) fn refused(reason: impl std::fmt::Display) -> Error {
    Error::InvalidData(format!("{CARRIED_STATE_REFUSED}: {reason}"))
}

/// Refuse the carried state if the census refuses `path` for `caller`.
fn check(path: CarriedPath, caller: CarriedCaller) -> Result<()> {
    match coverage(path, caller) {
        Coverage::Refused(words) => Err(refused(words)),
        Coverage::Covered
        | Coverage::Reconciled
        | Coverage::QuotedAgain
        | Coverage::NotCarried(_) => Ok(()),
    }
}

/// A carried state as read and checked, with the records it held plans for
/// before any plan was dropped.
struct Read {
    state: UploadState,
    planned: HashSet<XorName>,
}

/// Read the carried `bytes` for an upload of `records` paid by `caller`, and
/// refuse them whole on any failure or any path the census refuses.
fn read(bytes: &[u8], records: &HashSet<XorName>, caller: CarriedCaller) -> Result<Read> {
    let parsed = UploadState::parse(bytes).map_err(refused)?;
    if parsed.proofs_len.is_some() {
        return Err(refused(MAIN_FILE_WITHOUT_PROOFS));
    }
    // Noted before validation drops a plan whose amounts can't be
    // recomputed: its record is still quoted again.
    let planned = parsed.state.plan_addresses();
    let state = parsed.state.validated().map_err(refused)?;
    for bytes in state.proofs().values() {
        // `validated` refuses a proof of a type this client doesn't know.
        if let Some(proof_type) = detect_proof_type(bytes) {
            check(proof_path(proof_type), caller)?;
        }
    }
    if state.pending_merkle.is_some() {
        check(CarriedPath::PendingMerkle, caller)?;
    }
    if let Some(attempt) = &state.pending_payment {
        if attempt.merkle {
            check(CarriedPath::PendingMerkle, caller)?;
        }
        match super::native_payment::carried_journal_path(attempt) {
            Some(path) => check(path, caller)?,
            None => {
                let mut path = CarriedPath::PayerPendingPayment;
                for plan in state.pending_plans().map_err(refused)? {
                    if pending_vault_path(plan.vault) == CarriedPath::PayerPendingRootPayment {
                        path = CarriedPath::PayerPendingRootPayment;
                    }
                }
                check(path, caller)?;
            }
        }
        if attempt
            .addresses
            .iter()
            .any(|address| !records.contains(address))
        {
            return Err(refused(PENDING_OUTSIDE_UPLOAD));
        }
    }
    let names_this_upload = state
        .proofs()
        .keys()
        .chain(planned.iter())
        .chain(
            state
                .pending_payment
                .iter()
                .flat_map(|attempt| attempt.addresses.iter()),
        )
        .chain(state.paid_again().iter())
        .any(|address| records.contains(address));
    if !names_this_upload {
        return Err(refused(NO_PAYMENT_FOR_UPLOAD));
    }
    Ok(Read { state, planned })
}

/// The state an upload of `records` starts from, and what it took from a
/// carried state if it was given one.
///
/// The base is the upload's saved checkpoint (`saved`), used as it was
/// saved, or else this machine's receipts and paid-again marks
/// (`receipts`). With no carried state that is all, as before. With one
/// (`carried`), the carried state is read and checked first ([`read`]); a
/// refusal comes before anything is saved, so a saved checkpoint is left as
/// it was. A carried payment not yet confirmed is left out when the base
/// already holds it (an earlier run of this upload took it from the same
/// state, and it is counted as settled this run), when the base proves,
/// has paid again or holds pending every one of its records, or when the
/// base proves one of its records with the quote it paid (an earlier run of
/// this upload settled it, and released the records whose quote another
/// payment holds: they are quoted afresh); beside another payment the base
/// holds, or when the base holds some of its records and not the others,
/// it is refused; otherwise it is taken only if its paid quotes are within
/// the payer's client's price ceiling. Then the base takes from it only
/// what it lacks ([`UploadState::take_carried`]).
pub(crate) fn starting_state(
    saved: Option<UploadState>,
    receipts: impl FnOnce() -> Result<UploadState>,
    carried: Option<&[u8]>,
    records: &HashSet<XorName>,
    caller: CarriedCaller,
) -> Result<(UploadState, Option<TakeReport>)> {
    let read = carried
        .map(|bytes| read(bytes, records, caller))
        .transpose()?;
    let mut base = match saved {
        Some(state) => state,
        None => receipts()?,
    };
    let Some(Read { mut state, planned }) = read else {
        return Ok((base, None));
    };
    let mut pending_here = None;
    if let Some(attempt) = state.pending_payment.clone() {
        if same_attempt(&base, &state) {
            // An earlier run of this upload took it and saved it: the base
            // settles it, as on any resume.
            state.pending_payment = None;
            pending_here = Some(attempt.addresses.iter().copied().collect());
        } else if attempt.addresses.iter().all(|address| held(&base, address)) {
            // This upload already took, settled or is paying every one of
            // its records itself: the payer is never asked to pay a record
            // this upload proves, and no record of it is quoted afresh.
            state.pending_payment = None;
        } else if settled_here(&base, &state) {
            // This upload settled that very payment: it confirmed the
            // records whose paid quote was free and released those whose
            // quote another payment holds. The released ones are quoted
            // afresh, as that settling left them.
            state.pending_payment = None;
        } else if base.pending_payment.is_some() || base.pending_merkle.is_some() {
            return Err(refused(BOTH_PENDING));
        } else if attempt.addresses.iter().any(|address| held(&base, address)) {
            // A payment is settled whole. Left out, the records this upload
            // does not hold would be quoted afresh and paid under new
            // quotes, while the carried payment of them may be on chain;
            // taken, the payer would be asked to pay records this upload
            // proves.
            return Err(refused(PENDING_PARTLY_HELD));
        } else if let CarriedCaller::Payer { ceiling, .. } = caller {
            within_ceiling(&state, ceiling)?;
        }
    }
    let mut report = base.take_carried(state, records, &planned);
    if let Some(addresses) = pending_here {
        report.reconciled = addresses;
    }
    Ok((base, Some(report)))
}

/// Whether `base`, this upload's own state, proves `address`, has paid it
/// again once already, or names it in its own payment not yet confirmed.
fn held(base: &UploadState, address: &XorName) -> bool {
    base.proof(address).is_some()
        || base.was_paid_again(address)
        || base
            .pending_payment
            .as_ref()
            .is_some_and(|attempt| attempt.addresses.contains(address))
}

/// Whether `base` proves a record of `carried`'s payment not yet confirmed
/// with the quote that payment paid for it: that payment was settled into
/// this upload's state. Settling confirms each of its records whose paid
/// quote was free and releases each whose quote another payment holds
/// ([`UploadState::release_occupied`]), so a record of it that `base` does
/// not hold was released, and its carried quote is not used.
fn settled_here(base: &UploadState, carried: &UploadState) -> bool {
    let Ok(plans) = carried.pending_plans() else {
        return false;
    };
    plans.iter().any(|plan| {
        let paid = plan
            .payment
            .quotes
            .iter()
            .find(|quote| !quote.amount.is_zero())
            .map(|quote| quote.quote_hash);
        base.proof(&plan.address)
            .map(Vec::as_slice)
            .and_then(paid_quote)
            .is_some_and(|(_, hash, _)| Some(hash) == paid)
    })
}

/// Whether `base`'s payment not yet confirmed is the one `carried` holds:
/// a payer's (no wallet journal), for the same records, with the same
/// quotes. An earlier run of this upload took it from the same carried
/// state.
fn same_attempt(base: &UploadState, carried: &UploadState) -> bool {
    let (Some(ours), Some(theirs)) = (&base.pending_payment, &carried.pending_payment) else {
        return false;
    };
    let quotes = |state: &UploadState| {
        state.pending_plans().ok().map(|plans| {
            plans
                .into_iter()
                .map(|plan| {
                    let hashes = plan
                        .payment
                        .quotes
                        .iter()
                        .map(|quote| quote.quote_hash)
                        .collect::<Vec<_>>();
                    (plan.address, hashes)
                })
                .collect::<HashMap<_, _>>()
        })
    };
    let payer_journal = |attempt: &PaymentAttempt| {
        !attempt.merkle && attempt.submissions.is_empty() && attempt.receipt.is_none()
    };
    base.pending_merkle.is_none()
        && payer_journal(ours)
        && payer_journal(theirs)
        && ours.addresses.iter().collect::<HashSet<_>>()
            == theirs.addresses.iter().collect::<HashSet<_>>()
        && quotes(base).is_some_and(|ours| Some(ours) == quotes(carried))
}

/// Refuse a carried payment not yet confirmed whose plans pay a quote above
/// `ceiling` (`ClientConfig::max_chunk_price`): the payer is asked to pay
/// those plans as they are, without quoting them again, so the ceiling a
/// plan meets when it is made ([`crate::payment_policy`]) is checked here.
fn within_ceiling(state: &UploadState, ceiling: Option<Amount>) -> Result<()> {
    for plan in state.pending_plans().map_err(refused)? {
        for quote in plan.payment.quotes.iter().filter(|q| !q.amount.is_zero()) {
            crate::quote_validation::validate_price_ceiling(quote.price, ceiling)
                .map_err(|reason| refused(format!("{PENDING_ABOVE_CEILING}: {reason}")))?;
        }
    }
    Ok(())
}

/// What an upload did with a carried state ([`TakeReport`]), read from its
/// `state` at the end of a successful run: a taken record holding another
/// proof than the carried one was paid again, and a record the carried
/// state held only a plan for that holds a proof was quoted and paid
/// afresh. A record found stored, with no payment, is counted in neither.
pub(crate) fn outcome(report: &TakeReport, state: &UploadState) -> CarriedOutcome {
    let paid_again = report
        .taken
        .iter()
        .filter(|(address, carried)| {
            state
                .proof(address)
                .is_some_and(|bytes| blake3::hash(bytes).as_bytes() != *carried)
        })
        .count();
    let quoted_again = report
        .unpaid
        .iter()
        .filter(|address| state.proof(address).is_some())
        .count();
    CarriedOutcome {
        proofs: report.proofs,
        taken: report.taken.len(),
        reconciled: report.reconciled.len(),
        paid_again,
        quoted_again,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::data::client::upload_state::test_state::{plan, transactions};
    use crate::data::client::upload_state::PaymentAttempt;
    use std::collections::HashMap;
    use std::time::SystemTime;

    const PAYER: CarriedCaller = CarriedCaller::Payer {
        root_waves: false,
        ceiling: None,
    };
    const ROOT_PAYER: CarriedCaller = CarriedCaller::Payer {
        root_waves: true,
        ceiling: None,
    };

    fn now() -> SystemTime {
        crate::runtime::system_time()
    }

    /// The address and paid proof of a record of `content`.
    fn paid(content: &[u8]) -> (XorName, Vec<u8>) {
        let p = plan(content, now());
        let mut state = UploadState::default();
        state.prepare(p.clone());
        state
            .confirm(&[p.address], &transactions(&p), now())
            .unwrap();
        (p.address, state.proof(&p.address).unwrap().clone())
    }

    fn address(content: &[u8]) -> XorName {
        ant_protocol::compute_address(content)
    }

    fn records(contents: &[&[u8]]) -> HashSet<XorName> {
        contents.iter().map(|c| address(c)).collect()
    }

    /// A state holding the proofs of `contents`.
    fn proving(contents: &[&[u8]]) -> UploadState {
        UploadState::from_proofs(contents.iter().map(|c| paid(c)).collect())
    }

    /// A state with a payer's payment not yet confirmed of `contents`.
    fn pending(contents: &[&[u8]], vault: PaymentVault) -> UploadState {
        let mut state = UploadState::default();
        let mut addresses = Vec::new();
        for content in contents {
            let mut p = plan(content, now());
            p.vault = vault;
            addresses.push(p.address);
            state.prepare(p);
        }
        state.start_payment(false, addresses).unwrap();
        state
    }

    fn nothing_local() -> Result<UploadState> {
        Ok(UploadState::default())
    }

    fn reason(error: &Error) -> String {
        error.to_string()
    }

    fn assert_refused(result: Result<(UploadState, Option<TakeReport>)>, words: &str) {
        let error = result.expect_err("refused");
        let text = reason(&error);
        assert!(
            text.starts_with(&format!("invalid data: {CARRIED_STATE_REFUSED}: ")),
            "{text}"
        );
        assert!(text.ends_with(words), "{text}");
    }

    #[test]
    fn every_payment_path_is_covered_or_refused_by_a_carried_state() {
        use Coverage::*;
        let wallet = CarriedCaller::Wallet;
        let expected = |path: CarriedPath, caller: CarriedCaller| match (path, caller) {
            (CarriedPath::PerQuoteVault | CarriedPath::RootWave, _) => Covered,
            (CarriedPath::SharedWave, _) => Refused(SHARED_WAVE_PENDING),
            (CarriedPath::WalletPendingPayment, _) => Refused(WALLET_PENDING),
            (
                CarriedPath::PayerPendingPayment | CarriedPath::PayerPendingRootPayment,
                CarriedCaller::Wallet,
            ) => Refused(PAYER_PENDING_FOR_WALLET),
            (CarriedPath::PayerPendingPayment, CarriedCaller::Payer { .. }) => Reconciled,
            (
                CarriedPath::PayerPendingRootPayment,
                CarriedCaller::Payer {
                    root_waves: true, ..
                },
            ) => Reconciled,
            (
                CarriedPath::PayerPendingRootPayment,
                CarriedCaller::Payer {
                    root_waves: false, ..
                },
            ) => Refused(ROOT_PENDING_FOR_PER_QUOTE_PAYER),
            (CarriedPath::MerkleBatch | CarriedPath::PendingMerkle, _) => Refused(MERKLE_BATCH),
            (CarriedPath::UnpaidQuote, _) => QuotedAgain,
            (CarriedPath::LocalReceipts | CarriedPath::RecordCheckpoint, _) => {
                NotCarried(LOCAL_RECORDS)
            }
            (CarriedPath::PaidAgainMarks, _) => Covered,
            (CarriedPath::SameStateTwice, _) => NotCarried(SAME_STATE_TWICE),
        };
        let mut seen = HashSet::new();
        for path in CarriedPath::ALL {
            assert!(seen.insert(format!("{path:?}")), "{path:?} listed twice");
            for caller in [wallet, PAYER, ROOT_PAYER] {
                let coverage = coverage(path, caller);
                assert_eq!(coverage, expected(path, caller), "{path:?} for {caller:?}");
                match coverage {
                    Refused(words) | NotCarried(words) => {
                        assert!(!words.trim().is_empty(), "{path:?} has no words");
                    }
                    Covered | Reconciled | QuotedAgain => {}
                }
                // The engine refuses a refused path in the census words.
                let engine = check(path, caller);
                match coverage {
                    Refused(words) => assert_eq!(
                        reason(&engine.unwrap_err()),
                        format!("invalid data: {CARRIED_STATE_REFUSED}: {words}")
                    ),
                    _ => assert!(engine.is_ok(), "{path:?} for {caller:?}"),
                }
            }
        }
        assert_eq!(seen.len(), CarriedPath::ALL.len());
        // The paths proofs and plans map to.
        assert_eq!(
            proof_path(ProofType::SingleNode),
            CarriedPath::PerQuoteVault
        );
        assert_eq!(proof_path(ProofType::Root), CarriedPath::RootWave);
        assert_eq!(proof_path(ProofType::Merkle), CarriedPath::MerkleBatch);
        assert_eq!(
            pending_vault_path(PaymentVault::V2),
            CarriedPath::PayerPendingPayment
        );
        assert_eq!(
            pending_vault_path(PaymentVault::Root),
            CarriedPath::PayerPendingRootPayment
        );
        // A refusal is InvalidData, so callers match on the constant.
        assert!(
            matches!(refused("x"), Error::InvalidData(text) if text.starts_with(CARRIED_STATE_REFUSED))
        );
    }

    #[test]
    fn a_carried_state_with_one_quote_whose_signature_fails_is_refused_whole() {
        let (a, good) = paid(b"signed a");
        let (b, proof) = paid(b"signed b");
        let mut bad = ant_protocol::payment::proof::deserialize_single_node_proof(&proof).unwrap();
        let signature = &mut bad.proof_of_payment.peer_quotes[0].1.signature;
        signature[0] ^= 1;
        let bad = ant_protocol::payment::serialize_single_node_proof(&bad).unwrap();
        let carried = UploadState::from_proofs(HashMap::from([(a, good), (b, bad)]))
            .checkpoint()
            .unwrap();
        let mut base = proving(&[b"local c"]);
        base.prepare(plan(b"planned d", now()));
        base.add_paid_again([address(b"marked e")]);
        let before = base.checkpoint().unwrap();
        let upload = records(&[
            b"signed a",
            b"signed b",
            b"local c",
            b"planned d",
            b"marked e",
        ]);
        let result = starting_state(
            Some(base.clone()),
            nothing_local,
            Some(&carried),
            &upload,
            PAYER,
        );
        assert_refused(result, "invalid checkpoint payment proof");
        // The refusal took nothing: the saved state is as it was.
        assert_eq!(base.checkpoint().unwrap(), before);
        assert_eq!(base.proofs().len(), 1);
    }

    #[test]
    fn a_checkpoint_main_file_without_its_proofs_is_refused() {
        let carried = proving(&[b"main a", b"main b"]);
        let main = carried.checkpoint_without_proofs(1234).unwrap();
        let upload = records(&[b"main a", b"main b"]);
        assert_refused(
            starting_state(None, nothing_local, Some(&main), &upload, PAYER),
            MAIN_FILE_WITHOUT_PROOFS,
        );
        // The whole bytes are taken.
        let (state, report) = starting_state(
            None,
            nothing_local,
            Some(&carried.checkpoint().unwrap()),
            &upload,
            PAYER,
        )
        .unwrap();
        assert_eq!(report.unwrap().taken.len(), 2);
        assert_eq!(state.proofs().len(), 2);
    }

    #[test]
    fn a_carried_proof_stored_under_another_records_address_is_refused_by_restore() {
        let (_, for_b) = paid(b"other b");
        let a = address(b"under a");
        let carried = UploadState::from_proofs(HashMap::from([(a, for_b)]))
            .checkpoint()
            .unwrap();
        let base = proving(&[b"local"]);
        let before = base.checkpoint().unwrap();
        let upload = records(&[b"under a", b"other b", b"local"]);
        assert_refused(
            starting_state(
                Some(base.clone()),
                nothing_local,
                Some(&carried),
                &upload,
                PAYER,
            ),
            "invalid checkpoint payment proof",
        );
        assert_eq!(base.checkpoint().unwrap(), before);
    }

    #[test]
    fn a_carried_merkle_proof_is_refused() {
        use crate::data::client::merkle::test_support::{
            make_signed_prepared_merkle_batch, winner_hash_for,
        };
        let batch = make_signed_prepared_merkle_batch(2);
        let winner = winner_hash_for(&batch);
        let batch_paid =
            crate::data::client::merkle::finalize_merkle_batch(batch.clone(), winner).unwrap();
        // A Merkle proof for a record outside the upload, beside a
        // single-node proof of one of its records.
        let mut proofs = batch_paid.proofs.clone();
        let (a, proof) = paid(b"merkle a");
        proofs.insert(a, proof);
        let carried = UploadState::from_proofs(proofs);
        let upload = records(&[b"merkle a"]);
        for caller in [CarriedCaller::Wallet, PAYER, ROOT_PAYER] {
            assert_refused(
                starting_state(
                    None,
                    nothing_local,
                    Some(&carried.checkpoint().unwrap()),
                    &upload,
                    caller,
                ),
                MERKLE_BATCH,
            );
        }
        // A Merkle batch not yet confirmed.
        let mut carried = proving(&[b"merkle a"]);
        let addresses = batch.addresses().to_vec();
        carried.pending_merkle = Some(batch);
        carried.pending_payment = Some(PaymentAttempt {
            merkle: true,
            addresses,
            submissions: Vec::new(),
            receipt: None,
        });
        for caller in [CarriedCaller::Wallet, PAYER, ROOT_PAYER] {
            assert_refused(
                starting_state(
                    None,
                    nothing_local,
                    Some(&carried.checkpoint().unwrap()),
                    &upload,
                    caller,
                ),
                MERKLE_BATCH,
            );
        }
    }

    #[test]
    fn a_carried_pending_attempt_is_taken_for_a_payer() {
        let mut carried = proving(&[b"wave a", b"wave b"]);
        let attempt = pending(&[b"attempt c", b"attempt d"], PaymentVault::V2);
        // The attempt's own plans, as journaled.
        let plans = attempt.pending_plans().unwrap();
        for plan in &plans {
            carried.prepare(plan.clone());
        }
        carried.pending_payment = attempt.pending_payment.clone();
        let upload = records(&[b"wave a", b"wave b", b"attempt c", b"attempt d"]);
        for caller in [PAYER, ROOT_PAYER] {
            let (state, report) = starting_state(
                None,
                nothing_local,
                Some(&carried.checkpoint().unwrap()),
                &upload,
                caller,
            )
            .unwrap();
            let report = report.unwrap();
            assert_eq!(
                report.taken.keys().copied().collect::<HashSet<_>>(),
                records(&[b"wave a", b"wave b"])
            );
            assert!(state.is_paid(&address(b"wave a"), now()));
            assert_eq!(
                state.pending_payment.as_ref().unwrap().addresses,
                attempt.pending_payment.as_ref().unwrap().addresses
            );
            let taken_plans = state.pending_plans().unwrap();
            let hashes = |plans: &[crate::data::client::batch::ChunkPaymentPlan]| {
                plans
                    .iter()
                    .flat_map(|p| p.payment.quotes.iter().map(|q| q.quote_hash))
                    .collect::<Vec<_>>()
            };
            assert_eq!(hashes(&taken_plans), hashes(&plans));
            assert_eq!(report.reconciled, records(&[b"attempt c", b"attempt d"]));
            assert!(report.unpaid.is_empty());
        }
    }

    #[test]
    fn a_carried_pending_attempt_is_refused_for_the_wallet() {
        let mut carried = pending(&[b"wallet c"], PaymentVault::V2);
        let (a, proof) = paid(b"wallet a");
        carried = {
            let mut with = UploadState::from_proofs(HashMap::from([(a, proof)]));
            for plan in carried.pending_plans().unwrap() {
                with.prepare(plan);
            }
            with.pending_payment = carried.pending_payment.clone();
            with
        };
        let upload = records(&[b"wallet a", b"wallet c"]);
        let base = UploadState::default();
        assert_refused(
            starting_state(
                Some(base.clone()),
                nothing_local,
                Some(&carried.checkpoint().unwrap()),
                &upload,
                CarriedCaller::Wallet,
            ),
            PAYER_PENDING_FOR_WALLET,
        );
        assert!(base.proofs().is_empty());
    }

    #[test]
    fn a_carried_root_attempt_is_refused_for_a_payer_that_does_not_pay_root_waves() {
        let carried = pending(&[b"root a", b"root b"], PaymentVault::Root)
            .checkpoint()
            .unwrap();
        let upload = records(&[b"root a", b"root b"]);
        assert_refused(
            starting_state(None, nothing_local, Some(&carried), &upload, PAYER),
            ROOT_PENDING_FOR_PER_QUOTE_PAYER,
        );
        assert_refused(
            starting_state(
                None,
                nothing_local,
                Some(&carried),
                &upload,
                CarriedCaller::Wallet,
            ),
            PAYER_PENDING_FOR_WALLET,
        );
        let (state, report) =
            starting_state(None, nothing_local, Some(&carried), &upload, ROOT_PAYER).unwrap();
        assert_eq!(report.unwrap().reconciled, upload);
        assert!(state.pending_payment.is_some());
    }

    #[test]
    fn a_carried_pending_attempt_naming_records_outside_this_upload_is_refused() {
        let carried = pending(&[b"inside a", b"outside z"], PaymentVault::V2)
            .checkpoint()
            .unwrap();
        let upload = records(&[b"inside a", b"inside b"]);
        assert_refused(
            starting_state(None, nothing_local, Some(&carried), &upload, PAYER),
            PENDING_OUTSIDE_UPLOAD,
        );
    }

    #[test]
    fn proofs_for_records_this_upload_does_not_have_are_not_used() {
        let carried = proving(&[b"have a", b"stranger z"]).checkpoint().unwrap();
        let upload = records(&[b"have a", b"have b"]);
        let (state, report) =
            starting_state(None, nothing_local, Some(&carried), &upload, PAYER).unwrap();
        let report = report.unwrap();
        assert_eq!(report.proofs, 2);
        assert_eq!(report.taken.len(), 1);
        assert!(state.proof(&address(b"have a")).is_some());
        let z = address(b"stranger z");
        assert!(state.proof(&z).is_none());
        let bytes = state.checkpoint().unwrap();
        assert!(!bytes.windows(32).any(|window| window == z.as_slice()));
        assert_eq!(outcome(&report, &state).proofs, 2);
        assert_eq!(outcome(&report, &state).taken, 1);
    }

    #[test]
    fn a_carried_state_for_another_file_is_refused_before_any_payment() {
        let mut carried = proving(&[b"other file a"]);
        carried.prepare(plan(b"other file b", now()));
        carried.add_paid_again([address(b"other file c")]);
        let mut with_attempt = pending(&[b"other file d"], PaymentVault::V2);
        with_attempt.add_paid_again([address(b"other file e")]);
        let upload = records(&[b"this file a", b"this file b"]);
        for carried in [carried, with_attempt] {
            let carried = carried.checkpoint().unwrap();
            let result = starting_state(None, nothing_local, Some(&carried), &upload, PAYER);
            let text = reason(&result.err().unwrap());
            // An attempt outside the upload is refused first, in its own words.
            assert!(
                text.ends_with(NO_PAYMENT_FOR_UPLOAD) || text.ends_with(PENDING_OUTSIDE_UPLOAD),
                "{text}"
            );
        }
        let carried = proving(&[b"other file a"]).checkpoint().unwrap();
        assert_refused(
            starting_state(None, nothing_local, Some(&carried), &upload, PAYER),
            NO_PAYMENT_FOR_UPLOAD,
        );
    }

    #[test]
    fn a_proof_this_machine_holds_wins_over_a_carried_one() {
        let carried = proving(&[b"held a", b"free b"]).checkpoint().unwrap();
        let (a, local) = paid(b"held a");
        let upload = records(&[b"held a", b"free b"]);
        // From this machine's receipts.
        let receipts = || {
            Ok(UploadState::from_proofs(HashMap::from([(
                a,
                local.clone(),
            )])))
        };
        let (state, report) =
            starting_state(None, receipts, Some(&carried), &upload, PAYER).unwrap();
        assert_eq!(state.proof(&a), Some(&local));
        assert_eq!(
            report.unwrap().taken.keys().copied().collect::<Vec<_>>(),
            vec![address(b"free b")]
        );
        // From the saved checkpoint.
        let saved = UploadState::from_proofs(HashMap::from([(a, local.clone())]));
        let (state, report) = starting_state(
            Some(saved),
            || panic!("the receipts are read only without a saved checkpoint"),
            Some(&carried),
            &upload,
            PAYER,
        )
        .unwrap();
        assert_eq!(state.proof(&a), Some(&local));
        assert_eq!(report.unwrap().taken.len(), 1);
    }

    #[test]
    fn carried_paid_again_marks_are_kept_for_this_uploads_records() {
        let mut carried = proving(&[b"mark a", b"mark l"]);
        carried.add_paid_again([
            address(b"mark a"),
            address(b"mark c"),
            address(b"mark l"),
            address(b"mark z"),
        ]);
        let (l, local) = paid(b"mark l");
        let saved = UploadState::from_proofs(HashMap::from([(l, local)]));
        let upload = records(&[b"mark a", b"mark c", b"mark l"]);
        let (state, _) = starting_state(
            Some(saved),
            nothing_local,
            Some(&carried.checkpoint().unwrap()),
            &upload,
            PAYER,
        )
        .unwrap();
        assert!(state.was_paid_again(&address(b"mark a")));
        assert!(state.was_paid_again(&address(b"mark c")));
        assert!(!state.was_paid_again(&address(b"mark l")));
        assert!(!state.was_paid_again(&address(b"mark z")));
    }

    #[test]
    fn a_carried_states_unpaid_quotes_are_not_used() {
        let mut carried = proving(&[b"quoted a"]);
        let offer = plan(b"quoted b", now());
        carried.prepare(offer.clone());
        // A plan whose amounts can't be recomputed: dropped on reading.
        let mut changed = plan(b"quoted c", now());
        for quote in &mut changed.payment.quotes {
            if !quote.amount.is_zero() {
                quote.amount += ant_protocol::evm::Amount::from(1u8);
            }
        }
        carried.prepare(changed);
        let upload = records(&[b"quoted a", b"quoted b", b"quoted c"]);
        let (state, report) = starting_state(
            None,
            nothing_local,
            Some(&carried.checkpoint().unwrap()),
            &upload,
            PAYER,
        )
        .unwrap();
        let report = report.unwrap();
        assert!(state
            .retained_plan(&offer.address, offer.data_size, now())
            .is_none());
        assert!(state.plan_addresses().is_empty());
        assert_eq!(report.unpaid, records(&[b"quoted b", b"quoted c"]));
    }

    /// A record this upload marked as paid again and whose proof it dropped
    /// (every storer refused it) does not get the refused carried proof
    /// back when the upload runs again with the same carried state: it is
    /// quoted afresh, as without the carried state.
    #[test]
    fn a_proof_this_upload_dropped_to_pay_again_is_not_taken_again() {
        let carried = proving(&[b"dropped a", b"kept b"]).checkpoint().unwrap();
        let upload = records(&[b"dropped a", b"kept b"]);
        let (mut saved, report) =
            starting_state(None, nothing_local, Some(&carried), &upload, PAYER).unwrap();
        assert_eq!(report.unwrap().taken.len(), 2);
        // Every storer refused A: marked, its proof dropped and saved, then
        // the new quote failed before any payment.
        let a = address(b"dropped a");
        saved.mark_paid_again(a);
        saved.drop_proof(&a);
        let (state, report) =
            starting_state(Some(saved), nothing_local, Some(&carried), &upload, PAYER).unwrap();
        assert!(
            state.proof(&a).is_none(),
            "the refused proof is not put back"
        );
        assert!(state.was_paid_again(&a));
        assert!(state.proof(&address(b"kept b")).is_some());
        assert!(report.unwrap().taken.is_empty());
    }

    /// A carried payment not yet confirmed, with one confirmed proof beside
    /// it, as an upload's payer gives it.
    fn carried_attempt(contents: &[&[u8]]) -> (UploadState, Vec<XorName>) {
        let mut carried = proving(&[b"attempt proven"]);
        let attempt = pending(contents, PaymentVault::V2);
        for plan in attempt.pending_plans().unwrap() {
            carried.prepare(plan);
        }
        carried.pending_payment = attempt.pending_payment.clone();
        let addresses = attempt.pending_payment.unwrap().addresses;
        (carried, addresses)
    }

    /// A carried payment this upload took and settled is not taken again
    /// when the upload runs again with the same carried state, so its payer
    /// is not asked to pay records the upload proves. Nor is it taken when
    /// this upload's own state already proves or has paid again every one
    /// of its records.
    #[test]
    fn a_carried_attempt_this_upload_settled_is_not_taken_again() {
        let (carried, addresses) = carried_attempt(&[b"settled c", b"settled d"]);
        let bytes = carried.checkpoint().unwrap();
        let upload = records(&[b"attempt proven", b"settled c", b"settled d", b"later e"]);
        let (mut run, report) =
            starting_state(None, nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        assert_eq!(report.unwrap().reconciled.len(), 2);
        // Settled through the payer, then a later record failed to store.
        let mut paid_with = HashMap::new();
        for plan in run.pending_plans().unwrap() {
            paid_with.extend(transactions(&plan));
        }
        run.confirm(&addresses, &paid_with, now()).unwrap();
        assert!(run.pending_payment.is_none());
        let (again, report) = starting_state(
            Some(run.clone()),
            nothing_local,
            Some(&bytes),
            &upload,
            PAYER,
        )
        .unwrap();
        assert!(
            again.pending_payment.is_none(),
            "the payer is not asked again"
        );
        let report = report.unwrap();
        assert!(report.reconciled.is_empty());
        assert!(report.taken.is_empty());
        for address in &addresses {
            assert_eq!(again.proof(address), run.proof(address));
        }
        // One of its records was then dropped to be paid again.
        let mut dropped = run.clone();
        dropped.mark_paid_again(addresses[0]);
        dropped.drop_proof(&addresses[0]);
        let (again, report) =
            starting_state(Some(dropped), nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        assert!(again.pending_payment.is_none());
        assert!(report.unwrap().reconciled.is_empty());
    }

    /// A carried payment not yet confirmed of records some of which this
    /// upload already holds is refused whole. Left out, its other records
    /// would be quoted afresh and paid by this upload's payer under new
    /// quotes, while the carried payment of them may already be on chain.
    /// When this upload holds every one of its records, it is left out.
    #[test]
    fn a_carried_attempt_this_upload_holds_only_in_part_is_refused() {
        let (carried, addresses) = carried_attempt(&[b"part c", b"part d"]);
        let bytes = carried.checkpoint().unwrap();
        let upload = records(&[b"attempt proven", b"part c", b"part d"]);
        let (c, d) = (address(b"part c"), address(b"part d"));
        assert_eq!(addresses, vec![c, d]);
        // This machine's receipts prove one of its records.
        let (_, local) = paid(b"part c");
        let receipts = || {
            Ok(UploadState::from_proofs(HashMap::from([(
                c,
                local.clone(),
            )])))
        };
        assert_refused(
            starting_state(None, receipts, Some(&bytes), &upload, PAYER),
            PENDING_PARTLY_HELD,
        );
        // The saved checkpoint proves one and has paid the other again.
        let mut saved = UploadState::from_proofs(HashMap::from([(c, local.clone())]));
        assert_refused(
            starting_state(
                Some(saved.clone()),
                nothing_local,
                Some(&bytes),
                &upload,
                PAYER,
            ),
            PENDING_PARTLY_HELD,
        );
        saved.mark_paid_again(d);
        let (state, report) =
            starting_state(Some(saved), nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        assert!(state.pending_payment.is_none());
        assert_eq!(state.proof(&c), Some(&local));
        assert!(report.unwrap().reconciled.is_empty());
        // The saved checkpoint's own payment not yet confirmed holds one of
        // its records: refused, as beside any other saved payment.
        let own = pending(&[b"part c"], PaymentVault::V2);
        let before = own.checkpoint().unwrap();
        assert_refused(
            starting_state(
                Some(own.clone()),
                nothing_local,
                Some(&bytes),
                &upload,
                PAYER,
            ),
            BOTH_PENDING,
        );
        assert_eq!(own.checkpoint().unwrap(), before);
        // It proves one and its own payment not yet confirmed holds the
        // other: every record is held, and its own payment is kept.
        let mut own = UploadState::from_proofs(HashMap::from([(c, local.clone())]));
        own.prepare(plan(b"part d", now()));
        own.start_payment(false, vec![d]).unwrap();
        let (state, report) =
            starting_state(Some(own), nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        assert_eq!(state.pending_payment.as_ref().unwrap().addresses, vec![d]);
        assert_eq!(state.proof(&c), Some(&local));
        assert!(report.unwrap().reconciled.is_empty());
    }

    /// A run that took a carried payment not yet confirmed settled it and
    /// found one record's paid quote occupied by another payment: that
    /// record was released to be quoted again, and the others confirmed
    /// (`reconcile_upload_payment`). Run again with the same carried state
    /// before the released record is paid, the upload is not refused: the
    /// carried payment is left out, as it is settled, and the released
    /// record is quoted again, since its carried quote is another's.
    #[test]
    fn a_retry_after_a_carried_attempt_released_an_occupied_quote_is_not_refused() {
        use crate::data::client::occupied::{OccupiedQuote, VaultRecord};
        use ant_protocol::evm::EncodedPeerId;

        let (carried, _) = carried_attempt(&[b"occupied c", b"occupied d"]);
        let bytes = carried.checkpoint().unwrap();
        let upload = records(&[b"attempt proven", b"occupied c", b"occupied d"]);
        let (c, d) = (address(b"occupied c"), address(b"occupied d"));
        let (mut run, _) =
            starting_state(None, nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        // Settled: c's paid quote is occupied, so c is released, and d is
        // confirmed.
        let plans = run.pending_plans().unwrap();
        let quote_c = plans
            .iter()
            .find(|plan| plan.address == c)
            .unwrap()
            .payment
            .quotes
            .iter()
            .find(|quote| !quote.amount.is_zero())
            .unwrap()
            .clone();
        let occupied = OccupiedQuote {
            address: c,
            quote_hash: quote_c.quote_hash,
            issuer: EncodedPeerId::new([0; 32]),
            rewards_address: quote_c.rewards_address,
            amount: quote_c.amount,
            recorded: VaultRecord {
                rewards_prefix: [9; 16],
                amount: quote_c.amount,
            },
        };
        assert_eq!(run.release_occupied(&[occupied]), vec![c]);
        let mut paid_with = HashMap::new();
        for plan in &plans {
            paid_with.extend(transactions(plan));
        }
        run.confirm(&[d], &paid_with, now()).unwrap();
        assert!(run.pending_payment.is_none());
        assert!(run.proof(&c).is_none() && !run.was_paid_again(&c));
        let (again, report) = starting_state(
            Some(run.clone()),
            nothing_local,
            Some(&bytes),
            &upload,
            PAYER,
        )
        .expect("a carried payment this upload settled is not refused");
        assert!(
            again.pending_payment.is_none(),
            "the payer is not asked again"
        );
        assert_eq!(again.proof(&d), run.proof(&d));
        assert!(again.proof(&c).is_none());
        assert!(
            !again.plan_addresses().contains(&c),
            "the occupied quote is not used"
        );
        let report = report.unwrap();
        assert!(report.reconciled.is_empty());
        assert!(report.unpaid.contains(&c), "c is quoted again");
        // A proof of d from other quotes than the carried payment's is not
        // this upload's settling of it: still refused.
        let (_, other) = paid(b"occupied d");
        let foreign = UploadState::from_proofs(HashMap::from([(d, other)]));
        assert_refused(
            starting_state(Some(foreign), nothing_local, Some(&bytes), &upload, PAYER),
            PENDING_PARTLY_HELD,
        );
    }

    /// A run that took a carried payment not yet confirmed, and stopped
    /// before it was settled, keeps it in its checkpoint. Run again with the
    /// same carried state, the upload settles that saved payment and is not
    /// refused.
    #[test]
    fn a_retry_with_the_carried_attempt_it_already_took_is_not_refused() {
        let (carried, addresses) = carried_attempt(&[b"retry c", b"retry d"]);
        let bytes = carried.checkpoint().unwrap();
        let upload = records(&[b"attempt proven", b"retry c", b"retry d"]);
        let (run, _) = starting_state(None, nothing_local, Some(&bytes), &upload, PAYER).unwrap();
        let quotes = |state: &UploadState| {
            state
                .pending_plans()
                .unwrap()
                .iter()
                .flat_map(|plan| plan.payment.quotes.iter().map(|q| q.quote_hash))
                .collect::<HashSet<_>>()
        };
        let (again, report) = starting_state(
            Some(run.clone()),
            nothing_local,
            Some(&bytes),
            &upload,
            PAYER,
        )
        .expect("the same payment is not refused");
        assert_eq!(again.pending_payment.as_ref().unwrap().addresses, addresses);
        assert_eq!(quotes(&again), quotes(&run));
        let report = report.unwrap();
        assert_eq!(report.reconciled, addresses.iter().copied().collect());
        assert!(report.taken.is_empty());
        // Another payment, of other records, beside the saved one is still
        // refused.
        let (other, _) = carried_attempt(&[b"retry f"]);
        assert_refused(
            starting_state(
                Some(run),
                nothing_local,
                Some(&other.checkpoint().unwrap()),
                &records(&[b"attempt proven", b"retry c", b"retry d", b"retry f"]),
                PAYER,
            ),
            BOTH_PENDING,
        );
    }

    /// A carried payment not yet confirmed is paid as it is, without new
    /// quotes, so its paid quotes are checked against this client's price
    /// ceiling before it is taken.
    #[test]
    fn a_carried_attempt_above_this_clients_price_ceiling_is_refused() {
        // One quote at price 10.
        let carried = pending(&[b"priced c"], PaymentVault::V2)
            .checkpoint()
            .unwrap();
        let upload = records(&[b"priced c"]);
        let capped = |ceiling: u64| CarriedCaller::Payer {
            root_waves: false,
            ceiling: Some(Amount::from(ceiling)),
        };
        let error = starting_state(None, nothing_local, Some(&carried), &upload, capped(9))
            .expect_err("above the ceiling");
        assert_eq!(
            reason(&error),
            format!(
                "invalid data: {CARRIED_STATE_REFUSED}: {PENDING_ABOVE_CEILING}: price 10 is \
                 above the price ceiling 9"
            )
        );
        let (state, report) =
            starting_state(None, nothing_local, Some(&carried), &upload, capped(10)).unwrap();
        assert!(state.pending_payment.is_some());
        assert_eq!(report.unwrap().reconciled, upload);
    }

    #[test]
    fn the_result_counts_records_paid_again_and_quoted_again() {
        let carried = {
            let mut state = proving(&[b"count a", b"count b", b"count c"]);
            state.prepare(plan(b"count d", now()));
            state.prepare(plan(b"count e", now()));
            state
        };
        let upload = records(&[b"count a", b"count b", b"count c", b"count d", b"count e"]);
        let (state, report) = starting_state(
            None,
            nothing_local,
            Some(&carried.checkpoint().unwrap()),
            &upload,
            PAYER,
        )
        .unwrap();
        let report = report.unwrap();
        // a: stored with its carried proof. b: dropped, then found stored
        // during the payment again. c: paid again with a new proof. d:
        // quoted and paid afresh. e: found stored, nothing paid.
        let (_, new_c) = paid(b"count c");
        let (_, new_d) = paid(b"count d");
        let mut end = UploadState::from_proofs(
            [
                (
                    address(b"count a"),
                    state.proof(&address(b"count a")).unwrap().clone(),
                ),
                (address(b"count c"), new_c),
                (address(b"count d"), new_d),
            ]
            .into_iter()
            .collect(),
        );
        end.add_paid_again([address(b"count c")]);
        let counted = outcome(&report, &end);
        assert_eq!(
            counted,
            CarriedOutcome {
                proofs: 3,
                taken: 3,
                reconciled: 0,
                paid_again: 1,
                quoted_again: 1,
            }
        );
        let json = serde_json::to_value(&counted).unwrap();
        assert_eq!(json["taken"], 3);
    }
}
