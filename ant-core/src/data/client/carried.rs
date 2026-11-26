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
use super::upload_state::{TakeReport, UploadState};
use crate::data::client::file::{CarriedOutcome, CARRIED_STATE_REFUSED};
use crate::data::error::{Error, Result};
use ant_protocol::payment::{detect_proof_type, ProofType};
use ant_protocol::XorName;
use std::collections::HashSet;

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
    /// A payer outside the client (`UploadPayer`), and whether it pays
    /// root waves (as `UploadPayer::pays_root_waves` says).
    Payer {
        /// Whether the payer pays plans for the root vault.
        root_waves: bool,
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
/// that earlier payment first.
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
            CarriedCaller::Payer { root_waves: true } => Coverage::Reconciled,
            CarriedCaller::Payer { root_waves: false } => {
                Coverage::Refused(ROOT_PENDING_FOR_PER_QUOTE_PAYER)
            }
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
/// it was. A carried payment not yet confirmed beside one the base holds is
/// refused. Then the base takes from it only what it lacks
/// ([`UploadState::take_carried`]).
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
    let Some(Read { state, planned }) = read else {
        return Ok((base, None));
    };
    if (base.pending_payment.is_some() || base.pending_merkle.is_some())
        && state.pending_payment.is_some()
    {
        return Err(refused(BOTH_PENDING));
    }
    let report = base.take_carried(state, records, &planned);
    Ok((base, Some(report)))
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

    const PAYER: CarriedCaller = CarriedCaller::Payer { root_waves: false };
    const ROOT_PAYER: CarriedCaller = CarriedCaller::Payer { root_waves: true };

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
            (CarriedPath::PayerPendingRootPayment, CarriedCaller::Payer { root_waves: true }) => {
                Reconciled
            }
            (CarriedPath::PayerPendingRootPayment, CarriedCaller::Payer { root_waves: false }) => {
                Refused(ROOT_PENDING_FOR_PER_QUOTE_PAYER)
            }
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
