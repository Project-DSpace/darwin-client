// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared payment waves: the small payments of one wallet's uploads, paid
//! in one transaction.
//!
//! An upload pays its records in waves of up to [`PAYMENT_WAVE_SIZE`], one
//! transaction each, and a wallet has one transaction in flight at a time
//! (its lock). So small files, each a wave of a few records, paid one
//! transaction each, one after another. Now a payment of fewer records
//! than a wave joins the wallet's open wave instead, which pays every
//! member's quotes in one transaction, still one in flight per wallet:
//!
//! 1. **Joining.** A payment joins the open wave if its records fit, else
//!    opens a new one, which it leads. It saves the wave's id in its own
//!    journal before anything is signed for the wave, and then is ready.
//! 2. **Closing.** The leader takes the wallet's lock (so a wave stays open
//!    while an earlier one is in flight) and closes the wave once every
//!    member is ready and it holds [`PAYMENT_WAVE_SIZE`] records, or as many
//!    members as the client has uploads in progress, or
//!    [`SHARED_WAVE_WAIT`] has passed since it opened.
//! 3. **Signing.** The leader signs one transaction paying every member's
//!    quotes, in quote-hash order, and writes it, with those quotes, to the
//!    wave's file ([`write_wave_file`]) before anything else: the one
//!    record of what the wave signed. Every member then saves it in its own
//!    journal; once every member has, the file goes.
//! 4. **Sending.** The leader sends it and observes it, as a payment of its
//!    own is, and tells every member how it ended.
//!
//! A member's journal names the wave until the wave ends. No member is
//! quoted again before then: a resume reconciles the wave's transaction
//! from the chain, from the wave's file while it is there (it has the
//! latest the wave signed), else from the member's own copy, and a member
//! that saved only the wave's id, with no file, knows nothing was signed.
//! Each member's payment record and proofs show only its own quotes, and
//! its share of the amount; its records are stored, an envelope after its
//! content, as before.
//!
//! The wallet's lock is per process, so waves are per client: gateway
//! agents, each paying from a wallet of its own, don't share them.

use super::batch::PAYMENT_WAVE_SIZE;
use super::native_payment::Settled;
use crate::data::error::{Error, Result};
use ant_protocol::evm::journal::{PaymentReceipt, SignedPayment};
use ant_protocol::evm::{Amount, QuoteHash, RewardsAddress};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long after it opened a wave waits for others to join, unless it fills
/// or every upload in progress has joined; its leader closes it once it also
/// holds the wallet's lock. Claude's proposal (2026-10-25): short beside a
/// transaction's few seconds in flight, during which the next wave fills
/// anyway, and no wait at all for an upload alone.
pub(crate) const SHARED_WAVE_WAIT: Duration = Duration::from_millis(500);

/// Where waves' files are kept, under the data directory.
pub(crate) const WAVES: &str = "payments/waves";

/// A quote paid: its hash, its rewards address, and the amount.
pub(crate) type QuoteTuple = (QuoteHash, RewardsAddress, Amount);

/// A shared wave's signed transaction, as its file and its members'
/// journals hold it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WaveSigned {
    /// The wave's id (hex).
    pub(crate) wave: String,
    /// The transaction, signed and not necessarily sent.
    pub(crate) transaction: SignedPayment,
    /// Every quote it pays, in its order.
    pub(crate) quotes: Vec<QuoteTuple>,
}

/// How a wave ended, for its members.
pub(crate) enum WaveEnd {
    /// Its transaction was sent, and this is what became of it.
    Settled(Settled),
    /// Its transaction's first send was refused for a stale nonce twice:
    /// nothing was sent.
    StaleUnsent,
    /// Nothing was sent: why.
    NotSent(Error),
    /// Its leader stopped before it ended: each member reconciles it from
    /// its journal on a retry.
    Stopped,
}

/// What a member learns when its wave ends: how, and how many quotes the
/// wave paid in all.
pub(crate) struct Ended {
    pub(crate) ended: WaveEnd,
    pub(crate) quotes: usize,
}

/// What a member waiting on its wave is to do next ([`Member::next`]).
pub(crate) enum Step {
    /// Save the wave's transaction, signed in this round, in its journal,
    /// then say whether it did ([`Member::saved`]).
    Save(u32, WaveSigned),
    /// The wave ended.
    Ended(Ended),
}

/// A wallet's shared waves: the one open for joining, and how many uploads
/// are in progress.
#[derive(Default)]
pub(crate) struct SharedWaves {
    state: Mutex<Waves>,
    /// [`SHARED_WAVE_WAIT`], unless a test sets another.
    #[cfg(feature = "test-utils")]
    wait: Mutex<Option<Duration>>,
}

#[derive(Default)]
struct Waves {
    /// Uploads in progress ([`SharedWaves::upload`]).
    active: usize,
    /// The wave open for joining, if any.
    open: Option<Arc<Wave>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One upload in progress, counted while it lives.
pub(crate) struct Upload(Arc<SharedWaves>);

impl Drop for Upload {
    fn drop(&mut self) {
        let open = {
            let mut waves = lock(&self.0.state);
            waves.active = waves.active.saturating_sub(1);
            waves.open.clone()
        };
        // One fewer to wait for.
        if let Some(wave) = open {
            wave.changed.notify_waiters();
        }
    }
}

impl SharedWaves {
    /// Count an upload in progress until the value returned is dropped.
    pub(crate) fn upload(self: &Arc<Self>) -> Upload {
        lock(&self.state).active += 1;
        Upload(Arc::clone(self))
    }

    fn active(&self) -> usize {
        lock(&self.state).active
    }

    fn wait(&self) -> Duration {
        #[cfg(feature = "test-utils")]
        if let Some(wait) = *lock(&self.wait) {
            return wait;
        }
        SHARED_WAVE_WAIT
    }

    /// Wait this long in place of [`SHARED_WAVE_WAIT`]: for tests.
    #[cfg(feature = "test-utils")]
    pub(crate) fn set_wait(&self, wait: Duration) {
        *lock(&self.wait) = Some(wait);
    }

    /// Join the open wave with a payment of `records` records, or open a new
    /// one, which the payment leads.
    pub(crate) fn join(&self, records: usize) -> Member {
        let mut waves = lock(&self.state);
        if let Some(wave) = &waves.open {
            let mut state = lock(&wave.state);
            if !state.closed && state.records() + records <= PAYMENT_WAVE_SIZE {
                state.members.push(MemberState::new(records));
                return Member {
                    wave: Arc::clone(wave),
                    index: state.members.len() - 1,
                };
            }
        }
        let wave = Arc::new(Wave {
            id: rand::random(),
            opened: Instant::now(),
            state: Mutex::new(WaveState {
                members: vec![MemberState::new(records)],
                ..WaveState::default()
            }),
            changed: tokio::sync::Notify::new(),
        });
        waves.open = Some(Arc::clone(&wave));
        Member { wave, index: 0 }
    }

    /// No more joins of `wave`.
    fn closed(&self, wave: &Arc<Wave>) {
        let mut waves = lock(&self.state);
        if waves
            .open
            .as_ref()
            .is_some_and(|open| Arc::ptr_eq(open, wave))
        {
            waves.open = None;
        }
    }
}

/// One shared wave.
struct Wave {
    id: [u8; 32],
    opened: Instant,
    state: Mutex<WaveState>,
    /// Notified at every change of `state`.
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct WaveState {
    /// Whether it takes no more members.
    closed: bool,
    /// Its members, in the order they joined; the first leads.
    members: Vec<MemberState>,
    /// The latest transaction its leader signed and published, and its
    /// round.
    signed: Option<(u32, WaveSigned)>,
    /// How it ended, once it has.
    ended: Option<WaveEnd>,
    /// How many quotes it paid.
    quotes: usize,
}

impl WaveState {
    /// The records of the members still in it.
    fn records(&self) -> usize {
        self.members
            .iter()
            .filter(|member| !member.gone)
            .map(|member| member.records)
            .sum()
    }
}

struct MemberState {
    records: usize,
    /// Its quotes, once its journal names the wave.
    quotes: Option<Vec<QuoteTuple>>,
    /// Whether it left (its payment stopped).
    gone: bool,
    /// The round of the latest transaction it saved, and whether it did.
    saved: Option<(u32, bool)>,
}

impl MemberState {
    fn new(records: usize) -> Self {
        Self {
            records,
            quotes: None,
            gone: false,
            saved: None,
        }
    }
}

/// Whether a wave with `records` records from its ready members closes
/// now: once every member is ready, and it is full, or holds as many
/// members as there are uploads in progress (`active`), or has been open
/// `wait` (`open_for`).
pub(crate) fn closes(
    all_ready: bool,
    records: usize,
    members: usize,
    active: usize,
    open_for: Duration,
    wait: Duration,
) -> bool {
    all_ready && (records >= PAYMENT_WAVE_SIZE || members >= active || open_for >= wait)
}

/// A payment's place in a wave.
pub(crate) struct Member {
    wave: Arc<Wave>,
    index: usize,
}

impl Drop for Member {
    fn drop(&mut self) {
        let mut state = lock(&self.wave.state);
        if let Some(member) = state.members.get_mut(self.index) {
            member.gone = true;
        }
        if self.index == 0 {
            // A wave whose leader stopped takes no one else.
            state.closed = true;
        }
        drop(state);
        self.wave.changed.notify_waiters();
    }
}

impl Member {
    /// The wave's id (hex), which the payment's journal names.
    pub(crate) fn wave_id(&self) -> String {
        hex::encode(self.wave.id)
    }

    /// Whether this payment leads the wave.
    pub(crate) fn leads(&self) -> bool {
        self.index == 0
    }

    /// The payment's journal names the wave: these are its quotes.
    pub(crate) fn ready(&self, quotes: Vec<QuoteTuple>) {
        lock(&self.wave.state).members[self.index].quotes = Some(quotes);
        self.wave.changed.notify_waiters();
    }

    /// Wait until the wave closes ([`closes`]), then close it to joins:
    /// every ready member's quotes, in quote-hash order. A member that left
    /// before it was ready is left out.
    pub(crate) async fn close(&self, waves: &SharedWaves) -> Vec<QuoteTuple> {
        let wait = waves.wait();
        loop {
            let notified = self.wave.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let active = waves.active();
            {
                let mut state = lock(&self.wave.state);
                let live = state.members.iter().filter(|member| !member.gone);
                let all_ready = live.clone().all(|member| member.quotes.is_some());
                let members = live.clone().count();
                let records = state.records();
                if closes(
                    all_ready,
                    records,
                    members,
                    active,
                    self.wave.opened.elapsed(),
                    wait,
                ) {
                    state.closed = true;
                    let mut quotes = state
                        .members
                        .iter()
                        .filter(|member| !member.gone)
                        .flat_map(|member| member.quotes.iter().flatten().copied())
                        .collect::<Vec<_>>();
                    quotes.sort_by_key(|quote| quote.0);
                    state.quotes = quotes.len();
                    drop(state);
                    waves.closed(&self.wave);
                    return quotes;
                }
            }
            let left = wait.saturating_sub(self.wave.opened.elapsed());
            let _ = tokio::time::timeout(left.max(Duration::from_millis(20)), notified).await;
        }
    }

    /// Publish the transaction the leader signed for the wave, and wait
    /// until every member still in it has saved it, or left. Returns
    /// whether every member saved it.
    pub(crate) async fn publish(&self, journal: WaveSigned) -> bool {
        let round = {
            let mut state = lock(&self.wave.state);
            let round = state.signed.as_ref().map_or(0, |(round, _)| round + 1);
            state.signed = Some((round, journal));
            round
        };
        self.wave.changed.notify_waiters();
        loop {
            let notified = self.wave.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = lock(&self.wave.state);
                let members = state
                    .members
                    .iter()
                    .filter(|member| member.quotes.is_some());
                let mut all = true;
                let mut done = true;
                for member in members {
                    match member.saved {
                        Some((saved, ok)) if saved == round => all &= ok,
                        _ if member.gone => all = false,
                        _ => done = false,
                    }
                }
                if done {
                    return all;
                }
            }
            notified.await;
        }
    }

    /// Tell the wave's members how it ended.
    pub(crate) fn end(&self, ended: WaveEnd) {
        lock(&self.wave.state).ended = Some(ended);
        self.wave.changed.notify_waiters();
    }

    /// Wait for what the payment is to do next: save a transaction its
    /// leader published, or take how the wave ended.
    pub(crate) async fn next(&self) -> Step {
        loop {
            let notified = self.wave.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = lock(&self.wave.state);
                if let Some(ended) = &state.ended {
                    return Step::Ended(Ended {
                        ended: copy_end(ended),
                        quotes: state.quotes,
                    });
                }
                if self.index != 0 && state.members[0].gone {
                    return Step::Ended(Ended {
                        ended: WaveEnd::Stopped,
                        quotes: state.quotes,
                    });
                }
                if let Some((round, journal)) = &state.signed {
                    if state.members[self.index]
                        .saved
                        .is_none_or(|(saved, _)| saved != *round)
                    {
                        return Step::Save(*round, journal.clone());
                    }
                }
            }
            notified.await;
        }
    }

    /// The payment saved the transaction of `round` in its journal, or
    /// (`saved` false) couldn't.
    pub(crate) fn saved(&self, round: u32, saved: bool) {
        lock(&self.wave.state).members[self.index].saved = Some((round, saved));
        self.wave.changed.notify_waiters();
    }
}

/// How a wave ended, copied for each of its members.
fn copy_end(ended: &WaveEnd) -> WaveEnd {
    match ended {
        WaveEnd::Settled(Settled::Confirmed(receipt)) => {
            WaveEnd::Settled(Settled::Confirmed(receipt.clone()))
        }
        WaveEnd::Settled(Settled::Reverted) => WaveEnd::Settled(Settled::Reverted),
        WaveEnd::Settled(Settled::Replaced(hash)) => WaveEnd::Settled(Settled::Replaced(*hash)),
        WaveEnd::Settled(Settled::StaleUnsent) | WaveEnd::StaleUnsent => WaveEnd::StaleUnsent,
        WaveEnd::Settled(Settled::Kept(error)) => {
            WaveEnd::Settled(Settled::Kept(copy_error(error)))
        }
        WaveEnd::NotSent(error) => WaveEnd::NotSent(copy_error(error)),
        WaveEnd::Stopped => WaveEnd::Stopped,
    }
}

/// A copy of `error` for each member: a settlement refusal stays one, so
/// an upload says the client must be updated; anything else is a payment
/// error with its text.
fn copy_error(error: &Error) -> Error {
    match error {
        Error::ClientUpdateRequired(refusal) => Error::ClientUpdateRequired(refusal.clone()),
        Error::Payment(message) => Error::Payment(message.clone()),
        other => Error::Payment(other.to_string()),
    }
}

/// A member's share of what its wave paid: its own quotes' amount, and of
/// the gas, a part in proportion to its quotes.
pub(crate) struct Share {
    pub(crate) amount: Amount,
    pub(crate) gas: u128,
}

/// `quotes`' share of `receipt`, a transaction that paid `paid` quotes in
/// all: the whole receipt when they are all of them.
///
/// # Errors
///
/// If the amounts overflow.
pub(crate) fn share_of(
    receipt: &PaymentReceipt,
    quotes: &[QuoteTuple],
    paid: usize,
) -> Result<Share> {
    if quotes.len() >= paid {
        return Ok(Share {
            amount: receipt.amount,
            gas: receipt.gas_cost_wei,
        });
    }
    let amount = quotes.iter().try_fold(Amount::ZERO, |sum, quote| {
        sum.checked_add(quote.2)
            .ok_or_else(|| Error::Payment("payment total overflow".into()))
    })?;
    let gas = receipt.gas_cost_wei.saturating_mul(quotes.len() as u128) / (paid.max(1) as u128);
    Ok(Share { amount, gas })
}

/// The transaction to reconcile a member paying `quotes` by: the wave's
/// file's, while it is there (it holds the latest the wave signed), else the
/// member's own copy (`own`). `None` when nothing was signed for the member:
/// neither is there, or the member saved no copy and the file doesn't pay
/// its quotes, as when it left the wave before it closed. A wave's every
/// transaction pays the quotes it closed with, so the latest says whether
/// any paid them.
///
/// # Errors
///
/// If the member saved a copy and the transaction doesn't pay every one of
/// its quotes: its journal names a wave that didn't pay for its records,
/// and it is kept.
pub(crate) fn wave_payment(
    file: Option<WaveSigned>,
    own: Option<WaveSigned>,
    quotes: &[QuoteTuple],
) -> Result<Option<WaveSigned>> {
    let saved = own.is_some();
    let Some(signed) = file.or(own) else {
        return Ok(None);
    };
    let paid = signed.quotes.iter().copied().collect::<HashSet<_>>();
    if quotes.iter().all(|quote| paid.contains(quote)) {
        Ok(Some(signed))
    } else if saved {
        Err(Error::InvalidData(format!(
            "the shared wave {} doesn't pay this payment's quotes; its journal is kept",
            signed.wave
        )))
    } else {
        Ok(None)
    }
}

fn wave_path(wave: &str) -> Result<PathBuf> {
    if wave.len() != 64 || !wave.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidData(format!(
            "not a shared wave's id: {wave}"
        )));
    }
    Ok(crate::config::data_dir()
        .map_err(|e| Error::Config(e.to_string()))?
        .join(WAVES)
        .join(format!("{wave}.json")))
}

/// Write the wave's file, whole or not at all.
///
/// # Errors
///
/// If it can't be written: then nothing may be sent for the wave.
pub(crate) fn write_wave_file(journal: &WaveSigned) -> Result<()> {
    use std::io::Write;
    let path = wave_path(&journal.wave)?;
    let directory = path
        .parent()
        .ok_or_else(|| Error::Config("missing waves directory".into()))?;
    std::fs::create_dir_all(directory)?;
    let bytes = serde_json::to_vec(journal).map_err(|e| Error::Serialization(e.to_string()))?;
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(&path).map_err(|e| Error::Io(e.error))?;
    Ok(())
}

/// The wave's file, if it is there.
///
/// # Errors
///
/// If it is there and can't be read: the journal is kept.
pub(crate) fn read_wave_file(wave: &str) -> Result<Option<WaveSigned>> {
    match std::fs::read(wave_path(wave)?) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::Serialization(format!("the shared wave {wave}'s file: {e}"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

/// Remove the wave's file once every member saved its transaction. One left
/// behind is only logged: a member reconciling the wave prefers it, and it
/// holds the same transaction.
pub(crate) fn remove_wave_file(wave: &str) {
    if let Ok(path) = wave_path(wave) {
        if let Err(error) = std::fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("Could not remove {}: {error}", path.display());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ant_protocol::evm::TxHash;

    fn quote(byte: u8, amount: u64) -> QuoteTuple {
        (
            QuoteHash::from([byte; 32]),
            RewardsAddress::new([byte; 20]),
            Amount::from(amount),
        )
    }

    fn signed(bytes: &[u8]) -> SignedPayment {
        serde_json::from_value(serde_json::json!({ "raw": bytes })).unwrap()
    }

    fn receipt(amount: u64, gas: u128) -> PaymentReceipt {
        PaymentReceipt {
            transaction_hash: TxHash::from([7; 32]),
            amount: Amount::from(amount),
            winner_pool: None,
            gas_cost_wei: gas,
        }
    }

    /// A wave closes once every member is ready, and it is full, or holds
    /// every upload in progress, or has waited its time.
    #[test]
    fn a_wave_closes_when_ready_and_full_complete_or_waited() {
        let wait = SHARED_WAVE_WAIT;
        let short = Duration::from_millis(1);
        assert!(closes(true, PAYMENT_WAVE_SIZE, 1, 5, short, wait));
        assert!(closes(true, 3, 2, 2, short, wait));
        assert!(closes(true, 3, 1, 2, wait, wait));
        assert!(!closes(true, 3, 1, 2, short, wait));
        assert!(!closes(false, PAYMENT_WAVE_SIZE, 2, 2, wait, wait));
    }

    /// The first payment opens and leads a wave, the next joins it while
    /// its records fit, and one that doesn't fit, or comes after it
    /// closed, opens the next. A wave whose leader stopped takes no one.
    #[test]
    fn payments_join_the_open_wave_while_they_fit() {
        let waves = SharedWaves::default();
        let first = waves.join(10);
        assert!(first.leads());
        let second = waves.join(PAYMENT_WAVE_SIZE - 10);
        assert!(!second.leads());
        assert_eq!(first.wave_id(), second.wave_id());
        let third = waves.join(1);
        assert!(third.leads());
        assert_ne!(third.wave_id(), first.wave_id());
        drop(third);
        let fourth = waves.join(1);
        assert!(fourth.leads(), "a wave whose leader stopped takes no one");
    }

    /// Each member's share: its own quotes' amount, and the gas in
    /// proportion; a payment alone takes the whole receipt.
    #[test]
    fn a_member_pays_its_own_quotes_and_its_part_of_the_gas() {
        let mine = [quote(1, 30), quote(2, 10)];
        let share = share_of(&receipt(100, 900), &mine, 6).unwrap();
        assert_eq!(share.amount, Amount::from(40u64));
        assert_eq!(share.gas, 300);
        let alone = share_of(&receipt(40, 900), &mine, 2).unwrap();
        assert_eq!((alone.amount, alone.gas), (Amount::from(40u64), 900));
    }

    /// A member reconciles by the wave's file while it is there, else by
    /// its own copy; with neither, nothing was signed. A member that saved
    /// no copy, and isn't paid by the file, was left out of the wave: nothing
    /// was signed for it. One that saved a copy must be paid by it.
    #[test]
    fn a_member_reconciles_by_the_file_then_its_copy() {
        let journal = |raw: &[u8]| WaveSigned {
            wave: "ab".repeat(32),
            transaction: signed(raw),
            quotes: vec![quote(1, 30), quote(2, 10), quote(3, 5)],
        };
        let raw = |signed: &WaveSigned| serde_json::to_value(&signed.transaction).unwrap();
        let mine = [quote(1, 30), quote(3, 5)];
        let from_file = wave_payment(Some(journal(b"later")), Some(journal(b"earlier")), &mine)
            .unwrap()
            .unwrap();
        assert_eq!(raw(&from_file), raw(&journal(b"later")));
        let own = wave_payment(None, Some(journal(b"earlier")), &mine)
            .unwrap()
            .unwrap();
        assert_eq!(raw(&own), raw(&journal(b"earlier")));
        assert!(wave_payment(None, None, &mine).unwrap().is_none());
        let left_out = [quote(4, 5)];
        assert!(wave_payment(Some(journal(b"x")), None, &left_out)
            .unwrap()
            .is_none());
        assert!(wave_payment(Some(journal(b"x")), Some(journal(b"x")), &left_out).is_err());
        assert!(wave_payment(None, Some(journal(b"x")), &left_out).is_err());
    }

    /// A wave's file is written whole and read back, and goes once every
    /// member saved its transaction; an id that isn't one is refused.
    #[test]
    fn a_waves_file_is_written_read_and_removed() {
        let journal = WaveSigned {
            wave: hex::encode(rand::random::<[u8; 32]>()),
            transaction: signed(b"signed"),
            quotes: vec![quote(1, 30)],
        };
        assert!(read_wave_file(&journal.wave).unwrap().is_none());
        write_wave_file(&journal).unwrap();
        let read = read_wave_file(&journal.wave).unwrap().unwrap();
        assert_eq!(read.quotes, journal.quotes);
        remove_wave_file(&journal.wave);
        assert!(read_wave_file(&journal.wave).unwrap().is_none());
        assert!(read_wave_file("../escape").is_err());
    }

    /// A wave's file is never removed by age: one untouched for a year is
    /// still there after another wave writes its own. A member's checkpoint
    /// that names the wave is kept while its payment is pending, and the
    /// file may be its only record of what the wave signed.
    #[test]
    fn a_waves_file_is_never_removed_by_age() {
        let journal = |byte: u8| WaveSigned {
            wave: hex::encode(rand::random::<[u8; 32]>()),
            transaction: signed(&[byte]),
            quotes: vec![quote(byte, 30)],
        };
        let old = journal(1);
        write_wave_file(&old).unwrap();
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(365 * 24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(wave_path(&old.wave).unwrap())
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let new = journal(2);
        write_wave_file(&new).unwrap();
        assert!(read_wave_file(&old.wave).unwrap().is_some());
        remove_wave_file(&old.wave);
        remove_wave_file(&new.wave);
    }

    /// Two uploads in progress share one wave: its leader closes it once
    /// both are ready, publishes one transaction, which each saves, and
    /// each learns how it ended and how many quotes it paid.
    #[tokio::test]
    async fn two_uploads_share_one_wave_and_each_saves_its_transaction() {
        let waves = Arc::new(SharedWaves::default());
        let (_a, _b) = (waves.upload(), waves.upload());
        let leader = waves.join(2);
        let member = waves.join(1);
        leader.ready(vec![quote(3, 5), quote(1, 30)]);
        let lead = async {
            let quotes = leader.close(&waves).await;
            assert_eq!(quotes, vec![quote(1, 30), quote(2, 10), quote(3, 5)]);
            let journal = WaveSigned {
                wave: leader.wave_id(),
                transaction: signed(b"wave"),
                quotes,
            };
            assert!(leader.publish(journal).await, "both saved it");
            leader.end(WaveEnd::Settled(Settled::Confirmed(receipt(45, 30))));
        };
        let join_later = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            member.ready(vec![quote(2, 10)]);
            take(&member).await
        };
        let ((), (leader_saved, leader_end), (member_saved, member_end)) =
            tokio::join!(lead, take(&leader), join_later);
        assert_eq!((leader_saved, member_saved), (1, 1));
        for ended in [leader_end, member_end] {
            assert_eq!(ended.quotes, 3);
            assert!(matches!(
                ended.ended,
                WaveEnd::Settled(Settled::Confirmed(ref receipt))
                    if receipt.amount == Amount::from(45u64)
            ));
        }
        // Closed: the next payment opens a wave of its own.
        assert!(waves.join(1).leads());
    }

    /// What a member does until its wave ends: save each transaction
    /// published. Returns how many it saved and how the wave ended.
    async fn take(member: &Member) -> (usize, Ended) {
        let mut saved = 0;
        loop {
            match member.next().await {
                Step::Save(round, journal) => {
                    assert_eq!(journal.wave, member.wave_id());
                    saved += 1;
                    member.saved(round, true);
                }
                Step::Ended(ended) => return (saved, ended),
            }
        }
    }

    /// A member whose leader stops before the wave ends is told so, and
    /// keeps its journal to reconcile on a retry.
    #[tokio::test]
    async fn a_member_learns_its_leader_stopped() {
        let waves = SharedWaves::default();
        let leader = waves.join(1);
        let member = waves.join(1);
        member.ready(vec![quote(1, 1)]);
        drop(leader);
        let Step::Ended(ended) = member.next().await else {
            panic!("the wave stopped");
        };
        assert!(matches!(ended.ended, WaveEnd::Stopped));
    }
}
