//! Payments through a root vault: listings, payments found at upload and
//! proofs, read from a receipt that shows the wave whole, beside the
//! per-quote vault's; and the refusals, of a wave whose transfers don't
//! show and of a log from a contract outside the vault set.

use super::*;
use crate::envelope::Salt;
use crate::flags::{Flags, PaymentField, ShownFields};
use crate::proof::{check_proof, EnvelopeProof, ProofError};
use crate::root::{
    leaf_key, recorded_wave, RecordedWave, RecordedWaves, RootPayment, Wave, WaveError,
    WaveLogError, TRANSFER_TOPIC, WHOLE_CHECKS,
};
use crate::test_support::{
    address_word, data_map, metadata, payment_log, receipt, receipt_vector, root_wave_logs,
    root_wave_logs_at, signed_quote, BLOCK_TIME, PAYER, REWARDS, ROOT_VAULT, TOKEN, VAULT, VAULTS,
};
use ant_protocol::evm::Amount;
use std::cell::Cell;

const TX: [u8; 32] = [0x77; 32];
const BLOCK: u64 = 1_000;
const NOW: u64 = BLOCK_TIME + 30;
const SALT: Salt = [0x5a; 32];

/// A contract outside the vault set, as a retired vault is.
const RETIRED: [u8; 20] = [0x7e; 20];

/// Block timestamps: two seconds a block.
fn block_time(block: u64) -> u64 {
    BLOCK_TIME - 2 * BLOCK + 2 * block
}

/// Every valid flags byte.
fn every_flags() -> impl Iterator<Item = Flags> {
    (0..Flags::RESERVED).map(|byte| Flags::from_byte(byte).unwrap())
}

/// An envelope with `flags`.
fn envelope(flags: Flags) -> Envelope {
    let map = data_map(&[10, 10, 10]);
    let meta = metadata(Some("text/plain"), Some("a.txt"));
    if flags.withheld {
        Envelope::withheld(&map, &SALT, meta, flags.shown, flags.in_index)
    } else {
        Envelope::readable(&map, meta, flags.shown, flags.in_index)
    }
    .unwrap()
}

/// A payment of a content chunk: `amount` to an address of the byte
/// `payee`, for a quote whose hash is the byte `seed` 32 times.
fn other(seed: u8, payee: u8, amount: u64) -> RootPayment {
    RootPayment {
        quote_hash: [seed; 32],
        payee: [payee; 20],
        amount: Amount::from(amount),
    }
}

/// An envelope's payment through the root vault, in a wave with `others`.
struct Paid {
    envelope: Envelope,
    quote: PaymentQuote,
    wave: Wave,
    /// The envelope's payment's place in the wave.
    place: usize,
    /// The wave's logs, from log index `first` on.
    logs: Vec<PaymentLog>,
}

impl Paid {
    fn new(flags: Flags, others: &[RootPayment], first: u64) -> Self {
        let envelope = envelope(flags);
        let quote = signed_quote(envelope.address());
        let own = RootPayment {
            quote_hash: quote.hash().0,
            payee: REWARDS,
            amount: Amount::from(261),
        };
        let mut payments = others.to_vec();
        payments.push(own);
        payments.sort_by_key(|payment| payment.quote_hash);
        let place = payments.iter().position(|payment| *payment == own).unwrap();
        let wave = Wave::new(payments).unwrap();
        let logs = root_wave_logs(&wave, PAYER, first);
        Self {
            envelope,
            quote,
            wave,
            place,
            logs,
        }
    }

    /// In the index, showing all five fields.
    fn shown(others: &[RootPayment], first: u64) -> Self {
        Self::new(Flags::from_byte(0x3f).unwrap(), others, first)
    }

    /// The same payment, its logs from log index `first` on.
    fn moved(&self, first: u64) -> Self {
        Self {
            envelope: self.envelope.clone(),
            quote: self.quote.clone(),
            wave: self.wave.clone(),
            place: self.place,
            logs: root_wave_logs(&self.wave, PAYER, first),
        }
    }

    /// The log index of the envelope's `DataPaymentMade` log.
    fn log_index(&self) -> u64 {
        self.logs[self.place].log_index
    }

    /// A receipt holding the wave's logs alone.
    fn receipt(&self) -> PaymentReceipt {
        receipt(TX, BLOCK, self.logs.clone())
    }

    /// The payment a node finds for the envelope in `receipt`.
    fn find(&self, receipt: &PaymentReceipt) -> Result<Payment, PaymentError> {
        find_payment(
            &self.envelope.address(),
            std::slice::from_ref(&self.quote),
            receipt,
            block_time(receipt.block_number),
            &VAULTS,
        )
    }

    /// The listing a node records from `receipt`.
    fn listing(&self, receipt: &PaymentReceipt) -> Listing {
        Listing::new(&self.envelope, &self.find(receipt).unwrap(), NOW)
    }

    /// The envelope's payment as the wave's logs place it, in `TX` in block
    /// `BLOCK`, whether or not a receipt shows it.
    fn payment(&self) -> Payment {
        Payment {
            tx_hash: TX,
            block_number: BLOCK,
            block_timestamp: block_time(BLOCK),
            log_index: self.log_index(),
            quote: encode_quote(&self.quote).unwrap(),
        }
    }

    /// The uploader's proof, paid in `TX`.
    fn proof(&self) -> EnvelopeProof {
        EnvelopeProof::new(&self.envelope, TX, &self.quote).unwrap()
    }

    /// Every check of the envelope's payment in `receipt`, which must agree:
    /// found at upload, a listing showing all five fields, a listing showing
    /// only the tx hash and log index, and the uploader's proof. `Ok` with
    /// the log index the payment was found at.
    fn checks(&self, receipt: &PaymentReceipt) -> Result<u64, PaymentError> {
        let found = self.find(receipt).map(|payment| payment.log_index);
        let at = self.log_index();
        let honest = self.payment();
        let time = Some(block_time(BLOCK));
        let full = Listing::new(&self.envelope, &honest, NOW);
        let listed = verify_listing(&full, &self.envelope, Some(receipt), time, &VAULTS, NOW)
            .map(|check| check.paid_at.unwrap().log_index);
        let reported_envelope = envelope(Flags {
            shown: ShownFields::NONE
                .with(PaymentField::TxHash)
                .with(PaymentField::LogIndex),
            in_index: false,
            withheld: false,
        });
        let reported = Listing::new(&reported_envelope, &honest, NOW);
        let reported = verify_listing(
            &reported,
            &reported_envelope,
            Some(receipt),
            time,
            &VAULTS,
            NOW,
        )
        .map(|_| at);
        let proven = check_proof(&self.proof(), receipt, block_time(BLOCK), &VAULTS)
            .map(|proven| proven.payment.log_index)
            .map_err(|error| match error {
                ProofError::Payment(error) => error,
                other => panic!("{other}"),
            });
        assert_eq!(found, listed);
        assert_eq!(found, proven);
        assert_eq!(found, reported);
        found
    }
}

/// What a caller fetches for `lookup` from a chain holding `receipts`: each
/// receipt the lookup locates, by the vault set's logs, with its block's
/// timestamp.
fn fetch(
    receipts: &[PaymentReceipt],
    lookup: Lookup,
) -> Vec<(Option<PaymentReceipt>, Option<u64>)> {
    let vault_log = |log: &PaymentLog| {
        VAULTS.contains(&log.address)
            && log.topics.len() == 4
            && log.topics[0] == DATA_PAYMENT_MADE_TOPIC
    };
    let found: Vec<&PaymentReceipt> = match lookup {
        Lookup::Transaction { tx_hash } => {
            receipts.iter().filter(|r| r.tx_hash == tx_hash).collect()
        }
        Lookup::Quote {
            quote_hash,
            block_number,
            not_after,
            ..
        } => receipts
            .iter()
            .filter(|r| {
                block_number.is_none_or(|block| r.block_number == block)
                    && not_after.is_none_or(|latest| block_time(r.block_number) <= latest)
                    && r.logs
                        .iter()
                        .any(|log| vault_log(log) && log.topics[3] == quote_hash)
            })
            .collect(),
        Lookup::BlockLog {
            block_number,
            log_index,
        } => receipts
            .iter()
            .filter(|r| {
                r.block_number == block_number
                    && r.logs
                        .iter()
                        .any(|log| vault_log(log) && log.log_index == log_index)
            })
            .collect(),
        Lookup::Block { block_number } => return vec![(None, Some(block_time(block_number)))],
        Lookup::Nothing => return Vec::new(),
    };
    found
        .into_iter()
        .map(|r| (Some(r.clone()), Some(block_time(r.block_number))))
        .collect()
}

/// Check `listing` as a reader does: fetch what it says from `receipts`, and
/// check it against everything found.
fn check(
    receipts: &[PaymentReceipt],
    listing: &Listing,
    envelope: &Envelope,
) -> Result<ListingCheck, PaymentError> {
    let fetched = fetch(receipts, payment_lookup(listing)?);
    verify_listing_receipts(listing, envelope, &fetched, &VAULTS, NOW)
}

/// Each place in `receipt`, read for the tests' root vault with one
/// [`RecordedWaves`] in log order, as `paying_log` reads them, and again in
/// the reverse order, gives what [`recorded_wave`] gives it alone: a wave
/// checked once for all its logs is checked as it is for each.
fn read_together_as_alone(receipt: &PaymentReceipt) {
    let root = VAULTS.root.unwrap();
    read_together_as_alone_at(receipt, &root);
}

/// [`read_together_as_alone`] for `vault`.
fn read_together_as_alone_at(receipt: &PaymentReceipt, vault: &RootVault) {
    let mut places: Vec<u64> = receipt.logs.iter().map(|log| log.log_index).collect();
    places.sort_unstable();
    places.dedup();
    let reversed: Vec<u64> = places.iter().rev().copied().collect();
    for order in [places, reversed] {
        let mut waves = RecordedWaves::new(receipt, *vault);
        for at in order {
            assert_eq!(
                waves.check(at),
                recorded_wave(receipt, vault, at).map(drop),
                "{at}"
            );
        }
    }
}

/// What `run` gives, and how many waves it checked as a whole.
fn whole_checks<T>(run: impl FnOnce() -> T) -> (T, usize) {
    let before = WHOLE_CHECKS.with(Cell::get);
    let result = run();
    (result, WHOLE_CHECKS.with(Cell::get) - before)
}

/// A payment of a content chunk, as [`other`], whose quote hash is `n`
/// itself: below any quote's hash but a few.
fn low(n: u8, payee: u8, amount: u64) -> RootPayment {
    let mut payment = other(0, payee, amount);
    payment.quote_hash[31] = n;
    payment
}

/// A payment of a content chunk, as [`other`], whose quote hash is the
/// largest less `n`: above any quote's hash but a few.
fn high(n: u8, payee: u8, amount: u64) -> RootPayment {
    let mut payment = other(0xff, payee, amount);
    payment.quote_hash[31] = 0xff - n;
    payment
}

/// Content payments to four payees, the envelope's among them, two quote
/// hashes below the envelope's and three above. So the wave holds six
/// payments, the envelope's third, and four transfers.
fn others() -> Vec<RootPayment> {
    vec![
        low(1, 0x31, 7),
        low(2, 0xab, 11),
        high(2, 0x32, 13),
        high(1, 0x31, 17),
        high(0, 0x33, 19),
    ]
}

#[test]
fn the_vaults_own_receipt_reads_whole_from_each_payment() {
    // A receipt the vault's own code wrote on a local chain: five payments,
    // the last leaf carried up, two payees paid twice and the payer one of
    // the payees; the logs from log index 1 on, the payer's approval taking
    // index 0 in the block.
    let vector = receipt_vector();
    let root = vector.vault;
    let wave = &vector.wave;
    let count = wave.leaf_count();
    let first = vector.logs[0].log_index;
    assert_eq!((count, first), (5, 1));
    assert_eq!(vector.logs.len(), 5 + 1 + 3);
    let sums = wave.sums();
    assert_eq!(sums.len(), 3);
    assert!(sums.iter().any(|(payee, _)| *payee == vector.payer));
    assert_eq!(wave.path(4).map(|path| path.len()), Some(1));

    // What the vault gave for the wave is the wave's, and each path the
    // vault accepted is the payment's own and leads to the key.
    assert_eq!(wave.root(), vector.root);
    assert_eq!(wave.key(&root.address), vector.key);
    assert_eq!(wave.total(), vector.total);
    assert_eq!(vector.paths.len(), 5);
    for (at, path) in vector.paths.iter().enumerate() {
        assert_eq!(wave.path(at).as_ref(), Some(path), "{at}");
        let payment = &wave.payments()[at];
        assert_eq!(
            leaf_key(&root.address, payment, at as u64, count, path),
            Some(vector.key),
            "{at}"
        );
    }

    // The tests' fixture writes these logs exactly, given this vault and
    // token: the tests built on it read logs as the vault writes them.
    assert_eq!(
        root_wave_logs_at(&root, wave, vector.payer, first),
        vector.logs
    );

    // Each payment's log reads the wave back whole, and is the payment a
    // listing showing its log index finds; a listing showing no log index
    // finds the wave's first.
    let written = receipt(TX, BLOCK, vector.logs.clone());
    read_together_as_alone_at(&written, &root);
    let vaults = VaultSet::with_root(VAULT, root);
    let read = RecordedWave {
        wave: wave.clone(),
        key: vector.key,
        payer: vector.payer,
        first_log_index: first,
    };
    for at in first..first + count {
        assert_eq!(recorded_wave(&written, &root, at), Ok(read.clone()), "{at}");
        let found = paying_log(&written, &vaults, |log, vault| {
            at_index(log, Some(at)) && is_vault_payment(log, vault)
        });
        assert_eq!(found.map(|log| log.log_index), Ok(at), "{at}");
    }
    let found = paying_log(&written, &vaults, |log, vault| {
        at_index(log, None) && is_vault_payment(log, vault)
    });
    assert_eq!(found.map(|log| log.log_index), Ok(first));
    // RootPaid's place and the transfers' hold no payment of the wave.
    for at in first + count..first + count + 4 {
        assert_eq!(
            recorded_wave(&written, &root, at),
            Err(WaveLogError::Payments),
            "{at}"
        );
    }

    // Without any one of its transfers, the payer's to itself among them, the
    // wave reads as unpaid from each of its payments.
    for transfer in first + count + 1..first + count + 4 {
        let short = receipt(TX, BLOCK, without(&vector.logs, transfer));
        read_together_as_alone_at(&short, &root);
        for at in first..first + count {
            assert_eq!(
                recorded_wave(&short, &root, at).map(drop),
                Err(WaveLogError::Transfers),
                "{transfer}, {at}"
            );
        }
    }
}

#[test]
fn listings_paid_through_either_vault_verify() {
    for flags in every_flags() {
        let paid = Paid::new(flags, &others(), 3);
        let root_receipt = paid.receipt();

        // The same envelope paid through the per-quote vault instead.
        let v2_receipt = receipt(TX, BLOCK, vec![payment_log(&paid.quote, 3)]);

        for (receipt, log_index) in [(root_receipt, paid.log_index()), (v2_receipt, 3)] {
            let payment = paid.find(&receipt).unwrap();
            assert_eq!(payment.log_index, log_index, "{flags:?}");
            assert_eq!(payment.tx_hash, TX);
            let listing = Listing::new(&paid.envelope, &payment, NOW);
            let expected = if flags.shown.contains(PaymentField::Quote) {
                ListingCheck {
                    level: CheckLevel::Verified,
                    paid_at: Some(PaidAt {
                        block_number: BLOCK,
                        log_index,
                    }),
                }
            } else {
                ListingCheck {
                    level: CheckLevel::Reported,
                    paid_at: None,
                }
            };
            let receipts = [receipt.clone()];
            assert_eq!(
                check(&receipts, &listing, &paid.envelope),
                Ok(expected),
                "{flags:?}"
            );

            // The uploader's proof gives every field back.
            let proof = EnvelopeProof::from_payment(&paid.envelope, &payment).unwrap();
            let proven = check_proof(&proof, &receipt, block_time(BLOCK), &VAULTS).unwrap();
            assert_eq!(proven.payment, payment, "{flags:?}");
        }
    }
}

#[test]
fn pays_and_is_vault_payment_take_one_address() {
    let paid = Paid::shown(&others(), 0);
    let root_log = &paid.logs[paid.place];
    let v2_log = payment_log(&paid.quote, 0);
    assert!(pays(root_log, &ROOT_VAULT, &paid.quote));
    assert!(!pays(root_log, &VAULT, &paid.quote));
    assert!(pays(&v2_log, &VAULT, &paid.quote));
    assert!(!pays(&v2_log, &ROOT_VAULT, &paid.quote));
    assert!(is_vault_payment(root_log, &ROOT_VAULT));
    assert!(!is_vault_payment(root_log, &VAULT));
    assert!(!is_vault_payment(&v2_log, &ROOT_VAULT));

    // A reader whose set has no root vault doesn't take a root vault's
    // payment, and says why.
    let found = find_payment(
        &paid.envelope.address(),
        std::slice::from_ref(&paid.quote),
        &paid.receipt(),
        block_time(BLOCK),
        &VaultSet::v2_only(VAULT),
    );
    assert_eq!(found, Err(PaymentError::UnknownVault));

    assert_eq!(VAULTS.addresses(), [VAULT, ROOT_VAULT]);
    assert_eq!(VaultSet::v2_only(VAULT).addresses(), [VAULT]);
    assert!(VAULTS.contains(&VAULT) && VAULTS.contains(&ROOT_VAULT));
    assert!(!VAULTS.contains(&TOKEN) && !VAULTS.contains(&RETIRED));
}

/// `logs` with the log at `log_index` changed by `change`.
fn changed(
    logs: &[PaymentLog],
    log_index: u64,
    change: impl FnOnce(&mut PaymentLog),
) -> Vec<PaymentLog> {
    let mut logs = logs.to_vec();
    change(
        logs.iter_mut()
            .find(|log| log.log_index == log_index)
            .unwrap(),
    );
    logs
}

/// `logs` without the log at `log_index`, the later ones moved up one place.
fn without(logs: &[PaymentLog], log_index: u64) -> Vec<PaymentLog> {
    logs.iter()
        .filter(|log| log.log_index != log_index)
        .cloned()
        .map(|mut log| {
            if log.log_index > log_index {
                log.log_index -= 1;
            }
            log
        })
        .collect()
}

/// `logs` without the log at `log_index`, leaving its place empty.
fn gap(logs: &[PaymentLog], log_index: u64) -> Vec<PaymentLog> {
    logs.iter()
        .filter(|log| log.log_index != log_index)
        .cloned()
        .collect()
}

/// `logs` with `extra` put at `log_index`, the later ones moved down one place.
fn with(logs: &[PaymentLog], log_index: u64, extra: PaymentLog) -> Vec<PaymentLog> {
    let mut logs: Vec<PaymentLog> = logs
        .iter()
        .cloned()
        .map(|mut log| {
            if log.log_index >= log_index {
                log.log_index += 1;
            }
            log
        })
        .collect();
    logs.push(PaymentLog { log_index, ..extra });
    logs.sort_by_key(|log| log.log_index);
    logs
}

/// A token transfer of `amount` from `from` to `to`.
fn transfer(token: [u8; 20], from: [u8; 20], to: [u8; 20], amount: u64) -> PaymentLog {
    PaymentLog {
        address: token,
        topics: vec![TRANSFER_TOPIC, address_word(&from), address_word(&to)],
        data: Amount::from(amount).to_be_bytes::<32>().to_vec(),
        log_index: 0,
    }
}

/// A token approval, which the token may log beside a transfer.
fn approval() -> PaymentLog {
    use sha3::{Digest, Keccak256};
    let topic: [u8; 32] = Keccak256::digest(b"Approval(address,address,uint256)").into();
    PaymentLog {
        address: TOKEN,
        topics: vec![topic, address_word(&PAYER), address_word(&ROOT_VAULT)],
        data: vec![0; 32],
        log_index: 0,
    }
}

#[test]
fn a_wave_whose_transfers_dont_show_reads_as_unpaid() {
    // Logs 0 to 5: six payments; 6: RootPaid; 7 to 10: one transfer to each
    // of four payees, in the order they first appear.
    let paid = Paid::shown(&others(), 0);
    let logs = &paid.logs;
    assert_eq!(logs.len(), 11);
    assert_eq!(paid.wave.sums().len(), 4);
    assert_eq!(paid.checks(&paid.receipt()), Ok(paid.log_index()));

    let unpaid = Err(PaymentError::UnpaidWave(WaveLogError::Transfers));
    let refused: Vec<(&str, Vec<PaymentLog>)> = vec![
        ("one transfer missing", without(logs, 8)),
        ("the last transfer missing", without(logs, 10)),
        ("every transfer missing", logs[..7].to_vec()),
        (
            "a transfer one short",
            changed(logs, 9, |log| {
                let amount = Amount::from_be_bytes::<32>(log.data.as_slice().try_into().unwrap());
                log.data = (amount - Amount::from(1)).to_be_bytes::<32>().to_vec();
            }),
        ),
        (
            "a transfer one over",
            changed(logs, 7, |log| {
                let amount = Amount::from_be_bytes::<32>(log.data.as_slice().try_into().unwrap());
                log.data = (amount + Amount::from(1)).to_be_bytes::<32>().to_vec();
            }),
        ),
        (
            "a transfer from another account",
            changed(logs, 8, |log| log.topics[1] = address_word(&[0x51; 20])),
        ),
        (
            "a transfer to another account",
            changed(logs, 10, |log| log.topics[2] = address_word(&[0x34; 20])),
        ),
        (
            "a transfer from another contract",
            changed(logs, 9, |log| log.address = [0x71; 20]),
        ),
        (
            "a transfer without its amount",
            changed(logs, 9, |log| log.data.clear()),
        ),
        (
            "two transfers to one payee",
            changed(logs, 10, |log| log.topics[2] = logs[9].topics[2]),
        ),
        (
            "a transfer after another contract's log",
            with(
                logs,
                9,
                PaymentLog {
                    address: [0x71; 20],
                    topics: vec![[0x99; 32]],
                    data: Vec::new(),
                    log_index: 0,
                },
            ),
        ),
    ];
    for (case, logs) in refused {
        let receipt = receipt(TX, BLOCK, logs);
        assert_eq!(paid.checks(&receipt), unpaid, "{case}");
        read_together_as_alone(&receipt);
    }

    // The transfers in another order, the token's own other logs between
    // them, or more logs after them, change nothing.
    let mut reordered = logs.to_vec();
    reordered[7].log_index = 10;
    reordered[10].log_index = 7;
    let accepted: Vec<(&str, Vec<PaymentLog>)> = vec![
        ("transfers in another order", reordered),
        (
            "approvals between transfers",
            with(&with(logs, 7, approval()), 10, approval()),
        ),
        (
            "a later payment's transfer",
            with(logs, 11, transfer(TOKEN, PAYER, REWARDS, 261)),
        ),
    ];
    for (case, logs) in accepted {
        let receipt = receipt(TX, BLOCK, logs);
        assert_eq!(paid.checks(&receipt), Ok(paid.log_index()), "{case}");
        read_together_as_alone(&receipt);
    }
}

#[test]
fn a_wave_is_read_whole_or_not_at_all() {
    let paid = Paid::shown(&others(), 2);
    let logs = &paid.logs;
    assert_eq!(paid.log_index(), 4);
    let root_paid = 2 + 6;
    let unpaid = |error| Err(PaymentError::UnpaidWave(error));
    let words = |logs: &[PaymentLog], at: usize| -> Vec<u8> {
        logs.iter()
            .find(|log| log.log_index == root_paid)
            .unwrap()
            .data[at..at + 32]
            .to_vec()
    };
    let with_word = |at: usize, word: [u8; 32]| {
        changed(logs, root_paid, |log| {
            log.data[at..at + 32].copy_from_slice(&word)
        })
    };
    let count = |n: u64| Amount::from(n).to_be_bytes::<32>();
    assert_eq!(words(logs, 32), count(6));

    let mut high_payer = address_word(&PAYER);
    high_payer[0] = 1;
    let cases: Vec<(&str, Vec<PaymentLog>, WaveLogError)> = vec![
        (
            "no RootPaid",
            without(logs, root_paid),
            WaveLogError::NoRootPaid,
        ),
        (
            "RootPaid from another contract",
            changed(logs, root_paid, |log| log.address = RETIRED),
            WaveLogError::NoRootPaid,
        ),
        (
            "RootPaid with another key",
            changed(logs, root_paid, |log| log.topics[1][0] ^= 1),
            WaveLogError::NotTheWave,
        ),
        (
            "RootPaid with another total",
            with_word(64, count(1)),
            WaveLogError::NotTheWave,
        ),
        (
            "RootPaid naming one leaf more",
            with_word(32, count(7)),
            WaveLogError::Payments,
        ),
        (
            "RootPaid naming one leaf fewer",
            with_word(32, count(5)),
            WaveLogError::NotTheWave,
        ),
        (
            "RootPaid naming no leaves",
            with_word(32, count(0)),
            WaveLogError::BadRootPaid,
        ),
        (
            "RootPaid naming 513 leaves",
            with_word(32, count(513)),
            WaveLogError::BadRootPaid,
        ),
        (
            "RootPaid with a payer of more than 20 bytes",
            with_word(0, high_payer),
            WaveLogError::BadRootPaid,
        ),
        (
            "RootPaid without its total",
            changed(logs, root_paid, |log| log.data.truncate(64)),
            WaveLogError::BadRootPaid,
        ),
        (
            "RootPaid without its key",
            changed(logs, root_paid, |log| log.topics.truncate(1)),
            WaveLogError::BadRootPaid,
        ),
        // A payment's log missing after the envelope's, or before it.
        (
            "a payment's log missing after it",
            gap(logs, 6),
            WaveLogError::NoRootPaid,
        ),
        (
            "a payment's log missing before it",
            gap(logs, 2),
            WaveLogError::Payments,
        ),
        (
            "two payments' logs swapped",
            {
                let mut swapped = logs.to_vec();
                swapped[0].log_index = 3;
                swapped[1].log_index = 2;
                swapped
            },
            WaveLogError::Refused(WaveError::QuoteHashesNotAscending(1)),
        ),
        (
            "a payee of more than 20 bytes",
            changed(logs, 3, |log| log.topics[1][0] = 1),
            WaveLogError::Payments,
        ),
        (
            "two logs at one place",
            {
                let mut doubled = logs.to_vec();
                doubled.push(logs[0].clone());
                doubled
            },
            WaveLogError::Payments,
        ),
    ];
    for (case, logs, error) in cases {
        let receipt = receipt(TX, BLOCK, logs);
        assert_eq!(paid.checks(&receipt), unpaid(error), "{case}");
        read_together_as_alone(&receipt);
    }
}

#[test]
fn a_recorded_wave_reads_back_with_its_key_payer_and_places() {
    let paid = Paid::shown(&others(), 5);
    let receipt = paid.receipt();
    let root = VAULTS.root.unwrap();
    for at in 5..11 {
        let read = recorded_wave(&receipt, &root, at).unwrap();
        assert_eq!(read.wave, paid.wave);
        assert_eq!(read.key, paid.wave.key(&ROOT_VAULT));
        assert_eq!(read.payer, PAYER);
        assert_eq!(read.first_log_index, 5);
    }
    // RootPaid's own place, a transfer's, or a place outside the receipt
    // holds no payment of the wave.
    for at in [4, 11, 12, 16, 17, u64::MAX] {
        assert_eq!(
            recorded_wave(&receipt, &root, at),
            Err(WaveLogError::Payments),
            "{at}"
        );
    }
    // Read for another root vault, it isn't that vault's wave.
    let other = RootVault {
        address: [0x6b; 20],
        token: TOKEN,
    };
    assert_eq!(
        recorded_wave(&receipt, &other, 5),
        Err(WaveLogError::Payments)
    );
    // Paid in another token, the transfers aren't the vault's.
    let other = RootVault {
        token: [0x71; 20],
        ..root
    };
    assert_eq!(
        recorded_wave(&receipt, &other, 5),
        Err(WaveLogError::Transfers)
    );
}

#[test]
fn two_waves_or_two_vaults_in_one_receipt() {
    // Two waves in one transaction, as a contract making two payments in one
    // call logs them: each is read on its own, and the same payee paid the
    // same sum in both is paid by each.
    let shared = other(0x11, 0x31, 7);
    let first = Paid::shown(&[shared, other(0x12, 0x32, 5)], 0);
    let second = Paid::shown(&[shared, other(0x13, 0x33, 9)], 7);
    assert_eq!(first.logs.len(), 7);
    let logs: Vec<PaymentLog> = first.logs.iter().chain(&second.logs).cloned().collect();
    let both = receipt(TX, BLOCK, logs.clone());
    assert_eq!(first.checks(&both), Ok(first.log_index()));
    assert_eq!(second.checks(&both), Ok(second.log_index()));
    read_together_as_alone(&both);

    // Without the first wave's transfer to the shared payee, the second's
    // doesn't stand in for it.
    let first_shared = first
        .logs
        .iter()
        .find(|log| log.topics[0] == TRANSFER_TOPIC && log.topics[2] == address_word(&[0x31; 20]))
        .unwrap()
        .log_index;
    let broken = receipt(TX, BLOCK, without(&logs, first_shared));
    assert_eq!(
        first.checks(&broken),
        Err(PaymentError::UnpaidWave(WaveLogError::Transfers))
    );
    let second_moved = second.moved(6);
    assert_eq!(second_moved.checks(&broken), Ok(second_moved.log_index()));
    read_together_as_alone(&broken);

    // A per-quote payment and a wave in one transaction, either first, the
    // per-quote vault's transfer logged before its payment.
    let v2_paid = Paid::shown(&[], 0);
    for v2_first in [true, false] {
        let wave = Paid::shown(&others(), if v2_first { 2 } else { 0 });
        let v2_at = if v2_first { 0 } else { wave.logs.len() as u64 };
        let v2_logs = [
            PaymentLog {
                log_index: v2_at,
                ..transfer(TOKEN, PAYER, REWARDS, 87)
            },
            payment_log(&v2_paid.quote, v2_at + 1),
        ];
        let logs: Vec<PaymentLog> = wave.logs.iter().chain(&v2_logs).cloned().collect();
        let mixed = receipt(TX, BLOCK, logs);
        assert_eq!(wave.checks(&mixed), Ok(wave.log_index()), "{v2_first}");
        read_together_as_alone(&mixed);
        let v2_found = find_payment(
            &v2_paid.envelope.address(),
            std::slice::from_ref(&v2_paid.quote),
            &mixed,
            block_time(BLOCK),
            &VAULTS,
        );
        assert_eq!(v2_found.map(|payment| payment.log_index), Ok(v2_at + 1));
    }
}

#[test]
fn a_log_from_outside_the_vault_set_is_never_a_payment() {
    let paid = Paid::shown(&[], 0);
    let mut from_retired = payment_log(&paid.quote, 4);
    from_retired.address = RETIRED;
    let receipt_of = |logs: Vec<PaymentLog>| receipt(TX, BLOCK, logs);

    // Alone, it is refused with its own error, which says neither that
    // nothing was found nor that it was paid.
    let alone = receipt_of(vec![from_retired.clone()]);
    let found = paid.find(&alone);
    assert_eq!(found, Err(PaymentError::UnknownVault));
    assert_eq!(
        check_proof(&paid.proof(), &alone, block_time(BLOCK), &VAULTS).unwrap_err(),
        ProofError::Payment(PaymentError::UnknownVault)
    );
    let message = PaymentError::UnknownVault.to_string();
    assert_eq!(
        message,
        "a payment log from a contract this version doesn't recognise as a vault; \
         if a newer vault exists, update this tool"
    );
    assert_ne!(message, PaymentError::NotPaid.to_string());
    assert!(!message.contains("paid"), "{message}");
    // Every listing that locates it is refused too, the quote shown or not.
    for flags in every_flags() {
        let envelope = envelope(flags);
        let quote = signed_quote(envelope.address());
        let mut log = payment_log(&quote, 4);
        log.address = RETIRED;
        let receipts = [receipt_of(vec![log.clone()])];
        let payment = Payment {
            tx_hash: TX,
            block_number: BLOCK,
            block_timestamp: block_time(BLOCK),
            log_index: 4,
            quote: encode_quote(&quote).unwrap(),
        };
        let listing = Listing::new(&envelope, &payment, NOW);
        let result = check(&receipts, &listing, &envelope);
        match payment_lookup(&listing).unwrap() {
            Lookup::Transaction { .. } => {
                assert_eq!(result, Err(PaymentError::UnknownVault), "{flags:?}");
            }
            // A search over the vaults' logs doesn't find it at all.
            Lookup::Quote { .. } | Lookup::BlockLog { .. } => {
                assert_eq!(result, Err(PaymentError::NotFound), "{flags:?}");
                let fetched = [(Some(receipts[0].clone()), Some(block_time(BLOCK)))];
                assert_eq!(
                    verify_listing_receipts(&listing, &envelope, &fetched, &VAULTS, NOW),
                    Err(PaymentError::UnknownVault),
                    "{flags:?}"
                );
            }
            Lookup::Block { .. } | Lookup::Nothing => {
                assert_eq!(result.map(|check| check.level), Ok(CheckLevel::Reported));
            }
        }
    }

    // Beside a vault's payment of the same quote, the vault's counts.
    let v2_log = payment_log(&paid.quote, 5);
    let beside = receipt_of(vec![from_retired.clone(), v2_log]);
    assert_eq!(paid.find(&beside).map(|payment| payment.log_index), Ok(5));
    // Beside a root vault's wave that doesn't check out, that says more.
    let mut logs = paid.logs.clone();
    logs.retain(|log| log.topics[0] != TRANSFER_TOPIC);
    logs.push(PaymentLog {
        log_index: 9,
        ..from_retired
    });
    assert_eq!(
        paid.find(&receipt_of(logs)),
        Err(PaymentError::UnpaidWave(WaveLogError::Transfers))
    );
}

#[test]
fn the_payer_can_be_its_own_payee() {
    let paid = Paid::shown(&[other(0x10, 0x50, 4), other(0x20, 0x31, 6)], 0);
    assert!(paid.wave.sums().iter().any(|(payee, _)| *payee == PAYER));
    assert_eq!(paid.checks(&paid.receipt()), Ok(paid.log_index()));
}

/// 511 payments of content chunks, each to a payee of its own: with the
/// envelope's, a full wave.
fn to_every_payee() -> Vec<RootPayment> {
    (0..511u16)
        .map(|n| {
            let mut quote_hash = [0; 32];
            quote_hash[..2].copy_from_slice(&(n + 1).to_be_bytes());
            let mut payee = [0x40; 20];
            payee[18..].copy_from_slice(&n.to_be_bytes());
            RootPayment {
                quote_hash,
                payee,
                amount: Amount::from(u64::from(n) + 1),
            }
        })
        .collect()
}

#[test]
fn a_full_wave_to_every_payee_reads_whole() {
    let paid = Paid::shown(&to_every_payee(), 0);
    assert_eq!(paid.wave.leaf_count(), 512);
    assert_eq!(paid.wave.sums().len(), 512);
    assert_eq!(paid.checks(&paid.receipt()), Ok(paid.log_index()));
    let last = paid.logs.last().unwrap().log_index;
    assert_eq!(
        paid.checks(&receipt(TX, BLOCK, without(&paid.logs, last))),
        Err(PaymentError::UnpaidWave(WaveLogError::Transfers))
    );
}

#[test]
fn a_wave_is_checked_once_for_all_its_logs() {
    // A listing showing only the tx hash takes any vault payment in the tx,
    // so each of a wave's logs would be the payment. A full wave whose
    // transfers don't show is refused from one check of the wave as a whole,
    // not one for each of its 512 logs.
    let flags = Flags {
        shown: ShownFields::NONE.with(PaymentField::TxHash),
        in_index: false,
        withheld: false,
    };
    let paid = Paid::new(flags, &to_every_payee(), 0);
    assert_eq!(paid.wave.leaf_count(), 512);
    let listing = Listing::new(&paid.envelope, &paid.payment(), NOW);
    assert_eq!(
        payment_lookup(&listing),
        Ok(Lookup::Transaction { tx_hash: TX })
    );
    let mut unbacked = paid.logs.clone();
    unbacked.retain(|log| log.topics[0] != TRANSFER_TOPIC);
    assert_eq!(unbacked.len(), 512 + 1);
    let receipts = [receipt(TX, BLOCK, unbacked.clone())];
    assert_eq!(
        whole_checks(|| check(&receipts, &listing, &paid.envelope)),
        (Err(PaymentError::UnpaidWave(WaveLogError::Transfers)), 1)
    );

    // Whole, it checks out from its first log, with one check too.
    let receipts = [paid.receipt()];
    assert_eq!(
        whole_checks(|| check(&receipts, &listing, &paid.envelope).map(|check| check.level)),
        (Ok(CheckLevel::Reported), 1)
    );

    // Beside a second wave that checks out, each wave is checked once: the
    // first is refused once for all its logs, and the second counts.
    let second = Paid::shown(&others(), 513);
    let both: Vec<PaymentLog> = unbacked.iter().chain(&second.logs).cloned().collect();
    let receipts = [receipt(TX, BLOCK, both)];
    assert_eq!(
        whole_checks(|| check(&receipts, &listing, &paid.envelope).map(|check| check.level)),
        (Ok(CheckLevel::Reported), 2)
    );
}

#[test]
fn a_quote_in_two_waves_counts_from_its_first() {
    // A quote put in two different waves is paid twice, in two
    // transactions; a listing found through the quote counts from the
    // earlier, whichever order the search gives.
    let shown = ShownFields::NONE.with(PaymentField::Quote);
    let flags = Flags {
        shown,
        in_index: false,
        withheld: false,
    };
    let first = Paid::new(flags, &[other(0x10, 0x31, 7)], 0);
    let own = first.wave.payments()[first.place];
    let mut payments = vec![own, other(0x20, 0x32, 9)];
    payments.sort_by_key(|payment| payment.quote_hash);
    let again = Wave::new(payments).unwrap();
    let earlier = first.receipt();
    let later = receipt([0x78; 32], BLOCK + 9, root_wave_logs(&again, PAYER, 4));
    let listing = first.listing(&earlier);
    for receipts in [[earlier.clone(), later.clone()], [later, earlier]] {
        assert_eq!(
            check(&receipts, &listing, &first.envelope),
            Ok(ListingCheck {
                level: CheckLevel::Verified,
                paid_at: Some(PaidAt {
                    block_number: BLOCK,
                    log_index: first.log_index(),
                }),
            })
        );
    }
}

#[test]
fn the_earliest_payment_of_a_quote_in_a_receipt_counts() {
    // One quote paid through both vaults in one transaction: a one-payment
    // wave at logs 0 to 2, then the per-quote vault's payment at 3. The
    // receipt lists its logs backwards; the earlier log counts.
    let paid = Paid::shown(&[], 0);
    let mut logs = paid.logs.clone();
    logs.push(payment_log(&paid.quote, 3));
    logs.reverse();
    assert_eq!(paid.checks(&receipt(TX, BLOCK, logs.clone())), Ok(0));
    // Without the wave's transfer, the per-quote vault's payment counts.
    logs.retain(|log| log.topics[0] != TRANSFER_TOPIC);
    let found = paid.find(&receipt(TX, BLOCK, logs));
    assert_eq!(found.map(|payment| payment.log_index), Ok(3));
}
