// Copyright 2026 MaidSafe.net limited.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Root payments: records paid in waves through the root vault.
//!
//! A root vault takes one payment transaction for a whole wave of records
//! and keeps one record for it, under the wave's *key*, instead of one per
//! paid quote. The wave's tree, its key and each record's path come from
//! `ant_listings::root`, the code every reader and storer shares.
//!
//! - **The wave.** The paid quotes of a payment's plans, one leaf each
//!   (the quote's hash, its rewards address and its amount), in strictly
//!   ascending quote-hash order, as the vault requires and as payments are
//!   ordered today ([`wave_of`]). The same quote hash never enters a wave
//!   twice: the vault refuses that wave, and so does [`wave_of`] before
//!   anything is signed.
//! - **The payment.** The wave's leaves as one `payForQuotes` call, the
//!   same calldata a payment to the per-quote vault takes, through a wallet
//!   built for the root vault (`Client::with_root_payments`), journaled
//!   as any payment is.
//! - **The proof.** Each record's proof (tag 0x03) carries its quotes and
//!   commitments as a single-node proof does, the transaction, and its
//!   leaf: the paid quote's hash, the amount, the leaf's place in the wave,
//!   the wave's leaf count and its path ([`root_proof`]). A storer hashes
//!   the leaf up the path to the wave's key and reads the vault's record
//!   under it.
//! - **The vault a plan pays.** Each plan records it ([`PaymentVault`]),
//!   so a plan kept in a checkpoint is always paid, and reconciled, through
//!   the vault it recorded.
//! - **One signer at a time.** A root payment and a per-quote payment from
//!   one key go through two wallets, so the client serialises every
//!   transaction a key sends through one lock per signing key
//!   ([`signing_lock`]), not through either wallet's own lock.

// Browser builds pay through the page's wallet, which neither builds a wave
// nor sends from a key of its own.
#![cfg_attr(not(feature = "native"), allow(dead_code))]

use super::batch::ChunkPaymentPlan;
use crate::data::error::{Error, Result};
use ant_listings::root::{root_from_path, RootPayment, Wave};
use ant_protocol::evm::{Address, Amount, EncodedPeerId, PaymentQuote, QuoteHash, TxHash};
use ant_protocol::payment::{serialize_root_proof, PaymentProof, RootPaymentProof};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// The vault a plan pays: the per-quote vault, or the root vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentVault {
    /// The per-quote vault (`PaymentVaultV2`): one record per paid quote.
    /// A plan saved before plans recorded their vault paid this one.
    #[default]
    V2,
    /// The root vault: one record per wave, under the wave's key.
    Root,
}

impl PaymentVault {
    /// Whether this is the per-quote vault: a plan's field is left out of
    /// its checkpoint then, as a plan saved before the field was.
    #[must_use]
    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2)
    }
}

/// The vault every one of `plans` pays.
///
/// # Errors
///
/// If `plans` pay different vaults: one payment pays one vault.
pub(crate) fn vault_of(plans: &[ChunkPaymentPlan]) -> Result<PaymentVault> {
    let vault = plans.first().map_or(PaymentVault::V2, |plan| plan.vault);
    if plans.iter().any(|plan| plan.vault != vault) {
        return Err(Error::Payment(
            "one payment holds plans for both vaults; each vault is paid in a payment of its own"
                .into(),
        ));
    }
    Ok(vault)
}

/// The leaf a paid quote is in a wave.
fn leaf_of(quote_hash: &QuoteHash, payee: &Address, amount: Amount) -> RootPayment {
    RootPayment {
        quote_hash: quote_hash.0,
        payee: payee.0 .0,
        amount,
    }
}

/// The wave paying `plans`: the paid quote of each, in ascending
/// quote-hash order.
///
/// # Errors
///
/// If the wave is one the root vault refuses: no paid quote, more than its
/// leaf limit, a quote hash twice, a zero amount or a zero payee.
pub(crate) fn wave_of(plans: &[ChunkPaymentPlan]) -> Result<Wave> {
    let mut payments = plans
        .iter()
        .flat_map(|plan| plan.payment.quotes.iter())
        .filter(|quote| !quote.amount.is_zero())
        .map(|quote| leaf_of(&quote.quote_hash, &quote.rewards_address, quote.amount))
        .collect::<Vec<_>>();
    payments.sort_by_key(|payment| payment.quote_hash);
    Wave::new(payments).map_err(|e| Error::Payment(format!("a root wave can't be paid: {e}")))
}

/// The quote payments a wave's transaction sends, in the wave's order.
#[must_use]
pub(crate) fn wave_quotes(wave: &Wave) -> Vec<(QuoteHash, Address, Amount)> {
    wave.payments()
        .iter()
        .map(|payment| {
            (
                QuoteHash::from(payment.quote_hash),
                Address::from(payment.payee),
                payment.amount,
            )
        })
        .collect()
}

/// A wave the root vault recorded, as a payment of it was confirmed.
#[derive(Debug, Clone)]
pub struct RootWavePayment {
    /// The transaction that paid it.
    pub transaction: TxHash,
    /// The wave, with its tree.
    pub wave: Wave,
}

/// The root proof of `plan`'s record, paid in `paid`'s wave.
///
/// # Errors
///
/// If the plan's paid quote is not one leaf of the wave, as its quote hash,
/// payee and amount, or the proof can't be encoded.
pub(crate) fn root_proof(plan: &ChunkPaymentPlan, paid: &RootWavePayment) -> Result<Vec<u8>> {
    let mut quotes = plan.payment.quotes.iter().filter(|q| !q.amount.is_zero());
    let (Some(quote), None) = (quotes.next(), quotes.next()) else {
        return Err(Error::Payment(format!(
            "the plan for {} pays no single quote, so it has no leaf in a root wave",
            hex::encode(plan.address)
        )));
    };
    let leaf = leaf_of(&quote.quote_hash, &quote.rewards_address, quote.amount);
    let index = paid
        .wave
        .payments()
        .iter()
        .position(|payment| *payment == leaf)
        .ok_or_else(|| {
            Error::Payment(format!(
                "the paid quote {} of {} is not a leaf of the root wave its payment sent",
                hex::encode(quote.quote_hash),
                hex::encode(plan.address)
            ))
        })?;
    let path = paid
        .wave
        .path(index)
        .ok_or_else(|| Error::Payment("a root wave's leaf has no path".into()))?;
    let proof = RootPaymentProof {
        payment: PaymentProof {
            proof_of_payment: ant_protocol::evm::ProofOfPayment {
                peer_quotes: plan.peer_quotes.clone(),
            },
            tx_hashes: vec![paid.transaction],
            // ADR-0004: forwarded as a single-node proof forwards them.
            commitment_sidecars: plan.commitment_sidecars.clone(),
        },
        quote_hash: quote.quote_hash,
        amount: quote.amount,
        index: index as u64,
        leaf_count: paid.wave.leaf_count(),
        path: path.into_iter().map(QuoteHash::from).collect(),
    };
    serialize_root_proof(&proof)
        .map_err(|e| Error::Serialization(format!("Failed to serialize root proof: {e}")))
}

/// The leaf a root proof proves, from its paid quote's hash, the rewards
/// address of the quote in it with that hash, and its amount. `None` if
/// none of its quotes has that hash.
#[must_use]
pub(crate) fn proof_leaf(proof: &RootPaymentProof) -> Option<RootPayment> {
    proof
        .payment
        .proof_of_payment
        .peer_quotes
        .iter()
        .find(|(_, quote)| quote.hash() == proof.quote_hash)
        .map(|(_, quote)| leaf_of(&proof.quote_hash, &quote.rewards_address, proof.amount))
}

/// The paid quote of a root proof: its issuer, and the quote.
#[must_use]
pub(crate) fn proof_paid_quote(
    proof: &RootPaymentProof,
) -> Option<(&EncodedPeerId, &PaymentQuote)> {
    proof
        .payment
        .proof_of_payment
        .peer_quotes
        .iter()
        .find(|(_, quote)| quote.hash() == proof.quote_hash)
        .map(|(peer, quote)| (peer, quote))
}

/// Whether a root proof is well formed: a transaction, a nonzero amount,
/// its paid quote among its quotes, and a path that leads from its leaf to
/// a root for its place and leaf count. Whether the vault recorded that
/// root's key is the chain's to say.
#[must_use]
pub(crate) fn root_proof_well_formed(proof: &RootPaymentProof) -> bool {
    let path = proof.path.iter().map(|hash| hash.0).collect::<Vec<_>>();
    !proof.payment.tx_hashes.is_empty()
        && !proof.amount.is_zero()
        && proof_leaf(proof).is_some_and(|leaf| {
            root_from_path(&leaf.leaf(), proof.index, proof.leaf_count, &path).is_some()
        })
}

/// The key the wave of a root proof is recorded under at `vault`, or
/// `None` for a proof that isn't well formed.
#[must_use]
pub(crate) fn proof_key(proof: &RootPaymentProof, vault: &[u8; 20]) -> Option<[u8; 32]> {
    let path = proof.path.iter().map(|hash| hash.0).collect::<Vec<_>>();
    let leaf = proof_leaf(proof)?;
    ant_listings::root::leaf_key(vault, &leaf, proof.index, proof.leaf_count, &path)
}

/// The locks of the signing keys of this process, by address
/// ([`signing_lock`]).
static SIGNING_LOCKS: Mutex<Option<HashMap<Address, Weak<tokio::sync::Mutex<()>>>>> =
    Mutex::new(None);

/// The lock of the signing key `address`: one per key in this process,
/// shared by every client and every wallet built with that key. Every path
/// that sends a transaction from the key holds it, so one transaction is in
/// flight per key whichever vault it pays. Separate processes with one key
/// are not serialised: one key per process.
#[must_use]
pub(crate) fn signing_lock(address: Address) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = SIGNING_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let locks = locks.get_or_insert_with(HashMap::new);
    if let Some(lock) = locks.get(&address).and_then(Weak::upgrade) {
        return lock;
    }
    locks.retain(|_, lock| lock.strong_count() > 0);
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(address, Arc::downgrade(&lock));
    lock
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::data::client::upload_state::test_state::plan_priced;
    use ant_protocol::payment::deserialize_root_proof;
    use std::time::SystemTime;

    fn plans(count: u8) -> Vec<ChunkPaymentPlan> {
        (0..count)
            .map(|n| plan_priced(&[n, 0x5a], SystemTime::now(), &[1_000 + u64::from(n)]))
            .collect()
    }

    /// The wave holds each plan's paid quote, once, in ascending quote-hash
    /// order, and its transaction sends them in that order.
    #[test]
    fn a_wave_holds_the_paid_quotes_in_quote_hash_order() {
        let plans = plans(9);
        let wave = wave_of(&plans).unwrap();
        assert_eq!(wave.leaf_count(), 9);
        let hashes = wave
            .payments()
            .iter()
            .map(|p| p.quote_hash)
            .collect::<Vec<_>>();
        assert!(hashes.windows(2).all(|pair| pair[0] < pair[1]));
        let quotes = wave_quotes(&wave);
        assert_eq!(quotes.len(), 9);
        for plan in &plans {
            let paid = plan
                .payment
                .quotes
                .iter()
                .find(|q| !q.amount.is_zero())
                .unwrap();
            assert!(quotes.contains(&(paid.quote_hash, paid.rewards_address, paid.amount)));
        }
    }

    /// A wave never holds the same quote hash twice: one is refused before
    /// anything is signed, as the vault would refuse it.
    #[test]
    fn a_wave_never_holds_a_quote_hash_twice() {
        let mut plans = plans(3);
        plans.push(plans[1].clone());
        let error = wave_of(&plans).unwrap_err().to_string();
        assert!(error.contains("repeats the quote hash"), "{error}");
        assert!(wave_of(&[]).is_err());
    }

    /// Each record's root proof leads from its leaf to the wave's key, the
    /// key the vault records the wave under.
    #[test]
    fn each_root_proof_leads_to_the_waves_key() {
        let plans = plans(7);
        let wave = wave_of(&plans).unwrap();
        let vault = [0x6a; 20];
        let paid = RootWavePayment {
            transaction: TxHash::from([0x77; 32]),
            wave: wave.clone(),
        };
        for plan in &plans {
            let bytes = root_proof(plan, &paid).unwrap();
            assert_eq!(bytes.first(), Some(&ant_protocol::PROOF_TAG_ROOT));
            let proof = deserialize_root_proof(&bytes).unwrap();
            assert!(root_proof_well_formed(&proof));
            assert_eq!(proof.leaf_count, 7);
            assert_eq!(proof.payment.tx_hashes, vec![paid.transaction]);
            assert_eq!(proof.payment.proof_of_payment.peer_quotes, plan.peer_quotes);
            assert_eq!(proof_key(&proof, &vault), Some(wave.key(&vault)));
        }
    }

    /// A plan whose paid quote isn't in the wave gets no proof, and a proof
    /// whose amount or place was changed leads to another key or none.
    #[test]
    fn a_proof_is_only_for_its_own_leaf() {
        let plans = plans(4);
        let paid = RootWavePayment {
            transaction: TxHash::from([0x77; 32]),
            wave: wave_of(&plans[..3]).unwrap(),
        };
        assert!(root_proof(&plans[3], &paid).is_err());
        let vault = [0x6a; 20];
        let mut proof = deserialize_root_proof(&root_proof(&plans[0], &paid).unwrap()).unwrap();
        proof.amount += Amount::from(1u64);
        assert_ne!(proof_key(&proof, &vault), Some(paid.wave.key(&vault)));
        proof.amount -= Amount::from(1u64);
        proof.index = 3;
        assert!(!root_proof_well_formed(&proof));
        assert_eq!(proof_key(&proof, &vault), None);
    }

    /// Every caller with one key shares one lock, whichever wallet it
    /// holds, and another key has its own.
    #[tokio::test]
    async fn one_signing_lock_per_key() {
        let key = Address::from([0x11; 20]);
        let first = signing_lock(key);
        let second = signing_lock(key);
        assert!(Arc::ptr_eq(&first, &second));
        let held = first.lock().await;
        assert!(second.try_lock().is_err());
        assert!(signing_lock(Address::from([0x22; 20])).try_lock().is_ok());
        drop(held);
        assert!(second.try_lock().is_ok());
    }

    /// A plan saved before plans recorded their vault paid the per-quote
    /// vault, and one payment never pays both.
    #[test]
    fn plans_record_their_vault() {
        let mut plans = plans(2);
        assert_eq!(vault_of(&plans).unwrap(), PaymentVault::V2);
        plans[1].vault = PaymentVault::Root;
        assert!(vault_of(&plans).is_err());
        plans[0].vault = PaymentVault::Root;
        assert_eq!(vault_of(&plans).unwrap(), PaymentVault::Root);
    }
}
