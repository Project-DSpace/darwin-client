//! A carried upload state: one client's paid state of an upload, taken
//! from its payer's `state_saved`, given to a second client
//! (`UploadPayer::carried_state`, `Client::file_upload_carried`), which
//! stores the paid records without paying for them again.

use crate::support::runner::Case;
use crate::support::{test_client_config, MiniTestnet};
use ant_core::ant_listings::Envelope;
use ant_core::data::client::upload::{MerkleUploadPayment, UploadPayment};
use ant_core::data::client::upload_state::{UploadState, CHECKPOINT_FORMAT_ROOT};
use ant_core::data::{
    CarriedUploadOptions, ChunkPaymentPlan, Client, EnvelopeOptions, Error, PaymentMode,
    PreparedMerkleBatch, UploadPayer, Visibility, CARRIED_STATE_REFUSED,
};
use ant_protocol::evm::contract::payment_vault::interface::IPaymentVault;
use ant_protocol::evm::utils::http_provider;
use ant_protocol::evm::{Amount, QuoteHash, RewardsAddress, TxHash};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::{NamedTempFile, TempDir};

pub fn cases() -> Vec<Case> {
    vec![
        Case::on_network(
            "carried::a_second_client_with_the_carried_state_stores_the_paid_records_and_asks_its_payer_for_no_payment_for_them",
            a_second_client_with_the_carried_state_stores_the_paid_records_and_asks_its_payer_for_no_payment_for_them,
        ),
        Case::on_network(
            "carried::an_occupied_quote_of_the_first_payer_is_not_paid_again_from_the_carried_state",
            an_occupied_quote_of_the_first_payer_is_not_paid_again_from_the_carried_state,
        ),
        Case::on_network(
            "carried::a_carried_payment_not_yet_confirmed_is_settled_by_the_second_payer",
            a_carried_payment_not_yet_confirmed_is_settled_by_the_second_payer,
        ),
        Case::on_network(
            "carried::expired_quotes_are_paid_again_and_counted_in_the_result",
            expired_quotes_are_paid_again_and_counted_in_the_result,
        ),
        Case::on_network(
            "carried::the_occupied_quote_path_and_the_price_ceiling_hold_for_a_record_paid_again",
            the_occupied_quote_path_and_the_price_ceiling_hold_for_a_record_paid_again,
        ),
        Case::on_network(
            "carried::a_saved_checkpoint_is_kept_and_a_refused_carried_state_leaves_it_untouched",
            a_saved_checkpoint_is_kept_and_a_refused_carried_state_leaves_it_untouched,
        ),
        Case::on_network(
            "carried::a_carried_state_with_one_quote_whose_signature_fails_is_refused_before_any_payment",
            a_carried_state_with_one_quote_whose_signature_fails_is_refused_before_any_payment,
        ),
        Case::on_network(
            "carried::the_wallet_upload_takes_a_carried_state",
            the_wallet_upload_takes_a_carried_state,
        ),
    ]
}

/// Where an occupier sends its dust.
const STRANGER: [u8; 20] = [0xed; 20];

/// A payment a payer made: its transaction for each quote hash, and its
/// total. A payer asked again for the same quotes returns it.
type MadePayment = (HashMap<QuoteHash, TxHash>, Amount);

/// The payments made, shared by payers that stand for one operator: a payer
/// asked for a payment another made finds it here, as a payer must look for
/// an earlier payment of a request before paying.
type Made = Arc<Mutex<HashMap<Vec<QuoteHash>, MadePayment>>>;

/// A payer outside the client, as an operator runs one: it pays from the
/// funded wallet (a root wave from the funded wallet's root vault signer),
/// hands out the state the engine saves, and takes a carried state in.
struct CarryPayer<'a> {
    testnet: &'a MiniTestnet,
    /// Who it pays for ([`UploadPayer::checkpoint_scope`]).
    account: &'static str,
    /// Whether it pays root waves.
    root: bool,
    /// The carried state it gives the engine.
    carried: Mutex<Option<Vec<u8>>>,
    /// Payments made, shared with another payer.
    made: Made,
    /// Refuse every payment before anything is sent.
    refuse: bool,
    /// Fail once after paying, as a payer stopped then.
    stop_after_pay: AtomicBool,
    /// Record each payment's first quote first, with 1 atto to a
    /// stranger, before paying it, for this many payments.
    occupy: AtomicUsize,
    /// The plans of each payment asked for.
    asked: Mutex<Vec<Vec<ChunkPaymentPlan>>>,
    /// Payments sent.
    sent: AtomicUsize,
    /// Each state the engine saved, as `UploadState::checkpoint` writes it.
    saved: Mutex<Vec<Vec<u8>>>,
    /// Whether a payment was confirmed: a state saved after a payment was
    /// sent, with none pending.
    confirmed: AtomicBool,
    /// The state saved when a payment was first confirmed.
    at_confirm: Mutex<Option<Vec<u8>>>,
    /// Told when a payment is first confirmed.
    on_confirm: tokio::sync::Notify,
}

impl<'a> CarryPayer<'a> {
    fn new(testnet: &'a MiniTestnet, account: &'static str) -> Self {
        Self {
            testnet,
            account,
            root: false,
            carried: Mutex::new(None),
            made: Made::default(),
            refuse: false,
            stop_after_pay: AtomicBool::new(false),
            occupy: AtomicUsize::new(0),
            asked: Mutex::new(Vec::new()),
            sent: AtomicUsize::new(0),
            saved: Mutex::new(Vec::new()),
            confirmed: AtomicBool::new(false),
            at_confirm: Mutex::new(None),
            on_confirm: tokio::sync::Notify::new(),
        }
    }

    fn carrying(self, bytes: Vec<u8>) -> Self {
        *self.carried.lock().unwrap() = Some(bytes);
        self
    }

    /// The addresses of every plan it was asked to pay.
    fn asked_addresses(&self) -> Vec<[u8; 32]> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .flatten()
            .map(|plan| plan.address)
            .collect()
    }

    fn last_saved(&self) -> Vec<u8> {
        self.saved
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a saved state")
    }
}

#[async_trait::async_trait]
impl UploadPayer for CarryPayer<'_> {
    async fn pay_quotes(
        &self,
        plans: &[ChunkPaymentPlan],
    ) -> ant_core::data::Result<UploadPayment> {
        self.asked.lock().unwrap().push(plans.to_vec());
        if self.refuse {
            return Err(Error::Payment("this payer pays nothing".into()));
        }
        let root = plans.iter().any(|plan| !plan.vault.is_v2());
        let mut payments = plans
            .iter()
            .flat_map(|plan| plan.payment.quotes.iter())
            .filter(|quote| !quote.amount.is_zero())
            .map(|quote| (quote.quote_hash, quote.rewards_address, quote.amount))
            .collect::<Vec<_>>();
        payments.sort_by_key(|payment| payment.0);
        let hashes = payments.iter().map(|payment| payment.0).collect::<Vec<_>>();
        let amount = plans
            .iter()
            .fold(Amount::ZERO, |sum, plan| sum + plan.payment.total_amount());
        let made = self.made.lock().unwrap().get(&hashes).cloned();
        if let Some((transactions, amount)) = made {
            return Ok(UploadPayment {
                transactions,
                amount,
                gas: 0,
                root: None,
            });
        }
        if !root && self.occupy.load(Ordering::SeqCst) > 0 {
            self.occupy.fetch_sub(1, Ordering::SeqCst);
            self.testnet
                .wallet()
                .pay_for_quotes([(
                    payments[0].0,
                    RewardsAddress::new(STRANGER),
                    Amount::from(1u64),
                )])
                .await
                .expect("occupy the quote");
        }
        let wallet = if root {
            self.testnet.root_wallet()
        } else {
            self.testnet.wallet().clone()
        };
        let (transactions, gas) = wallet
            .pay_for_quotes(payments)
            .await
            .map_err(|e| Error::Payment(e.0.to_string()))?;
        let transactions = transactions.into_iter().collect::<HashMap<_, _>>();
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.made
            .lock()
            .unwrap()
            .insert(hashes, (transactions.clone(), amount));
        if self.stop_after_pay.swap(false, Ordering::SeqCst) {
            return Err(Error::Payment("stopped after paying".into()));
        }
        Ok(UploadPayment {
            transactions,
            amount,
            gas: gas.gas_cost_wei,
            root: None,
        })
    }

    async fn pay_merkle(
        &self,
        _batch: &PreparedMerkleBatch,
    ) -> ant_core::data::Result<MerkleUploadPayment> {
        Err(Error::Payment("not used here".into()))
    }

    fn checkpoint_scope(&self) -> Vec<u8> {
        self.account.as_bytes().to_vec()
    }

    fn pays_root_waves(&self) -> bool {
        self.root
    }

    fn exact_approvals(&self) -> bool {
        false
    }

    fn carried_state(&self) -> Option<Vec<u8>> {
        self.carried.lock().unwrap().clone()
    }

    fn state_saved(&self, state: &UploadState) {
        let bytes = state.checkpoint().expect("the state's bytes");
        if self.sent.load(Ordering::SeqCst) > 0
            && state.pending_payment.is_none()
            && !self.confirmed.swap(true, Ordering::SeqCst)
        {
            *self.at_confirm.lock().unwrap() = Some(bytes.clone());
            self.on_confirm.notify_one();
        }
        self.saved.lock().unwrap().push(bytes);
    }
}

/// A file of `len` bytes of its own.
fn input(len: usize) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp file");
    let data: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    file.write_all(&data).expect("write temp file");
    file.flush().expect("flush temp file");
    file
}

/// A file of its own, and a readable envelope for it, that a payer paying
/// root waves pays first in a root wave: each content record pays a known
/// vault, at least two the root vault (`root_payment::pays_root`) and the
/// rest the per-quote vault (`root_payment::pays_per_quote`), and the
/// envelope, its name picked for this, pays the root vault. So at least 3
/// records pay the root vault, and the envelope is never alone at the
/// per-quote vault, where a payment would not leave it: with it there and
/// only 3 records paying the root vault, the split moves them all to the
/// per-quote vault (`root_payment::split_vaults`) and no root proof is made.
///
/// A readable envelope's address comes from the data map and its choices,
/// so the name, not the file, puts it where the root vault is paid; files
/// whose content records and envelope all pay it are too rare in some
/// networks.
async fn root_file(testnet: &MiniTestnet) -> (NamedTempFile, Visibility) {
    let mut found = None;
    for _ in 0..100_000 {
        let file = input(20_000);
        let map = ant_core::data::file_data_map(file.path())
            .await
            .expect("encrypt the file");
        let addresses = map
            .infos()
            .iter()
            .map(|info| info.dst_hash.0)
            .collect::<Vec<_>>();
        let roots = addresses
            .iter()
            .filter(|address| crate::root_payment::pays_root(testnet, address))
            .count();
        let per_quote = addresses
            .iter()
            .filter(|address| crate::root_payment::pays_per_quote(testnet, address))
            .count();
        if roots >= 2 && roots + per_quote == addresses.len() {
            found = Some((file, map));
            break;
        }
    }
    let (file, map) = found
        .expect("a file whose content records each pay a known vault, two of them the root vault");
    let mut options = EnvelopeOptions::unlisted();
    for n in 0u32..100_000 {
        options.metadata.name = Some(format!("carried-{n}.bin"));
        let envelope = Envelope::readable(
            &map,
            options.metadata.clone(),
            options.shown,
            options.in_index,
        )
        .expect("the readable envelope");
        if crate::root_payment::pays_root(testnet, &envelope.address()) {
            return (file, Visibility::Envelope(options));
        }
    }
    panic!("no name whose readable envelope pays the root vault");
}

/// A client as an operator runs one: it names the devnet's root vault and
/// pays it only through a payer outside it.
fn operator_client(testnet: &MiniTestnet) -> Client {
    testnet
        .client()
        .without_root_payments()
        .with_root_vault(testnet.root_vault())
}

/// Upload `file` through `payer`, and stop the upload once its first
/// payment is confirmed (dropping it, as a client that stops does, at its
/// next wait), or let it end if it ends first. Returns the bytes of the
/// state saved when the payment was confirmed.
async fn first_upload(
    client: &Client,
    payer: &CarryPayer<'_>,
    file: &NamedTempFile,
    visibility: Visibility,
) -> Vec<u8> {
    {
        let upload = client.file_upload_with_payer(
            file.path(),
            visibility,
            PaymentMode::Single,
            payer,
            None,
        );
        tokio::pin!(upload);
        tokio::select! {
            biased;
            () = payer.on_confirm.notified() => {}
            ended = &mut upload => {
                ended.expect("the first upload");
            }
        }
    }
    assert!(
        payer.confirmed.load(Ordering::SeqCst),
        "a payment confirmed"
    );
    payer
        .at_confirm
        .lock()
        .unwrap()
        .clone()
        .expect("the confirmed state")
}

/// That `file` reads back from `result`'s data map.
async fn reads_back(
    testnet: &MiniTestnet,
    file: &NamedTempFile,
    result: &ant_core::data::FileUploadResult,
) {
    let output = TempDir::new().expect("a temp folder");
    let path = output.path().join("carried.bin");
    testnet
        .client()
        .file_download(&result.data_map, &path)
        .await
        .expect("download");
    assert_eq!(
        std::fs::read(&path).expect("read the download"),
        std::fs::read(file.path()).expect("read the file")
    );
}

/// A readable envelope, whose record is the same on any client.
fn readable() -> Visibility {
    Visibility::Envelope(EnvelopeOptions::unlisted())
}

/// The vault's record for `hash`: the first 16 bytes of its rewards
/// address, and its amount.
async fn vault_record(testnet: &MiniTestnet, hash: QuoteHash) -> ([u8; 16], u128) {
    let network = testnet.evm_network();
    let vault = IPaymentVault::new(
        *network.payment_vault_address(),
        http_provider(network.rpc_url().clone()),
    );
    let record = vault
        .completedPayments(hash)
        .call()
        .await
        .expect("read record");
    (record.rewardsAddress.0, record.amount)
}

/// The first client's payer pays and stops; a new client whose payer, under
/// another account, is given the bytes of the last state the first saved
/// stores every paid record and asks its payer to pay none of them. With a
/// readable envelope every record is carried; with the default private
/// envelope, whose salt stays with the first client, the second pays only
/// its own envelope, in one payment of one plan; with a payer that pays
/// root waves and a file and envelope picked so that its first payment is a
/// root wave ([`root_file`]), the root proofs are carried. The same file
/// encrypts to the same records on the second client.
async fn a_second_client_with_the_carried_state_stores_the_paid_records_and_asks_its_payer_for_no_payment_for_them(
    testnet: Arc<MiniTestnet>,
) {
    for (private, root) in [(false, false), (true, false), (false, true)] {
        let (file, visibility) = if root {
            root_file(&testnet).await
        } else if private {
            (input(200_000), Visibility::default())
        } else {
            (input(200_000), readable())
        };
        let first = CarryPayer {
            root,
            ..CarryPayer::new(&testnet, "carried: first")
        };
        let bytes = first_upload(
            &operator_client(&testnet),
            &first,
            &file,
            visibility.clone(),
        )
        .await;
        // The carried state is the one saved when the first payment was
        // confirmed: it proves that payment's records.
        let first_request = first.asked.lock().unwrap()[0].clone();
        let paid = first_request
            .iter()
            .map(|plan| plan.address)
            .collect::<Vec<_>>();
        assert!(!paid.is_empty());
        if root {
            assert!(
                first_request.iter().all(|plan| !plan.vault.is_v2()),
                "the first payment is the root wave"
            );
            assert_eq!(bytes[4], CHECKPOINT_FORMAT_ROOT, "root proofs are carried");
        }

        let second = CarryPayer {
            root,
            ..CarryPayer::new(&testnet, "carried: second")
        }
        .carrying(bytes);
        let result = operator_client(&testnet)
            .file_upload_with_payer(file.path(), visibility, PaymentMode::Single, &second, None)
            .await
            .expect("the second upload");
        let asked = second.asked_addresses();
        assert!(
            asked.iter().all(|address| !paid.contains(address)),
            "no carried record is paid again"
        );
        let carried = result.carried.clone().expect("a carried outcome");
        assert_eq!(carried.paid_again, 0);
        assert_eq!(carried.reconciled, 0);
        if private {
            // The first envelope's proof is carried and left out.
            assert_eq!(carried.taken + 1, paid.len());
            assert_eq!(carried.proofs, paid.len());
            assert_eq!(carried.quoted_again, 0);
            let requests = second.asked.lock().unwrap().clone();
            assert_eq!(requests.len(), 1, "one payment");
            assert_eq!(requests[0].len(), 1, "of the new envelope alone");
        } else if root {
            // The root wave is paid first; a content record that pays the
            // per-quote vault, in a payment not yet confirmed when the state
            // was saved, is quoted afresh.
            assert_eq!(carried.taken, paid.len());
            assert_eq!(
                carried.quoted_again,
                asked.iter().collect::<HashSet<_>>().len()
            );
        } else {
            assert_eq!(carried.taken, paid.len());
            assert_eq!(carried.quoted_again, 0);
            assert!(asked.is_empty(), "nothing to pay");
        }
        assert_eq!(result.chunks_stored, result.total_chunks);
        reads_back(&testnet, &file, &result).await;
    }
}

/// The first payer's quote is recorded first by a stranger: the engine
/// takes the record out of the paid state it saves, so the second client,
/// given that state, pays only that record, with a fresh quote.
async fn an_occupied_quote_of_the_first_payer_is_not_paid_again_from_the_carried_state(
    testnet: Arc<MiniTestnet>,
) {
    let file = input(60_000);
    let first = CarryPayer::new(&testnet, "carried: occupied first");
    first.occupy.store(1, Ordering::SeqCst);
    let bytes = first_upload(&testnet.client(), &first, &file, readable()).await;
    let first_request = first.asked.lock().unwrap()[0].clone();
    // The occupier records the payment's lowest quote hash first.
    let lowest = first_request
        .iter()
        .flat_map(|p| p.payment.quotes.iter())
        .filter(|q| !q.amount.is_zero())
        .map(|q| q.quote_hash)
        .min()
        .expect("a paid quote");
    let occupied = first_request
        .iter()
        .find(|p| p.payment.quotes.iter().any(|q| q.quote_hash == lowest))
        .map(|p| (p.address, lowest))
        .expect("the occupied plan");

    let second = CarryPayer::new(&testnet, "carried: occupied second").carrying(bytes);
    let result = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &second, None)
        .await
        .expect("the second upload");
    let requests = second.asked.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "one payment");
    assert_eq!(requests[0].len(), 1, "of the occupied record alone");
    assert_eq!(requests[0][0].address, occupied.0);
    let fresh = requests[0][0]
        .payment
        .quotes
        .iter()
        .find(|q| !q.amount.is_zero())
        .unwrap()
        .quote_hash;
    assert_ne!(fresh, occupied.1, "a fresh quote");
    assert_eq!(
        vault_record(&testnet, occupied.1).await,
        (STRANGER[..16].try_into().unwrap(), 1),
        "the occupied record stays the stranger's"
    );
    let carried = result.carried.clone().expect("a carried outcome");
    assert_eq!(carried.taken, first_request.len() - 1);
    assert_eq!(
        carried.quoted_again, 0,
        "its plan was released, not carried"
    );
    reads_back(&testnet, &file, &result).await;
}

/// The first payer pays, then fails before the engine confirms: the last
/// state it was handed holds the payment not yet confirmed. The second
/// payer, standing for the same operator, is asked for exactly those plans
/// and returns the same transactions: nothing is paid again.
async fn a_carried_payment_not_yet_confirmed_is_settled_by_the_second_payer(
    testnet: Arc<MiniTestnet>,
) {
    let file = input(60_000);
    let first = CarryPayer::new(&testnet, "carried: pending first");
    first.stop_after_pay.store(true, Ordering::SeqCst);
    let stopped = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &first, None)
        .await;
    assert!(stopped.is_err(), "the payer stopped after paying");
    assert_eq!(first.sent.load(Ordering::SeqCst), 1);
    let bytes = first.last_saved();
    let pending = UploadState::restore(&bytes)
        .unwrap()
        .pending_payment
        .expect("a payment not yet confirmed");
    let attempt = first.asked.lock().unwrap()[0].clone();
    assert_eq!(pending.addresses.len(), attempt.len());

    let second = CarryPayer {
        made: Arc::clone(&first.made),
        ..CarryPayer::new(&testnet, "carried: pending second")
    }
    .carrying(bytes);
    let result = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &second, None)
        .await
        .expect("the second upload");
    let requests = second.asked.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "asked once, for the journaled plans");
    assert_eq!(
        requests[0].iter().map(|p| p.address).collect::<Vec<_>>(),
        attempt.iter().map(|p| p.address).collect::<Vec<_>>()
    );
    assert_eq!(second.sent.load(Ordering::SeqCst), 0, "nothing paid again");
    let carried = result.carried.clone().expect("a carried outcome");
    assert_eq!(carried.reconciled, attempt.len());
    reads_back(&testnet, &file, &result).await;
}

/// A carried state built from the plans the engine handed a payer that
/// paid nothing: proofs confirmed with transactions that paid nothing for
/// some records, unpaid plans for the others.
async fn unpaid_carried_state(
    testnet: &MiniTestnet,
    file: &NamedTempFile,
    account: &'static str,
) -> (Vec<u8>, Vec<ChunkPaymentPlan>, Vec<ChunkPaymentPlan>) {
    let first = CarryPayer {
        refuse: true,
        ..CarryPayer::new(testnet, account)
    };
    let stopped = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &first, None)
        .await;
    assert!(stopped.is_err(), "the payer paid nothing");
    let plans = first.asked.lock().unwrap()[0].clone();
    assert!(plans.len() >= 2);
    let (proven, offered) = plans.split_at(plans.len() / 2);
    let mut state = UploadState::default();
    let now = std::time::SystemTime::now();
    for plan in proven {
        state.prepare(plan.clone());
        let unpaid = plan
            .payment
            .quotes
            .iter()
            .filter(|q| !q.amount.is_zero())
            .map(|q| (q.quote_hash, TxHash::from([0x77; 32])))
            .collect::<HashMap<_, _>>();
        state.confirm(&[plan.address], &unpaid, now).unwrap();
    }
    for plan in offered {
        state.prepare(plan.clone());
    }
    (
        state.checkpoint().unwrap(),
        proven.to_vec(),
        offered.to_vec(),
    )
}

/// Carried proofs whose transactions paid nothing are refused by every
/// storer; the vault shows no payment, so each record is paid again once.
/// The records the carried state held only unpaid plans for are quoted
/// and paid afresh. The result counts both, and every new quote differs
/// from the carried one.
async fn expired_quotes_are_paid_again_and_counted_in_the_result(testnet: Arc<MiniTestnet>) {
    let file = input(60_000);
    let (bytes, proven, offered) =
        unpaid_carried_state(&testnet, &file, "carried: expired first").await;
    let second = CarryPayer::new(&testnet, "carried: expired second").carrying(bytes);
    let result = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &second, None)
        .await
        .expect("the second upload");
    let asked = second.asked_addresses();
    let unique = asked.iter().collect::<HashSet<_>>();
    assert_eq!(unique.len(), asked.len(), "each record paid once");
    let expected = proven
        .iter()
        .chain(&offered)
        .map(|p| p.address)
        .collect::<HashSet<_>>();
    assert_eq!(asked.iter().copied().collect::<HashSet<_>>(), expected);
    let carried = result.carried.clone().expect("a carried outcome");
    assert_eq!(carried.taken, proven.len());
    assert_eq!(carried.paid_again, proven.len());
    assert_eq!(carried.quoted_again, offered.len());
    let old = proven
        .iter()
        .chain(&offered)
        .flat_map(|p| p.payment.quotes.iter().map(|q| q.quote_hash))
        .collect::<HashSet<_>>();
    for plan in second.asked.lock().unwrap().iter().flatten() {
        for quote in &plan.payment.quotes {
            assert!(!old.contains(&quote.quote_hash), "a new quote");
        }
    }
    reads_back(&testnet, &file, &result).await;
}

/// A record paid again from a carried state goes through the occupied-quote
/// path: a stranger records its quote first, and the engine pays it with a
/// fresh quote, the occupied record staying the stranger's. A client whose
/// price ceiling is below the network's quotes stops before its payer is
/// asked for anything.
async fn the_occupied_quote_path_and_the_price_ceiling_hold_for_a_record_paid_again(
    testnet: Arc<MiniTestnet>,
) {
    let file = input(60_000);
    let (bytes, _, _) = unpaid_carried_state(&testnet, &file, "carried: ceiling first").await;
    let capped = testnet.client_with(ant_core::data::ClientConfig {
        max_chunk_price: Some(Amount::from(1u64)),
        ..test_client_config()
    });
    let refused = CarryPayer::new(&testnet, "carried: ceiling capped").carrying(bytes.clone());
    let error = capped
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &refused, None)
        .await
        .expect_err("every quote is above the ceiling");
    // The ceiling's own words, and not a refusal of the carried state.
    let text = format!("{error:?}");
    assert!(text.contains("above the price ceiling 1"), "{text}");
    assert!(!text.contains(CARRIED_STATE_REFUSED), "{text}");
    assert!(refused.asked.lock().unwrap().is_empty(), "{error}");

    let second = CarryPayer::new(&testnet, "carried: occupied again").carrying(bytes);
    second.occupy.store(1, Ordering::SeqCst);
    let result = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &second, None)
        .await
        .expect("the second upload");
    let requests = second.asked.lock().unwrap().clone();
    assert!(
        requests.len() >= 2,
        "a payment, then one for the occupied record"
    );
    let occupied = requests[0]
        .iter()
        .flat_map(|p| p.payment.quotes.iter())
        .filter(|q| !q.amount.is_zero())
        .map(|q| q.quote_hash)
        .min()
        .expect("a paid quote");
    let occupied_record = requests[0]
        .iter()
        .find(|p| p.payment.quotes.iter().any(|q| q.quote_hash == occupied))
        .unwrap()
        .address;
    let again = requests
        .iter()
        .skip(1)
        .flatten()
        .find(|p| p.address == occupied_record)
        .expect("the occupied record paid again");
    assert!(again
        .payment
        .quotes
        .iter()
        .all(|q| q.quote_hash != occupied));
    assert_eq!(
        vault_record(&testnet, occupied).await,
        (STRANGER[..16].try_into().unwrap(), 1)
    );
    reads_back(&testnet, &file, &result).await;
}

/// The checkpoints this machine keeps, file by file.
fn kept_checkpoints() -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let directory = ant_core::config::data_dir()
        .expect("the data directory")
        .join("payments/upload");
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return BTreeMap::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e != "lock"))
        .map(|path| {
            let bytes = std::fs::read(&path).unwrap_or_default();
            (path, bytes)
        })
        .collect()
}

/// The bytes of a carried state whose one quote's signature fails.
async fn badly_signed_state(testnet: &MiniTestnet, file: &NamedTempFile) -> Vec<u8> {
    let (_, proven, _) = unpaid_carried_state(testnet, file, "carried: badly signed").await;
    let mut state = UploadState::default();
    let mut plan = proven[0].clone();
    plan.peer_quotes[0].1.signature[0] ^= 1;
    state.prepare(plan.clone());
    let unpaid = plan
        .payment
        .quotes
        .iter()
        .filter(|q| !q.amount.is_zero())
        .map(|q| (q.quote_hash, TxHash::from([0x78; 32])))
        .collect::<HashMap<_, _>>();
    state
        .confirm(&[plan.address], &unpaid, std::time::SystemTime::now())
        .unwrap();
    state.checkpoint().unwrap()
}

/// A payer's upload stopped after its own payment keeps its checkpoint. A
/// run given a carried state with a bad signature is refused before
/// anything is paid, and the checkpoint is left as it was; a run without it
/// finishes from the checkpoint, paying nothing again.
async fn a_saved_checkpoint_is_kept_and_a_refused_carried_state_leaves_it_untouched(
    testnet: Arc<MiniTestnet>,
) {
    let file = input(60_000);
    let bad = badly_signed_state(&testnet, &file).await;
    let payer = CarryPayer::new(&testnet, "carried: kept");
    payer.stop_after_pay.store(true, Ordering::SeqCst);
    let client = testnet.client();
    let stopped = client
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &payer, None)
        .await;
    assert!(stopped.is_err(), "the payer stopped after paying");
    assert_eq!(payer.sent.load(Ordering::SeqCst), 1);
    let asked = payer.asked.lock().unwrap().len();
    let before = kept_checkpoints();

    *payer.carried.lock().unwrap() = Some(bad);
    let error = client
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &payer, None)
        .await
        .expect_err("refused");
    assert!(
        error
            .to_string()
            .starts_with(&format!("invalid data: {CARRIED_STATE_REFUSED}: ")),
        "{error}"
    );
    assert_eq!(payer.asked.lock().unwrap().len(), asked, "nothing asked");
    assert_eq!(kept_checkpoints(), before, "the checkpoint is untouched");

    *payer.carried.lock().unwrap() = None;
    let result = client
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &payer, None)
        .await
        .expect("the upload, resumed");
    assert_eq!(payer.sent.load(Ordering::SeqCst), 1, "paid once");
    assert!(result.carried.is_none());
    reads_back(&testnet, &file, &result).await;
}

/// A carried state with one quote whose signature fails is refused whole,
/// before the payer is asked to pay anything.
async fn a_carried_state_with_one_quote_whose_signature_fails_is_refused_before_any_payment(
    testnet: Arc<MiniTestnet>,
) {
    let file = input(60_000);
    let bad = badly_signed_state(&testnet, &file).await;
    let payer = CarryPayer::new(&testnet, "carried: refused").carrying(bad);
    let error = testnet
        .client()
        .file_upload_with_payer(file.path(), readable(), PaymentMode::Single, &payer, None)
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, Error::InvalidData(reason) if reason.starts_with(CARRIED_STATE_REFUSED)),
        "{error}"
    );
    assert!(payer.asked.lock().unwrap().is_empty(), "nothing asked");
}

/// The client's own wallet uploads a file from a carried state: the
/// carried records are stored, and the wallet pays nothing for them.
async fn the_wallet_upload_takes_a_carried_state(testnet: Arc<MiniTestnet>) {
    let file = input(60_000);
    let first = CarryPayer::new(&testnet, "carried: for the wallet");
    let bytes = first_upload(&testnet.client(), &first, &file, readable()).await;
    let paid = first.asked_addresses();
    let before = testnet.wallet().balance_of_tokens().await.unwrap();
    let mut options = CarriedUploadOptions::new(bytes);
    options.visibility = readable();
    let result = testnet
        .client()
        .file_upload_carried(Path::new(file.path()), options)
        .await
        .expect("the wallet's upload");
    let after = testnet.wallet().balance_of_tokens().await.unwrap();
    assert_eq!(before, after, "nothing paid for the carried records");
    let carried = result.carried.clone().expect("a carried outcome");
    assert_eq!(carried.taken, paid.len());
    assert_eq!(carried.proofs, paid.len());
    reads_back(&testnet, &file, &result).await;
}
