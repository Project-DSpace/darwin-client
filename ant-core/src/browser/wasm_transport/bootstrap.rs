//! Bootstrap authentication belongs to the network pool. A single bounded
//! worker retains healthy sessions and publishes each result without waiting
//! for slower seeds. Pool closure also cancels pending handshakes.
//!
//! The worker authenticates [`BOOTSTRAP_SEEDS`] seeds, not every one
//! configured: it takes the seeds in a random order, leaves out those the
//! browser holds off after a failure or a busy refusal, and replaces each dial
//! that fails with the next seed. Only when lookups through the seeds it has
//! fall short does it take [`BOOTSTRAP_SEEDS`] more ([`Bootstrap::widen`]).
use super::*;
use futures_util::StreamExt;

#[derive(Clone, Default)]
pub(super) struct State {
    pub ready: Vec<BrowserHello>,
    pub failures: Vec<BrowserLookupFailure>,
    pub pending: usize,
    // Readiness can shrink after closure/eviction, so length is not a version.
    pub revision: u64,
}

pub(super) struct Bootstrap {
    started: Cell<bool>,
    expected: RefCell<Option<BrowserPaymentNetwork>>,
    state: watch::Sender<State>,
    retry_at: Cell<Option<web_time::Instant>>,
    /// How many seeds the worker keeps sessions with: [`BOOTSTRAP_SEEDS`], and
    /// more once lookups through them fell short.
    target: Cell<usize>,
}

impl Bootstrap {
    pub fn new() -> Self {
        let (state, _) = watch::channel(State::default());
        Self {
            started: Cell::new(false),
            expected: RefCell::new(None),
            state,
            retry_at: Cell::new(None),
            target: Cell::new(BOOTSTRAP_SEEDS),
        }
    }

    /// A lookup through the seeds the worker has found fewer nodes than it
    /// needs, as when the seeds know few of the others: take
    /// [`BOOTSTRAP_SEEDS`] more seeds, at once. Returns whether any is being
    /// dialled, so the lookup can wait for them; none is when every seed is
    /// already taken or held off.
    pub fn widen(&self, core: &BrowserNetworkCore) -> Result<bool, String> {
        if self.state.borrow().pending != 0 {
            return Ok(true);
        }
        let target = self.target.get();
        if target >= core.seeds.len() {
            return Ok(false);
        }
        self.target
            .set(target.saturating_add(BOOTSTRAP_SEEDS).min(core.seeds.len()));
        // These seeds are new to the worker, not a retry: no backoff.
        self.retry_at.set(None);
        drop(self.subscribe(core, None)?);
        Ok(self.state.borrow().pending != 0)
    }

    pub fn subscribe(
        &self,
        core: &BrowserNetworkCore,
        expected: Option<BrowserPaymentNetwork>,
    ) -> Result<watch::Receiver<State>, String> {
        if core.pool.availability.closed.get() {
            return Err("WebRTC client pool is closed".into());
        }
        if self.started.get() {
            if let Some(expected) = expected {
                if self.expected.borrow().as_ref() != Some(&expected) {
                    return Err("bootstrap payment policy cannot change after startup".into());
                }
            }
        } else {
            self.started.set(true);
            self.expected.replace(expected.clone());
            core.pool.bootstrap_policy.configure(&core.seeds, expected);
            for (endpoint, entry) in core.pool.clients.borrow().iter() {
                core.pool.bootstrap_policy.register(endpoint, entry);
            }
        }
        // Readiness belongs to live pooled sessions, not a historic HELLO.
        self.state.send_modify(|state| {
            let before = state.ready.len();
            state
                .ready
                .retain(|hello| core.pool.has_authenticated_connection(&hello.endpoint));
            if state.ready.len() != before {
                state.revision = state.revision.wrapping_add(1);
            }
        });
        if self.state.borrow().pending != 0 {
            return Ok(self.state.subscribe());
        }
        // A few seeds, not all of them: lookups find every other node through
        // them. Sessions on seeds already ready are kept until the node closes
        // them for idleness, so reads reuse them, and only the shortfall is
        // dialled.
        let needed = self
            .target
            .get()
            .saturating_sub(self.state.borrow().ready.len());
        if needed == 0 {
            return Ok(self.state.subscribe());
        }
        // Seeds the browser holds off, after a refusal or a failure, are left
        // for others; each try takes the seeds in a new random order.
        let mut held_off = 0;
        let seeds: Vec<_> = core
            .seeds
            .iter()
            .filter(|endpoint| {
                core.pool
                    .bootstrap_policy
                    .check(&endpoint.multiaddr)
                    .is_ok()
                    && !self
                        .state
                        .borrow()
                        .ready
                        .iter()
                        .any(|hello| hello.endpoint == **endpoint)
            })
            .filter(|endpoint| {
                let held = core.pool.is_held_off(endpoint);
                held_off += usize::from(held);
                !held
            })
            .cloned()
            .collect();
        if seeds.is_empty() {
            if held_off > 0 && self.state.borrow().ready.is_empty() {
                let busy = core.pool.busy_seeds(&core.seeds);
                let failed = held_off.saturating_sub(busy);
                self.state.send_modify(|state| {
                    state.failures = vec![BrowserLookupFailure {
                        peer_id: String::new(),
                        message: match (busy, failed) {
                            (0, _) => "every seed failed recently and is held off".to_string(),
                            (_, 0) => "every seed is busy and declined a session; try again \
                                       shortly"
                                .to_string(),
                            _ => format!(
                                "every seed is held off: {busy} busy, which declined a session, \
                                 and {failed} that failed recently; try again shortly"
                            ),
                        },
                    }];
                });
            }
            return Ok(self.state.subscribe());
        }
        let seeds = crate::data::network::in_random_order(seeds, &mut rand::thread_rng());
        // A caller may start one new bounded batch after transient failures.
        // Concurrent callers share it; there is no autonomous retry loop.
        let now = web_time::Instant::now();
        let delay = self
            .retry_at
            .get()
            .map_or(Duration::ZERO, |at| at.saturating_duration_since(now));
        self.retry_at
            .set(Some(now + delay + Duration::from_secs(1)));
        let first = needed.min(seeds.len());
        self.state.send_modify(|state| {
            state.pending = first;
            // A seed's earlier failure goes once it is dialled again, and an
            // earlier "every seed is held off" once any seed is.
            state.failures.retain(|failure| {
                !failure.peer_id.is_empty()
                    && !seeds.iter().any(|seed| seed.multiaddr == failure.peer_id)
            });
        });
        let state = self.state.clone();
        let pool = Rc::clone(&core.pool);
        wasm_bindgen_futures::spawn_local(async move {
            let connect = async {
                if !delay.is_zero() {
                    crate::runtime::sleep(delay).await;
                }
                let attempt = |endpoint: BrowserEndpoint| {
                    let pool = Rc::clone(&pool);
                    async move {
                        let result = async {
                            let client = pool.client(&endpoint).await?;
                            let hello = client.hello().await?;
                            pool.bootstrap_policy
                                .validate(&endpoint.multiaddr, &hello)?;
                            Ok(hello)
                        }
                        .await;
                        (endpoint, result)
                    }
                };
                let mut queue = seeds.into_iter();
                let mut attempts = queue
                    .by_ref()
                    .take(first)
                    .map(attempt)
                    .collect::<futures_util::stream::FuturesUnordered<_>>();
                while let Some((endpoint, result)) = attempts.next().await {
                    // A seed that failed, or declined while busy, is replaced
                    // by the next one: at most `needed` dials are in flight.
                    let next = result.is_err().then(|| queue.next()).flatten();
                    let busy = result.is_err() && pool.is_busy(&endpoint);
                    state.send_modify(|state| {
                        if next.is_none() {
                            state.pending -= 1;
                        }
                        match result {
                            Ok(hello) => {
                                state.ready.push(hello);
                                state.revision = state.revision.wrapping_add(1);
                            }
                            Err(message) => state.failures.push(BrowserLookupFailure {
                                peer_id: endpoint.multiaddr,
                                message: if busy {
                                    format!("busy, it declined the session: {message}")
                                } else {
                                    message
                                },
                            }),
                        }
                    });
                    if let Some(next) = next {
                        attempts.push(attempt(next));
                    }
                }
            };
            let _ = select(Box::pin(connect), Box::pin(pool.availability.wait_closed())).await;
        });
        Ok(self.state.subscribe())
    }
}

/// Every pooled lane consults the same immutable seed policy. Revocation closes
/// both lanes, including RPCs and HELLOs already holding a lease or admission.
#[derive(Default)]
pub(super) struct Policies {
    seeds: RefCell<HashMap<String, SeedPolicy>>,
}

struct SeedPolicy {
    expected: Option<BrowserPaymentNetwork>,
    rejected: Option<String>,
    lanes: [Weak<BrowserNodeClientCore>; 2],
}

impl Policies {
    fn configure(&self, seeds: &[BrowserEndpoint], expected: Option<BrowserPaymentNetwork>) {
        let mut policies = self.seeds.borrow_mut();
        for seed in seeds {
            policies.insert(
                seed.multiaddr.clone(),
                SeedPolicy {
                    expected: expected.clone(),
                    rejected: None,
                    lanes: [Weak::new(), Weak::new()],
                },
            );
        }
    }

    pub fn register(&self, endpoint: &str, entry: &PoolEntry) {
        if let Some(policy) = self.seeds.borrow_mut().get_mut(endpoint) {
            policy.lanes = [
                Rc::downgrade(&entry.client),
                Rc::downgrade(&entry.data_client),
            ];
        }
    }

    pub fn check(&self, endpoint: &str) -> Result<(), String> {
        match self
            .seeds
            .borrow()
            .get(endpoint)
            .and_then(|policy| policy.rejected.as_ref())
        {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub fn validate(&self, endpoint: &str, hello: &BrowserHello) -> Result<(), String> {
        self.check(endpoint)?;
        let rejection = {
            let mut seeds = self.seeds.borrow_mut();
            let Some(policy) = seeds.get_mut(endpoint) else {
                return Ok(());
            };
            match validate(hello, policy.expected.as_ref()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    policy.rejected = Some(error.clone());
                    (error, policy.lanes.clone())
                }
            }
        };
        for lane in rejection.1.iter().filter_map(Weak::upgrade) {
            lane.close();
            if let Some(pool) = &lane.pool_availability {
                pool.notify_waiters();
            }
        }
        Err(rejection.0)
    }
}

fn validate(hello: &BrowserHello, expected: Option<&BrowserPaymentNetwork>) -> Result<(), String> {
    if !hello
        .capabilities
        .iter()
        .any(|capability| capability == "chunk_protocol")
    {
        return Err("Bootstrap node does not support the shared storage protocol; upgrade ant-node to a version advertising chunk_protocol".into());
    }
    if let Some(expected) = expected {
        if hello.payment.chain_id != expected.chain_id
            || !hello
                .payment
                .payment_token_address
                .eq_ignore_ascii_case(&expected.payment_token_address)
            || !hello
                .payment
                .payment_vault_address
                .eq_ignore_ascii_case(&expected.payment_vault_address)
        {
            return Err("NETWORK_MISMATCH: Authenticated payment network does not match expectedPaymentNetwork".into());
        }
    }
    Ok(())
}

pub(super) fn candidate(hello: &BrowserHello) -> Result<BrowserLookupCandidate, String> {
    BrowserLookupCandidate::parse(BrowserNode {
        address_record: None,
        peer_record: None,
        peer_id: hello.peer_id.clone(),
        native_addresses: Vec::new(),
        reliability: 1.0,
        webrtc_direct: Some(hello.endpoint.clone()),
    })
}

pub(super) fn failure(state: &State) -> String {
    format!(
        "could not connect to any WebRtcDirect seed: {}",
        state
            .failures
            .iter()
            .map(|failure| failure.message.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    )
}

impl BrowserNetworkCore {
    pub(super) async fn connect(
        &self,
        expected: Option<BrowserPaymentNetwork>,
    ) -> Result<BrowserHello, String> {
        let mut updates = self.bootstrap.subscribe(self, expected)?;
        loop {
            let state = updates.borrow_and_update().clone();
            if self.pool.availability.closed.get() {
                return Err("WebRTC client pool is closed".into());
            }
            if let Some(hello) = state
                .ready
                .iter()
                .find_map(|hello| self.pool.authenticated_hello(&hello.endpoint))
            {
                return Ok(hello);
            }
            if state.pending == 0 {
                return Err(failure(&state));
            }
            self.bootstrap_changed(&mut updates).await?;
        }
    }

    pub(super) async fn bootstrap_changed(
        &self,
        updates: &mut watch::Receiver<State>,
    ) -> Result<(), String> {
        match select(
            Box::pin(updates.changed()),
            Box::pin(self.pool.availability.wait_closed()),
        )
        .await
        {
            Either::Left((result, _)) => result.map_err(|_| "bootstrap worker closed".into()),
            Either::Right(_) => Err("WebRTC client pool is closed".into()),
        }
    }
}
