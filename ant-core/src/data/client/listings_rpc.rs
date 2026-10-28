//! The payment chain's JSON-RPC providers, as a
//! [`ListingChain`](super::listings::ListingChain) reads them. Every call it
//! makes goes through here:
//!
//! - **Order.** A call goes to the providers in the order of what it reads
//!   ([`Kind`]), on to the next whenever one fails it, and the next call
//!   starts at the first again. Log queries have an order of their own. On
//!   the bundled network, receipts and blocks go to the network's own RPC
//!   (PublicNode's) first, then Robinhood's RPC, then ordofi's; log queries
//!   go to Robinhood's RPC first, then PublicNode's, then ordofi's. ordofi's
//!   is last for both, since it answered payment reads "busy" or too late in
//!   October 2026. A provider that refuses a kind of call outright (HTTP
//!   403, as PublicNode refuses ranged `eth_getLogs`) is asked last for that
//!   kind for the next [`BUSY_MAX`], then in its place again.
//! - **Batches.** Calls known together go to a provider in one request, a
//!   JSON-RPC batch of up to [`RPC_BATCH`], and every call carries an id of
//!   its own, unique for the reader's life.
//! - **Pacing.** A provider is sent at most [`RPC_CALLS_PER_SECOND`] calls a
//!   second on average, and at most [`RPC_BATCH`] at once: a call waits its
//!   turn there rather than going elsewhere.
//! - **Backoff.** A provider over its limit (JSON-RPC error [`BUSY_CODE`],
//!   HTTP 429 or 5xx) or not answering is held off: for [`BUSY_FIRST`], and
//!   twice as long each time in a row, up to [`BUSY_MAX`]; an answer ends it.
//!   Calls go to the next provider meanwhile, the rest of a set sent in
//!   batches too, and wait for one held off only when every other has failed
//!   them. [`BUSY_CODE`] in answer to a log query from a provider that gives
//!   it as a span answer (ordofi, wherever it is listed) fails that query
//!   alone and holds nothing off: ordofi gives it to a query over a wider
//!   span than it serves, and the query goes on to the next provider, if
//!   any. From any other provider it holds that provider off.
//! - **Redaction.** An error names a provider by its host alone, never its
//!   URL, which can carry a key.
//! - **Chain.** Where the chain is known (a list of RPCs given in place of
//!   the bundled network's), a provider answers nothing until it has said it
//!   is on that chain, and one on another is never used.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::time::Instant;
use tracing::{debug, error};

use super::listings_v1::RpcCalls;

/// How long one request to a provider may take.
pub(crate) const RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// How many calls a provider is sent each second, at most, on average.
pub(crate) const RPC_CALLS_PER_SECOND: u32 = 10;

/// The most calls one request carries (a JSON-RPC batch), and so the most a
/// provider is sent at once after a quiet spell.
pub(crate) const RPC_BATCH: usize = 100;

/// The JSON-RPC error code of a provider over its limit: "limit exceeded",
/// or ordofi's "the network is busy".
pub(crate) const BUSY_CODE: i64 = -32_005;

/// How long a busy provider is first held off.
pub(crate) const BUSY_FIRST: Duration = Duration::from_secs(1);

/// The longest a busy provider is held off, however often in a row: the
/// producer's minute.
pub(crate) const BUSY_MAX: Duration = Duration::from_secs(60);

/// What a call reads, which decides the order providers are asked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Receipts, blocks and everything but log queries.
    Chain,
    /// Log queries (`eth_getLogs`).
    Logs,
}

impl Kind {
    /// The call's kind by its method.
    pub(crate) fn of(method: &str) -> Self {
        if method == "eth_getLogs" {
            Self::Logs
        } else {
            Self::Chain
        }
    }

    fn slot(self) -> usize {
        match self {
            Self::Chain => 0,
            Self::Logs => 1,
        }
    }
}

/// One JSON-RPC call.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    pub(crate) method: &'static str,
    pub(crate) params: Value,
}

impl Call {
    pub(crate) fn new(method: &'static str, params: Value) -> Self {
        Self { method, params }
    }
}

/// A call's answer, and the provider (its index) that gave it.
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub(crate) value: Value,
    pub(crate) provider: usize,
}

/// Why a call failed at one provider.
#[derive(Debug, Clone)]
enum Failure {
    /// The provider is over its limit or doesn't answer: hold it off.
    Busy(String),
    /// The provider refuses this kind of call outright.
    Refused(String),
    /// This call failed there.
    Failed(String),
}

impl Failure {
    fn message(&self) -> &str {
        match self {
            Self::Busy(message) | Self::Refused(message) | Self::Failed(message) => message,
        }
    }
}

/// Whether a provider has said which chain it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnChain {
    Unchecked,
    Right,
    Wrong,
}

/// How many calls a provider may be sent now: a token bucket, refilled at
/// [`RPC_CALLS_PER_SECOND`] up to [`RPC_BATCH`]. A call taken from an empty
/// bucket leaves it owing, so calls queue up in the order they took.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(now: Instant) -> Self {
        Self {
            tokens: RPC_BATCH as f64,
            at: now,
        }
    }

    /// Take `calls` at `now`: when they may be sent, `None` for at once.
    fn take(&mut self, now: Instant, calls: usize) -> Option<Instant> {
        let rate = f64::from(RPC_CALLS_PER_SECOND);
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(RPC_BATCH as f64);
        self.at = self.at.max(now);
        self.tokens -= calls as f64;
        (self.tokens < 0.0).then(|| now + Duration::from_secs_f64(-self.tokens / rate))
    }
}

/// How long a provider is held off.
#[derive(Debug, Default, Clone, Copy)]
struct Hold {
    until: Option<Instant>,
    delay: Duration,
}

impl Hold {
    /// The provider was busy at `now`: hold it off, twice as long as last
    /// time if it was held then too.
    fn busy(&mut self, now: Instant) {
        self.delay = if self.delay.is_zero() {
            BUSY_FIRST
        } else {
            (self.delay * 2).min(BUSY_MAX)
        };
        self.until = Some(now + self.delay);
    }

    /// The provider answered: no longer held.
    fn clear(&mut self) {
        *self = Self::default();
    }

    /// Until when it is held off, if it still is at `now`.
    fn until(&self, now: Instant) -> Option<Instant> {
        self.until.filter(|until| *until > now)
    }
}

struct ProviderState {
    bucket: Bucket,
    hold: Hold,
    /// Until when it is asked last for each kind of call ([`Kind::slot`]),
    /// having refused one outright.
    refuses: [Option<Instant>; 2],
    chain: OnChain,
}

struct Provider {
    url: String,
    host: String,
    calls: AtomicU64,
    errors: AtomicU64,
    /// Whether its [`BUSY_CODE`] to a log query answers a span wider than it
    /// serves, not a limit (ordofi's).
    span_answers: bool,
    state: Mutex<ProviderState>,
}

impl Provider {
    fn state(&self) -> MutexGuard<'_, ProviderState> {
        // The state is plain data, whole after any panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The host of an RPC URL: all of it that is ever logged or reported.
pub(crate) fn rpc_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// The providers a reader calls. See the module docs.
pub(crate) struct Rpc {
    http: reqwest::Client,
    providers: Vec<Provider>,
    /// The order of [`Kind::Chain`] calls, as indexes into `providers`.
    chain_order: Vec<usize>,
    /// The order of [`Kind::Logs`] calls.
    logs_order: Vec<usize>,
    /// The chain each provider must say it is on before it is used, where
    /// known.
    chain_id: Option<u64>,
    next_id: AtomicU64,
    /// Whether calls are paced; tests that make many calls turn it off.
    paced: bool,
}

impl Rpc {
    /// Providers at `urls`, asked in that order for everything but log
    /// queries, which are asked in `logs_order` (indexes into `urls`; the
    /// same order when `None`). The providers at `span_answers` (indexes
    /// into `urls`) give [`BUSY_CODE`] to a log query over a span wider than
    /// they serve, which fails that query alone. With `chain_id`, each must
    /// say it is on that chain before it is used.
    ///
    /// # Errors
    ///
    /// If `urls` is empty, `logs_order` doesn't order each of them once, or
    /// the HTTP client can't be built.
    pub(crate) fn new(
        urls: Vec<String>,
        logs_order: Option<Vec<usize>>,
        span_answers: &[usize],
        chain_id: Option<u64>,
    ) -> std::result::Result<Self, String> {
        if urls.is_empty() {
            return Err("payment chain client: no RPC".into());
        }
        let chain_order: Vec<usize> = (0..urls.len()).collect();
        let logs_order = logs_order.unwrap_or_else(|| chain_order.clone());
        let mut sorted = logs_order.clone();
        sorted.sort_unstable();
        if sorted != chain_order {
            return Err("payment chain client: the log queries' order isn't of its RPCs".into());
        }
        let http = reqwest::Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|e| format!("payment chain client: {}", e.without_url()))?;
        let now = Instant::now();
        let providers = urls
            .into_iter()
            .enumerate()
            .map(|(index, url)| Provider {
                host: rpc_host(&url),
                url,
                calls: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                span_answers: span_answers.contains(&index),
                state: Mutex::new(ProviderState {
                    bucket: Bucket::full(now),
                    hold: Hold::default(),
                    refuses: [None; 2],
                    chain: OnChain::Unchecked,
                }),
            })
            .collect();
        Ok(Self {
            http,
            providers,
            chain_order,
            logs_order,
            chain_id,
            next_id: AtomicU64::new(1),
            paced: true,
        })
    }

    /// Tests: send calls as fast as they come.
    #[cfg(test)]
    pub(crate) fn unpaced(&mut self) {
        self.paced = false;
    }

    /// The providers' URLs, in the order of [`Kind::Chain`] calls.
    #[cfg(test)]
    pub(crate) fn urls(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.url.clone()).collect()
    }

    /// The order calls of `kind` ask the providers in, as indexes: its own,
    /// with those that refused such a call in the last [`BUSY_MAX`] moved
    /// last.
    pub(crate) fn order(&self, kind: Kind) -> Vec<usize> {
        self.order_at(kind, Instant::now())
    }

    /// [`order`](Self::order) at `now`.
    fn order_at(&self, kind: Kind, now: Instant) -> Vec<usize> {
        let base = match kind {
            Kind::Chain => &self.chain_order,
            Kind::Logs => &self.logs_order,
        };
        let (refused, first): (Vec<usize>, Vec<usize>) = base.iter().copied().partition(|index| {
            self.providers[*index].state().refuses[kind.slot()].is_some_and(|until| until > now)
        });
        first.into_iter().chain(refused).collect()
    }

    /// Provider `index` refused a call of `kind` outright at `now`: ask it
    /// last for such calls for the next [`BUSY_MAX`].
    fn refused(&self, index: usize, kind: Kind, now: Instant) {
        self.providers[index].state().refuses[kind.slot()] = Some(now + BUSY_MAX);
    }

    /// The host of provider `index`.
    pub(crate) fn host(&self, index: usize) -> &str {
        &self.providers[index].host
    }

    /// The providers to ask to confirm what provider `source` answered, in
    /// the order of `kind`: those on another host, and not known to be on
    /// another chain.
    pub(crate) fn others(&self, kind: Kind, source: usize) -> Vec<usize> {
        let host = &self.providers[source].host;
        self.order(kind)
            .into_iter()
            .filter(|index| {
                let provider = &self.providers[*index];
                provider.host != *host && provider.state().chain != OnChain::Wrong
            })
            .collect()
    }

    /// Whether provider `index` is held off now.
    pub(crate) fn is_held(&self, index: usize) -> bool {
        self.providers[index]
            .state()
            .hold
            .until(Instant::now())
            .is_some()
    }

    /// The calls made to each provider, and how many failed, by host.
    pub(crate) fn calls(&self) -> Vec<RpcCalls> {
        let mut providers: Vec<RpcCalls> = Vec::new();
        for provider in &self.providers {
            let calls = provider.calls.load(Ordering::Relaxed);
            let errors = provider.errors.load(Ordering::Relaxed);
            match providers
                .iter_mut()
                .find(|known| known.provider == provider.host)
            {
                Some(known) => {
                    known.calls += calls;
                    known.errors += errors;
                }
                None => providers.push(RpcCalls {
                    provider: provider.host.clone(),
                    calls,
                    errors,
                }),
            }
        }
        providers
    }

    /// One call, through the providers in the order of its kind until one
    /// answers; every provider's error if none does.
    pub(crate) async fn call(
        &self,
        method: &'static str,
        params: Value,
    ) -> std::result::Result<Answer, String> {
        self.batch(&[Call::new(method, params)])
            .await
            .pop()
            .unwrap_or_else(|| Err("payment chain: no answer".into()))
    }

    /// Several calls of one kind (that of the first), sent together to the
    /// providers in its order: each provider is sent those calls no
    /// provider before it answered, in batches of up to [`RPC_BATCH`]. Each
    /// call's answer, or every provider's error for it.
    pub(crate) async fn batch(&self, calls: &[Call]) -> Vec<std::result::Result<Answer, String>> {
        let Some(first) = calls.first() else {
            return Vec::new();
        };
        let kind = Kind::of(first.method);
        let mut answers: Vec<Option<Answer>> = calls.iter().map(|_| None).collect();
        let mut errors: Vec<Vec<String>> = calls.iter().map(|_| Vec::new()).collect();
        let mut pending: Vec<usize> = (0..calls.len()).collect();
        let mut tried = vec![false; self.providers.len()];
        while !pending.is_empty() {
            let Some(index) = self.next_provider(kind, &tried).await else {
                break;
            };
            tried[index] = true;
            let asked: Vec<&Call> = pending.iter().map(|i| &calls[*i]).collect();
            let results = self.send(index, kind, &asked).await;
            let mut left = Vec::new();
            for (i, result) in pending.iter().copied().zip(results) {
                match result {
                    Ok(value) => {
                        answers[i] = Some(Answer {
                            value,
                            provider: index,
                        });
                    }
                    Err(e) => {
                        if self.providers.len() > 1 {
                            debug!("{e}");
                        }
                        errors[i].push(e);
                        left.push(i);
                    }
                }
            }
            pending = left;
        }
        answers
            .into_iter()
            .zip(errors)
            .map(|(answer, errors)| {
                answer.ok_or_else(|| {
                    if errors.is_empty() {
                        "payment chain: no RPC to ask".to_string()
                    } else {
                        errors.join("; ")
                    }
                })
            })
            .collect()
    }

    /// `calls`, of `kind`, sent to provider `index` alone, unless it is held
    /// off: each call's answer or error.
    pub(crate) async fn batch_to(
        &self,
        index: usize,
        kind: Kind,
        calls: &[Call],
    ) -> Vec<std::result::Result<Value, String>> {
        if self.is_held(index) {
            return calls
                .iter()
                .map(|call| Err(self.held_off(index, call)))
                .collect();
        }
        let asked: Vec<&Call> = calls.iter().collect();
        self.send(index, kind, &asked).await
    }

    /// The error of `call` not sent to provider `index`, which is held off.
    fn held_off(&self, index: usize, call: &Call) -> String {
        format!(
            "payment chain {} via {}: held off while busy",
            call.method,
            self.host(index)
        )
    }

    /// The next provider to ask calls of `kind` that none of `tried` has
    /// answered: the first in order that isn't held off, or once only held
    /// ones are left, the one free soonest, once it is. `None` when every
    /// provider has been tried, or is on another chain.
    async fn next_provider(&self, kind: Kind, tried: &[bool]) -> Option<usize> {
        let now = Instant::now();
        let mut soonest: Option<(Instant, usize)> = None;
        for index in self.order(kind) {
            if tried[index] {
                continue;
            }
            let (chain, held) = {
                let state = self.providers[index].state();
                (state.chain, state.hold.until(now))
            };
            if chain == OnChain::Wrong {
                continue;
            }
            match held {
                None => return Some(index),
                Some(until) => {
                    if soonest.is_none_or(|(first, _)| until < first) {
                        soonest = Some((until, index));
                    }
                }
            }
        }
        let (until, index) = soonest?;
        tokio::time::sleep_until(until).await;
        Some(index)
    }

    /// `calls` sent to provider `index`, in batches of up to [`RPC_BATCH`],
    /// once it has said it is on the chain where that is checked. Once a
    /// batch's answer holds the provider off, the calls not yet sent fail
    /// there as held off, unsent, so they go to the next provider.
    async fn send(
        &self,
        index: usize,
        kind: Kind,
        calls: &[&Call],
    ) -> Vec<std::result::Result<Value, String>> {
        if let Err(e) = self.check_chain(index).await {
            let host = self.host(index);
            return calls
                .iter()
                .map(|call| Err(format!("payment chain {} via {host}: {e}", call.method)))
                .collect();
        }
        let mut results = Vec::with_capacity(calls.len());
        for chunk in calls.chunks(RPC_BATCH) {
            if !results.is_empty() && self.is_held(index) {
                break;
            }
            results.extend(self.request(index, kind, chunk).await);
        }
        let unsent = &calls[results.len()..];
        results.extend(unsent.iter().map(|call| Err(self.held_off(index, call))));
        results
    }

    /// Ask provider `index` which chain it is on, once, if that is checked:
    /// an error if it doesn't say, or is on another.
    async fn check_chain(&self, index: usize) -> std::result::Result<(), String> {
        let Some(want) = self.chain_id else {
            return Ok(());
        };
        match self.providers[index].state().chain {
            OnChain::Right => return Ok(()),
            OnChain::Wrong => return Err("on another chain: not used".into()),
            OnChain::Unchecked => {}
        }
        let call = Call::new("eth_chainId", json!([]));
        let answer = self
            .request(index, Kind::Chain, &[&call])
            .await
            .pop()
            .unwrap_or_else(|| Err("no answer".into()))?;
        let id = answer
            .as_str()
            .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok());
        let mut state = self.providers[index].state();
        if id == Some(want) {
            state.chain = OnChain::Right;
            return Ok(());
        }
        state.chain = OnChain::Wrong;
        drop(state);
        error!(
            "The RPC at {} is on chain {id:?}, not the payment network's {want}: not used",
            self.host(index)
        );
        Err(format!("on chain {id:?}, not {want}: not used"))
    }

    /// One request to provider `index`, carrying `calls` (at most
    /// [`RPC_BATCH`]), once its pace allows: each call's answer or error.
    /// Holds the provider off if it was busy, ends a hold if it answered,
    /// and asks it last for `kind` for a while if it refused.
    async fn request(
        &self,
        index: usize,
        kind: Kind,
        calls: &[&Call],
    ) -> Vec<std::result::Result<Value, String>> {
        let provider = &self.providers[index];
        if self.paced {
            let at = provider.state().bucket.take(Instant::now(), calls.len());
            if let Some(at) = at {
                tokio::time::sleep_until(at).await;
            }
        }
        let ids: Vec<u64> = calls
            .iter()
            .map(|_| self.next_id.fetch_add(1, Ordering::Relaxed))
            .collect();
        let mut requests: Vec<Value> = calls
            .iter()
            .zip(&ids)
            .map(|(call, id)| {
                json!({ "jsonrpc": "2.0", "id": id, "method": call.method, "params": call.params })
            })
            .collect();
        let body = if requests.len() == 1 {
            requests.pop().unwrap_or(Value::Null)
        } else {
            Value::Array(requests)
        };
        provider
            .calls
            .fetch_add(calls.len() as u64, Ordering::Relaxed);
        let (outcome, over_rpc) = match self.post(&provider.url, &body).await {
            Ok(answer) => (answers_by_id(&answer, &ids), true),
            Err(failure) => (ids.iter().map(|_| Err(failure.clone())).collect(), false),
        };
        let (mut busy, mut refused, mut answered) = (false, false, false);
        let results = calls
            .iter()
            .zip(outcome)
            .map(|(call, result)| match result {
                Ok(value) => {
                    answered = true;
                    Ok(value)
                }
                Err(failure) => {
                    // ordofi answers a log query over a wider span than it
                    // serves with BUSY_CODE too. From ordofi (a provider
                    // marked as giving span answers, wherever it is in the
                    // order), the query fails there and goes on to the next
                    // provider, if any, but holds nothing off, so its other
                    // calls go on. From any other provider it is over its
                    // limit, and is held off like any busy provider.
                    let failure = match failure {
                        Failure::Busy(message)
                            if over_rpc
                                && Kind::of(call.method) == Kind::Logs
                                && provider.span_answers =>
                        {
                            Failure::Failed(message)
                        }
                        failure => failure,
                    };
                    busy |= matches!(failure, Failure::Busy(_));
                    refused |= matches!(failure, Failure::Refused(_));
                    provider.errors.fetch_add(1, Ordering::Relaxed);
                    Err(format!(
                        "payment chain {} via {}: {}",
                        call.method,
                        provider.host,
                        failure.message()
                    ))
                }
            })
            .collect();
        let mut state = provider.state();
        if busy {
            state.hold.busy(Instant::now());
            debug!(
                "Holding off the RPC at {} for {:?}",
                provider.host, state.hold.delay
            );
        } else if answered {
            state.hold.clear();
        }
        drop(state);
        if refused {
            self.refused(index, kind, Instant::now());
        }
        results
    }

    /// POST `body` to `url`. The URL never shows in an error.
    async fn post(&self, url: &str, body: &Value) -> std::result::Result<Value, Failure> {
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| Failure::Busy(request_error(e)))?;
        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            return Err(Failure::Refused(format!("HTTP {status}")));
        }
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(Failure::Busy(format!("HTTP {status}")));
        }
        if !status.is_success() {
            return Err(Failure::Failed(format!("HTTP {status}")));
        }
        response
            .json::<Value>()
            .await
            .map_err(|e| Failure::Failed(request_error(e)))
    }
}

/// A request's error, without the URL it was sent to
/// ([`reqwest::Error::without_url`]).
fn request_error(error: reqwest::Error) -> String {
    let why = if error.is_timeout() {
        " (timed out)"
    } else if error.is_connect() {
        " (could not connect)"
    } else {
        ""
    };
    format!("{}{why}", error.without_url())
}

/// Each of `ids`' answer in `answer`, the response to a request carrying
/// them: one object for one call, a list for a batch, matched by id.
fn answers_by_id(answer: &Value, ids: &[u64]) -> Vec<std::result::Result<Value, Failure>> {
    let whole = |failure: Failure| ids.iter().map(|_| Err(failure.clone())).collect();
    match answer {
        Value::Array(items) if ids.len() > 1 => {
            let by_id: HashMap<u64, &Value> = items
                .iter()
                .filter_map(|item| Some((item.get("id")?.as_u64()?, item)))
                .collect();
            ids.iter()
                .map(|id| match by_id.get(id) {
                    Some(item) => rpc_result(item),
                    None => Err(Failure::Failed("no answer to it in the batch".into())),
                })
                .collect()
        }
        Value::Object(_)
            if ids.len() == 1 && answer.get("id").and_then(Value::as_u64) == Some(ids[0]) =>
        {
            vec![rpc_result(answer)]
        }
        // An error for the whole request, such as a batch refused.
        Value::Object(_) if answer.get("error").is_some() => whole(
            rpc_result(answer)
                .err()
                .unwrap_or_else(|| Failure::Failed("an error".into())),
        ),
        Value::Object(_) => whole(Failure::Failed("the answer is to another request".into())),
        _ => whole(Failure::Failed("the answer is not JSON-RPC".into())),
    }
}

/// One call's result, or its error.
fn rpc_result(item: &Value) -> std::result::Result<Value, Failure> {
    match item.get("error") {
        Some(error) if error.get("code").and_then(Value::as_i64) == Some(BUSY_CODE) => {
            Err(Failure::Busy(error.to_string()))
        }
        Some(error) => Err(Failure::Failed(error.to_string())),
        None => Ok(item.get("result").cloned().unwrap_or(Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::listings::test_chain::{serve, MockChain};
    use super::*;

    #[test]
    fn a_full_bucket_sends_a_batch_at_once_then_paces_calls() {
        let start = Instant::now();
        let mut bucket = Bucket::full(start);
        // One full batch goes at once.
        assert_eq!(bucket.take(start, RPC_BATCH), None);
        // The next call waits for its token: a tenth of a second.
        let at = bucket.take(start, 1).unwrap();
        assert_eq!(at - start, Duration::from_millis(100));
        // And the one after it, behind it.
        let at = bucket.take(start, 1).unwrap();
        assert_eq!(at - start, Duration::from_millis(200));
        // Ten seconds of quiet refill a whole batch, and no more.
        let later = start + Duration::from_secs(60);
        assert_eq!(bucket.take(later, RPC_BATCH), None);
        assert!(bucket.take(later, 1).is_some());
    }

    #[test]
    fn calls_are_paced_at_ten_a_second_on_average() {
        let start = Instant::now();
        let mut bucket = Bucket::full(start);
        assert_eq!(bucket.take(start, RPC_BATCH), None);
        // A thousand more calls, one at a time as fast as they are allowed:
        // they take a hundred seconds.
        let mut now = start;
        for _ in 0..1_000 {
            if let Some(at) = bucket.take(now, 1) {
                now = at;
            }
        }
        let took = (now - start).as_secs_f64();
        assert!((took - 100.0).abs() < 0.01, "{took}");
    }

    #[test]
    fn a_busy_provider_is_held_off_twice_as_long_each_time_up_to_a_minute() {
        let start = Instant::now();
        let mut hold = Hold::default();
        assert_eq!(hold.until(start), None);
        let mut expected = Vec::new();
        let mut now = start;
        for _ in 0..9 {
            hold.busy(now);
            expected.push(hold.delay);
            // Held off until then, and no longer.
            assert_eq!(hold.until(now), Some(now + hold.delay));
            now += hold.delay;
            assert_eq!(hold.until(now), None);
        }
        let seconds: Vec<u64> = expected.iter().map(Duration::as_secs).collect();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        // An answer ends it: the next hold is short again.
        hold.clear();
        hold.busy(now);
        assert_eq!(hold.delay, BUSY_FIRST);
    }

    #[test]
    fn answers_are_matched_to_calls_by_id() {
        let batch = json!([
            { "jsonrpc": "2.0", "id": 8, "result": "0x2" },
            { "jsonrpc": "2.0", "id": 7, "result": "0x1" },
            { "jsonrpc": "2.0", "id": 9, "error": { "code": BUSY_CODE, "message": "busy" } },
        ]);
        let answers = answers_by_id(&batch, &[7, 8, 9, 10]);
        assert_eq!(answers[0].as_ref().unwrap(), &json!("0x1"));
        assert_eq!(answers[1].as_ref().unwrap(), &json!("0x2"));
        assert!(matches!(answers[2], Err(Failure::Busy(_))));
        assert!(matches!(answers[3], Err(Failure::Failed(_))));
        // One call: its own id only.
        let one = json!({ "jsonrpc": "2.0", "id": 3, "result": null });
        assert_eq!(answers_by_id(&one, &[3])[0].as_ref().unwrap(), &Value::Null);
        assert!(answers_by_id(&one, &[4])[0].is_err());
        // An error for the whole request fails every call.
        let refused =
            json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "no" } });
        assert!(answers_by_id(&refused, &[1, 2]).iter().all(Result::is_err));
    }

    #[test]
    fn hosts_alone_are_reported() {
        assert_eq!(
            rpc_host("https://rpc.example.org/v1/a-key"),
            "rpc.example.org"
        );
        assert_eq!(rpc_host("not a url"), "unknown");
    }

    #[test]
    fn the_log_queries_order_must_order_every_rpc_once() {
        let urls = || vec!["http://a.test".to_string(), "http://b.test".to_string()];
        assert!(Rpc::new(urls(), Some(vec![1, 0]), &[], None).is_ok());
        assert!(Rpc::new(urls(), Some(vec![1, 1]), &[], None).is_err());
        assert!(Rpc::new(urls(), Some(vec![0]), &[], None).is_err());
        assert!(Rpc::new(Vec::new(), None, &[], None).is_err());
        let rpc = Rpc::new(urls(), Some(vec![1, 0]), &[], None).unwrap();
        assert_eq!(rpc.order(Kind::Chain), vec![0, 1]);
        assert_eq!(rpc.order(Kind::Logs), vec![1, 0]);
    }

    #[test]
    fn a_provider_refusing_a_kind_of_call_is_asked_last_for_it_for_a_while() {
        let urls = ["http://a.test", "http://b.test", "http://c.test"]
            .map(String::from)
            .to_vec();
        let rpc = Rpc::new(urls, Some(vec![1, 0, 2]), &[], None).unwrap();
        let now = Instant::now();
        rpc.refused(1, Kind::Logs, now);
        assert_eq!(rpc.order_at(Kind::Logs, now), vec![0, 2, 1]);
        // Other calls still ask it in its place.
        assert_eq!(rpc.order_at(Kind::Chain, now), vec![0, 1, 2]);
        let later = now + BUSY_MAX;
        assert_eq!(
            rpc.order_at(Kind::Logs, later - Duration::from_millis(1)),
            vec![0, 2, 1]
        );
        // Then in its place again, until it refuses again.
        assert_eq!(rpc.order_at(Kind::Logs, later), vec![1, 0, 2]);
    }

    /// Two mock chains served locally, and paced-off providers for them in
    /// that order.
    async fn two_mocks() -> (Arc<Mutex<MockChain>>, Arc<Mutex<MockChain>>, Rpc) {
        let first = Arc::new(Mutex::new(MockChain::with_blocks(10, 1_700_000_000)));
        let second = Arc::new(Mutex::new(MockChain::with_blocks(10, 1_700_000_000)));
        let urls = vec![
            serve(Arc::clone(&first)).await,
            serve(Arc::clone(&second)).await,
        ];
        let mut rpc = Rpc::new(urls, None, &[], None).unwrap();
        rpc.unpaced();
        (first, second, rpc)
    }

    fn receipt_call(n: u64) -> Call {
        Call::new("eth_getTransactionReceipt", json!([format!("0x{n:064x}")]))
    }

    /// Three mock chains served locally, and paced-off providers for them
    /// with log queries in `logs_order` and span answers from the one at
    /// `ordofi`.
    async fn three_mocks(
        logs_order: Option<Vec<usize>>,
        ordofi: usize,
    ) -> (Vec<Arc<Mutex<MockChain>>>, Rpc) {
        let mut mocks = Vec::new();
        let mut urls = Vec::new();
        for _ in 0..3 {
            let mock = Arc::new(Mutex::new(MockChain::with_blocks(10, 1_700_000_000)));
            urls.push(serve(Arc::clone(&mock)).await);
            mocks.push(mock);
        }
        let mut rpc = Rpc::new(urls, logs_order, &[ordofi], None).unwrap();
        rpc.unpaced();
        (mocks, rpc)
    }

    #[tokio::test]
    async fn a_busy_answer_to_a_log_query_holds_off_every_provider_but_ordofi() {
        let filter = json!({ "fromBlock": "0x0", "toBlock": "0x9" });
        let logs_call = || Call::new("eth_getLogs", json!([filter]));
        // The bundled network: log queries to Robinhood's RPC (1), then
        // PublicNode's (0), then ordofi's (2) last. Listed in RPC_URLS as
        // the gateway's README gives them: ordofi's (0), Robinhood's (1),
        // PublicNode's (2), in that order for everything, so PublicNode's,
        // not ordofi's, is asked last for log queries.
        for (logs_order, ordofi, others) in [(Some(vec![1, 0, 2]), 2, [1, 0]), (None, 0, [1, 2])] {
            // Any other provider, over its limit, is held off, wherever it is
            // in the order...
            for other in others {
                let (mocks, rpc) = three_mocks(logs_order.clone(), ordofi).await;
                mocks[other].lock().unwrap().failing = vec![("eth_getLogs", BUSY_CODE)];
                let logs = rpc.batch_to(other, Kind::Logs, &[logs_call()]).await;
                assert!(logs[0].is_err());
                assert!(rpc.is_held(other), "{other} of {logs_order:?}");
            }
            // ...and a query goes on past it to the next.
            let (mocks, rpc) = three_mocks(logs_order.clone(), ordofi).await;
            let order = rpc.order(Kind::Logs);
            let at = order.iter().position(|index| *index != ordofi).unwrap();
            for before in &order[..at] {
                mocks[*before].lock().unwrap().failing = vec![("eth_getLogs", -32_000)];
            }
            mocks[order[at]].lock().unwrap().failing = vec![("eth_getLogs", BUSY_CODE)];
            let logs = rpc.call("eth_getLogs", json!([filter])).await.unwrap();
            assert_eq!(logs.provider, order[at + 1]);
            assert!(rpc.is_held(order[at]));

            // ordofi, answering a span wider than it serves: the query fails
            // there alone and holds nothing off, wherever it is in the
            // order...
            let (mocks, rpc) = three_mocks(logs_order.clone(), ordofi).await;
            for other in others {
                mocks[other].lock().unwrap().failing = vec![("eth_getLogs", -32_000)];
            }
            mocks[ordofi].lock().unwrap().failing = vec![("eth_getLogs", BUSY_CODE)];
            assert!(rpc.call("eth_getLogs", json!([filter])).await.is_err());
            assert_eq!(mocks[ordofi].lock().unwrap().calls_to("eth_getLogs"), 1);
            assert!(!rpc.is_held(ordofi), "{logs_order:?}");
            // ...so it still answers everything else in its place.
            let receipt = rpc.batch_to(ordofi, Kind::Chain, &[receipt_call(1)]).await;
            assert!(receipt[0].is_ok());
            // The same answer to any other call holds it off.
            mocks[ordofi].lock().unwrap().failing = vec![("eth_getTransactionReceipt", BUSY_CODE)];
            let receipt = rpc.batch_to(ordofi, Kind::Chain, &[receipt_call(2)]).await;
            assert!(receipt[0].is_err());
            assert!(rpc.is_held(ordofi));
        }
    }

    #[tokio::test]
    async fn calls_left_after_a_busy_batch_go_to_the_next_provider() {
        let (first, second, rpc) = two_mocks().await;
        first.lock().unwrap().failing = vec![("eth_getTransactionReceipt", BUSY_CODE)];
        let calls: Vec<Call> = (0..250).map(receipt_call).collect();
        let answers = rpc.batch(&calls).await;
        assert!(answers
            .iter()
            .all(|answer| answer.as_ref().is_ok_and(|answer| answer.provider == 1)));
        // One batch of 100 to the busy provider, none of the 150 after it.
        {
            let first = first.lock().unwrap();
            assert_eq!(first.requests, 1);
            assert_eq!(first.calls_to("eth_getTransactionReceipt"), 100);
        }
        assert_eq!(
            second.lock().unwrap().calls_to("eth_getTransactionReceipt"),
            250
        );
        // Sent to it alone, as facts are confirmed: those left are held off,
        // unsent.
        let (first, _, rpc) = two_mocks().await;
        first.lock().unwrap().failing = vec![("eth_getTransactionReceipt", BUSY_CODE)];
        let answers = rpc.batch_to(0, Kind::Chain, &calls).await;
        assert_eq!(first.lock().unwrap().requests, 1);
        assert!(answers.iter().all(Result::is_err));
        assert!(answers[100..]
            .iter()
            .all(|answer| answer.as_ref().unwrap_err().contains("held off")));
    }
}
