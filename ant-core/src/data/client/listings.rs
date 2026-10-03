//! Reading the listings index.
//!
//! Nodes that support listings answer requests on [`ant_listings::TOPIC`]. A
//! client collects listings from every node it can find, then checks each one
//! before trusting it: the envelope must be on the network and match the
//! listing, and the payment must be on chain ([`Client::check_listing`]).

use crate::data::client::Client;
use crate::data::error::{Error, Result};
use ant_listings::{
    verify_listing, Envelope, Listing, ListingKey, ListingsBody, ListingsMessage, PaymentLog,
    PaymentReceipt, MAX_LIST_LIMIT, TOPIC,
};
use ant_protocol::evm::Network as EvmNetwork;
use ant_protocol::transport::{P2PEvent, PeerId};
use ant_protocol::XorName;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tracing::debug;

/// How long to wait for a node to answer a listings request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Random lookups made to find nodes beyond the ones already connected.
const CRAWL_LOOKUPS: usize = 8;

/// Nodes asked for per lookup.
const CRAWL_WIDTH: usize = 20;

/// The most pages read from one node in one collection.
const MAX_PAGES_PER_NODE: usize = 1_000;

/// Nodes asked at once. A node that doesn't answer (an older one, or one that
/// is down) costs one request timeout, paid alongside the others.
const PEER_CONCURRENCY: usize = 64;

impl Client {
    /// Collect listings with keys from `from` onwards from every node this
    /// client can find, oldest first.
    ///
    /// The result is unchecked: a node can send anything. Exact duplicates are
    /// merged; different listings claiming the same address are all returned,
    /// for [`Client::check_listing`] to tell apart.
    ///
    /// # Errors
    ///
    /// Returns an error only if no node can be found.
    pub async fn collect_listings(&self, from: ListingKey) -> Result<Vec<Listing>> {
        let peers = self.listing_peers().await;
        if peers.is_empty() {
            return Err(Error::InsufficientPeers(
                "no nodes found to ask for listings".into(),
            ));
        }
        let per_peer: Vec<Vec<Listing>> = stream::iter(&peers)
            .map(|peer| self.listings_from(peer, from))
            .buffer_unordered(PEER_CONCURRENCY)
            .collect()
            .await;
        let mut by_address: HashMap<XorName, Vec<Listing>> = HashMap::new();
        for listing in per_peer.into_iter().flatten() {
            let candidates = by_address.entry(listing.address).or_default();
            if !candidates.contains(&listing) {
                candidates.push(listing);
            }
        }
        let mut listings: Vec<Listing> = by_address.into_values().flatten().collect();
        listings.sort_by_key(Listing::key);
        debug!(
            "Collected {} listings from {} nodes",
            listings.len(),
            peers.len()
        );
        Ok(listings)
    }

    /// Check a listing: its envelope is on the network and matches it, and its
    /// payment is on chain. Returns the envelope, which carries the file's data
    /// map.
    ///
    /// # Errors
    ///
    /// Returns why the listing can't be trusted.
    pub async fn check_listing(
        &self,
        listing: &Listing,
        chain: &ListingChain,
    ) -> std::result::Result<Envelope, String> {
        let chunk = self
            .chunk_get(&listing.address)
            .await
            .map_err(|e| format!("could not fetch the envelope: {e}"))?
            .ok_or("the envelope is not on the network")?;
        let envelope =
            Envelope::from_bytes(&chunk.content).map_err(|e| format!("bad envelope: {e}"))?;
        if !listing.matches(&envelope) {
            return Err("the listing doesn't match its envelope".into());
        }
        let (receipt, timestamp) = chain
            .payment(&listing.payment.tx_hash)
            .await?
            .ok_or("the payment transaction is not on chain")?;
        verify_listing(listing, &receipt, timestamp, &chain.vault).map_err(|e| e.to_string())?;
        Ok(envelope)
    }

    /// Every listing `peer` holds from `from` onwards, a page at a time. Empty
    /// if the peer doesn't answer.
    async fn listings_from(&self, peer: &PeerId, from: ListingKey) -> Vec<Listing> {
        let mut collected = Vec::new();
        let mut next = from;
        for _ in 0..MAX_PAGES_PER_NODE {
            let request = ListingsBody::ListRequest {
                from: next,
                limit: MAX_LIST_LIMIT,
            };
            let Some(ListingsBody::ListResponse { listings, more }) =
                self.ask_for_listings(peer, request).await
            else {
                break;
            };
            let last = listings.last().map(Listing::key);
            collected.extend(listings);
            match last {
                Some(key) if more => next = key.next(),
                _ => break,
            }
        }
        collected
    }

    /// The nodes to ask: those connected, plus those found by a few random
    /// lookups.
    async fn listing_peers(&self) -> Vec<PeerId> {
        let network = self.network();
        let mut peers: HashSet<PeerId> = network.connected_peers().await.into_iter().collect();
        let targets: Vec<[u8; 32]> = (0..CRAWL_LOOKUPS).map(|_| rand::random()).collect();
        let lookups = futures::future::join_all(
            targets
                .iter()
                .map(|target| network.find_closest_peers(target, CRAWL_WIDTH)),
        )
        .await;
        for lookup in lookups {
            match lookup {
                Ok(found) => peers.extend(found.into_iter().map(|(peer, _)| peer)),
                Err(e) => debug!("Listing crawl lookup failed: {e}"),
            }
        }
        peers.into_iter().collect()
    }

    /// Send one listings request to `peer` and wait for its answer.
    async fn ask_for_listings(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody> {
        let node = self.network().node();
        let request_id: u64 = rand::random();
        let request = ListingsMessage { request_id, body }.encode().ok()?;

        // Subscribe before sending, so the answer can't be missed.
        let mut events = node.subscribe_events();
        if let Err(e) = node.send_message(peer, TOPIC, request, &[]).await {
            debug!("Could not ask {peer} for listings: {e}");
            return None;
        }
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                debug!("{peer} did not answer a listings request");
                return None;
            }
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(P2PEvent::Message {
                    topic,
                    source: Some(source),
                    data,
                    ..
                })) if topic == TOPIC && source == *peer => match ListingsMessage::decode(&data) {
                    Ok(response) if response.request_id == request_id => {
                        return Some(response.body);
                    }
                    _ => {}
                },
                Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
                Ok(Err(RecvError::Closed)) | Err(_) => return None,
            }
        }
    }
}

/// Reads payments from the payment chain, for checking listings.
pub struct ListingChain {
    http: reqwest::Client,
    rpc_url: String,
    vault: [u8; 20],
}

impl ListingChain {
    /// A reader for `network`'s chain and payment vault.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client can't be built.
    pub fn new(network: &EvmNetwork) -> Result<Self> {
        let mut vault = [0u8; 20];
        vault.copy_from_slice(network.payment_vault_address().as_slice());
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| Error::Network(format!("payment chain client: {e}")))?;
        Ok(Self {
            http,
            rpc_url: network.rpc_url().to_string(),
            vault,
        })
    }

    /// The receipt of `tx_hash` and its block's timestamp, or `None` if the
    /// chain doesn't know the transaction.
    async fn payment(
        &self,
        tx_hash: &[u8; 32],
    ) -> std::result::Result<Option<(PaymentReceipt, u64)>, String> {
        let receipt = self
            .call(
                "eth_getTransactionReceipt",
                json!([format!("0x{}", hex::encode(tx_hash))]),
            )
            .await?;
        if receipt.is_null() {
            return Ok(None);
        }
        let block_hex = receipt["blockNumber"]
            .as_str()
            .ok_or("the receipt has no block number")?;
        let block = self
            .call("eth_getBlockByNumber", json!([block_hex, false]))
            .await?;
        let timestamp = block["timestamp"]
            .as_str()
            .and_then(parse_u64)
            .ok_or("the block has no timestamp")?;
        let logs = receipt["logs"]
            .as_array()
            .map(|logs| logs.iter().filter_map(parse_log).collect())
            .unwrap_or_default();
        Ok(Some((
            PaymentReceipt {
                tx_hash: *tx_hash,
                success: receipt["status"].as_str() == Some("0x1"),
                block_number: parse_u64(block_hex).ok_or("bad block number")?,
                logs,
            },
            timestamp,
        )))
    }

    async fn call(&self, method: &str, params: Value) -> std::result::Result<Value, String> {
        let response: Value = self
            .http
            .post(&self.rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("payment chain {method}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("payment chain {method}: {e}"))?;
        if let Some(error) = response.get("error") {
            return Err(format!("payment chain {method}: {error}"));
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn parse_log(log: &Value) -> Option<PaymentLog> {
    Some(PaymentLog {
        address: parse_bytes(log["address"].as_str()?)?,
        topics: log["topics"]
            .as_array()?
            .iter()
            .map(|topic| topic.as_str().and_then(parse_bytes))
            .collect::<Option<Vec<[u8; 32]>>>()?,
        log_index: parse_u64(log["logIndex"].as_str()?)?,
    })
}

fn parse_u64(hex: &str) -> Option<u64> {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
}

fn parse_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    hex::decode(hex.trim_start_matches("0x"))
        .ok()?
        .try_into()
        .ok()
}
