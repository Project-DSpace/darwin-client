//! `darwin listings` and `darwin listing`: listings collected from the nodes, merged
//! across them and checked.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use ant_core::ant_listings::{CheckLevel, Listing, ListingKey, PaymentField, QUORUM_THRESHOLD};
use ant_core::data::{
    paid_quote_hash, Carry, CheckedListing, Client, ListingChain, ListingLookup, RejectedListing,
    WalkOutcome, WalkState, XorName, NEAREST_NODES,
};
use clap::Args;
use serde::Serialize;
use serde_json::{Map, Value};

use super::chunk::parse_address;

/// Arguments of `darwin listings`.
#[derive(Args)]
pub struct ListingsArgs {
    /// Only listings from this time on, in Unix seconds: the block timestamp,
    /// or for a listing that hides it, when it was first seen (to the hour).
    #[arg(long, default_value_t = 0)]
    pub since: u64,
    /// Also show listings that fail their checks, with the reason.
    #[arg(long)]
    pub all: bool,
    /// Keep the walks' state in this file, read if it exists and written
    /// after the read: walks of nodes' indexes stopped early carry on in the
    /// next read, and a read that finds far fewer nodes than recent ones
    /// decides nothing.
    #[arg(long, value_name = "FILE")]
    pub state: Option<PathBuf>,
    /// A previous `--json` output of this command: its entries for addresses
    /// this read doesn't decide are printed again, marked "carried". Needs
    /// `--json`; a missing file carries nothing.
    #[arg(long, value_name = "FILE")]
    pub carry: Option<PathBuf>,
}

/// Arguments of `darwin listing`.
#[derive(Args)]
pub struct ListingArgs {
    /// The envelope's address (hex): the file's address.
    pub address: String,
}

/// What `darwin listings` takes from earlier reads: the walks' state
/// (`--state`) and the entries to carry (`--carry`). Read before the network,
/// so a file that can't be used fails the command before anything else.
#[derive(Debug)]
pub struct EarlierReads {
    state: WalkState,
    previous: Vec<PreviousEntry>,
}

/// One entry of a previous `--json` output, for `--carry`: as it was printed,
/// with its address and index key.
#[derive(Debug, Clone)]
struct PreviousEntry {
    address: XorName,
    key: ListingKey,
    entry: Map<String, Value>,
}

/// A listing as `--json` prints it. Hidden payment fields are absent.
#[derive(Serialize)]
struct ListingJson {
    address: String,
    name: Option<String>,
    content_type: Option<String>,
    size: Option<u64>,
    /// Whether anyone with the address can read the file.
    readable: bool,
    /// Whether the listing is in the index.
    in_index: bool,
    /// The payment fields the uploader hid.
    hidden: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_index: Option<u64>,
    /// The hash of the paid quote, when the quote is shown.
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_hash: Option<String>,
    /// When the listing was first seen, rounded down to the hour: only for a
    /// listing in the index that hides its block timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen: Option<u64>,
    /// The time the index sorts by: the block timestamp, else `first_seen`.
    time: u64,
    /// `verified` (the payment is checked and tied to this address) or
    /// `reported` (shown fields checked; it rests on the nodes nearest the
    /// address). Absent for a listing that fails its checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    check: Option<CheckLevel>,
    /// How many of the nodes nearest the address serve this listing.
    nodes: usize,
    /// How many nearest nodes were asked (normally 7).
    nearest: usize,
    /// Whether `nodes` reaches the quorum (4 of 7).
    quorum: bool,
    /// The file's data map, hex-encoded, for a readable listing that passes
    /// its checks: what a client needs to read the file without the envelope.
    data_map: Option<String>,
    valid: bool,
    problem: Option<String>,
    /// True on an earlier read's entry that `--carry` printed again, as it
    /// was, because this read didn't decide its address
    /// ([`merge_carried`]); absent otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    carried: bool,
}

impl ListingJson {
    fn new(listing: &Listing, nodes: usize, nearest: usize) -> Self {
        let payment = &listing.payment;
        Self {
            address: hex::encode(listing.address),
            name: listing.metadata.name.clone(),
            content_type: listing.metadata.content_type.clone(),
            size: listing.size,
            readable: !listing.flags.withheld,
            in_index: listing.flags.in_index,
            hidden: listing
                .flags
                .shown
                .hidden()
                .map(PaymentField::name)
                .collect(),
            tx_hash: payment
                .tx_hash
                .map(|hash| format!("0x{}", hex::encode(hash))),
            block_number: payment.block_number,
            block_timestamp: payment.block_timestamp,
            log_index: payment.log_index,
            quote_hash: payment
                .quote
                .as_deref()
                .and_then(paid_quote_hash)
                .map(|hash| format!("0x{}", hex::encode(hash))),
            first_seen: listing.first_seen,
            time: listing.key().time,
            check: None,
            nodes,
            nearest,
            quorum: false,
            data_map: None,
            valid: false,
            problem: None,
            carried: false,
        }
    }

    fn checked(checked: &CheckedListing) -> Self {
        Self {
            check: Some(checked.level),
            quorum: checked.quorum,
            data_map: checked.envelope.data_map_bytes().map(hex::encode),
            valid: true,
            ..Self::new(&checked.listing, checked.nodes, checked.nearest)
        }
    }

    fn rejected(rejected: &RejectedListing) -> Self {
        Self {
            problem: Some(rejected.problem.clone()),
            ..Self::new(&rejected.listing, rejected.nodes, rejected.nearest)
        }
    }
}

/// An entry `darwin listings --json` prints: this read's, or an earlier read's
/// that `--carry` printed again.
#[derive(Serialize)]
#[serde(untagged)]
enum PrintedEntry {
    Read(Box<ListingJson>),
    Carried(Map<String, Value>),
}

impl ListingsArgs {
    /// Read the `--state` and `--carry` files, if they exist: before the
    /// network, so a file that can't be used fails the command before anything
    /// is printed (and a timer keeps its last output).
    ///
    /// # Errors
    ///
    /// `--carry` without `--json`, or a file that exists but can't be read or
    /// isn't what this command writes.
    pub fn load_earlier(&self, json: bool) -> anyhow::Result<EarlierReads> {
        if self.carry.is_some() && !json {
            anyhow::bail!("--carry merges a previous --json output into this one: add --json");
        }
        let mut earlier = EarlierReads {
            state: WalkState::default(),
            previous: Vec::new(),
        };
        if let Some(path) = &self.state {
            if let Some(bytes) = read_if_exists(path)? {
                earlier.state = serde_json::from_slice(&bytes).map_err(|e| {
                    anyhow::anyhow!(
                        "--state {}: not a walk state ({e}); delete it to start afresh",
                        path.display()
                    )
                })?;
            }
        }
        if let Some(path) = &self.carry {
            if let Some(bytes) = read_if_exists(path)? {
                earlier.previous = parse_previous(&bytes)
                    .map_err(|e| anyhow::anyhow!("--carry {}: {e}", path.display()))?;
            }
        }
        Ok(earlier)
    }

    /// Collect listings from the nodes, merge and check them, and print them
    /// in index order, with the entries of `earlier` this read didn't decide.
    pub async fn execute(
        &self,
        client: &Client,
        chain: &ListingChain,
        json: bool,
        earlier: EarlierReads,
    ) -> anyhow::Result<()> {
        let EarlierReads {
            mut state,
            previous,
        } = earlier;
        let index = client
            .index_listings_with(self.since, chain, &mut state)
            .await?;
        if let Some(path) = &self.state {
            save_state(path, &state)?;
        }
        let stopped: Vec<WalkOutcome> = index
            .walks
            .iter()
            .filter(|walk| walk.resume.is_some())
            .map(|walk| walk.outcome)
            .collect();
        for note in read_notes(
            index.nodes_asked,
            index.too_few_nodes,
            &stopped,
            index.deferred,
            self.state.is_some(),
        ) {
            eprintln!("{note}");
        }
        let rejected = if self.all {
            index.rejected.as_slice()
        } else {
            &[]
        };

        if json {
            let entries = index
                .listings
                .iter()
                .map(|checked| (checked.listing.key(), ListingJson::checked(checked)))
                .chain(
                    rejected
                        .iter()
                        .map(|rejected| (rejected.listing.key(), ListingJson::rejected(rejected))),
                )
                .collect();
            let out = merge_carried(entries, previous, |address, key| {
                // The read covers listings from `since` on: it says nothing
                // about earlier ones.
                if key.time < self.since {
                    Carry::Keep
                } else {
                    index.carry(address, key)
                }
            });
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }

        if index.listings.is_empty() && rejected.is_empty() {
            println!(
                "No listings found ({} of {} nodes answered).",
                index.nodes_answered, index.nodes_asked
            );
            return Ok(());
        }
        for checked in &index.listings {
            print_row(&checked.listing, &check_text(checked));
        }
        for rejected in rejected {
            print_row(&rejected.listing, rejected_text(rejected));
            println!("    {}", printable(&rejected.problem));
        }
        Ok(())
    }
}

impl ListingArgs {
    /// Fetch one listing from the nodes nearest its address, check it and
    /// print it.
    pub async fn execute(
        &self,
        client: &Client,
        chain: &ListingChain,
        json: bool,
    ) -> anyhow::Result<()> {
        let address = parse_address(&self.address)?;
        let lookup = client.listing(&address, chain).await?;
        if json {
            #[derive(Serialize)]
            struct LookupJson {
                listing: Option<ListingJson>,
                rejected: Vec<ListingJson>,
                nearest: usize,
                answered: usize,
            }
            let out = LookupJson {
                listing: lookup.listing.as_ref().map(ListingJson::checked),
                rejected: lookup.rejected.iter().map(ListingJson::rejected).collect(),
                nearest: lookup.nearest,
                answered: lookup.answered,
            };
            println!("{}", serde_json::to_string(&out)?);
            // As in text mode: no valid listing is a failure, for scripts.
            return require_listing(&lookup, &self.address);
        }
        match &lookup.listing {
            Some(checked) => print_details(&checked.listing, &check_text(checked)),
            None => println!(
                "No listing for {} passed its checks ({} of the {} nearest nodes answered).",
                self.address, lookup.answered, lookup.nearest
            ),
        }
        for rejected in &lookup.rejected {
            println!();
            print_details(&rejected.listing, rejected_text(rejected));
            println!("  Problem:  {}", printable(&rejected.problem));
            println!(
                "  Nodes:    {} of {} nearest",
                rejected.nodes, rejected.nearest
            );
        }
        require_listing(&lookup, &self.address)
    }
}

/// `darwin listing` fails, in text and JSON alike, when no listing for the
/// address passed its checks.
fn require_listing(lookup: &ListingLookup, address: &str) -> anyhow::Result<()> {
    if lookup.listing.is_none() {
        anyhow::bail!("no valid listing for {address}");
    }
    Ok(())
}

/// A file's bytes, or `None` if it doesn't exist.
fn read_if_exists(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", path.display())),
    }
}

/// Save `state` to `path` so that a crash leaves the old state or the new
/// one: write `<path>.tmp`, then rename it over `path`.
fn save_state(path: &Path, state: &WalkState) -> anyhow::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let bytes = serde_json::to_vec(state)?;
    let written = std::fs::File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("cannot save the walk state to {}: {e}", path.display())
    })
}

/// The entries of a previous `--json` output, each keyed as
/// [`Listing::key`] keys its listing: by `time`, the block number and log
/// index (0 where hidden) and the address. Output from before `time` was
/// printed is keyed by the block timestamp, else `first_seen`, as
/// [`Listing::key`] takes them.
///
/// # Errors
///
/// If it isn't a list of entries, each with a hex address and with whole
/// numbers where it has a time, block number or log index.
fn parse_previous(bytes: &[u8]) -> anyhow::Result<Vec<PreviousEntry>> {
    let entries: Vec<Map<String, Value>> = serde_json::from_slice(bytes)
        .map_err(|e| anyhow::anyhow!("not a list of listings: {e}"))?;
    entries
        .into_iter()
        .enumerate()
        .map(|(n, entry)| {
            previous_entry(entry).map_err(|e| anyhow::anyhow!("entry {}: {e}", n + 1))
        })
        .collect()
}

fn previous_entry(entry: Map<String, Value>) -> Result<PreviousEntry, String> {
    let address = entry
        .get("address")
        .and_then(Value::as_str)
        .and_then(|address| parse_address(address).ok())
        .ok_or("no address")?;
    let number = |field: &str| match entry.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{field} is not a whole number")),
    };
    let time = match number("time")? {
        Some(time) => time,
        None => number("block_timestamp")?
            .or(number("first_seen")?)
            .unwrap_or(0),
    };
    let key = ListingKey {
        time,
        block_number: number("block_number")?.unwrap_or(0),
        log_index: number("log_index")?.unwrap_or(0),
        address,
    };
    Ok(PreviousEntry {
        address,
        key,
        entry,
    })
}

/// This read's entries, each with its index key, and the earlier entries
/// `previous`, in index order. `carry` says what this read makes of each
/// earlier entry ([`ListingsIndex::carry`](ant_core::data::ListingsIndex::carry)):
/// one whose address it decided is left out, since its own entries cover the
/// address, and so is one whose file the network no longer stores, which only
/// the whole close group says; any other is printed again as it was, marked
/// `"carried": true`.
fn merge_carried(
    entries: Vec<(ListingKey, ListingJson)>,
    previous: Vec<PreviousEntry>,
    carry: impl Fn(&XorName, &ListingKey) -> Carry,
) -> Vec<PrintedEntry> {
    let mut merged: Vec<(ListingKey, PrintedEntry)> = entries
        .into_iter()
        .map(|(key, entry)| (key, PrintedEntry::Read(Box::new(entry))))
        .collect();
    for PreviousEntry {
        address,
        key,
        mut entry,
    } in previous
    {
        match carry(&address, &key) {
            Carry::Decided | Carry::NoLongerServed => continue,
            Carry::Keep => {}
        }
        entry.insert("carried".into(), Value::Bool(true));
        merged.push((key, PrintedEntry::Carried(entry)));
    }
    merged.sort_by_key(|(key, _)| *key);
    merged.into_iter().map(|(_, entry)| entry).collect()
}

/// What `darwin listings` says on stderr about a read, if anything: that it
/// found too few of the `nodes` to decide anything, how the walks that
/// stopped before the end of a node's index (`stopped`, their outcomes)
/// stopped, and how many addresses it left for a later read.
fn read_notes(
    nodes: usize,
    too_few_nodes: bool,
    stopped: &[WalkOutcome],
    deferred: usize,
    with_state: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    if too_few_nodes {
        notes.push(format!(
            "warning: this read found {nodes} nodes, too few to trust its view of the network \
             (fewer than {NEAREST_NODES}, or under three quarters as many as recent reads \
             found), so it decided nothing; --carry keeps earlier entries as they are"
        ));
    }
    if !stopped.is_empty() {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for outcome in stopped {
            *counts.entry(outcome_text(*outcome)).or_default() += 1;
        }
        let counts: Vec<String> = counts
            .into_iter()
            .map(|(outcome, count)| format!("{count} {outcome}"))
            .collect();
        let next = if with_state {
            "they carry on where they stopped in the next read"
        } else {
            "with --state they would carry on in the next read"
        };
        notes.push(format!(
            "walks stopped early: {} ({}); {next}",
            stopped.len(),
            counts.join(", ")
        ));
    }
    if deferred > 0 {
        notes.push(format!(
            "addresses left for a later read: {deferred} (fewer than {QUORUM_THRESHOLD} of the \
             {NEAREST_NODES} nodes nearest each one serve it yet, or something couldn't be read)"
        ));
    }
    notes
}

/// How a walk ended, for [`read_notes`].
fn outcome_text(outcome: WalkOutcome) -> &'static str {
    match outcome {
        WalkOutcome::Complete => "complete",
        WalkOutcome::Budget => "out of earned pages",
        WalkOutcome::Deadline => "at the deadline",
        WalkOutcome::NoAnswer => "stopped answering",
        WalkOutcome::BadPage => "sent a bad page",
    }
}

/// `verified 7/7`, `verified 2/7 (no quorum)` or `reported 5/7`.
fn check_text(checked: &CheckedListing) -> String {
    let level = match checked.level {
        CheckLevel::Verified => "verified",
        CheckLevel::Reported => "reported",
    };
    let quorum = if checked.quorum { "" } else { " (no quorum)" };
    format!("{level} {}/{}{quorum}", checked.nodes, checked.nearest)
}

/// The check column of a listing that failed: `undecided (try again)` when
/// nothing final was decided and a later read may list it.
fn rejected_text(rejected: &RejectedListing) -> &'static str {
    if rejected.again {
        "undecided (try again)"
    } else {
        "not valid"
    }
}

/// When a listing was paid, as far as it shows: the block time to the
/// second, or `~` and the hour it was first seen, or `-`.
fn time_text(listing: &Listing) -> String {
    match (listing.payment.block_timestamp, listing.first_seen) {
        (Some(timestamp), _) => utc(timestamp),
        (None, Some(first_seen)) => format!("~{}", &utc(first_seen)[..16]),
        (None, None) => "-".into(),
    }
}

/// The payment fields a listing hides, for its row: `-` when it shows all.
fn hidden_text(listing: &Listing) -> String {
    let hidden: Vec<&str> = listing
        .flags
        .shown
        .hidden()
        .map(PaymentField::name)
        .collect();
    if hidden.is_empty() {
        "-".into()
    } else {
        format!("hidden: {}", hidden.join(","))
    }
}

/// Text from a listing (its name or content type) or about one, for the
/// terminal: control characters, and characters that reorder or break the
/// line (bidi controls, line and paragraph separators), are shown escaped,
/// as `\u{1b}`, so a node can't move the cursor, recolour the terminal or
/// make a row read as something else. `--json` output is escaped by JSON.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let reorders = matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        );
        if c.is_control() || reorders {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

fn print_row(listing: &Listing, check: &str) {
    println!("{}", row_text(listing, check));
}

fn row_text(listing: &Listing, check: &str) -> String {
    let size = listing
        .size
        .map_or_else(|| "-".to_string(), |size| format!("{size} B"));
    format!(
        "{:<19}  {}  {:>12}  {:<24}  {:<24}  {:<22}  {}",
        time_text(listing),
        hex::encode(listing.address),
        size,
        printable(listing.metadata.content_type.as_deref().unwrap_or("-")),
        printable(listing.metadata.name.as_deref().unwrap_or("-")),
        hidden_text(listing),
        check,
    )
}

fn print_details(listing: &Listing, check: &str) {
    let hidden = || "hidden".to_string();
    let payment = &listing.payment;
    println!("Listing {}", hex::encode(listing.address));
    println!("  Check:    {check}");
    println!(
        "  Readable: {}",
        if listing.flags.withheld {
            "no (data map withheld)"
        } else {
            "yes"
        }
    );
    println!(
        "  Index:    {}",
        if listing.flags.in_index { "yes" } else { "no" }
    );
    println!(
        "  Name:     {}",
        printable(listing.metadata.name.as_deref().unwrap_or("-"))
    );
    println!(
        "  Type:     {}",
        printable(listing.metadata.content_type.as_deref().unwrap_or("-"))
    );
    println!(
        "  Size:     {}",
        listing
            .size
            .map_or_else(|| "-".to_string(), |size| format!("{size} B"))
    );
    println!(
        "  Tx:       {}",
        payment
            .tx_hash
            .map_or_else(hidden, |hash| format!("0x{}", hex::encode(hash)))
    );
    println!(
        "  Block:    {}",
        payment.block_number.map_or_else(hidden, |n| n.to_string())
    );
    println!(
        "  Time:     {}",
        payment
            .block_timestamp
            .map_or_else(hidden, |t| format!("{} UTC", utc(t)))
    );
    println!(
        "  Log:      {}",
        payment.log_index.map_or_else(hidden, |n| n.to_string())
    );
    println!(
        "  Quote:    {}",
        payment.quote.as_deref().map_or_else(hidden, |quote| {
            paid_quote_hash(quote).map_or_else(
                || "shown".to_string(),
                |hash| format!("0x{}", hex::encode(hash)),
            )
        })
    );
    if let Some(first_seen) = listing.first_seen {
        println!("  Seen:     {} UTC, to the hour", utc(first_seen));
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS` in UTC.
pub(crate) fn utc(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let seconds = unix_seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_core::ant_listings::{Flags, ListingPayment, Metadata, ShownFields};

    #[test]
    fn formats_utc_times() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(utc(1_786_315_427), "2026-08-09 22:43:47");
    }

    fn listing(shown: ShownFields, in_index: bool) -> Listing {
        let payment = ListingPayment {
            tx_hash: shown.contains(PaymentField::TxHash).then_some([1; 32]),
            block_number: shown
                .contains(PaymentField::BlockNumber)
                .then_some(52_614_903),
            block_timestamp: shown
                .contains(PaymentField::BlockTimestamp)
                .then_some(1_786_315_427),
            log_index: shown.contains(PaymentField::LogIndex).then_some(3),
            quote: None,
        };
        Listing {
            address: [9; 32],
            flags: Flags {
                shown,
                in_index,
                withheld: false,
            },
            metadata: Metadata {
                content_type: Some("text/plain".into()),
                name: None,
            },
            size: Some(20_480),
            payment,
            first_seen: (in_index && !shown.contains(PaymentField::BlockTimestamp))
                .then_some(1_786_312_800),
        }
    }

    #[test]
    fn json_leaves_hidden_fields_out() {
        let shown = ShownFields::ALL
            .without(PaymentField::Quote)
            .without(PaymentField::BlockTimestamp)
            .without(PaymentField::TxHash);
        let json = serde_json::to_value(ListingJson::new(&listing(shown, true), 5, 7)).unwrap();
        let object = json.as_object().unwrap();
        for absent in [
            "tx_hash",
            "block_timestamp",
            "quote_hash",
            "check",
            "carried",
            "served",
        ] {
            assert!(!object.contains_key(absent), "{absent} should be absent");
        }
        assert_eq!(json["block_number"], 52_614_903);
        assert_eq!(json["log_index"], 3);
        assert_eq!(json["first_seen"], 1_786_312_800);
        assert_eq!(json["time"], 1_786_312_800);
        assert_eq!(json["nodes"], 5);
        assert_eq!(json["nearest"], 7);
        assert_eq!(
            json["hidden"],
            serde_json::json!(["tx-hash", "timestamp", "quote"])
        );
        // A listing showing everything but its quote carries the time it was
        // paid and no first_seen.
        let json =
            serde_json::to_value(ListingJson::new(&listing(ShownFields::ALL, true), 7, 7)).unwrap();
        assert_eq!(json["block_timestamp"], 1_786_315_427);
        assert!(json.get("first_seen").is_none());
        assert_eq!(json["tx_hash"], format!("0x{}", "01".repeat(32)));
        // The mark a carried entry gets, under the name it gets it.
        let marked = ListingJson {
            carried: true,
            ..ListingJson::new(&listing(ShownFields::ALL, true), 7, 7)
        };
        let json = serde_json::to_value(marked).unwrap();
        assert_eq!(json["carried"], true);
    }

    #[test]
    fn a_rejected_listing_counts_its_nodes_against_its_own_nearest() {
        // On a network of five nodes, five are nearest, not seven.
        let rejected = RejectedListing {
            listing: listing(ShownFields::ALL, true),
            problem: "bad".into(),
            nodes: 2,
            nearest: 5,
            again: false,
        };
        let json = serde_json::to_value(ListingJson::rejected(&rejected)).unwrap();
        assert_eq!(json["nodes"], 2);
        assert_eq!(json["nearest"], 5);
        assert_eq!(json["valid"], false);
        assert_eq!(json["problem"], "bad");
        assert_eq!(rejected_text(&rejected), "not valid");
        let again = RejectedListing {
            problem: "served by 2 of the 7 nodes nearest its address so far, needs 4; try again"
                .into(),
            again: true,
            ..rejected
        };
        assert_eq!(rejected_text(&again), "undecided (try again)");
    }

    #[test]
    fn no_valid_listing_fails_the_command() {
        let none = ListingLookup::default();
        let error = require_listing(&none, "ab").unwrap_err();
        assert_eq!(error.to_string(), "no valid listing for ab");
        let rejected_only = ListingLookup {
            rejected: vec![RejectedListing {
                listing: listing(ShownFields::ALL, true),
                problem: "bad".into(),
                nodes: 1,
                nearest: 7,
                again: false,
            }],
            ..ListingLookup::default()
        };
        assert!(require_listing(&rejected_only, "ab").is_err());
    }

    #[test]
    fn rows_show_which_payment_fields_are_hidden() {
        assert_eq!(hidden_text(&listing(ShownFields::ALL, true)), "-");
        let shown = ShownFields::ALL
            .without(PaymentField::TxHash)
            .without(PaymentField::Quote);
        assert_eq!(hidden_text(&listing(shown, true)), "hidden: tx-hash,quote");
        assert_eq!(
            hidden_text(&listing(ShownFields::NONE, true)),
            "hidden: tx-hash,block,timestamp,log-index,quote"
        );
    }

    #[test]
    fn hidden_times_show_the_hour_first_seen() {
        let shown = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        assert_eq!(time_text(&listing(shown, true)), "~2026-08-09 22:00");
        assert_eq!(
            time_text(&listing(ShownFields::ALL, true)),
            "2026-08-09 22:43:47"
        );
        assert_eq!(time_text(&listing(shown, false)), "-");
    }

    #[test]
    fn names_and_types_cannot_drive_the_terminal() {
        assert_eq!(printable("report.pdf"), "report.pdf");
        // Joiners stay: they spell emoji and words.
        assert_eq!(printable("👩\u{200d}💻 notes"), "👩\u{200d}💻 notes");
        assert_eq!(printable("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(printable("\u{9b}31m\u{7f}"), "\\u{9b}31m\\u{7f}");
        assert_eq!(
            printable("invoice\u{202e}fdp.exe"),
            "invoice\\u{202e}fdp.exe"
        );
        assert_eq!(
            printable("one\u{2028}two\r\n\u{2066}"),
            "one\\u{2028}two\\u{d}\\u{a}\\u{2066}"
        );

        // A listing that failed its checks is shown as a node sent it.
        let mut hostile = listing(ShownFields::ALL, true);
        hostile.metadata.name = Some("\u{1b}]0;title\u{7}x.txt".into());
        hostile.metadata.content_type = Some("text/plain\u{1b}[8m".into());
        let row = row_text(&hostile, "not valid");
        assert!(!row.chars().any(char::is_control), "{row:?}");
        assert!(row.contains("text/plain\\u{1b}[8m"), "{row:?}");
        assert!(row.contains("\\u{1b}]0;title\\u{7}x.txt"), "{row:?}");
    }

    /// A listing showing every field, at `[byte; 32]`, paid at `time` in
    /// `block`.
    fn paid(byte: u8, time: u64, block: u64) -> Listing {
        let mut listing = listing(ShownFields::ALL, true);
        listing.address = [byte; 32];
        listing.payment.block_timestamp = Some(time);
        listing.payment.block_number = Some(block);
        listing
    }

    /// `listing` as this read prints it, with its key.
    fn printed(listing: &Listing) -> (ListingKey, ListingJson) {
        (listing.key(), ListingJson::new(listing, 7, 7))
    }

    /// The entries of an earlier output that printed `listings`.
    fn previous_of(listings: &[&Listing]) -> Vec<PreviousEntry> {
        let output: Vec<ListingJson> = listings.iter().map(|listing| printed(listing).1).collect();
        parse_previous(serde_json::to_string(&output).unwrap().as_bytes()).unwrap()
    }

    fn to_json(entries: &[PrintedEntry]) -> Vec<Value> {
        entries
            .iter()
            .map(|entry| serde_json::to_value(entry).unwrap())
            .collect()
    }

    #[test]
    fn earlier_entries_are_kept_dropped_or_replaced_as_the_read_decides() {
        let kept = paid(1, 1_000, 10);
        let gone = paid(2, 2_000, 20);
        let decided = paid(3, 3_000, 30);
        let mut redecided = decided.clone();
        redecided.metadata.name = Some("new.txt".into());
        let out = to_json(&merge_carried(
            vec![printed(&redecided)],
            previous_of(&[&kept, &gone, &decided]),
            |address, _| match address[0] {
                1 => Carry::Keep,
                2 => Carry::NoLongerServed,
                _ => Carry::Decided,
            },
        ));
        // Its file is gone from the nodes nearest it: dropped.
        assert_eq!(out.len(), 2);
        let gone_address = hex::encode(gone.address);
        assert!(out
            .iter()
            .all(|entry| entry["address"] != gone_address.as_str()));
        // Not decided: as it was printed, marked as carried.
        let mut was = serde_json::to_value(printed(&kept).1).unwrap();
        was["carried"] = true.into();
        assert_eq!(out[0], was);
        // Decided: this read's entry stands for the address, alone.
        assert_eq!(out[1]["name"], "new.txt");
        assert!(out[1].get("carried").is_none());
    }

    #[test]
    fn carried_entries_are_printed_again_as_they_were() {
        // An entry from an earlier carry, with a field this version doesn't
        // print: kept whole until a read decides it.
        let address = "ab".repeat(32);
        let earlier = format!(
            r#"[{{"address":"{address}","time":5,"name":"a\u001b.txt","future":[1,{{"x":null}}],
               "valid":true,"carried":true}}]"#
        );
        let previous = parse_previous(earlier.as_bytes()).unwrap();
        let expected = serde_json::from_str::<Vec<Value>>(&earlier).unwrap();
        let kept = to_json(&merge_carried(Vec::new(), previous.clone(), |_, _| {
            Carry::Keep
        }));
        assert_eq!(kept, expected);
        let output = serde_json::to_string(&merge_carried(Vec::new(), previous.clone(), |_, _| {
            Carry::Keep
        }))
        .unwrap();
        assert!(output.contains(r#""name":"a\u001b.txt""#), "{output}");
        assert!(merge_carried(Vec::new(), previous.clone(), |_, _| Carry::Decided).is_empty());
        assert!(merge_carried(Vec::new(), previous, |_, _| Carry::NoLongerServed).is_empty());
    }

    #[test]
    fn earlier_entries_are_keyed_as_their_listings() {
        for shown in ShownFields::every() {
            for in_index in [true, false] {
                let listing = listing(shown, in_index);
                let previous = previous_of(&[&listing]);
                assert_eq!(previous[0].key, listing.key(), "{shown:?} {in_index}");
                assert_eq!(previous[0].address, listing.address);
            }
        }
        // Output from before `time` was printed (listings v1): keyed by the
        // block timestamp, as its listing is.
        let address = "ab".repeat(32);
        let v1 = format!(
            r#"[{{"address":"{address}","block_number":5,"block_timestamp":1000,"log_index":2,
               "tx_hash":"0x01","valid":true}},
               {{"address":"{address}","first_seen":3600}},
               {{"address":"{address}","time":null}}]"#
        );
        let keys: Vec<ListingKey> = parse_previous(v1.as_bytes())
            .unwrap()
            .into_iter()
            .map(|previous| previous.key)
            .collect();
        let key = |time, block_number, log_index| ListingKey {
            time,
            block_number,
            log_index,
            address: [0xab; 32],
        };
        assert_eq!(keys, [key(1_000, 5, 2), key(3_600, 0, 0), key(0, 0, 0)]);
    }

    #[test]
    fn this_read_and_carried_entries_are_merged_in_index_order() {
        // By time, then block number, log index and address.
        let first = paid(5, 100, 1);
        let second = paid(4, 200, 1);
        let third = paid(3, 200, 2);
        let fourth = paid(0x10, 200, 2);
        let mut fifth = paid(2, 200, 2);
        fifth.payment.log_index = Some(9);
        let sixth = paid(1, 300, 1);
        let out = to_json(&merge_carried(
            vec![printed(&sixth), printed(&third), printed(&fourth)],
            previous_of(&[&fifth, &second, &first]),
            |_, _| Carry::Keep,
        ));
        let order: Vec<&str> = out
            .iter()
            .map(|entry| entry["address"].as_str().unwrap())
            .collect();
        let expected: Vec<String> = [first, second, third, fourth, fifth, sixth]
            .iter()
            .map(|listing| hex::encode(listing.address))
            .collect();
        assert_eq!(order, expected);
        let carried: Vec<bool> = out.iter().map(|entry| entry["carried"] == true).collect();
        assert_eq!(carried, [true, true, false, false, true, false]);
    }

    #[test]
    fn a_carry_file_this_command_did_not_write_is_refused() {
        let address = "ab".repeat(32);
        for bad in [
            String::new(),
            "{}".into(),
            r#"{"listings": []}"#.into(),
            "[1]".into(),
            r#"[{"name": "a.txt"}]"#.into(),
            r#"[{"address": "abcd"}]"#.into(),
            format!(r#"[{{"address": "{address}", "time": "soon"}}]"#),
            format!(r#"[{{"address": "{address}", "time": 1, "block_number": -1}}]"#),
            format!(r#"[{{"address": "{address}", "log_index": 1.5}}]"#),
        ] {
            assert!(parse_previous(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(parse_previous(b"[]").unwrap().is_empty());
    }

    #[test]
    fn state_and_carry_files_are_read_first_and_the_state_saved_whole() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("walks.json");
        let carry_path = dir.path().join("listings.json");
        let args = |state: Option<&Path>, carry: Option<&Path>| ListingsArgs {
            since: 0,
            all: true,
            state: state.map(Path::to_path_buf),
            carry: carry.map(Path::to_path_buf),
        };

        // A first run: neither file exists yet.
        let first = args(Some(&state_path), Some(&carry_path))
            .load_earlier(true)
            .unwrap();
        assert_eq!(first.state, WalkState::default());
        assert!(first.previous.is_empty());
        // --carry merges into --json output only.
        assert!(args(None, Some(&carry_path)).load_earlier(false).is_err());

        // The state is saved whole, and nothing is left beside it.
        let state: WalkState =
            serde_json::from_str(r#"{"resume":{"01":"02"},"recent_nodes":[30,24]}"#).unwrap();
        save_state(&state_path, &state).unwrap();
        save_state(&state_path, &state).unwrap();
        assert!(!dir.path().join("walks.json.tmp").exists());
        std::fs::write(&carry_path, "[]").unwrap();
        let loaded = args(Some(&state_path), Some(&carry_path))
            .load_earlier(true)
            .unwrap();
        assert_eq!(loaded.state, state);
        assert_eq!(loaded.state.resuming(), 1);

        // Files that exist but can't be used fail the command.
        std::fs::write(&state_path, "not json").unwrap();
        let error = args(Some(&state_path), None)
            .load_earlier(true)
            .unwrap_err();
        assert!(error.to_string().contains("delete it"), "{error}");
        std::fs::write(&carry_path, "[{}]").unwrap();
        let error = args(None, Some(&carry_path))
            .load_earlier(true)
            .unwrap_err();
        assert!(error.to_string().contains("entry 1: no address"), "{error}");
        assert!(args(None, Some(dir.path())).load_earlier(true).is_err());
        assert!(save_state(&dir.path().join("missing").join("walks.json"), &state).is_err());
    }

    #[test]
    fn a_read_says_what_it_left_for_later() {
        assert!(read_notes(40, false, &[], 0, true).is_empty());
        let notes = read_notes(
            40,
            false,
            &[
                WalkOutcome::Budget,
                WalkOutcome::Deadline,
                WalkOutcome::Budget,
            ],
            12,
            true,
        );
        assert_eq!(
            notes,
            [
                "walks stopped early: 3 (1 at the deadline, 2 out of earned pages); they carry \
                 on where they stopped in the next read",
                "addresses left for a later read: 12 (fewer than 4 of the 7 nodes nearest each \
                 one serve it yet, or something couldn't be read)",
            ]
        );
        let without_state = read_notes(40, false, &[WalkOutcome::NoAnswer], 0, false);
        let note = "walks stopped early: 1 (1 stopped answering); with --state they would carry \
                    on in the next read";
        assert_eq!(without_state, [note]);
        let few = read_notes(5, true, &[], 5, true);
        assert_eq!(few.len(), 2);
        assert!(
            few[0].starts_with("warning: this read found 5 nodes, too few"),
            "{}",
            few[0]
        );
    }
}
