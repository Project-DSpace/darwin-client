//! `ant listings`: the listings index, collected from the nodes and checked.

use std::collections::HashSet;

use ant_core::ant_listings::{Listing, ListingKey};
use ant_core::data::{Client, ListingChain};
use clap::Args;
use serde::Serialize;

/// Arguments of `ant listings`.
#[derive(Args)]
pub struct ListingsArgs {
    /// Only listings paid in this block or later.
    #[arg(long, default_value_t = 0)]
    pub from_block: u64,
    /// Also show listings that fail their checks, with the reason.
    #[arg(long)]
    pub all: bool,
}

#[derive(Serialize)]
struct ListingJson {
    address: String,
    name: Option<String>,
    content_type: Option<String>,
    size: Option<u64>,
    block_number: u64,
    block_timestamp: u64,
    log_index: u64,
    tx_hash: String,
    /// The file's data map, hex-encoded, for listings that pass their checks:
    /// what a client needs to read the file without the envelope.
    data_map: Option<String>,
    valid: bool,
    problem: Option<String>,
}

impl ListingsArgs {
    /// Collect listings from the nodes, check each one, and print them oldest
    /// first. Of several listings claiming one address, the first that passes
    /// its checks is shown.
    pub async fn execute(
        &self,
        client: &Client,
        chain: &ListingChain,
        json: bool,
    ) -> anyhow::Result<()> {
        let from = ListingKey {
            block_number: self.from_block,
            log_index: 0,
        };
        let listings = client.collect_listings(from).await?;

        let mut listed = HashSet::new();
        let mut rows: Vec<(Listing, Result<Vec<u8>, String>)> = Vec::new();
        for listing in listings {
            if listed.contains(&listing.address) {
                continue;
            }
            match client.check_listing(&listing, chain).await {
                Ok(envelope) => {
                    listed.insert(listing.address);
                    let data_map = envelope.data_map_bytes().to_vec();
                    rows.push((listing, Ok(data_map)));
                }
                Err(problem) if self.all => rows.push((listing, Err(problem))),
                Err(_) => {}
            }
        }

        if json {
            let out: Vec<ListingJson> = rows
                .into_iter()
                .map(|(listing, checked)| ListingJson {
                    address: hex::encode(listing.address),
                    name: listing.metadata.name,
                    content_type: listing.metadata.content_type,
                    size: listing.size,
                    block_number: listing.payment.block_number,
                    block_timestamp: listing.payment.block_timestamp,
                    log_index: listing.payment.log_index,
                    tx_hash: format!("0x{}", hex::encode(listing.payment.tx_hash)),
                    valid: checked.is_ok(),
                    data_map: checked.as_ref().ok().map(hex::encode),
                    problem: checked.err(),
                })
                .collect();
            println!("{}", serde_json::to_string(&out)?);
            return Ok(());
        }

        if rows.is_empty() {
            println!("No listings found.");
            return Ok(());
        }
        for (listing, checked) in &rows {
            let size = listing
                .size
                .map_or_else(|| "-".to_string(), |size| format!("{size} B"));
            println!(
                "{}  {}  {:>12}  {:<24}  {}",
                utc(listing.payment.block_timestamp),
                hex::encode(listing.address),
                size,
                listing.metadata.content_type.as_deref().unwrap_or("-"),
                listing.metadata.name.as_deref().unwrap_or("-"),
            );
            if let Err(problem) = checked {
                println!("    not valid: {problem}");
            }
        }
        Ok(())
    }
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SS` in UTC.
fn utc(unix_seconds: u64) -> String {
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
    use super::utc;

    #[test]
    fn formats_utc_times() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(utc(1_790_998_797), "2026-10-03 03:39:57");
    }
}
