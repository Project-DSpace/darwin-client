use ant_core::data::{MultiAddr, U256};
use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

use crate::commands::data::{
    ChunkAction, FileAction, ListingArgs, ListingsArgs, ManifestAction, PointerAction, WalletAction,
};
use crate::commands::node::NodeCommand;
use crate::commands::update::UpdateArgs;

/// `darwin 0.3.11` on line 1, the git commit on line 2 (see build.rs).
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit ",
    env!("DARWIN_GIT_COMMIT")
);

#[derive(Parser)]
// NOTE: the version number MUST stay the last token of line 1: the self-update
// check (ant-core update.rs) reads that token from a new binary's `--version`.
#[command(
    name = "darwin",
    version = VERSION,
    about = "Darwin storage network client"
)]
pub struct Cli {
    /// Output structured JSON instead of human-readable text
    #[arg(long, global = true)]
    pub json: bool,

    /// Bootstrap peer addresses (for data operations).
    /// QUIC multiaddresses, comma-separated or repeated. Legacy ip:port is accepted.
    #[arg(long, short, value_delimiter = ',', value_parser = ant_core::network_defaults::parse_quic_seed)]
    pub bootstrap: Vec<MultiAddr>,

    /// Path to devnet manifest JSON (for data operations).
    #[arg(long)]
    pub devnet_manifest: Option<PathBuf>,

    /// Allow loopback connections (required for devnet/local testing).
    #[arg(long)]
    pub allow_loopback: bool,

    /// Force IPv4-only mode (disable dual-stack).
    /// Use on hosts without working IPv6 to avoid advertising
    /// unreachable addresses to the DHT.
    #[arg(long)]
    pub ipv4_only: bool,

    /// Per-op timeout for quote / DHT-lookup operations (seconds).
    /// Static knob; the adaptive controller does not currently size
    /// timeouts.
    #[arg(long, default_value_t = 10, hide = true)]
    pub quote_timeout_secs: u64,

    /// Per-op timeout for chunk store operations (seconds).
    /// Static knob; the adaptive controller does not currently size
    /// timeouts.
    #[arg(long, hide = true)]
    pub store_timeout_secs: Option<u64>,

    /// Per-peer timeout for chunk retrieve operations (seconds).
    /// Static knob; the adaptive controller does not currently size
    /// timeouts.
    #[arg(long, hide = true)]
    pub chunk_get_timeout_secs: Option<u64>,

    /// **Deprecated.** Adaptive controller now sizes quote
    /// concurrency from observed network signals. Setting this caps
    /// the controller's max for the quote channel only (does not
    /// affect store or download). Removed in a future release.
    /// Must be > 0.
    #[arg(long, hide = true, value_parser = parse_positive_usize)]
    pub quote_concurrency: Option<usize>,

    /// **Deprecated.** Adaptive controller now sizes store
    /// concurrency from observed network signals. Setting this caps
    /// the controller's max for the store channel only (does not
    /// affect quote or download). Removed in a future release.
    /// Must be > 0.
    #[arg(long, alias = "chunk-concurrency", hide = true, value_parser = parse_positive_usize)]
    pub store_concurrency: Option<usize>,

    /// Increase verbosity. By default no logs are emitted (privacy by design).
    /// -v: info + warnings, -vv: debug, -vvv: trace.
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// EVM network for payment processing: robinhood (DARWIN on Robinhood
    /// Chain, our network) or local (reads the devnet manifest's EVM config).
    /// Defaults to robinhood — except when a devnet manifest with EVM config
    /// is loaded, where an explicit choice is required so an irreversible
    /// on-chain payment never silently targets the wrong network. Upstream's
    /// arbitrum-one and arbitrum-sepolia, which pay Autonomi's ANT, are
    /// refused.
    #[arg(long, value_parser = ["robinhood", "local"])]
    pub evm_network: Option<String>,

    /// The most a node's quote may ask to store one chunk, in the payment
    /// token's base units (10^-18 of a token). Quotes asking more are
    /// ignored, as if their node hadn't answered, and no payment is made on
    /// one. A chunk is paid 3 times the median quote, so it then costs at
    /// most 3 times this. Default: no ceiling.
    #[arg(long, value_name = "BASE_UNITS", value_parser = parse_base_units)]
    pub max_chunk_price: Option<U256>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage local Autonomi nodes (off in this build: Darwin nodes run from the storage-node image)
    ///
    /// Off in this build: every `darwin node` command fails. Upstream's node
    /// manager would install Autonomi's ant-node from WithAutonomi's releases,
    /// and those nodes join Autonomi's network and take payment on Arbitrum.
    /// Darwin storage nodes run from the storage-node image (see the
    /// darwin-node repository's docker/README.md). Nodes added by an earlier
    /// build are managed with Autonomi's `ant`.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// File operations (multi-chunk upload/download with EVM payment)
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Single-chunk operations (low-level put/get without file splitting)
    Chunk {
        #[command(subcommand)]
        action: ChunkAction,
    },
    /// Pointer operations (owner-signed mutable references, paid per update)
    Pointer {
        #[command(subcommand)]
        action: PointerAction,
    },
    /// Listed files: what nodes list, merged across them, each checked against
    /// the network and the payment chain, oldest first
    Listings(ListingsArgs),
    /// One file's listing, in the index or not: from the nodes nearest its
    /// address, checked against the network and the payment chain
    Listing(ListingArgs),
    /// Manifest operations (torrent-like file sets shared as .darwin files or darwin:// links)
    Manifest {
        #[command(subcommand)]
        action: ManifestAction,
    },
    /// Update the darwin binary (off in this build: there are no darwin releases yet)
    Update(UpdateArgs),
}

/// clap value parser for an amount of the payment token in its base units:
/// a whole decimal number, as the chain counts it.
fn parse_base_units(s: &str) -> Result<U256, String> {
    if s.is_empty() || !s.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("not a whole number of base units".to_string());
    }
    s.parse::<U256>()
        .map_err(|e| format!("not a number of base units: {e}"))
}

/// clap value parser that rejects 0 for the deprecated concurrency
/// pins (a pin of 0 silently disables itself in the controller, which
/// is confusing — fail fast at parse time instead).
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|e| format!("not a non-negative integer: {e}"))?;
    if n == 0 {
        return Err("must be > 0".to_string());
    }
    Ok(n)
}

#[cfg(test)]
mod definition_tests {
    use super::*;
    use clap::CommandFactory;

    /// The whole command line is well formed: among other things, no two
    /// arguments of a command share an id, as flattened upload choices
    /// could.
    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }
}

#[cfg(test)]
mod held_back_tests {
    use super::*;
    use clap::CommandFactory;

    /// The words that run each leaf command under `command`, hidden ones
    /// included.
    fn leaves(command: &clap::Command, words: &str, found: &mut Vec<String>) {
        let mut subcommands = command.get_subcommands().peekable();
        if subcommands.peek().is_none() {
            found.push(words.to_string());
        }
        for subcommand in subcommands {
            leaves(
                subcommand,
                &format!("{words} {}", subcommand.get_name()),
                found,
            );
        }
    }

    /// Every `darwin node` command is refused before it is looked at, so one
    /// a merge adds is refused too. These are the commands
    /// ant-cli/tests/darwin_cli.rs runs to check it: a command that fails
    /// this test goes there too.
    #[test]
    fn the_node_commands_are_the_ones_checked_off() {
        let cli = Cli::command();
        let node = cli.find_subcommand("node").expect("darwin node");
        let mut found = Vec::new();
        leaves(node, "node", &mut found);
        found.sort();
        assert_eq!(
            found,
            [
                "node add",
                "node daemon info",
                "node daemon run",
                "node daemon start",
                "node daemon status",
                "node daemon stop",
                "node dismiss",
                "node logs forward disable",
                "node logs forward enable",
                "node logs forward status",
                "node reset",
                "node start",
                "node status",
                "node stop",
            ]
        );
    }
}

#[cfg(test)]
mod naming_tests {
    use super::*;
    use clap::CommandFactory;

    /// The help a command line asks for with `--help`.
    fn help(args: &[&str]) -> String {
        let mut argv = vec!["darwin"];
        argv.extend_from_slice(args);
        argv.push("--help");
        match Cli::try_parse_from(argv) {
            Err(e) if e.kind() == clap::error::ErrorKind::DisplayHelp => e.to_string(),
            Err(e) => panic!("{args:?}: {e}"),
            Ok(_) => panic!("{args:?}: --help did not print help"),
        }
    }

    /// Links and manifest files are shown as `darwin://` and `.darwin`:
    /// no help of `darwin`, its manifest commands or `darwin file download`
    /// gives an `ant://` example.
    #[test]
    fn the_help_names_darwin_links_and_files() {
        let manifest_commands: Vec<String> = Cli::command()
            .find_subcommand("manifest")
            .expect("darwin manifest")
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect();
        assert!(manifest_commands.len() >= 6, "{manifest_commands:?}");
        let mut pages = vec![
            (vec![], help(&[])),
            (vec!["manifest"], help(&["manifest"])),
            (vec!["file", "download"], help(&["file", "download"])),
        ];
        for name in &manifest_commands {
            let command = vec!["manifest", name.as_str()];
            let page = help(&command);
            pages.push((command, page));
        }
        for (command, page) in &pages {
            assert!(!page.contains("ant://"), "{command:?}:\n{page}");
            assert!(!page.contains(".ant "), "{command:?}:\n{page}");
            assert!(!page.contains(".ant`"), "{command:?}:\n{page}");
        }
        for command in [
            &["manifest", "show"][..],
            &["manifest", "link"],
            &["manifest", "export"],
            &["manifest", "download"],
            &["file", "download"],
        ] {
            assert!(help(command).contains("darwin://"), "{command:?}");
        }
        assert!(help(&[]).contains(".darwin files or darwin:// links"));
        assert!(help(&["manifest", "create"]).contains("<name>.darwin"));
    }
}

#[cfg(test)]
mod payment_network_tests {
    use super::*;

    /// A command of each kind that pays or holds a wallet, as typed after
    /// the global flags.
    const PAYING_COMMANDS: &[&[&str]] = &[
        &["file", "upload", "notes.txt"],
        &["chunk", "put", "chunk.bin"],
        &[
            "pointer",
            "create",
            "--key",
            "owner.key",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ],
        &[
            "pointer",
            "update",
            "--key",
            "owner.key",
            "0000000000000000000000000000000000000000000000000000000000000002",
        ],
        &[
            "pointer",
            "transfer",
            "--key",
            "owner.key",
            "0000000000000000000000000000000000000000000000000000000000000003",
        ],
        &["manifest", "create", "photos"],
        &["manifest", "export", "--compact", "photos.darwin"],
        &["wallet", "balance"],
    ];

    fn parse(network: Option<&str>, command: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec!["darwin"];
        if let Some(network) = network {
            argv.extend(["--evm-network", network]);
        }
        argv.extend_from_slice(command);
        Cli::try_parse_from(argv)
    }

    /// Payments are made in DARWIN only: upstream's Arbitrum presets, which
    /// pay Autonomi's ANT, are refused when the command line is read, before
    /// SECRET_KEY or the network, for every command that pays or holds a
    /// wallet. `robinhood` and `local` are taken, and no flag means the
    /// default.
    #[test]
    fn the_arbitrum_presets_are_refused() {
        for command in PAYING_COMMANDS {
            for preset in [
                "arbitrum-one",
                "arbitrum-sepolia",
                "Arbitrum-One",
                "mainnet",
            ] {
                let error = parse(Some(preset), command)
                    .err()
                    .unwrap_or_else(|| panic!("{preset} {command:?} parsed"));
                assert_eq!(
                    error.kind(),
                    clap::error::ErrorKind::InvalidValue,
                    "{preset} {command:?}: {error}"
                );
            }
            for network in ["robinhood", "local"] {
                let cli = parse(Some(network), command)
                    .unwrap_or_else(|error| panic!("{network} {command:?}: {error}"));
                assert_eq!(cli.evm_network.as_deref(), Some(network));
            }
            let cli = parse(None, command).unwrap_or_else(|error| panic!("{command:?}: {error}"));
            assert_eq!(cli.evm_network, None);
        }
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    #[test]
    fn accepts_multiaddresses_and_legacy_sockets_without_losing_pins() {
        let pin = format!("/ip6/::1/udp/10000/quic/p2p/{}", "ab".repeat(32));
        let cli = Cli::try_parse_from([
            "darwin",
            "--bootstrap",
            &pin,
            "-b",
            "127.0.0.1:10001",
            "wallet",
            "address",
        ])
        .unwrap();
        assert_eq!(cli.bootstrap[0].to_string(), pin);
        assert_eq!(
            cli.bootstrap[1].to_string(),
            "/ip4/127.0.0.1/udp/10001/quic"
        );
        assert!(Cli::try_parse_from([
            "darwin",
            "--bootstrap",
            "/ip4/127.0.0.1/tcp/10000",
            "wallet",
            "address"
        ])
        .is_err());
    }

    #[test]
    fn a_chunk_price_ceiling_is_optional_and_in_base_units() {
        let cli = Cli::try_parse_from(["darwin", "wallet", "address"]).unwrap();
        assert_eq!(cli.max_chunk_price, None, "no ceiling unless asked");
        let cli = Cli::try_parse_from([
            "darwin",
            "--max-chunk-price",
            "1250000000000000000",
            "wallet",
            "address",
        ])
        .unwrap();
        assert_eq!(
            cli.max_chunk_price,
            Some(U256::from(1_250_000_000_000_000_000u128))
        );
        for bad in ["1.25", "-1", "", "0x10", "1 DARWIN"] {
            assert!(
                Cli::try_parse_from(["darwin", "--max-chunk-price", bad, "wallet", "address"])
                    .is_err(),
                "{bad:?}"
            );
        }
    }
}
