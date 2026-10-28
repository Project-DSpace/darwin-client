//! The subcommand census: every command `darwin` has, hidden ones included,
//! with every argument it takes, against a reviewed table of how each one
//! stores and pays. A merge that adds a command or an argument, or renames
//! one, fails here until it is reviewed and listed.
//!
//! The kinds:
//!
//! - [`Kind::Envelope`]: stores files the standard way, each with an
//!   envelope (payment record, listing, `.record` proof), private by
//!   default with every payment field shown, paid per chunk;
//! - [`Kind::Raw`]: stores a raw chunk, by the user's choice, with no
//!   envelope; paid per chunk;
//! - [`Kind::CompactPublish`]: compacts a manifest, reusing the envelopes
//!   it finds; with `--yes` it publishes the data maps of entries with no
//!   public address as plain chunks, after saying they get no envelope;
//! - [`Kind::HeldBack`]: off in this build, refused before it does anything;
//! - [`Kind::Pointer`]: writes a pointer, paid per chunk with the paid quote
//!   read back; a pointer record has no data map, so no envelope;
//! - [`Kind::NoPayment`]: stores and pays nothing.

use crate::cli::Cli;
use clap::CommandFactory;

/// How a command stores and pays: see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Envelope,
    Raw,
    CompactPublish,
    HeldBack,
    Pointer,
    NoPayment,
}

/// One reviewed command: the words that run it (empty for `darwin` itself),
/// its kind, and the ids of the arguments it declares, in order.
type Reviewed = (&'static str, Kind, &'static [&'static str]);

use Kind::{CompactPublish, Envelope, HeldBack, NoPayment, Pointer, Raw};

/// Every command, reviewed.
const COMMANDS: &[Reviewed] = &[
    (
        "",
        NoPayment,
        &[
            "json",
            "bootstrap",
            "devnet_manifest",
            "allow_loopback",
            "ipv4_only",
            "quote_timeout_secs",
            "store_timeout_secs",
            "chunk_get_timeout_secs",
            "quote_concurrency",
            "store_concurrency",
            "verbose",
            "evm_network",
            "max_chunk_price",
            "root_payments",
        ],
    ),
    ("node", HeldBack, &[]),
    (
        "node add",
        HeldBack,
        &[
            "rewards_address",
            "count",
            "node_port",
            "data_dir_path",
            "log_dir_path",
            "path",
            "url",
            "bootstrap",
            "evm_network",
            "upgrade_channel",
            "env",
        ],
    ),
    ("node daemon", HeldBack, &[]),
    (
        "node daemon start",
        HeldBack,
        &["log_path", "port", "listen_addr"],
    ),
    ("node daemon stop", HeldBack, &[]),
    ("node daemon status", HeldBack, &[]),
    ("node daemon info", HeldBack, &[]),
    (
        "node daemon run",
        HeldBack,
        &["log_path", "port", "listen_addr"],
    ),
    ("node dismiss", HeldBack, &["node_id"]),
    ("node logs", HeldBack, &[]),
    ("node logs forward", HeldBack, &[]),
    (
        "node logs forward enable",
        HeldBack,
        &["token", "endpoint", "level"],
    ),
    ("node logs forward disable", HeldBack, &[]),
    ("node logs forward status", HeldBack, &[]),
    ("node reset", HeldBack, &["force"]),
    ("node start", HeldBack, &["service_name"]),
    ("node status", HeldBack, &[]),
    ("node stop", HeldBack, &["service_name"]),
    ("wallet", NoPayment, &[]),
    ("wallet address", NoPayment, &[]),
    ("wallet balance", NoPayment, &[]),
    ("file", NoPayment, &[]),
    (
        "file upload",
        Envelope,
        &[
            "path",
            "public",
            "visibility",
            "readable",
            "index",
            "hide",
            "name",
            "content_type",
            "merkle",
            "no_merkle",
            "store_timeout",
            "store_concurrency",
            "overwrite",
        ],
    ),
    (
        "file download",
        NoPayment,
        &[
            "address",
            "datamap",
            "proof",
            "output",
            "peers",
            "all_peers",
            "download_diagnostics",
        ],
    ),
    (
        "file prove",
        NoPayment,
        &["record", "output", "no_reveal", "force"],
    ),
    ("file verify", NoPayment, &["proof", "file"]),
    (
        "file cost",
        NoPayment,
        &[
            "path",
            "public",
            "visibility",
            "readable",
            "index",
            "hide",
            "name",
            "content_type",
            "merkle",
            "no_merkle",
        ],
    ),
    ("chunk", NoPayment, &[]),
    ("chunk put", Raw, &["file"]),
    (
        "chunk get",
        NoPayment,
        &["address", "output", "all_peers", "peer_count"],
    ),
    ("pointer", NoPayment, &[]),
    ("pointer keygen", NoPayment, &["output"]),
    ("pointer address", NoPayment, &["key"]),
    ("pointer create", Pointer, &["key", "target", "kind"]),
    ("pointer update", Pointer, &["key", "target", "kind"]),
    ("pointer transfer", Pointer, &["key", "recipient"]),
    ("pointer finality", NoPayment, &["address"]),
    ("pointer controller", NoPayment, &["address"]),
    ("pointer get", NoPayment, &["address"]),
    ("pointer resolve", NoPayment, &["address"]),
    ("listings", NoPayment, &["since", "all", "state", "carry"]),
    // Reads nodes and the payment chain, and writes files on this machine
    // only: it stores nothing on the network.
    (
        "listings serve",
        NoPayment,
        &["state_dir", "out_dir", "carry"],
    ),
    // Leaves a file in the producer's state directory, on this machine: no
    // network, no store, no payment.
    ("listings refresh-census", NoPayment, &["state_dir"]),
    ("listing", NoPayment, &["address"]),
    ("manifest", NoPayment, &[]),
    (
        "manifest create",
        Envelope,
        &[
            "paths",
            "output",
            "name",
            "compact",
            "public",
            "visibility",
            "readable",
            "index",
            "hide",
            "follow_symlinks",
            "public_files",
            "embed_public",
            "torrent_hashes",
            "merkle",
            "no_merkle",
            "overwrite",
            "link",
        ],
    ),
    ("manifest list", NoPayment, &[]),
    ("manifest show", NoPayment, &["source"]),
    ("manifest link", NoPayment, &["source"]),
    (
        "manifest export",
        CompactPublish,
        &["source", "output", "compact", "yes", "overwrite", "link"],
    ),
    (
        "manifest download",
        NoPayment,
        &["source", "output", "selection", "overwrite", "concurrency"],
    ),
    ("update", HeldBack, &["force", "channel"]),
];

/// Every command under `command`, itself included, as `(words, argument
/// ids)`; `--help` and `--version` are left out.
fn commands(command: &clap::Command, words: &str, found: &mut Vec<(String, Vec<String>)>) {
    let args = command
        .get_arguments()
        .map(|arg| arg.get_id().to_string())
        .filter(|id| id != "help" && id != "version")
        .collect();
    found.push((words.to_string(), args));
    for subcommand in command.get_subcommands() {
        let words = if words.is_empty() {
            subcommand.get_name().to_string()
        } else {
            format!("{words} {}", subcommand.get_name())
        };
        commands(subcommand, &words, found);
    }
}

/// The table as it would be written for what is found, kinds taken from
/// [`COMMANDS`] where listed, for a reviewer to check and paste.
fn table(found: &[(String, Vec<String>)]) -> String {
    let mut out = String::new();
    for (words, args) in found {
        let kind = COMMANDS
            .iter()
            .find(|(listed, _, _)| listed == words)
            .map_or_else(|| "REVIEW".to_string(), |(_, kind, _)| format!("{kind:?}"));
        let args: Vec<String> = args.iter().map(|id| format!("{id:?}")).collect();
        out.push_str(&format!(
            "    ({words:?}, {kind}, &[{}]),\n",
            args.join(", ")
        ));
    }
    out
}

/// Every command and argument `darwin` has is in [`COMMANDS`], with the
/// same arguments, and every listed one still exists.
#[test]
fn every_command_and_argument_is_reviewed() {
    let mut found = Vec::new();
    commands(&Cli::command(), "", &mut found);
    let listed: Vec<(String, Vec<String>)> = COMMANDS
        .iter()
        .map(|(words, _, args)| {
            (
                (*words).to_string(),
                args.iter().map(|id| (*id).to_string()).collect(),
            )
        })
        .collect();
    assert!(
        found == listed,
        "\nThe commands or arguments of `darwin` changed. Review each one that is new or \
         changed: whether it stores or pays, and how (see ant-cli/src/darwin_pins.rs). A \
         command of our own that stores files stores envelopes; one that pays pays per chunk; \
         a raw path says it carries no envelope; anything that would install or fetch \
         Autonomi's software stays off. Then make COMMANDS read:\n\n{}",
        table(&found)
    );
}

/// The kinds the reviewed table gives the commands that store or pay.
#[test]
fn the_commands_that_store_or_pay_are_the_reviewed_ones() {
    let of = |kind: Kind| -> Vec<&str> {
        COMMANDS
            .iter()
            .filter(|(_, listed, _)| *listed == kind)
            .map(|(words, _, _)| *words)
            .collect()
    };
    assert_eq!(of(Envelope), ["file upload", "manifest create"]);
    assert_eq!(of(Raw), ["chunk put"]);
    assert_eq!(of(CompactPublish), ["manifest export"]);
    assert_eq!(
        of(Pointer),
        ["pointer create", "pointer update", "pointer transfer"]
    );
    let held_back = of(HeldBack);
    assert!(held_back.contains(&"update"), "{held_back:?}");
    assert!(
        held_back
            .iter()
            .all(|words| *words == "update" || *words == "node" || words.starts_with("node ")),
        "{held_back:?}"
    );
    // `darwin node` and every command under it.
    let node: Vec<&str> = COMMANDS
        .iter()
        .map(|(words, _, _)| *words)
        .filter(|words| *words == "node" || words.starts_with("node "))
        .collect();
    assert!(node.len() > 1, "{node:?}");
    assert!(
        node.iter().all(|words| held_back.contains(words)),
        "{node:?}"
    );
    assert!(!of(NoPayment).is_empty());
}
