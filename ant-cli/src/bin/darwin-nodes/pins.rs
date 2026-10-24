//! The command census of `darwin-nodes`: every command it has, hidden ones included, with every
//! argument each takes, against the reviewed list below.
//!
//! The image's manager deletes no node's data, downloads nothing and forwards no logs. A change or
//! a merge that adds a command or an argument, or renames one, fails here until it is reviewed
//! against that and listed: a reset, a log-forwarding command, a download source for `add` or an
//! eviction setting never is.

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::daemon::{DaemonCommand, DAEMON_RUN};

/// One reviewed command: the words that run it (empty for `darwin-nodes` itself) and the ids of
/// the arguments it declares, in order.
type Reviewed = (&'static str, &'static [&'static str]);

/// Every command, reviewed: `ant node`'s of `ant` 0.3.9 that the storage-node image runs, and
/// `daemon start`, `stop` and `info`, which only start, stop and describe the daemon.
const COMMANDS: &[Reviewed] = &[
    ("", &["json"]),
    (
        "add",
        &[
            "rewards_address",
            "count",
            "node_port",
            "data_dir_path",
            "log_dir_path",
            "path",
            "bootstrap",
            "env",
        ],
    ),
    ("daemon", &[]),
    ("daemon start", &["log_path", "port", "listen_addr"]),
    ("daemon stop", &[]),
    ("daemon status", &[]),
    ("daemon info", &[]),
    ("daemon run", &["log_path", "port", "listen_addr"]),
    ("dismiss", &["node_id"]),
    ("start", &["service_name"]),
    ("status", &[]),
    ("stop", &["service_name"]),
];

/// Every command under `command`, itself included, as `(words, argument ids)`; `--help`, and the
/// top level's `--version`, are left out (a subcommand's `--version`, such as `ant node add`'s
/// download of a release, is counted).
fn commands(command: &clap::Command, words: &str, found: &mut Vec<(String, Vec<String>)>) {
    let args = command
        .get_arguments()
        .map(|arg| arg.get_id().to_string())
        .filter(|id| id != "help" && !(words.is_empty() && id == "version"))
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

fn found() -> Vec<(String, Vec<String>)> {
    let mut found = Vec::new();
    commands(&Cli::command(), "", &mut found);
    found
}

/// Every command and argument `darwin-nodes` has is in [`COMMANDS`], with the same arguments, and
/// every listed one still exists.
#[test]
fn every_command_and_argument_is_reviewed() {
    let listed: Vec<(String, Vec<String>)> = COMMANDS
        .iter()
        .map(|(words, args)| {
            (
                (*words).to_string(),
                args.iter().map(|id| (*id).to_string()).collect(),
            )
        })
        .collect();
    let found = found();
    let table: String = found
        .iter()
        .map(|(words, args)| format!("    ({words:?}, &{args:?}),\n"))
        .collect();
    assert!(
        found == listed,
        "\nThe commands or arguments of `darwin-nodes` changed. Review each one that is new or \
         changed: the image's manager deletes no node's data, downloads nothing and forwards no \
         logs (see ant-cli/src/bin/darwin-nodes/pins.rs). Then make COMMANDS read:\n\n{table}"
    );
}

/// No reset, no log forwarding, no self-update, no download source and no eviction setting, by
/// name, whatever the census lists.
#[test]
fn there_is_no_reset_log_forwarding_or_download_source() {
    for (words, args) in found() {
        for word in words.split(' ') {
            assert!(
                ![
                    "reset",
                    "logs",
                    "forward",
                    "update",
                    "evict",
                    "clear-evicted"
                ]
                .contains(&word),
                "darwin-nodes {words}"
            );
        }
        for arg in &args {
            assert!(
                ![
                    "url",
                    "version",
                    "upgrade_channel",
                    "evm_network",
                    "force",
                    "token",
                    "endpoint"
                ]
                .contains(&arg.as_str())
                    && !arg.contains("evict"),
                "darwin-nodes {words} --{arg}"
            );
        }
    }
}

/// `add` takes a node binary already on the machine, and only that: `--path` is required.
#[test]
fn add_requires_a_local_binary() {
    let cli = Cli::command();
    let add = cli.find_subcommand("add").expect("darwin-nodes add");
    let path = add
        .get_arguments()
        .find(|arg| arg.get_id() == "path")
        .expect("--path");
    assert!(path.is_required_set(), "--path must be required");

    let error = Cli::try_parse_from([
        "darwin-nodes",
        "add",
        "--rewards-address",
        "0x000000000000000000000000000000000000dEaD",
    ])
    .err()
    .expect("an add without --path is refused");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    assert!(error.to_string().contains("--path"), "{error}");
}

/// What `daemon start` spawns is this CLI's hidden `daemon run`.
#[test]
fn daemon_start_spawns_this_clis_daemon_run() {
    let argv = std::iter::once("darwin-nodes").chain(DAEMON_RUN.iter().copied());
    let cli = Cli::try_parse_from(argv).expect("daemon run parses");
    assert!(matches!(
        cli.command,
        Command::Daemon {
            command: DaemonCommand::Run(_)
        }
    ));
}

/// The whole command line is well formed.
#[test]
fn the_command_line_is_well_formed() {
    Cli::command().debug_assert();
}

/// The binary declares this census: a change that dropped the declaration would drop the pins.
#[test]
fn the_binary_declares_the_command_census() {
    let main = include_str!("main.rs");
    assert!(
        main.contains("#[cfg(test)]\nmod pins;") || main.contains("#[cfg(test)]\r\nmod pins;"),
        "ant-cli/src/bin/darwin-nodes/main.rs must declare `#[cfg(test)] mod pins;`"
    );
}
