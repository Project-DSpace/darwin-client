//! ant-core's end-to-end cases, against in-process darwin-node nodes (the
//! revision ant-core/Cargo.toml pins) and a local Anvil chain whose payment
//! vault runs the DARWIN vault's code.
//!
//! Built with `harness = false`: [`support::runner`] starts one 20-node
//! network, runs every case on it one after another, and tears it down once;
//! the ADR-0004 cases get a committed network of their own after it. Select
//! cases as with libtest, by name: `storage`, `envelopes`, `refusals`,
//! `pointers`, `root_payments` and `committed` are the groups, so
//!
//! ```text
//! cargo test -p ant-core --features test-utils --test e2e -- refusals
//! ```
//!
//! runs the refusal pins alone. Each case uses content of its own, since the
//! network is shared: a case that found its chunks stored by another would
//! pay nothing, and prove less.
//!
//! - `storage`: the raw chunk path, DARWIN payments per chunk, payment
//!   verification of tampered proofs, data and file uploads, cost estimates,
//!   occupied quotes, and payment recovery: a native payment's journal, a
//!   record paid on its own whose payment the RPC answered with an error,
//!   two files sharing one payment wave recovered from their journals, and
//!   kept proofs that every storer refuses, paid again at most once, never
//!   when the payment was settled from the journal, and never while the
//!   vault's record of the payment can't be read.
//! - `envelopes`: envelopes as the default of our own tools, and manifests (ADR-0006).
//! - `refusals`: merkle refusal, darwin-node refusing batch payments at quote
//!   time with nothing paid (`BATCH_PAYMENTS_REFUSED`).
//! - `pointers`: pointer rules as the client sees them against real nodes.
//! - `committed`: ADR-0004 commitment-bound quotes, and the refusal of a
//!   batch on a commitment-bound network.
//! - `root_payments`: records paid in waves through the root vault, records
//!   whose close group holds a node without it paid through the per-quote
//!   vault instead, and what a client paying the root vault hands a payer
//!   outside it quoted for the per-quote vault.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

mod support;

#[path = "e2e/adr0004.rs"]
mod adr0004;
#[path = "e2e/chunk.rs"]
mod chunk;
#[path = "e2e/cost_estimate.rs"]
mod cost_estimate;
#[path = "e2e/data.rs"]
mod data;
#[path = "e2e/envelope.rs"]
mod envelope;
#[path = "e2e/file.rs"]
mod file;
#[path = "e2e/manifest.rs"]
mod manifest;
#[path = "e2e/merkle.rs"]
mod merkle;
#[path = "e2e/native_payment.rs"]
mod native_payment;
#[path = "e2e/occupied_quotes.rs"]
mod occupied_quotes;
#[path = "e2e/payment.rs"]
mod payment;
#[path = "e2e/payment_recovery.rs"]
mod payment_recovery;
#[path = "e2e/pointer.rs"]
mod pointer;
#[path = "e2e/root_payment.rs"]
mod root_payment;
#[path = "e2e/security.rs"]
mod security;
#[path = "e2e/size_pricing.rs"]
mod size_pricing;

use support::runner::{group, run};

fn main() -> std::process::ExitCode {
    let mut cases = Vec::new();
    cases.extend(group(
        "storage",
        [
            native_payment::cases(),
            chunk::cases(),
            payment::cases(),
            security::cases(),
            data::cases(),
            file::cases(),
            cost_estimate::cases(),
            occupied_quotes::cases(),
            payment_recovery::cases(),
            size_pricing::cases(),
        ],
    ));
    cases.extend(group("envelopes", [envelope::cases(), manifest::cases()]));
    cases.extend(group(
        "refusals",
        [
            merkle::cases(),
            envelope::refusals(),
            cost_estimate::refusals(),
        ],
    ));
    cases.extend(group("pointers", [pointer::cases()]));
    cases.extend(group("root_payments", [root_payment::cases()]));
    cases.extend(group("committed", [adr0004::cases()]));
    run(cases)
}
