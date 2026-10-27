//! The places in this crate that read a payment from a receipt, listed.
//!
//! Every check that reads a payment takes the vault set and goes through
//! `paying_log`, which tells the per-quote vault, the root vault and contracts
//! outside the set apart: only `paying_log` reads a root vault's waves in a
//! check, through `RecordedWaves`, and only it refuses a log as `UnknownVault`
//! or `UnpaidWave`. `recorded_wave`, the same read for one log, is for callers
//! of the crate, and no check here calls it. `pays` and `is_vault_payment`
//! each take one address, and are called only in the checks `paying_log`
//! runs. A new read, or a read moved, fails here until it is listed and
//! reviewed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The calls and names counted, in the crate's own code outside its tests.
const COUNTED: &[&str] = &[
    "pays(",
    "is_vault_payment(",
    "paying_log(",
    "recorded_wave(",
    "RecordedWaves::new(",
    "PaymentError::UnknownVault",
    "PaymentError::UnpaidWave(",
];

/// Every counted call or name, by file, function and what it is, with how
/// many times it appears there.
const REVIEWED: &[(&str, &str, &str, usize)] = &[
    // The node's check of an envelope it stores, and the uploader's.
    ("src/payment.rs", "find_payment", "paying_log(", 1),
    ("src/payment.rs", "find_payment", "pays(", 1),
    // A listing: paid to a vault in the set, with its quote or without.
    ("src/payment.rs", "verify_listing", "paying_log(", 2),
    ("src/payment.rs", "verify_listing", "pays(", 1),
    ("src/payment.rs", "verify_listing", "is_vault_payment(", 1),
    // One address's payment for a quote.
    ("src/payment.rs", "pays", "is_vault_payment(", 1),
    // The one place a payment log is found, a root vault's waves read and a
    // log from outside the set refused.
    ("src/payment.rs", "paying_log", "RecordedWaves::new(", 1),
    (
        "src/payment.rs",
        "paying_log",
        "PaymentError::UnpaidWave(",
        1,
    ),
    (
        "src/payment.rs",
        "paying_log",
        "PaymentError::UnknownVault",
        1,
    ),
    // An upload proof.
    ("src/proof.rs", "check_proof", "paying_log(", 1),
    ("src/proof.rs", "check_proof", "pays(", 1),
    // The read of one log's wave, for callers of the crate: the same reader.
    ("src/root.rs", "recorded_wave", "RecordedWaves::new(", 1),
];

/// The crate's source files, its tests left out.
fn production_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let name = path.file_name().unwrap().to_str().unwrap();
                let tests = ["tests.rs", "root_tests.rs", "test_support.rs", "census.rs"];
                if !tests.contains(&name) {
                    out.push(path);
                }
            }
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    files.sort();
    files
}

/// `text` up to its own test module, if it has one inline.
fn without_tests(text: &str) -> &str {
    text.find("#[cfg(test)]\nmod tests {")
        .map_or(text, |end| &text[..end])
}

/// The name of the function a line declares, if it declares one at the top
/// level or in an `impl`.
fn declared(line: &str) -> Option<&str> {
    let indent = line.len() - line.trim_start().len();
    if indent > 4 {
        return None;
    }
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("const ").unwrap_or(rest);
    let name = rest.strip_prefix("fn ")?;
    name.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
}

/// How many times `what` appears in `line` as a call or name of its own,
/// not as the end of a longer name.
fn appearances(line: &str, what: &str) -> usize {
    line.match_indices(what)
        .filter(|(at, _)| {
            line[..*at]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
        .count()
}

#[test]
fn every_payment_read_is_listed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut found: BTreeMap<(String, String, &str), usize> = BTreeMap::new();
    for path in production_files() {
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let file = path
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let mut function = String::from("(module)");
        for line in without_tests(&text).lines() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if let Some(name) = declared(line) {
                function = name.to_string();
                // A declaration isn't a call.
                continue;
            }
            for &what in COUNTED {
                let count = appearances(line, what);
                if count > 0 {
                    *found
                        .entry((file.clone(), function.clone(), what))
                        .or_default() += count;
                }
            }
        }
    }
    let reviewed: BTreeMap<(String, String, &str), usize> = REVIEWED
        .iter()
        .map(|&(file, function, what, count)| ((file.into(), function.into(), what), count))
        .collect();
    assert_eq!(
        found, reviewed,
        "\nA payment is read somewhere new, or a listed read moved.\n\
         Every check that reads a payment from a receipt goes through paying_log with \
         the vault set, which reads a root vault's wave and refuses a log from outside the \
         set; pays and is_vault_payment take one address each.\n"
    );
}

#[test]
fn the_census_sees_the_crates_code() {
    let files = production_files();
    let names: Vec<String> = files
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
        .collect();
    for expected in ["lib.rs", "payment.rs", "proof.rs", "root.rs", "listing.rs"] {
        assert!(names.contains(&expected.to_string()), "{expected}");
    }
    assert_eq!(declared("pub fn find_payment("), Some("find_payment"));
    assert_eq!(declared("    pub(crate) fn pays(log"), Some("pays"));
    assert_eq!(declared("        fn nested() {"), None);
    assert_eq!(appearances("x.pays(log) && pays(log)", "pays("), 2);
    assert_eq!(appearances("overpays(log)", "pays("), 0);
}
