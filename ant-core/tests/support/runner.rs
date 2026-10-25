//! A small case runner for the `e2e` target, which is built with
//! `harness = false`.
//!
//! libtest runs each test with a network of its own, and starting a network
//! costs far more than most cases do. This runner starts each network the
//! selected cases need once, runs the cases on it one after another on one
//! multi-thread runtime (a panic ends that case only, reported as failed),
//! and tears the network down once. Cases are selected by the
//! arguments as libtest selects tests: names containing any filter given, or
//! equal to one with `--exact`, less those matching a `--skip`; `--list`
//! lists them. Other libtest options (`--test-threads`, `--nocapture`, ...)
//! are accepted and change nothing: cases always run one at a time.
//!
//! Cases run in the order given, except that the cases marked [`Case::last`]
//! run after every other case on the same network: they change the network
//! for the cases after them (a node shut down, for one). After each case,
//! every node handles pointer requests again, whatever the case left
//! silenced.

use super::{MiniTestnet, DEFAULT_NODE_COUNT};
use futures::FutureExt;
use std::future::Future;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The committed key count of the committed network's nodes. Picked above
/// the pricing baseline so `calculate_price(N)` is strictly greater than the
/// empty-node baseline: a bound quote is visibly distinct from a baseline
/// one.
pub const COMMITTED_KEYS: u32 = 9_000;

/// How long one case may run before it is reported failed, so that one case
/// that hangs can't hold the whole run until the job's own limit.
const CASE_TIME_LIMIT: Duration = Duration::from_secs(900);

/// A case's future. Not required to be `Send`: cases run on the runtime's
/// main task, as `#[tokio::test]` runs a test, and some client futures can't
/// be proven `Send` for every lifetime.
type CaseFuture = Pin<Box<dyn Future<Output = ()>>>;

/// The network a case runs on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Needs {
    /// None: the case starts what it needs itself.
    Nothing,
    /// The shared network: [`DEFAULT_NODE_COUNT`] nodes quoting baseline
    /// `(0, None)` quotes, on the DARWIN vault's code.
    Network,
    /// The same, but every node carries a live storage commitment over
    /// [`COMMITTED_KEYS`] keys (ADR-0004).
    Committed,
}

enum Run {
    Alone(Box<dyn Fn() -> CaseFuture>),
    On(Box<dyn Fn(Arc<MiniTestnet>) -> CaseFuture>),
}

/// One case: a name, the network it runs on, and what it runs.
pub struct Case {
    name: String,
    needs: Needs,
    last: bool,
    run: Run,
}

impl Case {
    /// A case on the shared network.
    pub fn on_network<F, Fut>(name: &str, case: F) -> Self
    where
        F: Fn(Arc<MiniTestnet>) -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        Self::on(name, Needs::Network, case)
    }

    /// A case on the committed network.
    pub fn on_committed<F, Fut>(name: &str, case: F) -> Self
    where
        F: Fn(Arc<MiniTestnet>) -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        Self::on(name, Needs::Committed, case)
    }

    /// A case that needs no network of the runner's.
    pub fn alone<F, Fut>(name: &str, case: F) -> Self
    where
        F: Fn() -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        Self {
            name: name.to_string(),
            needs: Needs::Nothing,
            last: false,
            run: Run::Alone(Box::new(move || Box::pin(case()))),
        }
    }

    fn on<F, Fut>(name: &str, needs: Needs, case: F) -> Self
    where
        F: Fn(Arc<MiniTestnet>) -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        Self {
            name: name.to_string(),
            needs,
            last: false,
            run: Run::On(Box::new(move |net| Box::pin(case(net)))),
        }
    }

    /// Run this case after every other case on its network.
    #[must_use]
    pub fn last(mut self) -> Self {
        self.last = true;
        self
    }

    /// The same case under `group::name`.
    #[must_use]
    pub fn in_group(mut self, group: &str) -> Self {
        self.name = format!("{group}::{}", self.name);
        self
    }
}

/// The cases of every list in `lists`, each named `group::name`.
pub fn group(group: &str, lists: impl IntoIterator<Item = Vec<Case>>) -> Vec<Case> {
    lists
        .into_iter()
        .flatten()
        .map(|case| case.in_group(group))
        .collect()
}

/// What the arguments select.
#[derive(Default)]
struct Selection {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    list: bool,
    ignored_only: bool,
}

impl Selection {
    fn parse(args: impl Iterator<Item = String>) -> Self {
        // libtest options that take a value in the next argument.
        const WITH_VALUE: &[&str] = &[
            "--test-threads",
            "--format",
            "--color",
            "--logfile",
            "--report-time",
            "-Z",
        ];
        let mut selection = Self::default();
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--exact" => selection.exact = true,
                "--list" => selection.list = true,
                "--ignored" => selection.ignored_only = true,
                "--skip" => {
                    if let Some(skip) = args.next() {
                        selection.skips.push(skip);
                    }
                }
                other if WITH_VALUE.contains(&other) => {
                    args.next();
                }
                other if other.starts_with('-') => {}
                other => selection.filters.push(other.to_string()),
            }
        }
        selection
    }

    fn selects(&self, name: &str) -> bool {
        if self.ignored_only {
            return false;
        }
        let matches = |pattern: &String| {
            if self.exact {
                name == pattern
            } else {
                name.contains(pattern.as_str())
            }
        };
        (self.filters.is_empty() || self.filters.iter().any(matches))
            && !self.skips.iter().any(matches)
    }
}

/// Run the cases the process's arguments select, and say how it went.
pub fn run(cases: Vec<Case>) -> ExitCode {
    let selection = Selection::parse(std::env::args().skip(1));
    let mut seen = std::collections::HashSet::new();
    for case in &cases {
        assert!(
            seen.insert(case.name.clone()),
            "two cases named {}",
            case.name
        );
    }
    let selected: Vec<Case> = cases
        .into_iter()
        .filter(|case| selection.selects(&case.name))
        .collect();

    if selection.list {
        for case in &selected {
            println!("{}: test", case.name);
        }
        println!();
        println!("{} tests, 0 benchmarks", selected.len());
        return ExitCode::SUCCESS;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build the runtime");
    let failed = runtime.block_on(run_selected(selected));
    runtime.shutdown_timeout(Duration::from_secs(10));
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Run `cases`, grouped by the network they need; true if any failed.
async fn run_selected(cases: Vec<Case>) -> bool {
    let started = Instant::now();
    println!();
    println!("running {} tests", cases.len());

    let mut failures = Vec::new();
    let mut passed = 0usize;
    for needs in [Needs::Nothing, Needs::Network, Needs::Committed] {
        let mut these: Vec<&Case> = cases.iter().filter(|case| case.needs == needs).collect();
        if these.is_empty() {
            continue;
        }
        // Stable: the order given, the last ones last.
        these.sort_by_key(|case| case.last);

        let network = match needs {
            Needs::Nothing => None,
            Needs::Network | Needs::Committed => {
                let start = Instant::now();
                let network = if needs == Needs::Committed {
                    MiniTestnet::start_with_commitments(DEFAULT_NODE_COUNT, COMMITTED_KEYS).await
                } else {
                    MiniTestnet::start(DEFAULT_NODE_COUNT).await
                };
                println!(
                    "network ({needs:?}, {} nodes) started in {:.1} s",
                    network.running_node_count(),
                    start.elapsed().as_secs_f64()
                );
                Some(Arc::new(network))
            }
        };

        for case in these {
            let start = Instant::now();
            let future = match (&case.run, &network) {
                (Run::Alone(run), _) => run(),
                (Run::On(run), Some(network)) => run(Arc::clone(network)),
                (Run::On(_), None) => unreachable!("a case on a network has one"),
            };
            // A panic unwinds out of the case's future alone; whatever it
            // left half done is the case's own state, dropped with it.
            let caught = std::panic::AssertUnwindSafe(future).catch_unwind();
            let outcome = match tokio::time::timeout(CASE_TIME_LIMIT, caught).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err("panicked".to_string()),
                Err(_) => Err(format!(
                    "ran past {} s and was stopped",
                    CASE_TIME_LIMIT.as_secs()
                )),
            };
            if let Some(network) = &network {
                network.reset_switches();
            }
            let seconds = start.elapsed().as_secs_f64();
            match outcome {
                Ok(()) => {
                    passed += 1;
                    println!("test {} ... ok ({seconds:.1} s)", case.name);
                }
                Err(why) => {
                    println!("test {} ... FAILED ({seconds:.1} s): {why}", case.name);
                    failures.push(case.name.clone());
                }
            }
        }

        if let Some(network) = network {
            network.teardown().await;
        }
    }

    println!();
    if !failures.is_empty() {
        println!("failures:");
        for name in &failures {
            println!("    {name}");
        }
        println!();
    }
    println!(
        "test result: {}. {passed} passed; {} failed; finished in {:.1} s",
        if failures.is_empty() { "ok" } else { "FAILED" },
        failures.len(),
        started.elapsed().as_secs_f64()
    );
    !failures.is_empty()
}
