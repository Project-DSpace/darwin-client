#!/usr/bin/env bash
#
# Checks that the GitHub workflows keep what a release relies on: a client
# release is published only after the tagged commit's Test and Build runs
# passed, and those runs carry every pin. The Build workflow's
# upstream-installers job and the Test workflow's targets job run it; run it
# by hand with `bash scripts/check-workflows.sh` on a checkout with LF line
# endings. Modelled on darwin-node's scripts/check-workflows.sh.
#
# It fails unless:
# - .github/workflows holds exactly build.yml, release.yml and test.yml;
# - every action a workflow uses is pinned to a full commit SHA;
# - release.yml runs only for v*+ds.* tags and grants no permissions unless
#   a job asks for them;
# - its checks job makes sure the release environment exists and asks for
#   approval (required reviewers), and runs darwin-node-pin.py --release;
# - it waits for the tagged commit's Test and Build runs and
#   fails unless both succeeded, the Test run from the push to main or one
#   run by hand, the Build run from the push to main;
# - its package job needs the checks, takes darwin-linux-x64 from the Build
#   run they found, and checks the archive against its SHA256SUMS.txt and the
#   binary's version and commit;
# - its publish job runs in the release environment and needs checks and
#   package;
# - test.yml's jobs run every end-to-end target (the matrix that
#   scripts/test-targets.py lists, after its check), the browser core's tests
#   and the browser harness;
# - build.yml's linux-x64 job runs the unit tests, the targets that need no
#   nodes and the vendored crates' own tests, then builds darwin and
#   darwin-nodes for release, checks darwin-nodes
#   (scripts/check-darwin-nodes.sh), and uploads darwin-linux-x64;
# - build.yml and test.yml run this check;
# - no workflow has an if: or continues on error, so no job runs after a
#   failed need, no step skips a check, and a Build or Test run that
#   succeeded ran every job and step.
#
# A release runs release.yml as it is at the tagged commit, so this can't
# stop a tag on a commit that changed it; it makes that commit's Build and
# Test runs fail, and the release waits for both.
#
# scripts/test_check_workflows.sh tests it, in the Test workflow.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
DIR=.github/workflows
BUILD="${DIR}/build.yml"
RELEASE="${DIR}/release.yml"
TEST="${DIR}/test.yml"
PROBLEMS=0

problem() {
    echo "::error::$*"
    PROBLEMS=$((PROBLEMS + 1))
}

# A top-level section of a workflow, release.yml unless another is given:
# its key line and the lines under it, leaving out comments and blank lines.
section() {
    awk -v key="$1" '
        /^[^ #]/ { inside = (index($0, key ":") == 1) }
        inside && !/^[ \t]*(#|$)/ { print }
    ' "${2:-${RELEASE}}"
}

# A job of a workflow, release.yml unless another is given: its key line and
# the lines under it, leaving out comments and blank lines.
job() {
    awk -v name="$1" '
        /^[^ #]/ { in_jobs = ($0 ~ /^jobs:/); current = ""; next }
        in_jobs && /^  [A-Za-z0-9_-]+:/ { current = $1; sub(/:$/, "", current) }
        in_jobs && current == name && !/^[ \t]*(#|$)/ { print }
    ' "${2:-${RELEASE}}"
}

# The jobs a job of release.yml needs, one a line, from `needs: x` or
# `needs: [x, y]`.
needs() {
    job "$1" | sed -n 's/^    needs:[[:space:]]*//p' | sed 's/[][]//g' | tr ',' '\n' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d'
}

# Every line of `lines` must appear in `text`; otherwise one problem, `what`,
# naming the first missing line.
require() {
    local what=$1 text=$2 line
    shift 2
    for line in "$@"; do
        if ! grep -qF -- "${line}" <<<"${text}"; then
            problem "${what} (missing: ${line})"
            return
        fi
    done
}

# The workflow files.
found=$(ls -A "${DIR}" | LC_ALL=C sort | tr '\n' ' ')
if [[ "${found}" != "build.yml release.yml test.yml " ]]; then
    problem "${DIR} holds: ${found% }; expected exactly build.yml release.yml test.yml"
fi

# Every action pinned to a commit: owner/repo[/path]@<40 hex digits>.
while IFS= read -r hit; do
    place=${hit%%:*}
    rest=${hit#*:}
    place="${place}:${rest%%:*}"
    ref=$(sed -e 's/^[[:space:]]*-\{0,1\}[[:space:]]*uses:[[:space:]]*//' \
        -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' -e "s/^[\"']//" -e "s/[\"']\$//" \
        <<<"${rest#*:}")
    if [[ ! "${ref}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$ ]]; then
        problem "${place}: '${ref}' is not pinned to a full commit SHA"
    fi
done < <(grep -nE '^[[:space:]]*(-[[:space:]]*)?uses:' "${DIR}"/*.yml || true)

if [[ ! -f "${RELEASE}" ]]; then
    problem "${RELEASE} is missing"
else
    # Triggered only by a v*+ds.* tag.
    expected_on=$(printf '%s\n' "on:" "  push:" "    tags: ['v*\\+ds.*']")
    if [[ "$(section on)" != "${expected_on}" ]]; then
        problem "release.yml must run only for v*+ds.* tags (on: push: tags: ['v*\\+ds.*']); it has: $(section on | tr '\n' ' ')"
    fi

    # No permissions unless a job asks for them.
    if [[ "$(section permissions)" != "permissions: {}" ]]; then
        problem "release.yml must set permissions: {} at the top; it has: $(section permissions | tr '\n' ' ')"
    fi

    # The checks job makes sure the release environment exists and asks for
    # approval: GitHub would create a missing one with no reviewers.
    checks=$(job checks)
    require "release.yml's checks job no longer makes sure the release environment asks for approval" "${checks}" \
        'gh api "repos/$GH_REPO/environments/release"' \
        'if [[ ",$rules," != *",required_reviewers,"* ]]; then'

    # It checks the darwin-node revision the tests ran against may be
    # released against.
    require "release.yml's checks job no longer checks the darwin-node revision may be released against" "${checks}"         'run: python3 scripts/darwin-node-pin.py --release'

    # It waits for the commit's Test and Build runs, and fails unless both
    # succeeded.
    require "release.yml's checks job no longer looks for the commit's runs" "${checks}" \
        'actions/workflows/test.yml/runs' \
        'actions/workflows/build.yml/runs'
    if [[ $(grep -cF -- '-f head_sha="$GITHUB_SHA"' <<<"${checks}" || true) -ne 2 ]]; then
        problem "release.yml's checks job must look for both runs of the tagged commit (-f head_sha=\"\$GITHUB_SHA\")"
    fi
    if [[ $(grep -cF -- 'gh run watch "$run" --exit-status' <<<"${checks}" || true) -ne 2 ]]; then
        problem "release.yml's checks job must wait for both runs (gh run watch \"\$run\" --exit-status)"
    fi
    if [[ $(grep -cF -- '!= "success" ]]; then' <<<"${checks}" || true) -ne 2 ]]; then
        problem "release.yml's checks job must fail unless both runs succeeded"
    fi

    # The Test run it takes is the newest from the push to main or by hand;
    # the Build run, the one from the push to main.
    pick='--jq '\''[.workflow_runs[] | select((.event == "push" and .head_branch == "main") or .event == "workflow_dispatch")] | max_by(.run_number) | .id // empty'\'''
    if ! grep -qF -- "${pick}" <<<"${checks}"; then
        problem "release.yml's checks job must take the Test run from the push to main, or one by hand (missing: ${pick})"
    fi
    if ! grep -qF -- '-f head_sha="$GITHUB_SHA" -f event=push -f branch=main -f per_page=1' <<<"${checks}"; then
        problem "release.yml's checks job must take the Build run from the push to main (missing: -f event=push -f branch=main)"
    fi

    # The package job takes that Build run's binary, and checks it.
    package=$(job package)
    if ! needs package | grep -qx checks; then
        problem "release.yml's package job must need checks"
    fi
    require "release.yml's package job no longer takes the checked Build run's darwin-linux-x64, or no longer checks it" "${package}" \
        'RUN: ${{ needs.checks.outputs.build_run }}' \
        'gh run download "$RUN" --name darwin-linux-x64 --dir dist' \
        'sha256sum -c SHA256SUMS.txt' \
        'if [[ "$version" != "darwin ${TAG#v}" ]]; then' \
        'if [[ ${#commit} -lt 7 || "$GITHUB_SHA" != "$commit"* ]]; then'

    # Publishing waits for the checks and the package, in the release
    # environment, whose reviewers approve it.
    if ! grep -qx '    environment: release' <<<"$(job publish)"; then
        problem "release.yml's publish job must run in the release environment"
    fi
    for need in checks package; do
        if ! needs publish | grep -qx "${need}"; then
            problem "release.yml's publish job must need ${need}"
        fi
    done
fi

if [[ ! -f "${TEST}" ]]; then
    problem "${TEST} is missing"
else
    # Every end-to-end target, as scripts/test-targets.py lists them once its
    # check passed; the browser core's tests; and the browser harness.
    require "test.yml's targets job no longer lists every end-to-end target after the check" "$(job targets "${TEST}")" \
        'python3 scripts/test-targets.py check' \
        'e2e=$(python3 scripts/test-targets.py e2e)'
    require "test.yml's e2e job no longer runs each listed end-to-end target" "$(job e2e "${TEST}")" \
        'needs: targets' \
        'target: ${{ fromJSON(needs.targets.outputs.e2e) }}' \
        'run: cargo test --locked -p ant-core --features test-utils --test "${{ matrix.target }}" -- --test-threads=1'
    require "test.yml's wasm job no longer tests the browser core" "$(job wasm "${TEST}")" \
        '--test ./wasm-tests/*.test.mjs'
    require "test.yml's browser job no longer runs the browser harness" "$(job browser "${TEST}")" \
        'working-directory: darwin-client/ant-core/browser-tests' \
        'run: npm test'
fi

if [[ ! -f "${BUILD}" ]]; then
    problem "${BUILD} is missing"
else
    # The tests a Build run carries, before the binary it uploads.
    require "build.yml's linux-x64 job no longer runs every test before the build it uploads" "$(job linux-x64 "${BUILD}")" \
        'run: cargo test --locked -p ant-core --lib && cargo test --locked -p ant-cli' \
        'targets=$(python3 scripts/test-targets.py no-nodes)' \
        'cargo test --locked -p ant-core --no-fail-fast $targets' \
        'run: cargo test --locked -p ant-listings' \
        'run: cargo test --locked --manifest-path vendor/ant-protocol/Cargo.toml --target-dir target' \
        'run: cargo build --release --locked -p ant-cli --bin darwin --bin darwin-nodes' \
        'run: bash scripts/check-darwin-nodes.sh target/release/darwin-nodes' \
        'name: darwin-linux-x64'
fi

# Build and Test run this check, so a change that breaks it fails both.
for workflow in "${BUILD}" "${TEST}"; do
    if [[ -f "${workflow}" ]] && ! grep -qE '^[[:space:]]+run: bash scripts/check-workflows\.sh[[:space:]]*$' "${workflow}"; then
        problem "${workflow##*/} must run scripts/check-workflows.sh"
    fi
done

# A job runs only once the jobs it needs succeeded, and a step only once the
# steps before it did. A condition would change that: if: always() on
# publish runs it after a failed need, if: false on a step skips its check,
# and a skipped job or step leaves its run green. So would a job or step
# that continues on error.
for workflow in "${DIR}"/*.yml; do
    while IFS= read -r hit; do
        problem "${workflow##*/} must have no if: (a condition can run a job after a failed need, or skip a check): ${hit}"
    done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?if:' "${workflow}" || true)
    while IFS= read -r hit; do
        problem "${workflow##*/} must not continue on error: ${hit}"
    done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?continue-on-error:' "${workflow}" || true)
done

if ((PROBLEMS > 0)); then
    echo "${PROBLEMS} problem(s) in ${DIR}" >&2
    exit 1
fi
echo "${DIR}: build.yml, release.yml and test.yml, every action pinned; release.yml runs for v*+ds.* tags with no default permissions, and publishes, in the release environment (checked to ask for approval), the darwin-linux-x64 of the tagged commit's Build run, checked, only after that run and the commit's Test run succeeded; test.yml runs every end-to-end target, the browser core's tests and the browser harness; build.yml runs the unit tests and the targets that need no nodes before the build it uploads; both run this check; no workflow has a condition or continues on error."
