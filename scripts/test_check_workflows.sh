#!/usr/bin/env bash
#
# Tests scripts/check-workflows.sh. The Test workflow runs it after the
# check; run it by hand with `bash scripts/test_check_workflows.sh` on a
# checkout with LF line endings. It needs jq, which GitHub's runners have.
#
# The check runs on copies of .github/workflows: once as they are, where it
# must pass, and once for each change below, where it must fail with that
# change's problem alone. Each change would let a release skip something it
# relies on. Then the filter release.yml's checks job picks the tagged
# commit's Test run with runs on sample lists of runs.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
DIR=.github/workflows
BUILD="${DIR}/build.yml"
RELEASE="${DIR}/release.yml"
TEST="${DIR}/test.yml"
PASSED=0
FAILED=0
STALE=""

fail() {
    echo "::error::$*"
    FAILED=$((FAILED + 1))
}

if ! command -v jq > /dev/null; then
    echo "::error::jq is needed to run release.yml's filter" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
COPY="${WORK}/copy"

# A fresh copy of the check and the workflows, for the next case.
fresh() {
    STALE=""
    rm -rf "${COPY}"
    mkdir -p "${COPY}/scripts" "${COPY}/${DIR}"
    cp scripts/check-workflows.sh "${COPY}/scripts/"
    cp -R "${DIR}/." "${COPY}/${DIR}/"
}

# Replaces the one place OLD appears in a file of the copy with NEW. If it
# isn't there exactly once, the case is out of date: it fails, unrun.
edit() {
    local file="${COPY}/$1" old=$2 new=$3 text rest
    text=$(cat "${file}"; printf x)
    text=${text%x}
    rest=${text#*"${old}"}
    if [[ "${rest}" == "${text}" || "${rest}" == *"${old}"* ]]; then
        STALE="$1 doesn't hold exactly one '${old}'"
        return
    fi
    printf '%s' "${text%%"${old}"*}${new}${rest}" > "${file}"
}

# Runs the check on the copy. It must pass when WANT is "pass", and
# otherwise fail with one problem, whose message contains WANT.
expect() {
    local name=$1 want=$2 out rc=0
    if [[ -n "${STALE}" ]]; then
        fail "${name}: this case is out of date: ${STALE}"
        return
    fi
    out=$(bash "${COPY}/scripts/check-workflows.sh" 2>&1) || rc=$?
    if [[ "${want}" == pass ]]; then
        if ((rc != 0)); then
            fail "${name}: the check failed: ${out}"
            return
        fi
    elif ((rc == 0)); then
        fail "${name}: the check passed; it must fail with: ${want}"
        return
    elif [[ $(grep -c '^::error::' <<<"${out}") -ne 1 ]] || ! grep -qF -- "${want}" <<<"${out}"; then
        fail "${name}: the check must fail with this problem alone: ${want}; it said: ${out}"
        return
    fi
    PASSED=$((PASSED + 1))
}

fresh
expect "the workflows as they are" pass

# The workflows and their actions.
fresh
printf 'name: CI\non: push\n' > "${COPY}/${DIR}/ci.yml"
expect "a fourth workflow" "holds: build.yml ci.yml release.yml test.yml;"

fresh
edit "${TEST}" 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: 22

      - name: Lint the browser core' 'actions/setup-node@v4
        with:
          node-version: 22

      - name: Lint the browser core'
expect "an action used by its tag" "'actions/setup-node@v4' is not pinned to a full commit SHA"

fresh
edit "${RELEASE}" 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' 'actions/upload-artifact@ea165f8d'
expect "an action used by a short SHA" "'actions/upload-artifact@ea165f8d' is not pinned to a full commit SHA"

# release.yml's trigger and permissions.
TAGS="    tags: ['v*\\+ds.*']"
fresh
edit "${RELEASE}" "${TAGS}" "${TAGS}"$'\n'"    branches: [main]"
expect "a release on pushes to main" "release.yml must run only for v*+ds.* tags"

fresh
edit "${RELEASE}" "${TAGS}" "    tags: ['v*']"
expect "a release for any v* tag" "release.yml must run only for v*+ds.* tags"

fresh
edit "${RELEASE}" "${TAGS}" "${TAGS}"$'\n'"  workflow_dispatch:"
expect "a release by hand" "release.yml must run only for v*+ds.* tags"

fresh
edit "${RELEASE}" $'\npermissions: {}\n' $'\npermissions: write-all\n'
expect "default permissions" "release.yml must set permissions: {} at the top"

# The checks job.
fresh
edit "${RELEASE}" 'if [[ ",$rules," != *",required_reviewers,"* ]]; then' 'if false; then'
expect "the release environment's approval not checked" "no longer makes sure the release environment asks for approval"

fresh
edit "${RELEASE}" 'actions/workflows/test.yml/runs' 'actions/workflows/build.yml/runs'
expect "no Test run looked for" "missing: actions/workflows/test.yml/runs"

fresh
edit "${RELEASE}" $'if [[ "$conclusion" != "success" ]]; then\n            echo "::error::Test run' \
    $'if false; then\n            echo "::error::Test run'
expect "a failed Test run accepted" "must fail unless both runs succeeded"

fresh
edit "${RELEASE}" $'gh run watch "$run" --exit-status --interval 60 > /dev/null || true\n          conclusion=$(gh api "repos/$GH_REPO/actions/runs/$run" --jq \'.conclusion // empty\')\n          if [[ "$conclusion" != "success" ]]; then\n            echo "::error::Build run' \
    $'conclusion=$(gh api "repos/$GH_REPO/actions/runs/$run" --jq \'.conclusion // empty\')\n          if [[ "$conclusion" != "success" ]]; then\n            echo "::error::Build run'
expect "a Build run still going not waited for" "must wait for both runs"

fresh
edit "${RELEASE}" '(.event == "push" and .head_branch == "main") or .event == "workflow_dispatch"' \
    '.event == "push" or .event == "workflow_dispatch"'
expect "a Test run from a push to any branch taken" "must take the Test run from the push to main, or one by hand"

fresh
edit "${RELEASE}" '(.event == "push" and .head_branch == "main") or .event == "workflow_dispatch"' \
    '(.event == "push" and .head_branch == "main") or .event == "workflow_dispatch" or .event == "pull_request"'
expect "a pull request's Test run taken" "must take the Test run from the push to main, or one by hand"

fresh
edit "${RELEASE}" '-f event=push -f branch=main -f per_page=1' '-f per_page=1'
expect "any Build run of the commit taken" "must take the Build run from the push to main"

# The package job.
fresh
edit "${RELEASE}" $'  package:\n    needs: checks\n' $'  package:\n'
expect "the package taken before the checks" "package job must need checks"

fresh
edit "${RELEASE}" 'gh run download "$RUN" --name darwin-linux-x64 --dir dist' 'gh run download --name darwin-linux-x64 --dir dist'
expect "a binary from another run" "package job no longer takes the checked Build run's darwin-linux-x64"

fresh
edit "${RELEASE}" $'          sha256sum -c SHA256SUMS.txt\n          mkdir unpacked\n' $'          mkdir unpacked\n'
expect "the archive not checked against its sums" "(missing: sha256sum -c SHA256SUMS.txt)"

fresh
edit "${RELEASE}" 'if [[ "$version" != "darwin ${TAG#v}" ]]; then' 'if false; then'
expect "the version not checked" "(missing: if [[ \"\$version\" != \"darwin \${TAG#v}\" ]]; then)"

fresh
edit "${RELEASE}" 'if [[ ${#commit} -lt 7 || "$GITHUB_SHA" != "$commit"* ]]; then' 'if false; then'
expect "the commit not checked" "(missing: if [[ \${#commit} -lt 7 || \"\$GITHUB_SHA\" != \"\$commit\"* ]]; then)"

# Publishing waits for the checks and the package.
fresh
edit "${RELEASE}" $'    environment: release\n' ''
expect "publish outside the release environment" "publish job must run in the release environment"

fresh
edit "${RELEASE}" '    needs: [checks, package]' '    needs: package'
expect "publish without the checks" "publish job must need checks"

fresh
edit "${RELEASE}" '    needs: [checks, package]' '    needs: checks'
expect "publish without the checked package" "publish job must need package"

# No condition, and nothing continuing on error.
fresh
edit "${RELEASE}" $'    needs: [checks, package]\n' $'    needs: [checks, package]\n    if: ${{ always() }}\n'
expect "publish after a failed need" "release.yml must have no if:"

WAIT_TEST="      - name: Wait for the Test workflow's run of this commit"
fresh
edit "${RELEASE}" "${WAIT_TEST}"$'\n' "${WAIT_TEST}"$'\n        if: false\n'
expect "the Test run's check skipped" "release.yml must have no if:"

fresh
edit "${RELEASE}" $'  checks:\n    runs-on: ubuntu-24.04\n' $'  checks:\n    runs-on: ubuntu-24.04\n    continue-on-error: true\n'
expect "the checks job continuing on error" "release.yml must not continue on error"

fresh
edit "${RELEASE}" $'  checks:\n    runs-on: ubuntu-24.04\n' \
    $'  checks:\n    runs-on: ubuntu-24.04\n    # No if: or continue-on-error: true here.\n'
expect "a comment naming both" pass

# The Test run a release waits for runs every pin.
fresh
edit "${TEST}" $'  browser:\n    runs-on: ubuntu-24.04\n' $'  browser:\n    if: ${{ github.event_name == \'schedule\' }}\n    runs-on: ubuntu-24.04\n'
expect "the browser harness only weekly" "test.yml must have no if:"

fresh
edit "${TEST}" $'    timeout-minutes: 120\n' $'    timeout-minutes: 120\n    continue-on-error: true\n'
expect "end-to-end failures let through" "test.yml must not continue on error"

fresh
edit "${TEST}" 'target: ${{ fromJSON(needs.targets.outputs.e2e) }}' 'target: [e2e_merkle, e2e_envelope]'
expect "the end-to-end targets listed by hand" "e2e job no longer runs each listed end-to-end target"

fresh
edit "${TEST}" $'          python3 scripts/test-targets.py check\n' ''
expect "the targets listed without their check" "targets job no longer lists every end-to-end target after the check"

fresh
edit "${TEST}" '        run: npm test' '        run: npx playwright --version'
expect "the browser harness not run" "browser job no longer runs the browser harness"

fresh
edit "${TEST}" $'      - name: Run the release gate\'s check\n        run: bash scripts/check-workflows.sh\n' ''
expect "Test no longer running the check" "test.yml must run scripts/check-workflows.sh"

# The Build run a release takes its binary from runs every test before it.
fresh
edit "${BUILD}" '          cargo test --locked -p ant-core --no-fail-fast $targets' '          echo $targets'
expect "the targets that need no nodes not run" "linux-x64 job no longer runs every test before the build it uploads"

fresh
edit "${BUILD}" '        run: cargo test --locked -p ant-core --lib && cargo test --locked -p ant-cli' '        run: cargo test --locked -p ant-core --lib'
expect "ant-cli's tests left out" "linux-x64 job no longer runs every test before the build it uploads"

fresh
edit "${BUILD}" '        run: bash scripts/check-darwin-nodes.sh target/release/darwin-nodes' '        run: "true"'
expect "the release darwin-nodes not checked" "(missing: run: bash scripts/check-darwin-nodes.sh target/release/darwin-nodes)"

fresh
edit "${BUILD}" $'      - name: Free disk space\n' $'      - name: Free disk space\n        if: ${{ runner.os == \'Linux\' }}\n'
expect "a Build step under a condition" "build.yml must have no if:"

fresh
edit "${BUILD}" $'      - name: Run the release gate\'s check\n        run: bash scripts/check-workflows.sh\n' ''
expect "Build no longer running the check" "build.yml must run scripts/check-workflows.sh"

# The filter release.yml's checks job gives gh api --jq to pick the tagged
# commit's Test run from the runs of test.yml.
filter=$(awk -v q="'" '
    index($0, "actions/workflows/test.yml/runs") { found = 1 }
    found && index($0, "--jq " q) {
        rest = substr($0, index($0, "--jq " q) + 6)
        if (index(rest, q)) { print substr(rest, 1, index(rest, q) - 1) }
        exit
    }
' "${RELEASE}")

# A run as the API lists it: run number, event and branch. Its id is the
# run number plus 39000000000.
run() {
    printf '{"id": %s, "run_number": %s, "event": "%s", "head_branch": "%s"}\n' \
        "$((39000000000 + $1))" "$1" "$2" "$3"
}

# The filter must take the run numbered WANT ("" for none) from RUNS.
takes() {
    local name=$1 want=$2 runs=$3 got
    if [[ -z "${filter}" ]]; then
        fail "release.yml's filter, ${name}: this case is out of date: no --jq filter follows actions/workflows/test.yml/runs in ${RELEASE}"
        return
    fi
    if [[ -n "${want}" ]]; then
        want=$((39000000000 + want))
    fi
    if ! got=$(jq -s '{workflow_runs: .}' <<<"${runs}" | jq -r "${filter}"); then
        fail "release.yml's filter, ${name}: jq failed"
        return
    fi
    if [[ "${got}" != "${want}" ]]; then
        fail "release.yml's filter, ${name}: took '${got}', not '${want}'"
        return
    fi
    PASSED=$((PASSED + 1))
}

push=$(run 14 push main)
hand=$(run 15 workflow_dispatch v0.3.11+ds.1)
pull=$(run 16 pull_request step0-client)
weekly=$(run 17 schedule main)
elsewhere=$(run 18 push step0-client)

takes "the push to main" 14 "${push}"
takes "a later run by hand is taken" 15 "${push}"$'\n'"${hand}"
takes "the order runs are listed in doesn't matter" 15 "${hand}"$'\n'"${push}"
takes "a later pull request run is not taken" 14 "${push}"$'\n'"${pull}"
takes "a later weekly run is not taken" 14 "${push}"$'\n'"${weekly}"
takes "a push to another branch is not taken" 14 "${push}"$'\n'"${elsewhere}"
takes "only a pull request run" "" "${pull}"
takes "no run" "" ""

if ((FAILED > 0)); then
    echo "${FAILED} of $((PASSED + FAILED)) cases failed" >&2
    exit 1
fi
echo "scripts/check-workflows.sh: ${PASSED} cases pass. It passes on the workflows as they are and fails on each change that would let a release skip a check, and release.yml's filter takes the tagged commit's own Test run."
