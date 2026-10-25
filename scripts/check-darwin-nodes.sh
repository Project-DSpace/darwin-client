#!/usr/bin/env bash
#
# Checks a built darwin-nodes, the storage-node image's node manager, for
# what ant-cli/tests/darwin_nodes.rs pins on the test build: it holds neither
# of Autonomi's download and log addresses and no reset or log-forwarding
# route, and it holds the status and health routes and the registry file
# the image relies on. A string in the binary is code the linker kept, so
# the check means most on the release build the image ships:
#
#   bash scripts/check-darwin-nodes.sh target/release/darwin-nodes
#
# build.yml runs it on the release build it makes beside `darwin`.
# darwin-node's image build can run it, from the darwin-client commit it
# pins, on the binary it copies into the image. Keep the strings here and in
# the test alike.

set -euo pipefail

binary=${1:?usage: bash scripts/check-darwin-nodes.sh <path to darwin-nodes>}
if [[ ! -f "${binary}" ]]; then
    echo "::error::${binary} is not a file"
    exit 1
fi

problems=0
for needle in WithAutonomi logs.autonomi.com /api/v1/reset /api/v1/logs/forward; do
    if grep -aqF -- "${needle}" "${binary}"; then
        echo "::error::${binary} contains '${needle}'"
        problems=$((problems + 1))
    fi
done
for needle in /api/v1/nodes/status /api/v1/health node_registry.json; do
    if ! grep -aqF -- "${needle}" "${binary}"; then
        echo "::error::${binary} lacks '${needle}'"
        problems=$((problems + 1))
    fi
done

if ((problems > 0)); then
    exit 1
fi
echo "${binary}: no Autonomi download or log address, no reset or log-forwarding route; it serves node status and health, and reads node_registry.json."
