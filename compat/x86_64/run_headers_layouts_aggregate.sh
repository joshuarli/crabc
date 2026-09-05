#!/usr/bin/env bash
# Native Linux/x86-64 finite header accounting aggregate.
#
# The aggregate executes only the reviewed runner paths derived from the
# checked direct and foundation manifests, then checks their digest-bound
# accounting report. A successful run records finite partial evidence; it
# does not establish family completion, family promotion, product readiness,
# or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly AGGREGATE="$ROOT_DIR/compat/x86_64/headers_layouts_aggregate.py"
readonly ACCOUNTED_INCOMPLETE_RUNNER="compat/x86_64/run_header_callable_linkage_audit.sh"
readonly ACCOUNTED_INCOMPLETE_REPORT="$ROOT_DIR/compat/reports/x86_64/header-callable-linkage-audit/latest.json"

fail() {
    printf 'ERROR: x86 headers/layouts aggregate: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

run_accounted_incomplete_runner() {
    local runner="$1"
    local status

    [ "$runner" = "$ACCOUNTED_INCOMPLETE_RUNNER" ] || fail "unexpected accounted-incomplete runner: $runner"
    [ ! -L "$ACCOUNTED_INCOMPLETE_REPORT" ] || fail "accounted-incomplete report path is a symlink"
    # Do not accept an old report if the intentionally red runner fails before
    # it records this exact finite provider gap.
    rm -f -- "$ACCOUNTED_INCOMPLETE_REPORT"
    if bash "$ROOT_DIR/$runner"; then
        fail "accounted-incomplete runner unexpectedly passed"
    else
        status=$?
    fi
    [ "$status" -eq 1 ] || fail "accounted-incomplete runner failed with status $status"
    python3 "$AGGREGATE" --check-accounted-incomplete-linkage-audit
    printf 'x86 headers/layouts aggregate: ACCOUNTED-INCOMPLETE (declared callable-provider gap)\n'
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
require_tool python3
[ -f "$AGGREGATE" ] || fail "aggregate validator is missing"

mapfile -t runner_contracts < <(python3 "$AGGREGATE" --runner-contract-list)
[ "${#runner_contracts[@]}" -gt 0 ] || fail "aggregate emitted no native runners"

for runner_contract in "${runner_contracts[@]}"; do
    IFS=$'\t' read -r runner outcome <<< "$runner_contract"
    case "$runner" in
        compat/x86_64/*.sh) ;;
        *) fail "aggregate emitted an unsafe runner path: $runner" ;;
    esac
    [ -f "$ROOT_DIR/$runner" ] || fail "aggregate runner is missing: $runner"
    case "$outcome" in
        pass)
            bash "$ROOT_DIR/$runner"
            ;;
        accounted-incomplete)
            run_accounted_incomplete_runner "$runner"
            ;;
        *) fail "aggregate emitted an unsupported runner outcome: $outcome" ;;
    esac
done

python3 "$AGGREGATE" --check
printf 'x86 headers/layouts aggregate: PASS (completed header foundation; C-ABI closure remains downstream)\n'
