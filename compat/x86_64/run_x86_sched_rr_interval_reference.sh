#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl sched_rr_get_interval(2) reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sched_rr_get_interval reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-rr-interval.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-sched-rr-interval-reference"

"$ORACLE_CC" -std=c11 -pthread \
    "$ROOT_DIR/compat/x86_64/x86_sched_rr_interval_reference_probe.c" \
    -o "$probe"
expected='layout=timespec16/8 offsets=0,8 syscall=148 current=canonical direct=match task=live missing=ESRCH'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 sched_rr_get_interval reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl sched_rr_get_interval ABI and behavior reference: PASS\n'
