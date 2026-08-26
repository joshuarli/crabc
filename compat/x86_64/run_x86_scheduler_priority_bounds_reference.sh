#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl scheduler-priority bounds reference.
#
# This proves only the kernel-facing behavior used by the staged typed Rust
# process facade. It does not select crabc-rs as a target artifact or claim
# public x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 scheduler-priority reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-scheduler-priority.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-scheduler-priority-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_scheduler_priority_bounds_reference_probe.c" \
    -o "$probe"
expected='other=0:0 fifo=1:99 rr=1:99 invalid=EINVAL'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 scheduler-priority reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl scheduler-priority bounds reference: PASS\n'
