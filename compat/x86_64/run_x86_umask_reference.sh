#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl umask ABI/behavior reference.
#
# This proves only the typed process-mask exchange. It does not select a C
# process API, pathname creation, or broader x86-64 process support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 umask reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

# Establish compiler/header/runtime provenance before using musl as the oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-umask.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-umask-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_umask_reference_probe.c" \
    -o "$probe"
expected='umask=95 mode_t=unsigned32 lifecycle=raw-zero:musl-mask:raw-zero:restore child-contained'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 umask reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl umask ABI/behavior reference: PASS\n'
