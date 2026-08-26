#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl pidfd_open reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 pidfd_open reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

# Establish compiler/header provenance before using musl as the ABI oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pidfd-open.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-pidfd-open-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_pidfd_open_reference_probe.c" \
    -o "$probe"
actual="$($probe)"
case "$actual" in
    pidfd_open=unsupported)
        printf 'x86 pinned-musl pidfd_open reference: UNSUPPORTED (kernel lacks pidfd_open)\n'
        ;;
    'pidfd_open=available nonblock=enabled errors=preserved')
        printf 'x86 pinned-musl pidfd_open reference: PASS\n'
        ;;
    *)
        printf 'ERROR: x86 pidfd_open reference output mismatch: %s\n' "$actual" >&2
        exit 1
        ;;
esac
