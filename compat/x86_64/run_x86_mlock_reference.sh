#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl memory-locking ABI/behavior reference.
#
# This proves only the raw kernel memory-locking boundary used by the staged
# typed Rust facade. It does not select crabc-rs as a target artifact or claim
# public x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 memory-locking reference: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-mlock.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-mlock-reference"

"$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_mlock_reference_probe.c" -o "$probe"
actual="$($probe)"
case "$actual" in
    'syscalls=149,325,150 flag=1 lock=available unknown=EINVAL overflow=EINVAL'|'syscalls=149,325,150 flag=1 lock=limited unknown=EINVAL overflow=EINVAL')
        printf 'x86 pinned-musl memory-locking ABI/behavior reference: PASS\n'
        ;;
    *)
        printf 'ERROR: x86 memory-locking reference output mismatch: %s\n' "$actual" >&2
        exit 1
        ;;
esac
