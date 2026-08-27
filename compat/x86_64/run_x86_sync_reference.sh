#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw global sync ABI reference.
#
# This proves only that pinned musl's void sync wrapper returns and that the
# raw x86 syscall returns zero after writing a disposable regular file. It
# does not measure writeback timing or claim media/cache durability.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sync reference: %s\n' "$*" >&2
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

# Establish compiler/header/runtime provenance before using musl as the oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-sync.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-sync-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_sync_reference_probe.c" \
    -o "$probe"
expected='syscall=162 musl=returned raw=0 dirty-regular-file=used timing=unproved durability=unproved'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 sync reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw global sync ABI reference: PASS\n'
