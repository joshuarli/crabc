#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl msync ABI/behavior reference.
#
# This proves only the raw VM synchronization boundary used by a future
# typed facade. It does not select crabc-rs or claim public x86-64 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 msync reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-msync.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-msync-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_msync_reference_probe.c" -o "$probe"
expected='syscall=26 flags=0,1,2,3,4,6 accepted invalid=5,7=EINVAL'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 msync reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl msync ABI/behavior reference: PASS\n'
