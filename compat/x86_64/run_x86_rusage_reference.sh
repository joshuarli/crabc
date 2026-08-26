#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl getrusage ABI/behavior reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 rusage reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-rusage.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-rusage-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_rusage_reference_probe.c" \
    -o "$probe"
expected='layout=timeval16/8 prefix144/8 rusage272/8 offsets=0,16,32,136 tail=144+128 syscall=98 selectors=0,-1,1 canonical=valid self=nondecreasing direct=all-selectors children=prefix-equivalent invalid=EINVAL'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 rusage reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl getrusage ABI/behavior reference: PASS\n'
