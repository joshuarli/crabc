#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl calling-thread credential ABI reference.
#
# This proves only Linux's raw calling-task no-change words; it does not
# select musl's process-wide synchronized credential-transition behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 thread-credentials reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-thread-credentials.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-thread-credentials-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_thread_credentials_reference_probe.c" \
    -o "$probe"
expected='syscalls=setresuid:117,setresgid:119 ids=u32 no-change=musl+raw stable'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 thread-credentials reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl thread-credentials ABI/behavior reference: PASS\n'
