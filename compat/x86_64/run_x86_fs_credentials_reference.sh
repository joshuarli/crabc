#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl filesystem-credential reference.
#
# This proves only the direct calling-task setfsuid/setfsgid query and
# current-effective-ID request semantics. It does not select a C credential
# API, claim detectable permission failure, or emulate musl's process-wide
# credential synchronization.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 filesystem-credentials reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-fs-credentials.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-fs-credentials-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_fs_credentials_reference_probe.c" \
    -o "$probe"
expected='syscalls=setfsuid:122,setfsgid:123 ids=u32 lifecycle=musl-query:raw-query:raw-current:musl-current:raw-query child-contained'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 filesystem-credentials reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl filesystem-credentials ABI/behavior reference: PASS\n'
