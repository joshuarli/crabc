#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw sendfile(2) reference.
#
# This proves only direct regular-file descriptor transfers. Fixture
# paths are test machinery; it does not select a C API or claim path, socket,
# network, splice, or durability behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sendfile reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-sendfile.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-sendfile-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_sendfile_reference_probe.c" \
    -o "$probe"
expected='syscall=40 off_t=signed64 fixtures=regular-files explicit=offset2:advance6:input-position8:output-position4 null=short2:input-position10:output-position6 eof=zero payload=234589 raw=matches-musl-explicit errors=EINVAL,EBADF c-api-selection=excluded path-surface=excluded socket-network=excluded splice=excluded durability=unproved'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 sendfile reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw sendfile reference: PASS\n'
