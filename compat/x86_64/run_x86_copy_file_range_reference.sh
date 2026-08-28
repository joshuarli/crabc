#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw copy_file_range(2) reference.
#
# This proves only direct same-filesystem regular-file descriptor transfer with
# fixed zero flags. Fixture paths are test machinery; it does not select a C
# API or claim path, fallback, copy-policy, socket, splice, or durability
# behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 copy_file_range reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-copy-file-range.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-copy-file-range-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_copy_file_range_reference_probe.c" \
    -o "$probe"
expected='syscall=326 off_t=signed64 fixtures=same-filesystem-regular-files explicit=in1:out5:advance5,9:positions7,3 null=short3:positions10,6 eof=zero payload=1234,789 raw=matches-musl-explicit errors=EOVERFLOW,EINVAL,EBADF flags=zero-only c-api-selection=excluded path-surface=excluded sendfile-splice-fallback=excluded copy-policy=excluded'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 copy_file_range reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw copy_file_range reference: PASS\n'
