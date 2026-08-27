#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl lseek/fsync/fdatasync ABI/behavior reference.
#
# This proves only the direct typed file-position and descriptor-sync boundary.
# It does not select a C filesystem API or claim host-filesystem durability.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 file-position reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-file-position.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-file-position-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_file_position_reference_probe.c" \
    -o "$probe"
expected='syscalls=lseek:8,fsync:74,fdatasync:75 off_t=signed64 positions=start1:current3:end5 sparse=data4096:hole0 sync=memfd-position-stable over-i64=SEEK_SET:EINVAL,SEEK_DATA/HOLE:ENXIO errors=EINVAL,ENXIO,ESPIPE,EBADF'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 file-position reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl file-position ABI/behavior reference: PASS\n'
