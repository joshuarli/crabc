#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw statfs/statvfs ABI reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 statfs reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-statfs.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-statfs-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_statfs_reference_probe.c" \
    -o "$probe"
expected='statfs=137 fstatfs=138 struct-size=120 struct-align=8 offsets=proved path=regular-file fd=matches raw=matches-musl statvfs=invariants flags=NOATIME:1024,NODIRATIME:2048,RELATIME:4096 missing=ENOENT closed-fd=EBADF'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 statfs reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw statfs/statvfs ABI reference: PASS\n'
