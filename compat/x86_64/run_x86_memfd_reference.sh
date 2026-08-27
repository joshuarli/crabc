#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl memfd and sealing ABI/behavior reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 memfd reference: %s\n' "$*" >&2
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-memfd.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-memfd-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_memfd_reference_probe.c" \
    -o "$probe"
expected='syscalls=319,72 commands=1033,1034 mfd=1,2,4 seals=1,2,4,8,16 name=249-ok:250-einval:proc-label fd=cloexec-owned lifecycle=allow-empty:write-live-map-ebusy:grow-shrink-enforced:write-enforced:future-write-existing-map-preserved:direct-write-rejected:new-writable-map-rejected:final-seal plain=seal-seal errors=EINVAL,EPERM,EBUSY,EBADF'
if actual="$("$probe")"; then
    :
else
    status=$?
    printf 'ERROR: x86 memfd reference probe failed with exit %s\n' "$status" >&2
    exit "$status"
fi
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 memfd reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl memfd/sealing ABI/behavior reference: PASS\n'
