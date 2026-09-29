#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl ppoll/pause reference and owned ppoll differential.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 ppoll reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64/tmp"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/tmp/ppoll-reference.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-ppoll-reference"
candidate="$work_dir/x86-ppoll-candidate"
archive="$work_dir/libc.a"

"$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_ppoll_reference_probe.c" -o "$probe"
expected='ppoll=0,1,1 revents=0x0,pollin,pollhup mask-restored=1 pause=eintr'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 ppoll reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

build_source_runtime_libc "$archive"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PPOLL_CANDIDATE \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector \
    -ffunction-sections -fdata-sections -Wl,-e,_start \
    -Wl,--no-undefined -Wl,--gc-sections \
    "$ROOT_DIR/compat/x86_64/x86_ppoll_reference_probe.c" \
    "$ROOT_DIR/compat/x86_64/libc_readiness_waits_start.S" \
    "$archive" -o "$candidate"
if "$candidate"; then
    :
else
    status=$?
    fail "candidate invalid-timeout precedence probe exited ${status}"
fi

printf 'x86 pinned-musl ppoll/pause reference and crabc invalid-timeout differential: PASS\n'
