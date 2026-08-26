#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl timerfd ABI and lifecycle reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 timerfd reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-timerfd.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-timerfd-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_timerfd_reference_probe.c" \
    -o "$probe"
expected='layout=size32 align8 offsets=0,16 syscalls=283,286,287 flags=checked cloexec=enabled disarmed=zero arm=readable expirations=u64 disarm=zero errors=EINVAL,EAGAIN'
actual="$("$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 timerfd reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl timerfd ABI/lifecycle reference: PASS\n'
