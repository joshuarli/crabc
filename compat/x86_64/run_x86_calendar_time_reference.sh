#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw civil-time reference.
#
# The C calls in the probe are oracle-only.  In particular, its short-lived
# POSIX-TZ process state does not select a C time ABI, C timezone globals, or
# any public x86-64 runtime support for crabc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 civil-time reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-calendar-time.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-calendar-time-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_calendar_time_reference_probe.c" \
    -o "$probe"

expected='syscall=gettimeofday:96 abi=rdi-timeval:rsi-null layout=timeval16/8:offsets=0,8 raw=normalized:record-bounded utc=gmtime_r:timegm:epoch:pre-epoch:leap:400-year tz=POSIX-EST5EDT4-M3.2.0-M11.1.0 dst=start-gap:end-fold native=rule-input-only:no-c-time-abi:no-TZ-global c-api-selection=excluded'
actual="$(env -u TZ -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 civil-time reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw civil-time reference: PASS\n'
