#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw advanced-clock and POSIX-timer reference.
#
# The C/POSIX calls in the probe are oracle-only.  It creates only SIGEV_NONE
# timers in its short-lived process, so it neither selects a public C timer ABI
# nor establishes a timer/signal policy for the staged x86-64 evidence lane.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 advanced-time reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-advanced-time.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-advanced-time-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_advanced_time_reference_probe.c" \
    -o "$probe"

expected='layout=timespec16/8 itimerspec32/8 sigevent64/8 offsets=timespec0,8/itimerspec0,16/sigevent0,8,12,16 syscalls=timer:222,223,224,225,226/clock:227,229 process-clock=encoded,current,missing:raw-EINVAL,musl-ESRCH getres=musl+raw-normalized settime=monotonic-no-mutate:EINVAL|EPERM timers=SIGEV_NONE:initial,one-shot,periodic,disarm-interval-zero:stale-value,delete flags=ABSTIME+0x2,0x4,0x80000000-forwarded-ignored errors=invalid-nsec-EINVAL'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 advanced-time reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw advanced-time reference: PASS\n'
