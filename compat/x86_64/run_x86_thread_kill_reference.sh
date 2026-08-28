#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw exact-thread signal-delivery reference.
#
# The raw arm proves SYS_tgkill's numeric same-process TID contract. The musl
# arm deliberately uses its public pthread_kill behavior as an adjacent oracle:
# musl 1.2.6 implements that API with SYS_tkill, not a public tgkill wrapper.
# This runner selects neither a C tgkill API nor broader pthread signal control.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 thread-kill reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-thread-kill.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-thread-kill-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 -pthread \
    "$ROOT_DIR/compat/x86_64/x86_thread_kill_reference_probe.c" \
    -o "$probe"

expected='tgkill=234 gettid=186 sigusr1=10 raw=live-worker:pending:handler-tid:delivered musl=pthread_kill-tkill:live-worker:pending:handler-tid:delivered errors=ESRCH,EINVAL child-contained c-api-tgkill=absent'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 thread-kill reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw exact-thread signal-delivery reference: PASS\n'
