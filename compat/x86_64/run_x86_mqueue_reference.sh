#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw POSIX named-message-queue reference.
#
# This oracle is private evidence for the typed Rust IPC slice. It uses C only
# to compare POSIX behavior with the direct syscall ABI; it does not select a
# C IPC ABI, POSIX shared memory, errno/TLS, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 ipc reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-64-ipc.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-mqueue-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_mqueue_reference_probe.c" -o "$probe"

expected='syscalls=close:3,fcntl:72,mq_open:240,mq_unlink:241,mq_timedsend:242,mq_timedreceive:243,mq_getsetattr:245 abi=mqd_t:i32:mq_attr64@8:timespec16@8 names=posix-leading-slash:raw-without-slash:raw-public-EACCES attrs=maxmsg2:msgsize64:nonblock:cloexec priority=order:range full-empty=EAGAIN deadline=absolute-realtime-ETIMEDOUT lifetime=unlink-after-open direct-errors=EINVAL:ENOENT:EBADF c-api-selection=excluded'

set +e
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe" 2>"$work_dir/probe.stderr")"
probe_status=$?
set -e
if [ "$probe_status" -ne 0 ]; then
    if [ "$probe_status" -eq 77 ]; then
        fail "POSIX mqueuefs is unavailable; ipc-reference requires live native queue evidence (no fallback or skip)"
    fi
    if [ -s "$work_dir/probe.stderr" ]; then
        sed 's/^/probe: /' "$work_dir/probe.stderr" >&2
    fi
    fail "mqueue probe failed with status $probe_status"
fi
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 ipc reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw POSIX named-message-queue reference: PASS\n'
