#!/usr/bin/env bash
# Pinned-musl/raw same-process x86-64 queued thread-signal control.
set -euo pipefail
ulimit -c 0

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 signal-thread-queue reference: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || fail 'takes no arguments'
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'refuses emulation' ;; esac
[ -x "$ORACLE_CC" ] || fail 'missing pinned musl compiler'
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'requires checkout-local TMPDIR'
case "$TMPDIR" in "$ROOT_DIR"/.work/*) ;; *) fail 'TMPDIR escapes checkout .work' ;; esac
[ "$(realpath -e "$TMPDIR")" = "$TMPDIR" ] || fail 'TMPDIR is not physical'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" > /dev/null

readonly work="$(mktemp -d "$TMPDIR/signal-thread-queue-reference.XXXXXX")"
trap 'chmod -R a+rX "$work"' EXIT
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 -O2 -pthread -static -fno-pie -no-pie \
    "$ROOT_DIR/compat/x86_64/x86_signal_thread_queue_reference_probe.c" \
    -o "$work/musl-control" > "$work/compile.stdout" 2> "$work/compile.stderr"
timeout 10 env -i LC_ALL=C TZ=UTC "$work/musl-control" \
    > "$work/musl.stdout" 2> "$work/musl.stderr"
expected='threadqueue=297 target=known-worker,self pending=thread-only values=realtime-fifo,ordinary-first metadata=SI_QUEUE,pid,uid errors=ESRCH'
[ "$(cat "$work/musl.stdout")" = "$expected" ] || fail 'musl control observations differ'
[ ! -s "$work/musl.stderr" ] || fail 'musl control wrote stderr'
printf 'x86 pinned-musl/raw signal-thread-queue reference: PASS; evidence: %s\n' "$work"
