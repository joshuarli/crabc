#!/usr/bin/env bash
# Observe clock selection in pinned musl's timed condition implementation.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly REPORT_DIR="$ROOT_DIR/.work/x86_64/reports/libc-pthread-condattr-clock"

mkdir -p "$REPORT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/compat/x86_64/libc_pthread_condattr_clock_timed_oracle.c" \
    -o "$REPORT_DIR/musl-condattr-timed-oracle"
timeout 10s "$REPORT_DIR/musl-condattr-timed-oracle" >"$REPORT_DIR/musl-timed.stdout"
printf '%s\n' \
    'musl-realtime-past-monotonic-deadline: pass' \
    'musl-monotonic-future-deadline: pass' >"$REPORT_DIR/musl-timed.expected"
cmp "$REPORT_DIR/musl-timed.expected" "$REPORT_DIR/musl-timed.stdout"
