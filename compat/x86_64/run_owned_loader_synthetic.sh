#!/usr/bin/env bash
set -euo pipefail
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || { echo "usage: $0 DYNAMIC-SYSROOT" >&2; exit 2; }
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) echo "TMPDIR must be under $ROOT/.work" >&2; exit 2;; esac
exec python3 -B "$ROOT/compat/ldso/run_x86.py" --dynamic-sysroot "$1"
