#!/usr/bin/env bash
# Residual signal workload; the family coordinator retains named reused cases.
# Usage: [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT/compat/x86_64/owned_posix_signals.py" "$@"
