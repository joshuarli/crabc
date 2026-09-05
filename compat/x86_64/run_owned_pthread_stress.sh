#!/usr/bin/env bash
# Replay the unchanged aggregate with supplied installed owned products.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT/compat/x86_64/owned_pthread_stress.py" "$@"
