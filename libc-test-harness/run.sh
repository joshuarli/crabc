#!/usr/bin/env bash
# Compatibility entry point for the libc-test harness.
# Usage: ./run.sh [functional|math|regression|api|all]
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "FATAL: Python 3 is required to run libc-test-harness" >&2
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/runner.py" "$@"
