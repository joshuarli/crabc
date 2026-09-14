#!/usr/bin/env bash
# Collect or replay the finite installed public-data variable runtime receipt.
#
# This wrapper accepts already selected products and current companion reports;
# it never builds a sysroot.  ``collect`` runs only in the pinned native image,
# while ``validate-report`` replays retained bytes and supplied current cohort
# identities without invoking a compiler, linker, or target tool.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT/compat/x86_64/owned_public_data_variable_runtime.py" "$@"
