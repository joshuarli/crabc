#!/usr/bin/env bash
# Collect or replay the finite installed public-data variable matrix.
#
# The Python reader owns source/report validation.  A native collection caller
# must supply already selected products; this runner never invokes a sysroot
# builder and will be extended with the retained command matrix alongside the
# reader's `collect` command before its first native collection.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT/compat/x86_64/owned_public_data_variable_runtime.py" "$@"
