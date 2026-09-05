#!/usr/bin/env bash
# Canonical native owned-dynamic product gate. Schema checks alone never publish.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "$#" in
    0) exec bash "$ROOT_DIR/compat/x86_64/run_materialized_dynamic_sysroot.sh" ;;
    1)
        [ "$1" = --check-contract ] || exit 2
        python3 -B "$ROOT_DIR/compat/x86_64/dynamic_product_contract.py" --check
        python3 -B "$ROOT_DIR/compat/x86_64/validate_loader_libc_tls_runtime_v1.py" --json
        ;;
    *) exit 2 ;;
esac
