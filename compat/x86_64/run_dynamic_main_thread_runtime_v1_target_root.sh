#!/usr/bin/env bash
# Feature-gated crabc-ldso target-root proof for the real-Scrt1 RuntimeV1 bridge.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CRABC_DYNAMIC_MAIN_THREAD_RUNTIME_V1_LOADER_ROOT=crabc-target \
    bash "$ROOT_DIR/compat/x86_64/run_dynamic_main_thread_runtime_v1.sh"

printf '%s\n' 'x86 private crabc-ldso dynamic main-thread RuntimeV1 target-root: PASS'
