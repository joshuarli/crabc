#!/usr/bin/env bash
# Feature-gated crabc-ldso target-root proof for the general RuntimeV1 wire.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CRABC_LDSO_GENERAL_TLS_RUNTIME_V1_ROOT=crabc-target \
    bash "$ROOT_DIR/compat/x86_64/run_loader_libc_general_tls_runtime_v1.sh"

printf '%s\n' 'x86 private crabc-ldso general RuntimeV1 target-root: PASS'
