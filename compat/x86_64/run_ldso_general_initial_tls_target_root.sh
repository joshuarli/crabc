#!/usr/bin/env bash
# Feature-gated crabc-ldso target-root admission for general initial TLS.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CRABC_LDSO_GENERAL_INITIAL_TLS_ROOT=crabc-target \
    bash "$ROOT_DIR/compat/x86_64/run_ldso_general_initial_tls.sh"

printf '%s\n' 'x86 private crabc-ldso general-initial-TLS target-root: PASS'
