#!/usr/bin/env bash
# Native evidence launcher for the cfg-isolated x86 initial-exec TLS sibling.
#
# Keep the implementation in the established initial-TLS runner so both
# artifacts exercise the same fixed mapping, relocation, and malformed-ELF
# harness.  This wrapper is the only selector for the DF_STATIC_TLS/TPOFF64
# cfg; it never changes the GNU-Dynamic artifact's default command.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec env CRABC_LDSO_INITIAL_EXEC_TLS=1 \
    bash "$ROOT_DIR/compat/x86_64/run_ldso_initial_tls.sh"
