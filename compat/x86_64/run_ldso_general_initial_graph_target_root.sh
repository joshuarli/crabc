#!/usr/bin/env bash
# Feature-gated crabc-ldso target-root admission for the general graph.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CRABC_LDSO_GENERAL_INITIAL_GRAPH_ROOT=crabc-target \
    bash "$ROOT_DIR/compat/x86_64/run_ldso_general_initial_graph.sh"

printf '%s\n' 'x86 private crabc-ldso general-initial target-root: PASS'
