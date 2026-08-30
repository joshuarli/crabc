#!/usr/bin/env bash
# Native admission evidence for the private x86 crabc-ldso ET_DYN root.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The shared fixed graph runner owns every fixture and negative mutation. This
# wrapper changes only its interpreter construction: Cargo must build the
# feature-gated `crabc-ldso` cdylib target root, which the graph then executes
# through PT_INTERP. It deliberately does not widen that graph or introduce
# an installed loader, CRT/sysroot, libc, or public x86 support claim.
CRABC_LDSO_INITIAL_GRAPH_ROOT=crabc-target \
    bash "$ROOT_DIR/compat/x86_64/run_ldso_initial_graph.sh"

printf '%s\n' 'x86 private crabc-ldso target-root admission: PASS (fixed ET_DYN interpreter graph)'
