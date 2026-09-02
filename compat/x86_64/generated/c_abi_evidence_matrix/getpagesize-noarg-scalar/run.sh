#!/usr/bin/env bash
# Generated from c_abi_evidence_matrix.toml and family fragments; do not edit.
# The focused runner owns the pinned-musl oracle/candidate build-and-run and
# static export check; the checked matrix family aggregate executes this wrapper.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
bash "$ROOT_DIR/compat/x86_64/run_getpagesize_header_abi.sh"
bash "$ROOT_DIR/compat/x86_64/run_libc_getpagesize.sh"
