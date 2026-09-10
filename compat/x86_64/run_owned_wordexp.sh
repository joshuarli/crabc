#!/usr/bin/env bash
# Retain bounded installed-product wordexp evidence.  The legacy static archive
# ownership/default-absence gate remains run_libc_owned_wordexp.sh.
set -euo pipefail
readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 -B "$ROOT_DIR/compat/x86_64/owned_wordexp_evidence.py" run "$@"
