#!/usr/bin/env bash
# Compile and run only the private wordexp process-adapter fake boundary.
# This script is called by the native Docker dispatcher; do not run it on a
# host outside the pinned image. It imports no selected wordexp C ABI provider.
set -euo pipefail

readonly ROOT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly WORK_DIR="$ROOT_DIR/.work/x86_64/wordexp-process-adapter"
readonly SOURCE="$ROOT_DIR/compat/x86_64/owned_wordexp_process_adapter_tests.rs"
readonly BINARY="$WORK_DIR/owned_wordexp_process_adapter_tests"

[ "$(uname -m)" = x86_64 ] || {
    printf 'ERROR: private wordexp process adapter tests require native x86_64\n' >&2
    exit 1
}
mkdir -p "$WORK_DIR"
TMPDIR="$WORK_DIR" rustc --edition=2021 --test "$SOURCE" -o "$BINARY"
"$BINARY" --test-threads=1
printf 'private x86 wordexp process adapter boundary: PASS (unselected fake boundary)\n'
