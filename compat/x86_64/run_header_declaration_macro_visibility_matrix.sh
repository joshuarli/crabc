#!/usr/bin/env bash
# Native Linux/x86-64 all-public-header declaration/macro visibility evidence.
#
# The existing declaration-form runner owns the one compiler collection pass.
# This derived checked report then strips source spellings to compare only named
# visibility identities, preserving source-form differences as separate facts.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MATRIX="$ROOT_DIR/compat/x86_64/header_declaration_macro_visibility_matrix.py"

fail() {
    printf 'ERROR: x86 header declaration/macro visibility matrix: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
[ -x "$MATRIX" ] || fail "matrix generator is not executable"

bash "$ROOT_DIR/compat/x86_64/run_header_abi_matrix.sh" >/dev/null
python3 "$MATRIX" --check

printf 'x86 header declaration/macro visibility matrix: PASS (checked finite identity report)\n'
