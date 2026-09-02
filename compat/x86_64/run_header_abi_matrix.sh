#!/usr/bin/env bash
# Native Linux/x86-64 all-public-header prototype and named declaration-form inventory.
#
# The matrix compiles every direct public include/profile through the pinned
# musl 1.2.6 and Linux 5.10 roots, then checks one reviewed partial declaration-form
# inventory.  A red difference record is expected while header completion is
# still in progress; a stale report or a failed candidate compile is not.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MATRIX="$ROOT_DIR/compat/x86_64/header_abi_matrix.py"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include

fail() {
    printf 'ERROR: x86 header ABI matrix: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in clang python3; do
    require_tool "$tool"
done
[ -x "$MATRIX" ] || fail "matrix generator is not executable"
[ -d "$MUSL_INCLUDE" ] || fail "Pinned musl include root is missing"
[ -d "$LINUX_UAPI_INCLUDE" ] || fail "Linux 5.10 UAPI include root is missing"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh" >/dev/null
python3 "$MATRIX" \
    --compiler clang \
    --project-include "$ROOT_DIR/include" \
    --musl-include "$MUSL_INCLUDE" \
    --linux-uapi-include "$LINUX_UAPI_INCLUDE" \
    --check

printf 'x86 header ABI matrix: PASS (checked partial declaration-form inventory)\n'
