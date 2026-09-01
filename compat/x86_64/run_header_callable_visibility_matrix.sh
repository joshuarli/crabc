#!/usr/bin/env bash
# Native Linux/x86-64 all-header callable feature-visibility evidence.
#
# The compiler-derived inventory is regenerated and checked first. The matrix
# then compares its direct public-include callable name/class observations
# against the reviewed finite report. A passing check means the current red
# report is accounted for; it does not mean header ABI, archive linkage,
# runtime behavior, family promotion, or public x86 support is complete.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly INVENTORY_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_inventory.py"
readonly MATRIX_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_visibility_matrix.py"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/header_callable_inventory.json"
readonly MATRIX="$ROOT_DIR/compat/x86_64/generated/header_callable_visibility_matrix/report.json"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include

fail() {
    printf 'ERROR: x86 header callable visibility matrix: %s\n' "$*" >&2
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
[ -x "$INVENTORY_GENERATOR" ] || fail "inventory generator is not executable"
[ -x "$MATRIX_GENERATOR" ] || fail "matrix generator is not executable"
[ -f "$INVENTORY" ] || fail "checked callable inventory is missing"
[ -f "$MATRIX" ] || fail "checked callable visibility matrix is missing"
[ -d "$MUSL_INCLUDE" ] || fail "pinned musl headers are missing"
[ -d "$LINUX_UAPI_INCLUDE" ] || fail "pinned Linux 5.10 UAPI headers are missing"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh" >/dev/null
python3 "$INVENTORY_GENERATOR" \
    --compiler clang \
    --project-include "$ROOT_DIR/include" \
    --musl-include "$MUSL_INCLUDE" \
    --linux-uapi-include "$LINUX_UAPI_INCLUDE" \
    --check
python3 "$MATRIX_GENERATOR" --check

printf 'x86 header callable visibility matrix: PASS (checked finite report)\n'
