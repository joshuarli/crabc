#!/usr/bin/env bash
# Native Linux/x86-64 checked header-callable ownership routing.
#
# The compiler-derived inventory remains the selected declaration boundary.
# This runner verifies its exact checked provider/deferred-owner projection,
# including the distinct missing-reference declaration roster. A pass does not claim archive extraction,
# runtime semantics, declaration parity, family
# promotion, final C ABI closure, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly INVENTORY_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_inventory.py"
readonly DISPOSITION_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_disposition.py"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/header_callable_inventory.json"
readonly DISPOSITION="$ROOT_DIR/compat/x86_64/header_callable_disposition.json"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include

fail() {
    printf 'ERROR: x86 header callable disposition: %s\n' "$*" >&2
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
[ -x "$DISPOSITION_GENERATOR" ] || fail "disposition generator is not executable"
[ -f "$INVENTORY" ] || fail "checked callable inventory is missing"
[ -f "$DISPOSITION" ] || fail "checked callable disposition report is missing"
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
python3 "$DISPOSITION_GENERATOR" --check

printf 'x86 header callable disposition: PASS (checked ownership routing)\n'
