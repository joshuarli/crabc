#!/usr/bin/env bash
# Native Linux/x86-64 planned public-header callable linkage audit.
#
# The compiler-derived inventory is checked first.  Then this runner builds
# only the candidate static libc archive and makes `ld` perform ordinary
# per-symbol extraction; it intentionally never uses `--whole-archive` or an
# ambient libc.  A nonempty finite complement or failed extraction is a red,
# durable report, not a partial pass or a promotion claim.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly INVENTORY_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_inventory.py"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/header_callable_inventory.json"
readonly AUDIT="$ROOT_DIR/compat/x86_64/header_callable_linkage_audit.py"
readonly STATIC_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/header-callable-linkage-audit"
readonly REPORT_PATH="$REPORT_DIR/latest.json"

fail() {
    printf 'ERROR: x86 header callable linkage audit: %s\n' "$*" >&2
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

prepare_report_path() {
    local path
    for path in "$ROOT_DIR/compat" "$ROOT_DIR/compat/reports" "$ROOT_DIR/compat/reports/x86_64" "$REPORT_DIR"; do
        [ ! -L "$path" ] || fail "report path component is a symlink: $path"
        if [ -e "$path" ] && [ ! -d "$path" ]; then
            fail "report path component is not a directory: $path"
        fi
    done
    mkdir -p "$REPORT_DIR"
    [ -d "$REPORT_DIR" ] && [ ! -L "$REPORT_DIR" ] || fail "report directory is unsafe after creation"
    [ ! -L "$REPORT_PATH" ] || fail "report path is a symlink: $REPORT_PATH"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in cargo clang ld nm python3 rustup; do
    require_tool "$tool"
done
[ -x "$INVENTORY_GENERATOR" ] || fail "inventory generator is not executable"
[ -x "$AUDIT" ] || fail "linkage audit harness is not executable"
[ -f "$INVENTORY" ] || fail "checked callable inventory is missing"
[ -f "$STATIC_EXPORTS" ] || fail "static export ratchet is missing"
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

work_dir="$(mktemp -d /tmp/crabc-x86-header-callable-linkage.XXXXXX)"
report_tmp="$work_dir/report.json"
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
trap 'rm -rf -- "$work_dir"' EXIT

cd "$ROOT_DIR"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

python3 "$AUDIT" \
    --inventory "$INVENTORY" \
    --static-exports "$STATIC_EXPORTS" \
    --archive "$archive" \
    --linker ld \
    --nm nm \
    --output "$report_tmp" \
    --allow-incomplete

prepare_report_path
mv "$report_tmp" "$REPORT_PATH"
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"

if python3 - "$REPORT_PATH" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
raise SystemExit(0 if report["summary"]["complete"] else 1)
PY
then
    printf 'x86 header callable linkage audit: PASS (%s)\n' "$REPORT_PATH"
    exit 0
fi

printf 'x86 header callable linkage audit: INCOMPLETE (%s)\n' "$REPORT_PATH" >&2
exit 1
