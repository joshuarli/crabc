#!/usr/bin/env bash
# Native Linux/x86-64 selected header-callable provider linkage audit.
#
# This is a deliberately non-promoting companion to the default-archive
# linkage audit. It proves ordinary archive extraction for the default static
# provider and every verified opt-in provider profile. It reports the explicit
# unprovided complement without treating it as a false passing closure. The
# named crypt/allocator composition is topology-only: its dedicated runner
# proves the intentionally rejected manual pair and selected allocator route.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly INVENTORY_GENERATOR="$ROOT_DIR/compat/x86_64/header_callable_inventory.py"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/header_callable_inventory.json"
readonly AUDIT="$ROOT_DIR/compat/x86_64/header_callable_provider_linkage_audit.py"
readonly ROSTER="$ROOT_DIR/compat/x86_64/feature_archive_roster.py"
readonly STATIC_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly MUSL_INCLUDE=/opt/musl-1.2.6/include
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/header-callable-provider-linkage-audit"
readonly REPORT_PATH="$REPORT_DIR/latest.json"
readonly TARGET=x86_64-unknown-linux-musl
readonly TOPOLOGY_ONLY_PROFILE=x86-crypt-allocator-composition

fail() {
    printf 'ERROR: x86 header callable provider linkage audit: %s\n' "$*" >&2
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

build_archive() {
    local target_dir="$1"
    local feature_request="$2"
    local archive="$target_dir/$TARGET/debug/libc.a"
    local -a command=(cargo rustc --locked -p crabc-libc --lib --no-default-features)

    if [ -n "$feature_request" ]; then
        command+=(--features "$feature_request")
    fi
    command+=(--target "$TARGET" -- -C relocation-model=static -C code-model=small -C panic=abort)
    CARGO_TARGET_DIR="$target_dir" "${command[@]}"
    [ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive for ${feature_request:-the default profile}"
}

verified_feature_profile_rows() {
    PYTHONPATH="$ROOT_DIR/compat/x86_64" python3 - <<'PY'
from feature_archive_roster import load_feature_archive_roster

for row in load_feature_archive_roster():
    if row.state == "verified":
        print(f"{row.identifier}\t{','.join(row.baseline_features)}")
PY
}

run_topology_only_profile_evidence() {
    bash "$ROOT_DIR/compat/x86_64/run_libc_crypt_allocator_composition.sh" >/dev/null
}

# Reuse only exact canonical roster baseline feature sets during this one audit
# invocation. Every profile still receives an explicit baseline argument, every
# enabled profile is built in its own target directory, and the fresh work tree
# prevents an inter-run archive cache or a changed final-product build.
build_profile_archives() {
    local work_dir="$1"
    local default_target="$work_dir/default"
    local identifier baseline_features
    local enabled_target enabled_archive
    local baseline_target baseline_archive
    declare -A baseline_archives=()

    default_archive="$default_target/$TARGET/debug/libc.a"
    build_archive "$default_target" ""
    baseline_args=()
    enabled_args=()

    while IFS=$'\t' read -r identifier baseline_features; do
        [ -n "$identifier" ] || fail "feature archive roster emitted an empty identifier"
        enabled_target="$work_dir/$identifier-enabled"
        enabled_archive="$enabled_target/$TARGET/debug/libc.a"
        build_archive "$enabled_target" "$identifier"
        enabled_args+=(--profile-enabled "$identifier=$enabled_archive")

        if [ "$identifier" = "$TOPOLOGY_ONLY_PROFILE" ]; then
            [ "$baseline_features" = "x86-allocator-runtime,x86-crypt" ] ||
                fail "topology-only composition baseline drifted"
            run_topology_only_profile_evidence
            continue
        fi

        if [ -z "$baseline_features" ]; then
            baseline_archive="$default_archive"
        elif [[ -v "baseline_archives[$baseline_features]" ]]; then
            baseline_archive="${baseline_archives[$baseline_features]}"
        else
            baseline_target="$work_dir/$identifier-baseline"
            baseline_archive="$baseline_target/$TARGET/debug/libc.a"
            build_archive "$baseline_target" "$baseline_features"
            baseline_archives["$baseline_features"]="$baseline_archive"
        fi
        baseline_args+=(--profile-baseline "$identifier=$baseline_archive")
    done < <(verified_feature_profile_rows)
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in cargo clang ld nm python3 readelf rustup stat; do
    require_tool "$tool"
done
[ -x "$INVENTORY_GENERATOR" ] || fail "inventory generator is not executable"
[ -x "$AUDIT" ] || fail "selected provider audit is not executable"
[ -f "$ROSTER" ] || fail "feature archive roster is missing"
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

work_dir="$(mktemp -d /tmp/crabc-x86-header-callable-provider-linkage.XXXXXX)"
report_tmp="$work_dir/report.json"
trap 'rm -rf -- "$work_dir"' EXIT

cd "$ROOT_DIR"
build_profile_archives "$work_dir"

python3 "$AUDIT" \
    --inventory "$INVENTORY" \
    --static-exports "$STATIC_EXPORTS" \
    --default-archive "$default_archive" \
    "${baseline_args[@]}" \
    "${enabled_args[@]}" \
    --linker ld \
    --nm nm \
    --readelf readelf \
    --output "$report_tmp"

prepare_report_path
mv "$report_tmp" "$REPORT_PATH"
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"

python3 - "$REPORT_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
summary = report["summary"]
scope = report["scope"]
if not summary["selected_provider_closure_complete"]:
    raise SystemExit("selected provider closure is incomplete")
if summary["complete"]:
    raise SystemExit("unexpectedly claimed full callable closure")
if summary["unprovided_callable_count"] <= 0:
    raise SystemExit("unprovided complement unexpectedly disappeared")
for field in (
    "family_promotion",
    "full_callable_closure",
    "public_support",
    "uses_whole_archive",
):
    if scope.get(field) is not False:
        raise SystemExit(f"provider audit unexpectedly claimed {field}")
PY

printf 'x86 header callable provider linkage audit: PASS (%s)\n' "$REPORT_PATH"
