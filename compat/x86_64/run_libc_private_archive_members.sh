#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly work_dir="$ROOT_DIR/.work/x86_64/private-archive-members"
mkdir -p "$work_dir"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
export CARGO_PROFILE_DEV_OPT_LEVEL=0
build_source_runtime_libc "$work_dir/libc.a" \
    --features x86-owned-static-runtime --relocation-model pic \
    -- --cfg crabc_owned_static_sysroot -Zmerge-functions=disabled
readelf --symbols --wide "$work_dir/libc.a" >"$work_dir/candidate-symbols"
readelf --symbols --wide /opt/musl-1.2.6/lib/libc.a >"$work_dir/oracle-symbols"

assert_provider() {
    local symbols="$1" symbol="$2" kind="$3"
    awk -v name="$symbol" -v kind="$kind" '
        $8 == name && $7 != "UND" {
            count++
            if ($4 != kind || $5 != "GLOBAL" || $6 != "HIDDEN") bad = 1
        }
        END { exit (count != 1 || bad) }
    ' "$symbols" || {
        printf 'ERROR: private archive provider %s must be one GLOBAL HIDDEN %s\n' "$symbol" "$kind" >&2
        return 1
    }
}

assert_provider "$work_dir/oracle-symbols" __tsearch_balance FUNC
assert_provider "$work_dir/oracle-symbols" __memcpy_fwd NOTYPE
assert_provider "$work_dir/candidate-symbols" __tsearch_balance FUNC
assert_provider "$work_dir/candidate-symbols" __memcpy_fwd FUNC
assert_provider "$work_dir/candidate-symbols" __crabc_owned_vfork_result FUNC
printf 'x86 libc private archive members: PASS\n'
