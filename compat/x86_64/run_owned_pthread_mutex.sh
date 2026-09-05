#!/usr/bin/env bash
# Installed static/dynamic recursive, error-checking, and timed mutex evidence.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_pthread_mutex_probe.c"
readonly -a SCENARIOS=(recursive errorcheck timed robust recursive-condition c11)

[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_dynamic_sysroot="${1:-}"
if [ -n "$provided_dynamic_sysroot" ]; then
    provided_dynamic_sysroot="$(realpath -e "$provided_dynamic_sysroot")"
fi

fail() {
    printf 'ERROR: x86 owned pthread mutex: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout="$(realpath -e "$ROOT")" || fail "cannot resolve checkout root"
temporary="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$temporary" in
    "$checkout"/.work/*) ;;
    *) fail "TMPDIR physically escapes checkout .work: $temporary" ;;
esac

work="$(mktemp -d "$TMPDIR/owned-pthread-mutex.XXXXXX")"
trap 'status=$?; if [ "$status" -ne 0 ]; then printf "x86 owned pthread mutex: retained failure evidence at %s\n" "$work" >&2; else rm -rf -- "$work"; fi; exit "$status"' EXIT

run_case() {
    local root="$1" executable="$2" scenario="$3" output="$4"
    timeout 30 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" \
        "$root" "$executable" "$scenario" >"$output"
}

"$ORACLE_CC" -std=c11 -pthread -I"$ROOT/include" "$PROBE" -o "$work/oracle"
for scenario in "${SCENARIOS[@]}"; do
    run_case "" "$work/oracle" "$scenario" "$work/oracle-$scenario.stdout" ||
        fail "pinned musl $scenario regression failed"
done

check_static_mode() {
    local mode="$1" label="$2"
    "$work/static-sysroot/bin/crabc-cc" "$mode" -std=c11 -DCRABC_OWNED_WITNESS \
        "$PROBE" -o "$work/$label"
    local scenario
    for scenario in "${SCENARIOS[@]}"; do
        run_case "" "$work/$label" "$scenario" "$work/$label-$scenario.stdout" ||
            fail "owned $label $scenario regression failed"
        cmp "$work/oracle-$scenario.stdout" "$work/$label-$scenario.stdout" ||
            fail "owned $label $scenario output differs from pinned musl"
    done
}

if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" \
        >"$work/static-build.json"
    check_static_mode -static static
    check_static_mode -static-pie static-pie
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" \
        >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi

cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 \
        -DCRABC_OWNED_WITNESS "$PROBE" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${SCENARIOS[@]}"; do
        run_case "$work/execution-root" "/consumer-$mode" "$scenario" \
            "$work/dynamic-$mode-$scenario.stdout" ||
            fail "owned dynamic $mode $scenario regression failed"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout" ||
            fail "owned dynamic $mode $scenario output differs from pinned musl"
    done
done

printf 'owned pthread mutexes: PASS (musl + installed static ET_EXEC/static-PIE and dynamic PIE/non-PIE recursive, error-checking, timed, robust-owner, condition, and C11 behavior)\n'
