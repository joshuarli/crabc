#!/usr/bin/env bash
# Installed static/dynamic timed conditions with pinned-musl semantics.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_pthread_cond_timed_probe.c"
# Aggregate dynamic gates supply an already built installed or extracted
# product. The focused command also builds and checks both static entries.
[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic_sysroot="${1:-}"
if [ -n "$provided_dynamic_sysroot" ]; then
    provided_dynamic_sysroot="$(realpath -e "$provided_dynamic_sysroot")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('pthread-cond-timed TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-pthread-cond-timed.XXXXXX")"
readonly work
printf 'pthread-cond-timed evidence: %s\n' "$work"
# Compile the same cancellation and cross-process fixtures into every product.
compile_and_check_companions() {
    local product="$1" root="$2"
    shift 2
    local variant scenario executable
    local -a defines scenarios
    for variant in timed-private shared timed-shared fork-shared; do
        defines=()
        scenarios=(main-entry main-blocked worker-entry worker-blocked main-disabled worker-disabled main-masked worker-masked main-signaled worker-signaled)
        local source="$ROOT/compat/x86_64/owned_pthread_cond_cancel_probe.c"
        case "$variant" in
            timed-private) defines=(-DCRABC_TIMED_CONDITION) ;;
            shared) defines=(-DCRABC_SHARED_CONDITION) ;;
            timed-shared) defines=(-DCRABC_TIMED_CONDITION -DCRABC_SHARED_CONDITION) ;;
            fork-shared)
                source="$ROOT/compat/x86_64/owned_pthread_cond_shared_probe.c"
                scenarios=(ordinary timed)
                ;;
        esac
        "$@" -std=c11 "${defines[@]}" "$source" -o "$work/$product-$variant"
        executable="$work/$product-$variant"
        if [ -n "$root" ]; then
            cp "$executable" "$root/$product-$variant"
            executable="/$product-$variant"
        fi
        for scenario in "${scenarios[@]}"; do
            timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" \
                "$root" "$executable" "$scenario" >"$work/$product-$variant-$scenario.stdout"
            if [ "$product" != oracle ]; then
                cmp "$work/oracle-$variant-$scenario.stdout" "$work/$product-$variant-$scenario.stdout"
            fi
        done
    done
}
compile_and_check_companions oracle "" "$oracle_cc" -pthread -I"$ROOT/include"
"$oracle_cc" -std=c11 -pthread -I"$ROOT/include" "$probe" -o "$work/oracle"
for scenario in realtime monotonic attributes pending-validation c11 robust-timeout robust-cancel robust-unrecoverable private-shared-mutex; do
    timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "" "$work/oracle" "$scenario" >"$work/oracle-$scenario.stdout"
done
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        compile_and_check_companions "$mode" "" "$work/static-sysroot/bin/crabc-cc" "-$mode"
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 -DCRABC_OWNED_WITNESS "$probe" -o "$work/$mode"
        for scenario in realtime monotonic attributes pending-validation c11 robust-timeout robust-cancel robust-unrecoverable private-shared-mutex; do
            timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "" "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    compile_and_check_companions "dynamic-$mode" "$work/execution-root" "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode"
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -DCRABC_OWNED_WITNESS "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in realtime monotonic attributes pending-validation c11 robust-timeout robust-cancel robust-unrecoverable private-shared-mutex; do
        timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
    done
done
printf 'owned timed pthread conditions: PASS (musl + requested installed entries, clocks/timeouts, C11, timed/shared cancellation, distinct-address fork handoffs and robust relock precedence); evidence: %s\n' "$work"
