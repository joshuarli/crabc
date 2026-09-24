#!/usr/bin/env bash
# Installed static/dynamic condition cancellation with pinned-musl semantics.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_pthread_cond_cancel_probe.c"
# Aggregate dynamic gates supply an already built installed or extracted
# product. The focused command builds and checks both static entries; the
# pthread family supplies its sealed static product with --static-sysroot.
. "$ROOT/compat/x86_64/owned_pthread_product_arguments.sh"
owned_pthread_product_arguments pthread-cond-cancel "$@"
work="$(mktemp -d "$TMPDIR/owned-pthread-cond-cancel.XXXXXX")"
readonly work
printf 'pthread-cond-cancel evidence: %s\n' "$work"
"$oracle_cc" -std=c11 -pthread -I"$ROOT/include" "$probe" -o "$work/oracle"
for scenario in main-entry main-blocked worker-entry worker-blocked main-disabled worker-disabled main-masked worker-masked main-signaled worker-signaled; do
    timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "" "$work/oracle" "$scenario" >"$work/oracle-$scenario.stdout"
done
if [ "$check_static" -eq 1 ]; then
    static_sysroot="$provided_static_sysroot"
    if [ -z "$static_sysroot" ]; then
        static_sysroot="$work/static-sysroot"
        python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$static_sysroot" >"$work/static-build.json"
    fi
    for mode in static static-pie; do
        "$static_sysroot/bin/crabc-cc" "-$mode" -std=c11 -DCRABC_OWNED_WITNESS "$probe" -o "$work/$mode"
        for scenario in main-entry main-blocked worker-entry worker-blocked main-disabled worker-disabled main-masked worker-masked main-signaled worker-signaled; do
            timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "" "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
fi
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 -DCRABC_OWNED_WITNESS "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in main-entry main-blocked worker-entry worker-blocked main-disabled worker-disabled main-masked worker-masked main-signaled worker-signaled; do
        timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
    done
done
printf 'owned pthread_cond_wait cancellation: PASS (musl + requested installed entries, main/worker entry/blocked cancellation, disabled/masked states, mutex reacquisition and reuse); evidence: %s\n' "$work"
