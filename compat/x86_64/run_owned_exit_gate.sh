#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
eval "$(python3 -B "$ROOT/compat/x86_64/native_arch.py")"
readonly work="$(mktemp -d "$TMPDIR/owned-exit-gate.XXXXXX")"
chmod a+rx "$work"
printf 'owned exit gate evidence: %s\n' "$work"
python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-product" >"$work/dynamic-build.json"
python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_exit_gate_probe.c" -o "$work/probe.o"
"$oracle" -static -fno-pie -no-pie "$work/probe.o" -o "$work/oracle"
timeout 60 "$work/oracle" | tee "$work/oracle.stdout"
for mode in static static-pie; do
    "$work/static-product/bin/crabc-cc" "-$mode" "$work/probe.o" -o "$work/$mode"
    timeout 60 "$work/$mode" | tee "$work/$mode.stdout"
    cmp "$work/oracle.stdout" "$work/$mode.stdout"
done
for mode in pie non-pie; do
    "$work/dynamic-product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/probe.o" -o "$work/consumer-$mode"
    cp -a "$work/dynamic-product" "$work/root-$mode"
    cp "$work/consumer-$mode" "$work/root-$mode/consumer"
    for entry in kernel direct; do
        if [ "$entry" = kernel ]; then
            timeout 60 chroot "$work/root-$mode" /consumer | tee "$work/$mode-$entry.stdout"
        else
            timeout 60 chroot "$work/root-$mode" "/lib/ld-crabc-$arch.so.1" /consumer | tee "$work/$mode-$entry.stdout"
        fi
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done
printf 'owned exit gate: PASS\n'
