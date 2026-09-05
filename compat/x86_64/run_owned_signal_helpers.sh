#!/usr/bin/env bash
# One ordinary application object through pinned musl and owned linkage modes.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('signal helpers TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('signal helpers product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-signal-helpers.XXXXXX")"
chmod a+rx "$work"
printf 'signal helpers evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_signal_helpers_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly cases=(actions interrupt failed-interrupt restart partial-action cancellation reporting partial-reporting)
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    "$work/static-sysroot/bin/crabc-cc" -static-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
else
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
fi
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
for scenario in "${cases[@]}"; do
    timeout 20 "$work/oracle" "$scenario" >"$work/oracle-$scenario.stdout" 2>"$work/oracle-$scenario.stderr"
done
if [ -z "$provided_dynamic" ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/$mode"
        for scenario in "${cases[@]}"; do
            timeout 20 "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout" 2>"$work/$mode-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$scenario.stderr"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            command=("/consumer-$mode")
            if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode"); fi
            timeout 20 chroot "$work/execution-root" "${command[@]}" "$scenario" >"$work/$mode-$entry-$scenario.stdout" 2>"$work/$mode-$entry-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$entry-$scenario.stderr"
        done
    done
done
printf 'owned signal helpers: PASS (same object, musl + installed entries, aliases/actions/masks, EINTR and cancellation bookkeeping, reporting locale/orientation/error state); evidence: %s\n' "$work"
