#!/usr/bin/env bash
# Native kernel mechanisms through each owned product, with pinned-musl ABI.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('Linux control TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('Linux control product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-linux-control.XXXXXX")"
chmod a+rx "$work"
printf 'Linux control evidence: %s\n' "$work"
provided_dynamic="${1:-}"
if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$(realpath -e "$provided_dynamic")"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$ROOT/compat/x86_64/owned_linux_control_probe.c" -o "$work/workload.o"
mkdir "$work/oracle-root"
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle-root/consumer"
timeout 30 env -i PATH="$PATH" chroot "$work/oracle-root" /consumer >"$work/oracle.stdout" 2>"$work/oracle.stderr"
grep -qx owned-linux-control-ok "$work/oracle.stdout"

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/consumer-$mode"
        mkdir "$work/$mode-root"
        cp "$work/consumer-$mode" "$work/$mode-root/consumer"
        timeout 30 env -i PATH="$PATH" chroot "$work/$mode-root" /consumer \
            >"$work/$mode.stdout" 2>"$work/$mode.stderr"
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
fi
for mode in pie non-pie; do
    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    readelf -hW "$work/consumer-$mode" >"$work/consumer-$mode.header"
    readelf -lW "$work/consumer-$mode" >"$work/consumer-$mode.segments"
    readelf -dW "$work/consumer-$mode" >"$work/consumer-$mode.dynamic"
    cp -a "$installed" "$work/$mode-root"
    cp "$work/consumer-$mode" "$work/$mode-root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 /consumer); fi
        timeout 30 env -i PATH="$PATH" chroot "$work/$mode-root" "${command[@]}" \
            >"$work/$mode-$entry.stdout" 2>"$work/$mode-$entry.stderr"
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done
printf 'owned Linux control: PASS (same workload object, musl, requested static/dynamic entries, raw error equivalence, capabilities, process memory and ptrace word semantics); evidence: %s\n' "$work"
