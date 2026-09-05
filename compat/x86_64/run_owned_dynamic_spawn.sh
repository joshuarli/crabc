#!/usr/bin/env bash
# The existing spawn semantic workload through ordinary installed dynamic entry.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
python3 -B - "$ROOT" "${TMPDIR:-}" "${1:-}" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('dynamic spawn TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3]).resolve(strict=True)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('dynamic spawn product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-spawn.XXXXXX")"
chmod a+rx "$work"
printf 'dynamic spawn evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_spawn_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
provided_dynamic="${1:-}"
if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$provided_dynamic" >"$work/build.json"
fi
readonly installed="$(realpath -e "$provided_dynamic")"
mkdir "$work/oracle-root"
# One application object is linked by the pinned oracle and each installed
# entry. A fixed owned path permits exec from chdir actions without mounting
# host procfs inside the isolated execution roots.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    '-DCRABC_SPAWN_EXECUTABLE="/consumer"' -c "$probe" -o "$work/workload.o"
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle-root/consumer"
timeout 40 env -i PATH="$PATH" chroot "$work/oracle-root" /consumer /spawn-state >"$work/oracle.stdout" 2>"$work/oracle.stderr"
grep -qx owned-spawn-ok "$work/oracle.stdout"
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
        timeout 40 env -i PATH="$PATH" chroot "$work/$mode-root" "${command[@]}" /spawn-state \
            >"$work/$mode-$entry.stdout" 2>"$work/$mode-$entry.stderr"
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done
printf 'owned dynamic spawn: PASS (same workload object, musl, PIE/non-PIE kernel/direct entry, attributes, file actions, PATH, worker spawn and failure rollback); evidence: %s\n' "$work"
