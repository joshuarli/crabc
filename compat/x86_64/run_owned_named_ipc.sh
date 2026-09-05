#!/usr/bin/env bash
# Same-object installed named semaphore/shared-memory namespace and lifecycle.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_named_ipc_probe.c"
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('named IPC TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('named IPC product must be a physical checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-named-ipc.XXXXXX")"
chmod a+rx "$work"
printf 'named IPC evidence: %s\n' "$work"
"$oracle_cc" -std=c11 -pthread -fPIC -I"$ROOT/include" -c "$probe" -o "$work/probe.o"
sha256sum "$work/probe.o" >"$work/probe.sha256"
"$oracle_cc" -static -no-pie -pthread "$work/probe.o" -o "$work/oracle"
mkdir -p "$work/oracle-root/dev/shm"
chmod 1777 "$work/oracle-root/dev/shm"
cp "$work/oracle" "$work/oracle-root/consumer"
timeout 35 python3 -B "$witness" "$work/oracle-root" /consumer >"$work/oracle.stdout"
grep -qx owned-named-ipc-ok "$work/oracle.stdout"
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/probe.o" -o "$work/$mode"
        mkdir -p "$work/$mode-root/dev/shm"
        chmod 1777 "$work/$mode-root/dev/shm"
        cp "$work/$mode" "$work/$mode-root/consumer"
        timeout 35 python3 -B "$witness" "$work/$mode-root" /consumer >"$work/$mode.stdout"
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-product" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-product"
fi
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/probe.o" -o "$work/dynamic-$mode"
    cp -a "$provided_dynamic" "$work/$mode-root"
    mkdir -p "$work/$mode-root/dev/shm"
    chmod 1777 "$work/$mode-root/dev/shm"
    cp "$work/dynamic-$mode" "$work/$mode-root/consumer"
    for entry in kernel direct; do
        command=(/consumer)
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 /consumer); fi
        timeout 35 python3 -B "$witness" "$work/$mode-root" "${command[@]}" >"$work/$mode-$entry.stdout"
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
    done
done
python3 -B - "$work" <<'PYCHECK'
from pathlib import Path
import sys
for directory in Path(sys.argv[1]).glob('*-root/dev/shm'):
    if any(directory.iterdir()):
        raise SystemExit(f'named IPC leaked namespace files: {directory}')
PYCHECK
printf 'owned named IPC: PASS (same object, musl + installed static/dynamic entries, named semaphores/shared memory); evidence: %s\n' "$work"
