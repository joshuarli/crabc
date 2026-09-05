#!/usr/bin/env bash
# Installed clone/vfork/daemon behavior against pinned musl 1.2.6.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_process_trio_probe.c"
# Aggregate dynamic gates supply an already built installed or extracted
# product. The focused command also builds and checks both static entries.
[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic_sysroot="${1:-}"
if [ -n "$provided_dynamic_sysroot" ]; then
    provided_dynamic_sysroot="$(realpath -e "$provided_dynamic_sysroot")"
fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic_sysroot" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('process-trio TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('process-trio product must be a checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-process-trio.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'process-trio evidence: %s\n' "$work"
mkdir -p "$work/oracle-root/state" "$work/oracle-root/dev"
mknod "$work/oracle-root/dev/null" c 1 3
"$oracle_cc" -static -fno-pie -no-pie -std=c11 -pthread "$probe" -o "$work/oracle"
for scenario in ordinary errors redirect; do
    cp "$work/oracle" "$work/oracle-root/consumer"
    timeout 20 chroot "$work/oracle-root" /consumer "$scenario" >"$work/oracle-$scenario.stdout"
done
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    nm -g --defined-only "$work/static-sysroot/usr/lib/libc.a" >"$work/static-symbols.txt"
    for symbol in clone vfork daemon; do
        [ "$(awk -v name="$symbol" '$2 == "T" && $3 == name {n++} END {print n+0}' "$work/static-symbols.txt")" -eq 1 ]
    done
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 "$probe" -o "$work/$mode"
        for scenario in ordinary errors redirect; do
            mkdir -p "$work/$mode-root/state" "$work/$mode-root/dev"
            [ -e "$work/$mode-root/dev/null" ] || mknod "$work/$mode-root/dev/null" c 1 3
            cp "$work/$mode" "$work/$mode-root/consumer"
            timeout 20 chroot "$work/$mode-root" /consumer "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
readelf --dyn-syms -W "$provided_dynamic_sysroot/usr/lib/libc.so" >"$work/dynamic-symbols.txt"
for symbol in clone vfork daemon; do
    [ "$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name {n++} END {print n+0}' "$work/dynamic-symbols.txt")" -eq 1 ]
done
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
mkdir -p "$work/execution-root/state" "$work/execution-root/dev"
mknod "$work/execution-root/dev/null" c 1 3
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer"
    for scenario in ordinary errors redirect; do
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
        timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "$scenario" >"$work/direct-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/direct-$mode-$scenario.stdout"
    done
done
printf 'owned process trio: PASS (musl + installed static/static-PIE/dynamic PIE/non-PIE, worker/child clone lifecycle and robust lists, vfork shared memory/exec, daemon redirection/lifecycle, syscall-error rollback); evidence: %s\n' "$work"
