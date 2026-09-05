#!/usr/bin/env bash
# Installed pthread scheduling/default attributes; one object linked to every runtime.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_pthread_scheduling_probe.c"
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
    raise SystemExit('pthread-scheduling TMPDIR must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-pthread-scheduling.XXXXXX")"
readonly work
printf 'pthread-scheduling evidence: %s\n' "$work"
"$oracle_cc" -std=c11 -pthread -fPIC -I"$ROOT/include" -c "$probe" -o "$work/probe.o"
"$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"
for scenario in ordinary; do
    timeout 20 "$work/oracle" "$scenario" >"$work/oracle-$scenario.stdout"
done
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 "$work/probe.o" -o "$work/$mode"
        for scenario in ordinary; do
            timeout 20 "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$work/probe.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in ordinary; do
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
        timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "$scenario" >"$work/direct-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/direct-$mode-$scenario.stdout"
    done
done
printf 'owned pthread scheduling/default attributes: PASS (same object, musl + installed modes, target errno, explicit setup/failure reclamation, defaults + C11); evidence: %s\n' "$work"
