#!/usr/bin/env bash
# Resource-sized installed pthread_atfork registry against pinned musl.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_atfork_registry_probe.c"
readonly private_probe="$ROOT/compat/x86_64/owned_process_private_symbols_probe.c"
[ "$(uname -sm)" = 'Linux x86_64' ] || { printf 'atfork registry requires native Linux/x86-64\n' >&2; exit 1; }
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
    raise SystemExit('atfork-registry TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('atfork-registry product must be a checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-atfork-registry.XXXXXX")"
readonly work
chmod a+rx "$work"
printf 'atfork-registry evidence: %s\n' "$work"
uname -smr >"$work/execution-host.txt"
"$oracle_cc" -static -fno-pie -no-pie -std=c11 -pthread "$probe" -o "$work/oracle"
for scenario in ordinary exit-hooks; do
    timeout 20 "$work/oracle" "$scenario" >"$work/oracle-$scenario.stdout"
done
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" -std=c11 "$probe" -o "$work/$mode"
        for scenario in ordinary exit-hooks; do
            timeout 20 "$work/$mode" "$scenario" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 \
    -c "$private_probe" -o "$work/private-symbols.o"
"$oracle_cc" "$work/private-symbols.o" -o "$work/oracle-private-symbols"
timeout 20 "$work/oracle-private-symbols" >"$work/oracle-private-symbols.stdout"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$work/private-symbols.o" -o "$work/execution-root/private-symbols-$mode"
    timeout 20 chroot "$work/execution-root" "/private-symbols-$mode" \
        >"$work/private-symbols-$mode.stdout"
    cmp "$work/oracle-private-symbols.stdout" "$work/private-symbols-$mode.stdout"
    timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
        "/private-symbols-$mode" >"$work/private-symbols-direct-$mode.stdout"
    cmp "$work/oracle-private-symbols.stdout" "$work/private-symbols-direct-$mode.stdout"
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$probe" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in ordinary exit-hooks; do
        timeout 20 chroot "$work/execution-root" "/consumer-$mode" "$scenario" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
        timeout 20 chroot "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "$scenario" >"$work/direct-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/direct-$mode-$scenario.stdout"
    done
done
printf 'owned atfork registry: PASS (musl + installed static/static-PIE/dynamic PIE/non-PIE kernel/direct, 4096-4099 ordered callbacks, three-generation inherited registry, child/parent/worker registration, failed-fork parent completion; atexit/__cxa_atexit order, registration during exit, fork-inherited and worker-thread exit hooks; dynamic private-hook lookup rejection and public aliases); evidence: %s\n' "$work"
