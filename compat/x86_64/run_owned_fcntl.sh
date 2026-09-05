#!/usr/bin/env bash
# Installed fcntl command/variadic ABI and cancellation with pinned-musl semantics.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly witness="$ROOT/compat/x86_64/run_pthread_wait_witness.py"
readonly probe="$ROOT/compat/x86_64/owned_fcntl_probe.c"
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
    raise SystemExit('fcntl TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('fcntl product must be a physical checkout .work directory')
PY
work="$(mktemp -d "$TMPDIR/owned-fcntl.XXXXXX")"
readonly work
printf 'fcntl evidence: %s\n' "$work"
"$oracle_cc" -std=c11 -I"$ROOT/include" -E -H "$probe" >/dev/null 2>"$work/header-trace"
for header in fcntl.h bits/fcntl.h pthread.h; do
    grep -Fq "$ROOT/include/$header" "$work/header-trace"
done
"$oracle_cc" -std=c11 -pthread -fPIC -I"$ROOT/include" -c "$probe" -o "$work/probe.o"
"$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"
sha256sum "$work/probe.o" >"$work/probe.sha256"
for scenario in ordinary; do
    timeout 35 python3 -B "$witness" '' "$work/oracle" "$work/oracle-files" >"$work/oracle-$scenario.stdout"
done
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/probe.o" -o "$work/$mode"
        for scenario in ordinary; do
            timeout 35 python3 -B "$witness" '' "$work/$mode" "$work/$mode-files" >"$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/probe.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in ordinary; do
        timeout 35 python3 -B "$witness" "$work/execution-root" "/consumer-$mode" "/kernel-$mode-files" >"$work/dynamic-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
        timeout 35 python3 -B "$witness" "$work/execution-root" /lib/ld-crabc-x86_64.so.1 \
            "/consumer-$mode" "/direct-$mode-files" >"$work/direct-$mode-$scenario.stdout"
        cmp "$work/oracle-$scenario.stdout" "$work/direct-$mode-$scenario.stdout"
    done
done
printf 'owned fcntl: PASS (same object, musl + installed modes, noarg/int/word/pointer ABI, duplication/owner/pipe/seal/lease/hints, POSIX/OFD lock and cancellation semantics); evidence: %s\n' "$work"
