#!/usr/bin/env bash
# Pinned-musl legacy timers and safe clock-adjustment evidence for owned x86 products.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_legacy_time_probe.c"
readonly SCENARIOS='times timer-query timer-delivery ualarm-cancel timer-errors adjustment-query adjustment-guards settimeofday-null settimeofday-guards adjustment-seccomp'

[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath -e "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product = Path(sys.argv[3]) if sys.argv[3] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned legacy-time TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned legacy-time dynamic product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-legacy-time.XXXXXX")"
chmod a+rx "$work"
printf 'owned legacy-time evidence: %s\n' "$work"

assert_ok() {
    local output="$1"
    shift
    set +e
    timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output}.stderr"
    local status=$?
    set -e
    [ "$status" -eq 0 ] || {
        printf 'owned legacy-time: expected success, got %s: %s\n' "$status" "$*" >&2
        return 1
    }
    [ ! -s "$output" ] && [ ! -s "${output}.stderr" ] || {
        printf 'owned legacy-time: fixture wrote output: %s\n' "$*" >&2
        return 1
    }
}

run_cases() {
    local prefix="$1" binary="$2"
    shift 2
    local scenario output
    for scenario in $SCENARIOS; do
        output="$work/$prefix-$scenario.stdout"
        assert_ok "$output" "$@" "$binary" "$scenario"
    done
}

assert_static_providers() {
    local archive="$1" symbols="$2" symbol
    nm -g --defined-only "$archive" >"$symbols"
    for symbol in times getitimer setitimer ualarm adjtime adjtimex settimeofday stime; do
        [ "$(awk -v name="$symbol" '$2 == "T" && $3 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'owned legacy-time: static archive does not provide exactly one strong %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_providers() {
    local library="$1" symbols="$2" symbol
    readelf --dyn-syms --wide "$library" >"$symbols"
    for symbol in times getitimer setitimer ualarm adjtime adjtimex settimeofday stime; do
        [ "$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'owned legacy-time: shared libc does not provide exactly one global-default %s\n' "$symbol" >&2
            return 1
        }
    done
}

if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-product" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-product"
fi

"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/oracle"
run_cases oracle "$work/oracle"

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-product" >"$work/static-build.json"
    assert_static_providers "$work/static-product/usr/lib/libc.a" "$work/static-symbols.txt"
    for mode in static static-pie; do
        "$work/static-product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/consumer-$mode"
        run_cases "$mode" "$work/consumer-$mode"
    done
fi

assert_dynamic_providers "$provided_dynamic/usr/lib/libc.so" "$work/dynamic-symbols.txt"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/consumer-$mode"
    root="$work/$mode-root"
    cp -a "$provided_dynamic" "$root"
    cp "$work/consumer-$mode" "$root/consumer"
    run_cases "dynamic-$mode-kernel" /consumer chroot "$root"
    run_cases "dynamic-$mode-direct" /consumer chroot "$root" /lib/ld-crabc-x86_64.so.1
done

printf 'owned legacy-time: PASS (same installed-header C object through musl and owned static/static-PIE/dynamic PIE/non-PIE kernel/direct; raw times return/wrap, interval query/disarm/delivery/error/cancel, query-only adjustment, local timeval bounds, null settimeofday, and seccomp-contained clock-mutation errors); evidence: %s\n' "$work"
