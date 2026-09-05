#!/usr/bin/env bash
# Source-faithful C11 quick-exit registry through every installed x86 product.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_quick_exit_probe.c"
readonly SCENARIOS='lifo capacity reentrant worker concurrent contention fork'

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
    raise SystemExit('owned quick-exit TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned quick-exit dynamic product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-quick-exit.XXXXXX")"
chmod a+rx "$work"
printf 'owned quick-exit evidence: %s\n' "$work"

assert_result() {
    local expected_status="$1" output="$2"
    shift 2
    local status
    set +e
    timeout 30 env -i PATH="$PATH" "$@" >"$output" 2>"${output}.stderr"
    status=$?
    set -e
    [ "$status" -eq "$expected_status" ] || {
        printf 'owned quick-exit: expected status %s, got %s: %s\n' "$expected_status" "$status" "$*" >&2
        return 1
    }
}

expected_output() {
    case "$1" in
        lifo) printf CBA ;;
        capacity) printf '%032d' 0 | tr 0 X ;;
        reentrant) printf RN; printf '%031d' 0 | tr 0 F ;;
        worker) printf W ;;
        concurrent) printf QQQQ ;;
        contention) printf '%032d' 0 | tr 0 Q ;;
        fork) printf CIPI ;;
        *) return 2 ;;
    esac
}

expected_status() {
    case "$1" in
        lifo) printf 41 ;;
        capacity) printf 43 ;;
        reentrant) printf 42 ;;
        worker) printf 44 ;;
        concurrent) printf 45 ;;
        contention) printf 48 ;;
        fork) printf 47 ;;
        *) return 2 ;;
    esac
}

run_cases() {
    local prefix="$1" binary="$2"
    shift 2
    local scenario expected status output
    for scenario in $SCENARIOS; do
        expected="$(expected_output "$scenario")"
        status="$(expected_status "$scenario")"
        output="$work/$prefix-$scenario.stdout"
        assert_result "$status" "$output" "$@" "$binary" "$scenario"
        [ "$(cat "$output")" = "$expected" ] || {
            printf 'owned quick-exit: output mismatch for %s/%s\n' "$prefix" "$scenario" >&2
            return 1
        }
    done
}

assert_static_providers() {
    local archive="$1" symbols="$2" symbol
    nm -g --defined-only "$archive" >"$symbols"
    for symbol in at_quick_exit quick_exit; do
        [ "$(awk -v name="$symbol" '$2 == "T" && $3 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'owned quick-exit: static archive does not provide exactly one strong %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_providers() {
    local library="$1" symbols="$2" symbol
    readelf --dyn-syms --wide "$library" >"$symbols"
    for symbol in at_quick_exit quick_exit; do
        [ "$(awk -v name="$symbol" '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == name { count++ } END { print count + 0 }' "$symbols")" -eq 1 ] || {
            printf 'owned quick-exit: shared libc does not provide exactly one global-default %s\n' "$symbol" >&2
            return 1
        }
    done
    if awk '$8 == "__funcs_on_quick_exit" { found = 1 } END { exit found ? 0 : 1 }' "$symbols"; then
        printf 'owned quick-exit: shared libc exported musl hidden __funcs_on_quick_exit\n' >&2
        return 1
    fi
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
        for scenario in $SCENARIOS; do
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
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
    for entry in kernel direct; do
        for scenario in $SCENARIOS; do
            cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$entry-$scenario.stdout"
        done
    done
done

printf 'owned quick-exit: PASS (same C11 object, musl and owned static/static-PIE/dynamic PIE/non-PIE kernel/direct; LIFO, fixed 32-slot errno, reentrant refill, ordinary-exit/fini/stdio exclusion, worker exit_group, controlled concurrent and 32-way contended registration, and fork registry repair); evidence: %s\n' "$work"
