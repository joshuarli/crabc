#!/usr/bin/env bash
# Pinned-musl differential for residual system.kernel-admin C spellings.
#
# One installed-driver object calls the eighteen names that are deliberately
# outside the existing linux-control, syslog, and system-cancellation cases.
# It is linked first to musl, then unchanged to each static/dynamic product.
# Each selector has a private process/root boundary, retains raw status and
# streams, and compares them to the pinned reference.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_kernel_residual_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly OWNED_SYMBOLS='__sched_cpucount confstr fpathconf getdtablesize gethostid membarrier pathconf personality prctl sched_getparam sched_getscheduler sched_setparam sched_setscheduler setdomainname sethostname syscall sysconf ulimit'
readonly CASES=(
    cpucount
    configuration
    sysconf-signal-stack
    hostid-membarrier
    personality
    prctl
    scheduler
    syscall
    ulimit
    uts-namespace
    uts-seccomp
    all
)

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
product_argument = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned kernel residual TMPDIR must be a physical checkout .work directory')
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned kernel residual product must be a checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-kernel-residual.XXXXXX")"
chmod a+rx "$work"
printf 'owned kernel residual evidence: %s\n' "$work"

run_in_root() {
    local root="$1" output="$2" status
    shift 2
    if timeout 30 env -i PATH="$PATH" chroot "$root" "$@" \
        >"$output" 2>"${output%.stdout}.stderr"; then
        status=0
    else
        status=$?
    fi
    printf '%s\n' "$status" >"${output%.stdout}.status"
    return "$status"
}

run_case_in_root() {
    local root="$1" label="$2" selector="$3" output
    shift 3
    output="$work/$label-$selector.stdout"
    if ! run_in_root "$root" "$output" "$@" /consumer "$selector"; then
        printf 'owned kernel residual %s %s: child failed\n' "$label" "$selector" >&2
        return 1
    fi
    if ! grep -qx "owned-kernel-residual-$selector-ok" "$output"; then
        printf 'owned kernel residual %s %s: success marker missing\n' "$label" "$selector" >&2
        return 1
    fi
}

compare_case_output() {
    local label="$1" selector="$2"
    cmp "$work/oracle-$selector.status" "$work/$label-$selector.status"
    cmp "$work/oracle-$selector.stdout" "$work/$label-$selector.stdout"
    cmp "$work/oracle-$selector.stderr" "$work/$label-$selector.stderr"
}

run_oracle_cases() {
    local selector
    for selector in "${CASES[@]}"; do
        run_case_in_root "$work/oracle-root" oracle "$selector"
    done
}

assert_static_symbols() {
    local archive="$1" table symbol
    table="$work/static-symbols.txt"
    nm -g --defined-only "$archive" >"$table"
    for symbol in $OWNED_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$3 == symbol && ($2 == "T" || $2 == "W") { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned kernel residual: static symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

assert_dynamic_symbols() {
    local shared="$1" table symbol
    table="$work/dynamic-symbols.txt"
    readelf --dyn-syms -W "$shared" >"$table"
    for symbol in $OWNED_SYMBOLS; do
        [ "$(awk -v symbol="$symbol" '$4 == "FUNC" && ($5 == "GLOBAL" || $5 == "WEAK") && $6 == "DEFAULT" && $7 != "UND" && $8 == symbol { count++ } END { print count + 0 }' "$table")" -eq 1 ] || {
            printf 'owned kernel residual: dynamic symbol missing or duplicate: %s\n' "$symbol" >&2
            return 1
        }
    done
}

run_static_mode() {
    local product="$1" mode="$2" candidate root selector failures=0
    candidate="$work/consumer-static-$mode"
    "$product/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$candidate"
    root="$work/static-$mode-root"
    mkdir "$root"
    cp "$candidate" "$root/consumer"
    for selector in "${CASES[@]}"; do
        if ! run_case_in_root "$root" "static-$mode" "$selector"; then
            failures=1
            continue
        fi
        if ! compare_case_output "static-$mode" "$selector"; then
            printf 'owned kernel residual static-%s %s: raw result differs from pinned musl\n' \
                "$mode" "$selector" >&2
            failures=1
        fi
    done
    [ "$failures" -eq 0 ]
}

run_dynamic_mode() {
    local product="$1" mode="$2" entry="$3" candidate root selector output failures=0
    candidate="$work/consumer-dynamic-$mode"
    if [ ! -f "$candidate" ]; then
        "$product/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$candidate"
        readelf -hW "$candidate" >"$work/consumer-dynamic-$mode.header"
        readelf -lW "$candidate" >"$work/consumer-dynamic-$mode.segments"
        readelf -dW "$candidate" >"$work/consumer-dynamic-$mode.dynamic"
    fi
    root="$work/dynamic-$mode-$entry-root"
    cp -a "$product" "$root"
    cp "$candidate" "$root/consumer"
    for selector in "${CASES[@]}"; do
        output="$work/dynamic-$mode-$entry-$selector.stdout"
        if [ "$entry" = direct ]; then
            if ! run_in_root "$root" "$output" "$INTERPRETER" /consumer "$selector"; then
                printf 'owned kernel residual dynamic-%s-%s %s: child failed\n' \
                    "$mode" "$entry" "$selector" >&2
                failures=1
                continue
            fi
        elif ! run_in_root "$root" "$output" /consumer "$selector"; then
            printf 'owned kernel residual dynamic-%s-%s %s: child failed\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
            continue
        fi
        if ! grep -qx "owned-kernel-residual-$selector-ok" "$output"; then
            printf 'owned kernel residual dynamic-%s-%s %s: success marker missing\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
            continue
        fi
        if ! compare_case_output "dynamic-$mode-$entry" "$selector"; then
            printf 'owned kernel residual dynamic-%s-%s %s: raw result differs from pinned musl\n' \
                "$mode" "$entry" "$selector" >&2
            failures=1
        fi
    done
    [ "$failures" -eq 0 ]
}

bash "$ROOT/compat/x86_64/run_musl_oracle.sh" >/dev/null
"$ORACLE_CC" -std=c11 -I"$ROOT/include" -E -H "$PROBE" \
    >/dev/null 2>"$work/oracle.headers"
for header in errno.h sched.h signal.h sys/auxv.h sys/membarrier.h sys/personality.h sys/prctl.h sys/resource.h sys/syscall.h ulimit.h unistd.h; do
    grep -Fq "$ROOT/include/$header" "$work/oracle.headers"
done

if [ -z "$provided_dynamic" ]; then
    provided_dynamic="$work/dynamic-product"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$provided_dynamic" >"$work/dynamic-build.json"
fi
readonly installed="$provided_dynamic"

# This is the sole behavior workload object. The static pinned-musl reference
# is linked from it before every candidate uses identical bytes.
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/oracle"
mkdir "$work/oracle-root"
cp "$work/oracle" "$work/oracle-root/consumer"
run_oracle_cases
printf 'owned kernel residual pinned-musl oracle: PASS\n'

if [ "$#" -eq 0 ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-product" >"$work/static-build.json"
    assert_static_symbols "$work/static-product/usr/lib/libc.a"
    run_static_mode "$work/static-product" static
    run_static_mode "$work/static-product" static-pie
fi

assert_dynamic_symbols "$installed/usr/lib/libc.so"
for mode in pie non-pie; do
    for entry in kernel direct; do
        run_dynamic_mode "$installed" "$mode" "$entry"
    done
done

printf 'owned kernel residual: PASS (same project-header object with pinned musl; configuration, scheduler ENOSYS/output preservation, host identity, membarrier, personality, variadic prctl/syscall/ulimit, and private UTS/seccomp negatives; static/static-PIE/dynamic PIE/non-PIE kernel/direct); evidence: %s\n' "$work"
