#!/usr/bin/env bash
# Installed static/dynamic join cancellation with pinned-musl semantics.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly musl_libc=/opt/musl-1.2.6/lib/libc.a
readonly probe="$ROOT/compat/x86_64/owned_pthread_join_cancel_probe.c"
readonly -a scenarios=(try-status timed-status timed-exited-invalid entry blocked disabled masked cleanup-rejoin timed-entry timed-blocked timed-disabled timed-masked try-pending-busy try-pending-exited)
# Aggregate dynamic gates supply an already built installed or extracted
# product. The focused command builds and checks both static entries; the
# pthread family supplies its sealed static product with --static-sysroot.
. "$ROOT/compat/x86_64/owned_pthread_product_arguments.sh"
owned_pthread_product_arguments pthread-join-cancel "$@"
work="$(mktemp -d "$TMPDIR/owned-pthread-join-cancel.XXXXXX")"
readonly work
printf 'pthread-join-cancel evidence: %s\n' "$work"
if [ -z "$provided_dynamic_sysroot" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic_sysroot="$work/dynamic-sysroot"
fi
# The selected installed (including extracted) product owns compilation.
# Reuse this exact object in every musl, static, and dynamic link.
"$provided_dynamic_sysroot/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/probe.o"
"$oracle_cc" -pthread "$work/probe.o" -o "$work/oracle"
run_case() {
    local operation="$1" root="$2" output="$3"
    shift 3
    CRABC_TEST_PTHREAD_JOIN_FUTEX_OPERATION="$operation" \
        timeout 20 python3 -B "$ROOT/compat/x86_64/run_pthread_wait_witness.py" \
        "$root" "$@" >"$output"
}
assert_join_mode_aliases() {
    local artifact="$1" internal_bind="$2" internal_visibility="$3" label="$4"
    local symbols="$work/$label-symbols.txt"
    readelf --symbols --wide "$artifact" >"$symbols"
    python3 -B - "$symbols" "$internal_bind" "$internal_visibility" "$label" <<'PY'
from pathlib import Path
import sys

path, internal_bind, internal_visibility, label = sys.argv[1:]
symbols: dict[str, list[list[str]]] = {}
for line in Path(path).read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) != 8 or fields[3] != "FUNC" or fields[6] == "UND":
        continue
    symbols.setdefault(fields[7], []).append(fields)

for internal, public in (
    ("__pthread_tryjoin_np", "pthread_tryjoin_np"),
    ("__pthread_timedjoin_np", "pthread_timedjoin_np"),
):
    internal_rows = [
        row for row in symbols.get(internal, [])
        if (row[4] == internal_bind or
            internal_bind == "STRONG" and row[4] in ("GLOBAL", "LOCAL")) and
        row[5] == internal_visibility
    ]
    public_rows = [
        row for row in symbols.get(public, [])
        if row[4] == "WEAK" and row[5] == "DEFAULT"
    ]
    assert internal_rows, (label, internal, internal_bind, internal_visibility,
                           symbols.get(internal, []))
    assert public_rows, (label, public, symbols.get(public, []))
    internal_addresses = {(row[1], row[6]) for row in internal_rows}
    public_addresses = {(row[1], row[6]) for row in public_rows}
    assert internal_addresses & public_addresses, (
        label, internal, public, internal_addresses, public_addresses
    )
PY
}
[ -f "$musl_libc" ] || { printf 'missing pinned musl libc archive: %s\n' "$musl_libc" >&2; exit 1; }
assert_join_mode_aliases "$musl_libc" LOCAL DEFAULT musl-join
for scenario in "${scenarios[@]}"; do
    run_case 128 "" "$work/oracle-$scenario.stdout" "$work/oracle" "$scenario"
done
if [ "$check_static" -eq 1 ]; then
    static_sysroot="$provided_static_sysroot"
    if [ -z "$static_sysroot" ]; then
        static_sysroot="$work/static-sysroot"
        python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$static_sysroot" >"$work/static-build.json"
    fi
    assert_join_mode_aliases "$static_sysroot/usr/lib/libc.a" STRONG HIDDEN static-archive-join
    for mode in static static-pie; do
        "$static_sysroot/bin/crabc-cc" "-$mode" -std=c11 "$work/probe.o" -o "$work/$mode"
        assert_join_mode_aliases "$work/$mode" STRONG HIDDEN "$mode-join"
        for scenario in "${scenarios[@]}"; do
            run_case 0 "" "$work/$mode-$scenario.stdout" "$work/$mode" "$scenario"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
        done
    done
fi
assert_join_mode_aliases "$provided_dynamic_sysroot/usr/lib/libc.so" STRONG HIDDEN dynamic-provider-join
cp -a "$provided_dynamic_sysroot" "$work/execution-root"
for mode in pie non-pie; do
    "$provided_dynamic_sysroot/bin/crabc-cc-dynamic" "--dynamic-$mode" -std=c11 "$work/probe.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${scenarios[@]}"; do
        run_case 0 "$work/execution-root" "$work/dynamic-$mode-$scenario.stdout" \
            "/consumer-$mode" "$scenario"
        cmp "$work/oracle-$scenario.stdout" "$work/dynamic-$mode-$scenario.stdout"
        run_case 0 "$work/execution-root" "$work/direct-$mode-$scenario.stdout" \
            /lib/ld-crabc-x86_64.so.1 "/consumer-$mode" "$scenario"
        cmp "$work/oracle-$scenario.stdout" "$work/direct-$mode-$scenario.stdout"
    done
done
printf 'owned pthread join modes: PASS (one selected dynamic-product-built object through static ET_EXEC/static-PIE and dynamic PIE/non-PIE kernel/direct entries; weak same-address GNU aliases, tryjoin busy/result preservation, timed deadline ordering and timeout, entry/blocked cancellation, disabled/masked states, cleanup and target reclamation); evidence: %s\n' "$work"
