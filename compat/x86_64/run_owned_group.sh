#!/usr/bin/env bash
# Source-bound conventional local group-file evidence through every product.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_group_probe.c"

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

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
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("owned group TMPDIR must be a physical checkout .work directory")
if product_argument:
    product = Path(product_argument)
    if not product.is_dir() or not product.is_relative_to(root / ".work"):
        raise SystemExit("owned group product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-group.XXXXXX")"
chmod a+rx "$work"
printf 'owned group evidence: %s\n' "$work"

readonly cases=(
    lookup ranges enumeration stream output memberships memberships-missing
    memberships-not-directory initgroups missing directory not-directory
    read-error open-error local-only
    threads fork cancellation allocation
)

run_in_root() {
    local root="$1"
    local output="$2"
    shift 2
    mkdir -p "$root/tmp"
    timeout 30 env -i PATH="$PATH" chroot "$root" "$@" >"$output" 2>"${output%.stdout}.stderr"
}

# `getgrent.c` gives only endgrent the weak same-address alias. All remaining
# entries are ordinary strong/default exports in the pinned musl source. Check
# the archive, static final links, and the dynamic provider independently.
assert_group_symbols() {
    local binary="$1"
    local table="$2"
    local output="$3"

    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" <<'PYTHON'
from pathlib import Path
import sys

names = {
    "getgrnam", "getgrgid", "getgrnam_r", "getgrgid_r", "getgrent",
    "setgrent", "endgrent", "fgetgrent", "putgrent", "getgrouplist",
    "initgroups",
}
records = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in names:
        records.setdefault(fields[7], []).append(fields)

assert set(records) == names, records
symbols = {}
for name, entries in records.items():
    assert len(entries) == 1, (name, entries)
    fields = entries[0]
    binding = "WEAK" if name == "endgrent" else "GLOBAL"
    assert fields[3:6] == ["FUNC", binding, "DEFAULT"], fields
    assert fields[6] != "UND", fields
    symbols[name] = fields

assert symbols["endgrent"][1:3] == symbols["setgrent"][1:3], symbols
assert symbols["endgrent"][6] == symbols["setgrent"][6], symbols
PYTHON
}

mkdir -p "$work/execution-root/etc"

# Compile exactly one installed-header workload object. Every oracle/static/
# dynamic link below consumes these same bytes, so a passing matrix cannot hide
# mode-specific source, declaration, or application-object drift.
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    "$work/static-sysroot/bin/crabc-cc" -static-pie -std=c11 -fno-builtin -c \
        "$PROBE" -o "$work/workload.o"
    assert_group_symbols "$work/static-sysroot/usr/lib/libc.a" --syms \
        "$work/static-archive-symbols.txt"
else
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c \
        "$PROBE" -o "$work/workload.o"
fi

"$ORACLE_CC" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_group_symbols "$work/oracle" --syms "$work/oracle-symbols.txt"
cp "$work/oracle" "$work/execution-root/oracle"
for scenario in "${cases[@]}"; do
    run_in_root "$work/execution-root" "$work/oracle-$scenario.stdout" \
        /oracle "$scenario" oracle
done

if [ -z "$provided_dynamic" ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/$mode"
        assert_group_symbols "$work/$mode" --syms "$work/$mode-symbols.txt"
        cp "$work/$mode" "$work/execution-root/consumer-$mode"
        for scenario in "${cases[@]}"; do
            run_in_root "$work/execution-root" "$work/$mode-$scenario.stdout" \
                "/consumer-$mode" "$scenario" owned
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$scenario.stderr"
        done
    done

    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi

assert_group_symbols "$provided_dynamic/usr/lib/libc.so" --dyn-syms \
    "$work/dynamic-provider-symbols.txt"
cp -a "$provided_dynamic/." "$work/execution-root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" \
        -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            if [ "$entry" = direct ]; then
                command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode")
            else
                command=("/consumer-$mode")
            fi
            run_in_root "$work/execution-root" "$work/$mode-$entry-$scenario.stdout" \
                "${command[@]}" "$scenario" owned
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$entry-$scenario.stderr"
        done
    done
done

printf 'owned group: PASS (same object, musl/local-file parsing, storage, cursor, memberships, errors, cancellation, fork, and isolated initgroups); evidence: %s\n' "$work"
