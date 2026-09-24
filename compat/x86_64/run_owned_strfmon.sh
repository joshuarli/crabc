#!/usr/bin/env bash
# Same installed-header monetary object through pinned musl and owned x86 entries.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_strfmon_probe.c"
readonly HEADER_C="$ROOT/compat/x86_64/owned_strfmon_header_abi_probe.c"
readonly HEADER_CXX="$ROOT/compat/x86_64/owned_strfmon_header_abi_probe.cpp"

[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product = Path(sys.argv[3]) if sys.argv[3] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned strfmon TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned strfmon dynamic product must be a physical checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-strfmon.XXXXXX")"
chmod a+rx "$work"
printf 'owned strfmon evidence: %s\n' "$work"
mkdir -p "$work/root"

compile_header_witnesses() {
    local tree="$1" include_root="$2"
    local -a include_args=()
    local trace="$work/$tree-header.trace"
    local c_object="$work/$tree-header-c.o"
    local cxx_object="$work/$tree-header-cxx.o"
    if [ -n "$include_root" ]; then include_args=(-I "$include_root"); fi

    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin "${include_args[@]}" \
        -H -c "$HEADER_C" -o "$c_object" >/dev/null 2>"$trace"
    if [ "$tree" = project ]; then
        grep -Fq "$ROOT/include/monetary.h" "$trace" || {
            printf 'owned strfmon header witness did not use project monetary.h\n' >&2
            return 1
        }
    fi
    "$ORACLE_CC" -x c++ -std=c++17 -D_GNU_SOURCE -fno-builtin -nostdinc++ \
        "${include_args[@]}" -c "$HEADER_CXX" -o "$cxx_object"
    for object in "$c_object" "$cxx_object"; do
        local undefined
        undefined="$(nm --undefined-only "$object")"
        grep -Eq '[[:space:]]strfmon$' <<<"$undefined" || {
            printf 'owned strfmon header witness lacks unmangled strfmon: %s\n' "$object" >&2
            return 1
        }
        grep -Eq '[[:space:]]strfmon_l$' <<<"$undefined" || {
            printf 'owned strfmon header witness lacks unmangled strfmon_l: %s\n' "$object" >&2
            return 1
        }
    done
}

compile_header_witnesses oracle ""
compile_header_witnesses project "$ROOT/include"
sha256sum "$HEADER_C" "$HEADER_CXX" "$work"/*-header-*.o >"$work/header-input.sha256"

build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi

# The dynamic installed driver compiles this sole C object. Every musl, static,
# and dynamic final link below consumes unchanged bytes from that object.
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
sha256sum "$PROBE" "$work/workload.o" >"$work/input.sha256"

assert_symbols() {
    local artifact="$1" selector="$2" report="$3"
    if [ "$selector" = nm ]; then
        nm -g --defined-only "$artifact" >"$report"
    else
        readelf --dyn-syms --wide "$artifact" >"$report"
    fi
    python3 -B - "$report" "$selector" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text().splitlines()
selector = sys.argv[2]
for name in ('strfmon', 'strfmon_l'):
    if selector == 'nm':
        matches = [line.split() for line in lines
                   if len(line.split()) == 3 and line.split()[1] == 'T'
                   and line.split()[2] == name]
    else:
        matches = [line.split() for line in lines
                   if len(line.split()) == 8
                   and line.split()[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']
                   and line.split()[6] != 'UND' and line.split()[7] == name]
    assert len(matches) == 1, (name, matches)
PY
}

run_probe() {
    timeout 30 env -i PATH="$PATH" chroot "$work/root" "$@"
}

compare() {
    local label="$1"
    shift
    run_probe "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"
    cmp "$work/oracle.stdout" "$work/$label.stdout"
    cmp "$work/oracle.stderr" "$work/$label.stderr"
}

"$ORACLE_CC" -static -fno-pie -no-pie "$work/workload.o" -o "$work/root/oracle"
assert_symbols "$work/root/oracle" nm "$work/oracle-symbols.txt"
run_probe /oracle >"$work/oracle.stdout" 2>"$work/oracle.stderr"

if [ "$build_static" -eq 1 ]; then
    # Link before inspecting the archive: on the unimplemented baseline this
    # is the intended installed-header common-object link-red regression.
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        assert_symbols "$work/root/$mode" nm "$work/$mode-symbols.txt"
        compare "$mode" "/$mode"
    done
    assert_symbols "$work/static-sysroot/usr/lib/libc.a" nm "$work/archive-symbols.txt"
fi

assert_symbols "$provided_dynamic/usr/lib/libc.so" readelf "$work/dynamic-symbols.txt"
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    compare "dynamic-$mode-kernel" "/dynamic-$mode"
    compare "dynamic-$mode-direct" /lib/ld-crabc-x86_64.so.1 "/dynamic-$mode"
done

sha256sum -c "$work/header-input.sha256" >"$work/header-input-verified.txt"
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned strfmon: PASS (same installed-header object; pinned musl and selected owned entries; C/C++ declaration and unmangled-linkage witness, opaque C/C.UTF-8 locale tokens, variadic multi-value parsing, source flags/width/precision, literal and capacity boundaries, truncation/E2BIG, and byte canaries); evidence: %s\n' "$work"
