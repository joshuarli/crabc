#!/usr/bin/env bash
# Same installed-header utmpx object through pinned musl and owned x86 entries.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_utmpx_probe.c"
readonly HEADER_C="$ROOT/compat/x86_64/owned_utmpx_header_abi_probe.c"
readonly HEADER_CXX="$ROOT/compat/x86_64/owned_utmpx_header_abi_probe.cpp"

[ "$#" -le 1 ] || {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then
    provided_dynamic="$(realpath "$provided_dynamic")"
fi

python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
temporary = Path(sys.argv[2])
product = Path(sys.argv[3]) if sys.argv[3] else None
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned utmpx TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned utmpx dynamic sysroot must be a physical checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-utmpx.XXXXXX")"
chmod a+rx "$work"
printf 'owned utmpx evidence: %s\n' "$work"
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
        grep -Fq "$ROOT/include/utmpx.h" "$trace" || {
            printf 'owned utmpx header witness did not use project utmpx.h\n' >&2
            return 1
        }
    fi
    "$ORACLE_CC" -x c++ -std=c++17 -D_GNU_SOURCE -fno-builtin -nostdinc++ \
        "${include_args[@]}" -c "$HEADER_CXX" -o "$cxx_object"
    python3 -B - "$c_object" "$cxx_object" <<'PY'
from pathlib import Path
import subprocess
import sys

expected = {
    'endutxent', 'getutxent', 'getutxid', 'getutxline', 'pututxline',
    'setutxent',
}
for filename in sys.argv[1:]:
    lines = subprocess.check_output(['nm', '--undefined-only', filename], text=True)
    names = {
        line.split()[-1] for line in lines.splitlines() if line.split()
    } & expected
    if names != expected:
        raise SystemExit(f'{filename}: header witness references {sorted(names)!r}')
PY
}

compile_header_witnesses oracle ""
compile_header_witnesses project "$ROOT/include"
sha256sum "$HEADER_C" "$HEADER_CXX" "$work"/*-header-*.o >"$work/header-input.sha256"

build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" \
        --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" \
        --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi

# Compile this C object once through the installed driver. Every musl, static,
# and dynamic final link below consumes the unchanged object bytes.
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin \
    -c "$PROBE" -o "$work/workload.o"
sha256sum "$PROBE" "$work/workload.o" >"$work/input.sha256"

assert_symbol_set() {
    local artifact="$1" selector="$2" report="$3"
    if [ "$selector" = nm ]; then
        nm -g --defined-only "$artifact" >"$report"
    else
        readelf --dyn-syms --wide "$artifact" >"$report"
    fi
    python3 -B - "$report" "$selector" <<'PY'
from pathlib import Path
import sys

expected = {
    'endutxent', 'getutxent', 'getutxid', 'getutxline', 'pututxline',
    'setutxent',
}
lines = Path(sys.argv[1]).read_text().splitlines()
selector = sys.argv[2]
if selector == 'nm':
    names = {
        fields[2] for fields in (line.split() for line in lines)
        if len(fields) == 3 and fields[1] == 'T' and fields[2] in expected
    }
else:
    names = {
        fields[7] for fields in (line.split() for line in lines)
        if len(fields) == 8
        and fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']
        and fields[6] != 'UND' and fields[7] in expected
    }
if names != expected:
    raise SystemExit(f'{selector} symbol set mismatch: {sorted(names)!r}')
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
assert_symbol_set "$work/root/oracle" nm "$work/oracle-symbols.txt"
run_probe /oracle >"$work/oracle.stdout" 2>"$work/oracle.stderr"

if [ "$build_static" -eq 1 ]; then
    # The baseline fails at these links because the installed header declares
    # the six symbols before the owned leaf is registered.
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" \
            -o "$work/root/$mode"
        assert_symbol_set "$work/root/$mode" nm "$work/$mode-symbols.txt"
        compare "$mode" "/$mode"
    done
    assert_symbol_set "$work/static-sysroot/usr/lib/libc.a" nm \
        "$work/archive-symbols.txt"
fi

assert_symbol_set "$provided_dynamic/usr/lib/libc.so" readelf \
    "$work/dynamic-symbols.txt"
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$work/workload.o" -o "$work/root/dynamic-$mode"
    compare "dynamic-$mode-kernel" "/dynamic-$mode"
    compare "dynamic-$mode-direct" /lib/ld-crabc-x86_64.so.1 "/dynamic-$mode"
done

sha256sum -c "$work/header-input.sha256" >"$work/header-input-verified.txt"
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned utmpx: PASS (same installed-header object; pinned musl and selected owned entries; C/C++ declarations and unmangled linkage, six inert source stubs, unchanged errno and caller input, and static/static-PIE/dynamic PIE/non-PIE kernel/direct execution); evidence: %s\n' "$work"
