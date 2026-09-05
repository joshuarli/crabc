#!/usr/bin/env bash
# Same installed-header regex object through pinned musl and owned x86 entries.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_regex_probe.c"

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
    raise SystemExit('owned regex TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned regex dynamic product must be a physical checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-regex.XXXXXX")"
chmod a+rx "$work"
printf 'owned regex evidence: %s\n' "$work"
mkdir -p "$work/root"

build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi

# The dynamic installed driver compiles this sole object. Every musl, static,
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

report = Path(sys.argv[1]).read_text().splitlines()
selector = sys.argv[2]
names = ('regcomp', 'regexec', 'regerror', 'regfree')
for name in names:
    if selector == 'nm':
        matches = [line.split() for line in report
                   if len(line.split()) == 3 and line.split()[1] == 'T'
                   and line.split()[2] == name]
    else:
        matches = [line.split() for line in report
                   if len(line.split()) == 8 and line.split()[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT']
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
    assert_symbols "$work/static-sysroot/usr/lib/libc.a" nm "$work/archive-symbols.txt"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        assert_symbols "$work/root/$mode" nm "$work/$mode-symbols.txt"
        compare "$mode" "/$mode"
    done
fi

assert_symbols "$provided_dynamic/usr/lib/libc.so" readelf "$work/dynamic-symbols.txt"
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    compare "dynamic-$mode-kernel" "/dynamic-$mode"
    compare "dynamic-$mode-direct" /lib/ld-crabc-x86_64.so.1 "/dynamic-$mode"
done

sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned regex: PASS (same installed-header object; musl and owned static/static-PIE/dynamic PIE/non-PIE kernel/direct entries; signed LP64 regoff_t, TRE compiler/free/executor/error paths, captures, backreferences, C.UTF-8 byte offsets, C-locale errors, and installed musl interface boundary); evidence: %s\n' "$work"
