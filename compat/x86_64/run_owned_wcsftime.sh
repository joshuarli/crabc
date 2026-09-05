#!/usr/bin/env bash
# Same installed-header object through pinned musl and owned wide-time entries.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT/compat/x86_64/owned_wcsftime_probe.c"

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
    raise SystemExit('owned wcsftime TMPDIR must be a physical checkout .work directory')
if product and (not product.is_dir() or product.resolve() != product or not product.is_relative_to(root / '.work')):
    raise SystemExit('owned wcsftime dynamic product must be a physical checkout .work directory')
PY

readonly work="$(mktemp -d "$TMPDIR/owned-wcsftime.XXXXXX")"
chmod a+rx "$work"
printf 'owned wcsftime evidence: %s\n' "$work"
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
    python3 -B - "$report" <<'PY'
from pathlib import Path
import sys

report = Path(sys.argv[1]).read_text().splitlines()
names = {'wcsftime', '__wcsftime_l', 'wcsftime_l'}
observed = {name: [] for name in names}
for line in report:
    fields = line.split()
    if len(fields) >= 3 and fields[-1] in names:
        observed[fields[-1]].append(fields)
for name in ('wcsftime', '__wcsftime_l'):
    matches = [fields for fields in observed[name]
        if ('T' in fields or (len(fields) == 8 and fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and fields[6] != 'UND'))]
assert len(matches) == 1, (name, observed[name])
matches = [fields for fields in observed['wcsftime_l']
    if ('W' in fields or (len(fields) == 8 and fields[3:6] == ['FUNC', 'WEAK', 'DEFAULT'] and fields[6] != 'UND'))]
assert len(matches) == 1, ('wcsftime_l', observed['wcsftime_l'])
internal = [fields for fields in observed['__wcsftime_l']
    if ('T' in fields or (len(fields) == 8 and fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and fields[6] != 'UND'))][0]
alias = matches[0]
def symbol_value(fields):
    return fields[0] if len(fields) == 3 else fields[1]
assert symbol_value(internal) == symbol_value(alias), (internal, alias)
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
printf 'owned wcsftime: PASS (same object; musl and owned static/static-PIE/dynamic PIE/non-PIE kernel/direct entries; byte-to-wide directive bridge, C/POSIX/C.UTF-8 locale tokens, source-specific internal entry, weak public locale alias, width/sign/truncation, invalid directives, and wide literal/conversion boundaries); evidence: %s\n' "$work"
