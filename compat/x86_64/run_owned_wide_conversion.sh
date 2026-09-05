#!/usr/bin/env bash
# Same installed-header object through pinned musl and all owned link modes.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
provided_dynamic="${1:-}"
if [ -n "$provided_dynamic" ]; then provided_dynamic="$(realpath -e "$provided_dynamic")"; fi
python3 -B - "$ROOT" "${TMPDIR:-}" "$provided_dynamic" <<'PY'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:3])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned wide-conversion TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('owned wide-conversion product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-wide-conversion.XXXXXX")"
chmod a+rx "$work"
printf 'owned wide-conversion evidence: %s\n' "$work"
mkdir -p "$work/root/tmp"
build_static=0
if [ -z "$provided_dynamic" ]; then
    build_static=1
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
# The dynamic installed driver owns the common application's compilation.
# Both fresh products exist before this one object is compiled; every oracle,
# static and dynamic final link below consumes these unchanged object bytes.
"$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$ROOT/compat/x86_64/owned_wide_conversion_probe.c" -o "$work/workload.o"
sha256sum "$ROOT/compat/x86_64/owned_wide_conversion_probe.c" "$work/workload.o" >"$work/input.sha256"
assert_symbols() {
    readelf --wide "$2" "$1" >"$3"
    python3 -B - "$3" <<'PY'
from pathlib import Path
import sys
names = {'mbsnrtowcs', 'wcsnrtombs', 'wcsdup'}
seen = set()
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in names:
        assert fields[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and fields[6] != 'UND', fields
        assert fields[7] not in seen, fields
        seen.add(fields[7])
assert seen == names, (seen, names)
PY
}
run_probe() {
    timeout 30 env -i PATH="$PATH" chroot "$work/root" "$@"
}
/usr/local/bin/crabc-x86_64-musl-gcc -static -fno-pie -no-pie "$work/workload.o" -o "$work/root/oracle"
assert_symbols "$work/root/oracle" --syms "$work/oracle-symbols.txt"
run_probe /oracle >"$work/oracle.stdout" 2>"$work/oracle.stderr"
if [ "$build_static" -eq 1 ]; then
    assert_symbols "$work/static-sysroot/usr/lib/libc.a" --syms "$work/archive-symbols.txt"
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/root/$mode"
        assert_symbols "$work/root/$mode" --syms "$work/$mode-symbols.txt"
        run_probe "/$mode" >"$work/$mode.stdout" 2>"$work/$mode.stderr"
        cmp "$work/oracle.stdout" "$work/$mode.stdout"
        cmp "$work/oracle.stderr" "$work/$mode.stderr"
    done
fi
assert_symbols "$provided_dynamic/usr/lib/libc.so" --dyn-syms "$work/provider-symbols.txt"
cp -a "$provided_dynamic/." "$work/root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/root/dynamic-$mode"
    for entry in kernel direct; do
        command=("/dynamic-$mode")
        if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 "${command[@]}"); fi
        run_probe "${command[@]}" >"$work/$mode-$entry.stdout" 2>"$work/$mode-$entry.stderr"
        cmp "$work/oracle.stdout" "$work/$mode-$entry.stdout"
        cmp "$work/oracle.stderr" "$work/$mode-$entry.stderr"
    done
done
sha256sum -c "$work/input.sha256" >"$work/input-verified.txt"
printf 'owned wide-conversion: PASS (same object; bounded conversion, state, locales, errors, protected-page input, duplication); evidence: %s\n' "$work"
