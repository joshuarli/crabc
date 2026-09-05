#!/usr/bin/env bash
# One ordinary application object through pinned musl and owned linkage modes.
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
    raise SystemExit('passwd TMPDIR must be a physical checkout .work directory')
if sys.argv[3]:
    product = Path(sys.argv[3])
    if not product.is_dir() or not product.is_relative_to(root / '.work'):
        raise SystemExit('passwd product must be a checkout .work directory')
PY
readonly work="$(mktemp -d "$TMPDIR/owned-passwd.XXXXXX")"
chmod a+rx "$work"
printf 'passwd evidence: %s\n' "$work"
readonly probe="$ROOT/compat/x86_64/owned_passwd_probe.c"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly cases=(lookup ranges enumeration stream output missing directory not-directory read-error open-error local-only threads fork cancellation allocation)
mkdir -p "$work/execution-root/etc"
# Preserve the complete installed provider roster and musl's weak cursor alias.
assert_passwd_symbols() {
    local binary="$1" table="$2" output="$3"
    readelf --wide "$table" "$binary" >"$output"
    python3 -B - "$output" <<'PYTHON'
from pathlib import Path
import sys
names = {'getpwnam', 'getpwuid', 'getpwnam_r', 'getpwuid_r', 'getpwent',
         'setpwent', 'endpwent', 'fgetpwent', 'putpwent'}
symbols = {}
for line in Path(sys.argv[1]).read_text().splitlines():
    fields = line.split()
    if len(fields) == 8 and fields[7] in names:
        symbols[fields[7]] = fields
assert set(symbols) == names, symbols
for name, fields in symbols.items():
    binding = 'WEAK' if name == 'endpwent' else 'GLOBAL'
    assert fields[3:6] == ['FUNC', binding, 'DEFAULT'] and fields[6] != 'UND', fields
end, start = symbols['endpwent'], symbols['setpwent']
assert end[1:3] == start[1:3] and end[6] == start[6], (start, end)
PYTHON
}
if [ -z "$provided_dynamic" ]; then
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$work/static-sysroot" >"$work/static-build.json"
    "$work/static-sysroot/bin/crabc-cc" -static-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
else
    "$provided_dynamic/bin/crabc-cc-dynamic" --dynamic-pie -std=c11 -fno-builtin -c "$probe" -o "$work/workload.o"
fi
"$oracle_cc" -static -fno-pie -no-pie -pthread "$work/workload.o" -o "$work/oracle"
assert_passwd_symbols "$work/oracle" --syms "$work/oracle-symbols.txt"
cp "$work/oracle" "$work/execution-root/oracle"
for scenario in "${cases[@]}"; do
    timeout 30 chroot "$work/execution-root" /oracle "$scenario" oracle >"$work/oracle-$scenario.stdout" 2>"$work/oracle-$scenario.stderr"
done
if [ -z "$provided_dynamic" ]; then
    for mode in static static-pie; do
        "$work/static-sysroot/bin/crabc-cc" "-$mode" "$work/workload.o" -o "$work/$mode"
        assert_passwd_symbols "$work/$mode" --syms "$work/$mode-symbols.txt"
        cp "$work/$mode" "$work/execution-root/consumer-$mode"
        for scenario in "${cases[@]}"; do
            timeout 30 chroot "$work/execution-root" "/consumer-$mode" "$scenario" owned >"$work/$mode-$scenario.stdout" 2>"$work/$mode-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$scenario.stderr"
        done
    done
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" >"$work/dynamic-build.json"
    provided_dynamic="$work/dynamic-sysroot"
fi
assert_passwd_symbols "$provided_dynamic/usr/lib/libc.so" --dyn-syms "$work/dynamic-provider-symbols.txt"
cp -a "$provided_dynamic/." "$work/execution-root/"
for mode in pie non-pie; do
    "$provided_dynamic/bin/crabc-cc-dynamic" "--dynamic-$mode" "$work/workload.o" -o "$work/dynamic-$mode"
    cp "$work/dynamic-$mode" "$work/execution-root/consumer-$mode"
    for scenario in "${cases[@]}"; do
        for entry in kernel direct; do
            command=("/consumer-$mode")
            if [ "$entry" = direct ]; then command=(/lib/ld-crabc-x86_64.so.1 "/consumer-$mode"); fi
            timeout 30 chroot "$work/execution-root" "${command[@]}" "$scenario" owned >"$work/$mode-$entry-$scenario.stdout" 2>"$work/$mode-$entry-$scenario.stderr"
            cmp "$work/oracle-$scenario.stdout" "$work/$mode-$entry-$scenario.stdout"
            cmp "$work/oracle-$scenario.stderr" "$work/$mode-$entry-$scenario.stderr"
        done
    done
done
printf 'owned passwd: PASS (same object, musl + installed entries, local file parsing, lookup/storage/cursor/errors/cancellation); evidence: %s\n' "$work"
