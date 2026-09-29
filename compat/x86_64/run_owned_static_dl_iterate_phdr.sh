#!/usr/bin/env bash
# Musl's static main-image enumeration through actual installed CRT/TLS.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc
readonly probe="$ROOT/compat/x86_64/owned_static_dl_iterate_phdr_probe.c"
[ "$#" -eq 0 ] || [ "$#" -eq 1 ] || { printf 'usage: %s [STATIC_SYSROOT]\n' "$0" >&2; exit 2; }
python3 -B - "$ROOT" "${TMPDIR:-}" <<'CHECK'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / '.work'):
    raise SystemExit('static phdr TMPDIR must be a physical checkout .work directory')
CHECK
work="$(mktemp -d "$TMPDIR/owned-static-phdr.XXXXXX")"
readonly work
printf 'static phdr evidence: %s\n' "$work"
for mode in static static-pie; do
    defines=()
    if [ "$mode" = static-pie ]; then defines=(-DEXPECT_STATIC_PIE); fi
    "$oracle_cc" -std=c11 -pthread -fPIE "${defines[@]}" -I"$ROOT/include" -c "$probe" -o "$work/$mode.o"
    if [ "$mode" = static ]; then
        "$oracle_cc" -static -no-pie "$work/$mode.o" -o "$work/oracle-$mode"
    else
        # The pinned specs do not choose rcrt1.o for -static-pie. Name only
        # pinned musl startup/runtime inputs for its self-relocating entry.
        "$oracle_cc" -nostdlib -static-pie -Wl,--no-dynamic-linker \
            /opt/musl-1.2.6/lib/rcrt1.o /opt/musl-1.2.6/lib/crti.o \
            "$work/$mode.o" /opt/musl-1.2.6/lib/libc.a \
            /opt/musl-1.2.6/lib/crtn.o -o "$work/oracle-$mode"
    fi
    readelf -h -l -s "$work/oracle-$mode" >"$work/oracle-$mode.elf"
    timeout 20 "$work/oracle-$mode" >"$work/oracle-$mode.stdout"
done
product="${1:-}"
if [ -z "$product" ]; then
    product="$work/static-sysroot"
    python3 -B "$ROOT/scripts/build_x86_64_owned_sysroot.py" --output "$product" >"$work/static-build.json"
fi
for mode in static static-pie; do
    "$product/bin/crabc-cc" "-$mode" "$work/$mode.o" -o "$work/$mode"
    readelf -h -l -s "$work/$mode" >"$work/$mode.elf"
    timeout 20 "$work/$mode" >"$work/$mode.stdout"
    cmp "$work/oracle-$mode.stdout" "$work/$mode.stdout"
    python3 -B - "$work/$mode.elf" "$work/oracle-$mode.elf" "$mode" <<'VERIFY'
from pathlib import Path
import sys
candidate, oracle = (Path(name).read_text() for name in sys.argv[1:3])
expected = 'DYN' if sys.argv[3] == 'static-pie' else 'EXEC'
for image in (candidate, oracle):
    elf_type = next(line.split()[1] for line in image.splitlines() if line.strip().startswith('Type:'))
    if elf_type != expected or 'INTERP' in image:
        raise SystemExit('static phdr fixture has the wrong ELF type or an interpreter')
symbols = [line.split() for line in candidate.splitlines() if line.split() and line.split()[-1] == 'dl_iterate_phdr']
if len(symbols) != 1 or symbols[0][3:5] != ['FUNC', 'WEAK'] or symbols[0][6] == 'UND':
    raise SystemExit('static dl_iterate_phdr must remain one defined weak function')
VERIFY
    "$oracle_cc" -std=c11 -fPIE -I"$ROOT/include" -c \
        "$ROOT/compat/x86_64/owned_static_dl_iterate_phdr_override.c" -o "$work/override-$mode.o"
    if [ "$mode" = static ]; then
        "$oracle_cc" -static -no-pie "$work/override-$mode.o" -o "$work/oracle-override-$mode"
    else
        "$oracle_cc" -nostdlib -static-pie -Wl,--no-dynamic-linker \
            /opt/musl-1.2.6/lib/rcrt1.o /opt/musl-1.2.6/lib/crti.o \
            "$work/override-$mode.o" /opt/musl-1.2.6/lib/libc.a \
            /opt/musl-1.2.6/lib/crtn.o -o "$work/oracle-override-$mode"
    fi
    "$product/bin/crabc-cc" "-$mode" "$work/override-$mode.o" -o "$work/override-$mode"
    for image in "oracle-override-$mode" "override-$mode"; do
        readelf -h -l -s "$work/$image" >"$work/$image.elf"
        timeout 20 "$work/$image" >"$work/$image.stdout"
    done
    cmp "$work/oracle-override-$mode.stdout" "$work/override-$mode.stdout"
    python3 -B - "$work/oracle-override-$mode.elf" "$work/override-$mode.elf" "$mode" <<'VERIFY'
from pathlib import Path
import sys
expected = 'DYN' if sys.argv[3] == 'static-pie' else 'EXEC'
for name in sys.argv[1:3]:
    image = Path(name).read_text()
    elf_type = next(line.split()[1] for line in image.splitlines() if line.strip().startswith('Type:'))
    if elf_type != expected or 'INTERP' in image:
        raise SystemExit(f'{name}: override fixture has the wrong ELF type or an interpreter')
    symbols = [line.split() for line in image.splitlines() if line.split() and line.split()[-1] == 'dl_iterate_phdr']
    if len(symbols) != 1 or symbols[0][3:5] != ['FUNC', 'GLOBAL'] or symbols[0][6] == 'UND':
        raise SystemExit(f'{name}: strong application definition did not own dl_iterate_phdr')
VERIFY
done
cp "$probe" "$work/probe.c"
cp "$ROOT/compat/x86_64/owned_static_dl_iterate_phdr_override.c" "$work/override.c"
(
    cd "$work"
    sha256sum *.c *.o *.elf *.stdout oracle-static oracle-static-pie static static-pie \
        oracle-override-static oracle-override-static-pie override-static override-static-pie >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chmod g+rx "$work"
chmod g+r "$work"/*.c "$work"/*.o "$work"/*.elf "$work"/*.stdout "$work"/SHA256SUMS \
    "$work"/oracle-static "$work"/oracle-static-pie "$work"/static "$work"/static-pie \
    "$work"/oracle-override-static "$work"/oracle-override-static-pie \
    "$work"/override-static "$work"/override-static-pie
printf 'owned static dl_iterate_phdr: PASS (musl and installed ET_EXEC/static PIE, nested callbacks, override, TLS); evidence: %s\n' "$work"
