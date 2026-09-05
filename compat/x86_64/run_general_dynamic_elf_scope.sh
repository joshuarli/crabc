#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1" source="$ROOT/compat/x86_64/general_dynamic_elf_scope.c"
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-elf-scope.XXXXXX")"
trap 'printf "ELF scope FAIL arm=%s case=%s; evidence: %s\n" "${arm:-setup}" "${name:-build}" "$work" >&2' ERR
for arm in oracle candidate; do
    root="$work/$arm"
    mkdir -p "$root/lib" "$root/usr/lib"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        interpreter=/lib/ld-crabc-x86_64.so.1
    else
        cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        interpreter=/lib/ld-musl-x86_64.so.1
    fi
    for provider in a b; do
        if [ "$arm" = candidate ]; then
            "$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "-DPROVIDER_${provider^^}" "$source" -o "$root/usr/lib/libelf_$provider.so"
        else
            /usr/local/bin/crabc-x86_64-musl-gcc -fPIC -shared "-DPROVIDER_${provider^^}" "$source" -Wl,-soname,"libelf_$provider.so" -o "$root/usr/lib/libelf_$provider.so"
        fi
    done
    readelf --dyn-syms -W "$root/usr/lib/libelf_a.so" >"$work/$arm-a.symbols"
    python3 - "$work/$arm-a.symbols" <<'PY_SYMBOLS'
import pathlib
import sys
symbols = {parts[-1]: parts for line in pathlib.Path(sys.argv[1]).read_text().splitlines()
           if len(parts := line.split()) == 8 and parts[0].endswith(":")}
assert symbols["elf_choice"][4:6] == ["WEAK", "DEFAULT"]
assert symbols["elf_protected"][4:6] == ["GLOBAL", "PROTECTED"]
assert symbols["elf_absent"][4:7] == ["WEAK", "DEFAULT", "UND"]
assert "elf_hidden" not in symbols
PY_SYMBOLS
    for mode in pie non-pie; do
        for phase in initial runtime; do
            for order in a b; do
                name="$mode-$phase-$order"
                other=a; choice=22; protected=42
                if [ "$order" = a ]; then other=b; choice=11; protected=31; fi
                flags=("-DEXPECT_CHOICE=$choice" "-DEXPECT_PROTECTED=$protected")
                dependencies=()
                if [ "$phase" = runtime ]; then
                    flags+=(-DRUNTIME_SCOPE "-DFIRST_LIBRARY=\"libelf_$order.so\"" "-DSECOND_LIBRARY=\"libelf_$other.so\"")
                elif [ "$arm" = candidate ]; then
                    dependencies+=(--application-dso "$root/usr/lib/libelf_$order.so" --application-dso "$root/usr/lib/libelf_$other.so")
                else
                    dependencies+=("$root/usr/lib/libelf_$order.so" "$root/usr/lib/libelf_$other.so")
                fi
                if [ "$arm" = candidate ]; then
                    "$installed/bin/crabc-cc-dynamic" "--dynamic-$mode" "${flags[@]}" "$source" "${dependencies[@]}" -o "$root/$name"
                else
                    /usr/local/bin/crabc-x86_64-musl-gcc -fPIE "-${mode/non-pie/no-pie}" "${flags[@]}" "$source" -Wl,--dynamic-linker,"$interpreter",-rpath,/usr/lib,--no-as-needed "${dependencies[@]}" -o "$root/$name"
                fi
                timeout 20 chroot "$root" "/$name" >"$work/$arm-$name.stdout" 2>"$work/$arm-$name.stderr"
                if [ "$arm" = candidate ]; then
                    cmp "$work/oracle-$name.stdout" "$work/candidate-$name.stdout"
                    # The product alias must execute the owned loader both as a
                    # direct command and as the actual kernel PT_INTERP target.
                    [ "$(readlink "$root/lib/ld-musl-x86_64.so.1")" = ld-crabc-x86_64.so.1 ]
                    timeout 20 chroot "$root" /lib/ld-musl-x86_64.so.1 "/$name" >"$work/alias-direct-$name.stdout"
                    cmp "$work/oracle-$name.stdout" "$work/alias-direct-$name.stdout"
                    python3 - "$root/$name" "$root/$name-alias" <<'PY_ALIAS'
import pathlib
import struct
import sys
image = bytearray(pathlib.Path(sys.argv[1]).read_bytes())
assert image[:6] == b"\x7fELF\x02\x01"
phoff = struct.unpack_from("<Q", image, 32)[0]
phentsize, phnum = struct.unpack_from("<HH", image, 54)
interpreters = []
for index in range(phnum):
    at = phoff + index * phentsize
    if struct.unpack_from("<I", image, at)[0] == 3:
        offset = struct.unpack_from("<Q", image, at + 8)[0]
        size = struct.unpack_from("<Q", image, at + 32)[0]
        interpreters.append((offset, size))
assert len(interpreters) == 1
at, size = interpreters[0]
assert image[at:at + size].rstrip(b"\0") == b"/lib/ld-crabc-x86_64.so.1"
alias = b"/lib/ld-musl-x86_64.so.1\0"
assert len(alias) <= size
image[at:at + size] = alias.ljust(size, b"\0")
output = pathlib.Path(sys.argv[2])
output.write_bytes(image)
output.chmod(0o755)
PY_ALIAS
                    timeout 20 chroot "$root" "/$name-alias" >"$work/alias-interp-$name.stdout"
                    cmp "$work/oracle-$name.stdout" "$work/alias-interp-$name.stdout"
                fi
            done
        done
    done
done
printf 'ELF weak/protected scope and interpreter alias: PASS (8 cases per arm, 16 alias entries); evidence: %s\n' "$work"
