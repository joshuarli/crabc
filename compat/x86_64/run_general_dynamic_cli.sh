#!/usr/bin/env bash
# Installed command entry compared with a separate pinned-musl root.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
case "${TMPDIR:-}" in "$ROOT"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/general-dynamic-cli.XXXXXX")"
readonly source="$ROOT/compat/x86_64/general_dynamic_cli.c"
trap 'printf "direct interpreter FAIL arm=%s mode=%s case=%s; evidence: %s\n" "${arm:-setup}" "${mode:-setup}" "${test:-build}" "$work" >&2' ERR
for arm in oracle candidate; do
    root="$work/$arm"
    mkdir -p "$root/lib" "$root/usr/lib" "$root/plugins" "$root/override" "$root/prefix/lib" "$root/prefix/etc" "$root/p"
    if [ "$arm" = candidate ]; then
        cp -a "$installed/." "$root/"
        cc=("$installed/bin/crabc-cc-dynamic")
        "${cc[@]}" --dynamic-shared-object -DCLI_LIBRARY=7 "$source" -o "$root/plugins/libcli.so"
        "${cc[@]}" --dynamic-shared-object -DCLI_LIBRARY=9 "$source" -o "$root/override/libcli.so"
        interpreter=/lib/ld-crabc-x86_64.so.1
    else
        cp /opt/musl-1.2.6/lib/libc.so "$root/lib/ld-musl-x86_64.so.1"
        cp /opt/musl-1.2.6/lib/libc.so "$root/usr/lib/libc.so"
        cc=(/usr/local/bin/crabc-x86_64-musl-gcc)
        "${cc[@]}" -fPIC -shared -DCLI_LIBRARY=7 "$source" -Wl,-soname,libcli.so -o "$root/plugins/libcli.so"
        "${cc[@]}" -fPIC -shared -DCLI_LIBRARY=9 "$source" -Wl,-soname,libcli.so -o "$root/override/libcli.so"
        interpreter=/lib/ld-musl-x86_64.so.1
    fi
    cp "$root$interpreter" "$root/prefix/lib/loader"
    cp "$root$interpreter" "$root/ldd"
    printf invalid >"$root/invalid"
    printf '/override:/usr/lib' >"$root/prefix/etc/ld-musl-x86_64.path"
    cp "$root/plugins/libcli.so" "$root/p/libc.so"
    case_count=0
    for mode in pie non-pie; do
        if [ "$arm" = candidate ]; then
            "${cc[@]}" "--dynamic-$mode" -DCLI_CHECK_AUXV "$source" --application-runpath '$ORIGIN/plugins:/usr/lib' --application-dso "$root/plugins/libcli.so" -o "$root/consumer-$mode"
        else
            "${cc[@]}" -fPIE "-${mode/non-pie/no-pie}" "$source" -L"$root/plugins" -lcli '-Wl,-rpath,$ORIGIN/plugins:/usr/lib' -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$root/consumer-$mode"
        fi
        if [ "$arm" = candidate ]; then
            "${cc[@]}" "--dynamic-$mode" -DCLI_CHECK_AUXV "$source" --application-runpath /usr/lib --application-dso "$root/plugins/libcli.so" -o "$root/system-$mode"
        else
            "${cc[@]}" -fPIE "-${mode/non-pie/no-pie}" "$source" -L"$root/plugins" -lcli -Wl,-rpath,/usr/lib -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$root/system-$mode"
        fi
        cp "$root/system-$mode" "$root/system"
        cp "$root/consumer-$mode" "$root/consumer"
        cp "$root/consumer" "$root/--consumer"
        # The sealed driver intentionally rejects pathname DT_NEEDED. This
        # explicit same-size dynamic-string mutation isolates the loader's
        # existing pathname admission without relaxing the link interface.
        python3 -B - "$root/consumer" "$root/path-needed" <<'PYTHON'
from pathlib import Path
import struct
import sys
source, output = map(Path, sys.argv[1:])
elf = bytearray(source.read_bytes())
phoff = struct.unpack_from('<Q', elf, 32)[0]
phnum = struct.unpack_from('<H', elf, 56)[0]
loads = []
dynamic = None
for index in range(phnum):
    p = phoff + 56 * index
    kind, flags, offset, address, physical, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', elf, p)
    if kind == 1: loads.append((address, offset, filesz))
    if kind == 2: dynamic = (offset, filesz)
assert dynamic is not None
entries = [struct.unpack_from('<QQ', elf, offset) for offset in range(dynamic[0], sum(dynamic), 16)]
strtab = next(value for tag, value in entries if tag == 5)
strfile = next(offset + strtab - address for address, offset, size in loads if address <= strtab < address + size)
selected = [strfile + value for tag, value in entries if tag == 1 and elf[strfile + value:strfile + value + 10] == b'libcli.so\0']
assert len(selected) == 1
elf[selected[0]:selected[0] + 10] = b'p/libc.so\0'
output.write_bytes(elf)
PYTHON
        for test in ordinary separator argv0 argv0-equals library-path library-path-equals preload preload-equals list unknown missing-value missing-program malformed missing-file prefix ldd combined library-over-environment missing-dependency invalid-executable list-preload list-path-needed list-preload-alias; do
            [ -z "${CRABC_GENERAL_DYNAMIC_CLI_CASE:-}" ] || [ "$test" = "$CRABC_GENERAL_DYNAMIC_CLI_CASE" ] || continue
            case_count=$((case_count + 1))
            selected_interpreter="$interpreter"
            options=()
            program=(/consumer argument)
            expected=0
            environment_path=
            case "$test" in
                combined) options=(--argv0 first --argv0=replacement --library-path=/plugins --library-path /override);;
                library-over-environment) environment_path=/override; options=(--library-path=/plugins);;
                missing-dependency) program=(/system argument); expected=127;;
                invalid-executable) program=(/invalid); expected=1;;
                prefix) selected_interpreter=/prefix/lib/loader; program=(/system argument);;
                ldd) selected_interpreter=/ldd;;
                separator) options=(--); program=(./--consumer argument);;
                argv0) options=(--argv0 replacement);;
                argv0-equals) options=(--argv0=replacement);;
                library-path) options=(--library-path /override);;
                library-path-equals) options=(--library-path=/override);;
                preload) options=(--preload /override/libcli.so);;
                preload-equals) options=(--preload=/override/libcli.so);;
                list) options=(--list);;
                list-preload) options=(--list --preload /override/libcli.so);;
                list-preload-alias) options=(--list --preload /override/libcli.so --library-path /override);;
                list-path-needed) options=(--list); program=(/path-needed);;
                unknown) options=(--unknown); expected=1;;
                missing-value) options=(--argv0); program=(); expected=1;;
                missing-program) program=(); expected=1;;
                malformed) options=(--library-path-extra); expected=1;;
                missing-file) program=(/absent); expected=1;;
            esac
            status=0
            CLI_ENV=preserved LD_LIBRARY_PATH="$environment_path" timeout 20 chroot "$root" "$selected_interpreter" "${options[@]}" "${program[@]}" >"$work/$arm-$mode-$test.stdout" 2>"$work/$arm-$mode-$test.stderr" || status=$?
            [ "$status" -eq "$expected" ]
            if [[ "$test" = list* ]] || [ "$test" = ldd ]; then
                ! grep -q 'initialized\|application entered' "$work/$arm-$mode-$test.stdout"
                python3 -B - "$work/$arm-$mode-$test.stdout" >"$work/$arm-$mode-$test.names" <<'PYTHON'
from pathlib import Path
import re
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
assert lines and re.fullmatch(r'\t/lib/ld-(crabc|musl)-x86_64\.so\.1 \(0x[0-9a-f]+\)', lines[0])
application = []
for line in lines[1:]:
    match = re.fullmatch(r'\t(.+) => (.+) \(0x[0-9a-f]+\)', line)
    assert match, line
    requested, resolved = match.groups()
    # crabc and musl intentionally have different libc/loader layouts.
    if requested == 'libc.so' and resolved in ('/usr/lib/libc.so', '/lib/ld-musl-x86_64.so.1'): continue
    application.append((requested, resolved))
assert application
for requested, resolved in application: print(f'{requested} => {resolved}')
PYTHON
                if [ "$arm" = candidate ]; then
                    cmp "$work/oracle-$mode-$test.names" "$work/candidate-$mode-$test.names"
                fi
            elif [ "$arm" = candidate ]; then
                cmp "$work/oracle-$mode-$test.stdout" "$work/candidate-$mode-$test.stdout"
            fi
        done
    done
done
[ "$case_count" -gt 0 ]
printf 'direct interpreter: PASS %s cases per arm; evidence: %s\n' "$case_count" "$work"
