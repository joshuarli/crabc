#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 2 ] || exit 2
readonly installed="$1"
readonly static="$2"
case "${TMPDIR:-}" in "$root"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/hardened-entry.XXXXXX")"
readonly image="$work/root"
mkdir -p "$image/lib" "$image/usr/lib"
cp "$installed/lib/ld-crabc-x86_64-hardened.so.1" "$image/lib/"
cp "$installed/usr/lib/libc.so" "$image/usr/lib/"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/pie"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_alias_probe.c" -o "$image/alias"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "$root/compat/x86_64/hardened_relro_dso.c" -o "$image/usr/lib/hardened-relro-fixture.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object -DCRABC_BAD_DSO "$root/compat/x86_64/hardened_relro_dso.c" -o "$image/usr/lib/rejected-source.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_DSO_PROBE "$root/compat/x86_64/hardened_relro_probe.c" -o "$image/relro"
"$static/bin/crabc-cc" "$root/compat/x86_64/hardened_alias_probe.c" -o "$image/static-alias"
"$static/bin/crabc-cc" "$root/compat/x86_64/hardened_relro_probe.c" -o "$image/static-relro"
/usr/local/bin/crabc-x86_64-musl-gcc -fno-pie -no-pie \
    -Wl,--dynamic-linker=/lib/ld-crabc-x86_64-hardened.so.1 \
    "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/nonpie"
python3 -B - "$image" <<'PYTHON'
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
original = (root / "pie").read_bytes()
phoff = struct.unpack_from("<Q", original, 32)[0]
phnum = struct.unpack_from("<H", original, 56)[0]
headers = [phoff + index * 56 for index in range(phnum)]
for name, kind, flag in (("bad-stack", 0x6474e551, 1), ("bad-wx", 1, 2)):
    eligible = [offset for offset in headers if struct.unpack_from("<I", original, offset)[0] == kind
                and (kind != 1 or struct.unpack_from("<I", original, offset + 4)[0] & 1)]
    assert eligible
    result = bytearray(original)
    flags = struct.unpack_from("<I", result, eligible[0] + 4)[0]
    struct.pack_into("<I", result, eligible[0] + 4, flags | flag)
    (root / name).write_bytes(result)
    (root / name).chmod(0o755)
source = (root / "usr/lib/rejected-source.so").read_bytes()
phoff = struct.unpack_from("<Q", source, 32)[0]
phnum = struct.unpack_from("<H", source, 56)[0]
headers = [phoff + index * 56 for index in range(phnum)]
for name, kind, flag in (("rejected-stack.so", 0x6474e551, 1),
                         ("rejected-wx.so", 1, 2), ("rejected-relro.so", 0x6474e552, 0)):
    eligible = [offset for offset in headers if struct.unpack_from("<I", source, offset)[0] == kind
                and (kind != 1 or struct.unpack_from("<I", source, offset + 4)[0] & 1)]
    assert len(eligible) == 1
    result = bytearray(source)
    if flag:
        flags = struct.unpack_from("<I", result, eligible[0] + 4)[0]
        struct.pack_into("<I", result, eligible[0] + 4, flags | flag)
    else:
        struct.pack_into("<I", result, eligible[0], 0)
    (root / "usr/lib" / name).write_bytes(result)
PYTHON
timeout 20 chroot "$image" /pie
timeout 20 chroot "$image" /alias
timeout 20 chroot "$image" /relro
timeout 20 chroot "$image" /static-relro
static_status=0
timeout 20 chroot "$image" /static-alias || static_status=$?
if [ "$static_status" -eq 4 ]; then
    printf 'selected static data byte has no executable file-page alias\n'
else
    [ "$static_status" -eq 0 ]
fi
test -f "$image/marker"
rm "$image/marker"
for case in nonpie bad-stack bad-wx; do
    status=0
    timeout 20 chroot "$image" "/$case" >"$work/$case.stdout" 2>"$work/$case.stderr" || status=$?
    [ "$status" -eq 127 ]
    test ! -e "$image/marker"
done
printf 'hardened kernel entry: PASS; evidence: %s\n' "$work"
