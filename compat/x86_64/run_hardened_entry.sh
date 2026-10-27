#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 1 ] || exit 2
readonly installed="$1"
case "${TMPDIR:-}" in "$root"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/hardened-entry.XXXXXX")"
readonly image="$work/root"
mkdir -p "$image/lib" "$image/usr/lib"
cp "$installed/lib/ld-crabc-x86_64-hardened.so.1" "$image/lib/"
cp "$installed/usr/lib/libc.so" "$image/usr/lib/"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/pie"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_alias_probe.c" -o "$image/alias"
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
PYTHON
timeout 20 chroot "$image" /pie
timeout 20 chroot "$image" /alias
test -f "$image/marker"
rm "$image/marker"
for case in nonpie bad-stack bad-wx; do
    status=0
    timeout 20 chroot "$image" "/$case" >"$work/$case.stdout" 2>"$work/$case.stderr" || status=$?
    [ "$status" -eq 127 ]
    test ! -e "$image/marker"
done
printf 'hardened kernel entry: PASS; evidence: %s\n' "$work"
