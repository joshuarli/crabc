#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -eq 3 ] || exit 2
readonly installed="$1"
readonly static="$2"
readonly compatibility="$3"
case "${TMPDIR:-}" in "$root"/.work/*) ;; *) exit 2;; esac
readonly work="$(mktemp -d "$TMPDIR/hardened-entry.XXXXXX")"
readonly image="$work/root"
mkdir -p "$image/lib" "$image/usr/lib" "$image/plugins"
cp "$installed/lib/ld-crabc-x86_64-hardened.so.1" "$image/lib/"
cp "$installed/usr/lib/libc.so" "$image/usr/lib/"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/pie"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_alias_probe.c" -o "$image/alias"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "$root/compat/x86_64/hardened_relro_dso.c" -o "$image/usr/lib/hardened-relro-fixture.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object -DCRABC_BAD_DSO "$root/compat/x86_64/hardened_relro_dso.c" -o "$image/usr/lib/rejected-source.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "$root/compat/x86_64/hardened_tls_failure_dso.c" -o "$image/usr/lib/tls-fault.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-shared-object "$root/compat/x86_64/hardened_relro_dso.c" -o "$image/plugins/relative-only.so"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie --application-dso "$image/usr/lib/rejected-source.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/dependency"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie --application-dso "$image/plugins/relative-only.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/search-env"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie --application-runpath plugins --application-dso "$image/plugins/relative-only.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/search-relative"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie --application-runpath '$ORIGIN/plugins' --application-dso "$image/plugins/relative-only.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$image/search-origin"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_DSO_PROBE "$root/compat/x86_64/hardened_relro_probe.c" -o "$image/relro"
"$installed/bin/crabc-cc-dynamic" --dynamic-pie -DCRABC_HARDENED_PROBE "$root/compat/x86_64/installed_crt_startup_probe.c" -o "$image/startup"
"$static/bin/crabc-cc" "$root/compat/x86_64/hardened_alias_probe.c" -o "$image/static-alias"
"$static/bin/crabc-cc" "$root/compat/x86_64/hardened_relro_probe.c" -o "$image/static-relro"
"$static/bin/crabc-cc" -DCRABC_HARDENED_PROBE "$root/compat/x86_64/installed_crt_startup_probe.c" -o "$image/static-startup"
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
CRABC_STARTUP=yes timeout 20 chroot "$image" /startup owned >"$work/startup.stdout"
CRABC_STARTUP=yes timeout 20 chroot "$image" /lib/ld-crabc-x86_64-hardened.so.1 /startup owned >"$work/startup-direct.stdout"
CRABC_STARTUP=yes timeout 20 chroot "$image" /static-startup static >"$work/static-startup.stdout"
[ "$(cat "$work/startup.stdout")" = ICOMAFL ]
[ "$(cat "$work/startup-direct.stdout")" = ICOMAFL ]
[ "$(cat "$work/static-startup.stdout")" = PICSMAFL ]
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
    status=0
    timeout 20 chroot "$image" /lib/ld-crabc-x86_64-hardened.so.1 "/$case" >"$work/$case-direct.stdout" 2>"$work/$case-direct.stderr" || status=$?
    [ "$status" -eq 1 ]
    test ! -e "$image/marker"
done
readonly compatible_root="$work/compatibility"
mkdir -p "$compatible_root/lib" "$compatible_root/usr/lib" "$compatible_root/plugins"
cp "$compatibility/lib/ld-crabc-x86_64.so.1" "$compatible_root/lib/"
cp "$compatibility/usr/lib/libc.so" "$compatible_root/usr/lib/"
cp "$image/usr/lib/rejected-stack.so" "$compatible_root/usr/lib/"
cp "$image/plugins/relative-only.so" "$compatible_root/plugins/"
"$compatibility/bin/crabc-cc-dynamic" --dynamic-pie "$root/compat/x86_64/hardened_entry_probe.c" -o "$compatible_root/pie"
"$compatibility/bin/crabc-cc-dynamic" --dynamic-pie --application-runpath plugins --application-dso "$compatible_root/plugins/relative-only.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$compatible_root/search-relative"
"$compatibility/bin/crabc-cc-dynamic" --dynamic-pie --application-dso "$compatible_root/plugins/relative-only.so" "$root/compat/x86_64/hardened_entry_probe.c" -o "$compatible_root/search-env"
python3 -B - "$image" "$work" "$compatible_root" <<'PYTHON'
from pathlib import Path
import os
import shutil
import struct
import subprocess
import sys

root, work, compatible = map(Path, sys.argv[1:])
def pathname_dependencies(directory):
    original = (directory / "search-env").read_bytes()
    phoff = struct.unpack_from("<Q", original, 32)[0]
    phnum = struct.unpack_from("<H", original, 56)[0]
    headers = [struct.unpack_from("<IIQQQQQQ", original, phoff + index * 56) for index in range(phnum)]
    dynamic = next(header for header in headers if header[0] == 2)
    entries = [struct.unpack_from("<QQ", original, offset)
               for offset in range(dynamic[2], dynamic[2] + dynamic[5], 16)]
    string_address = next(value for tag, value in entries if tag == 5)
    strings = next(header[2] + string_address - header[3] for header in headers
                   if header[0] == 1 and header[3] <= string_address < header[3] + header[5])
    name = b"relative-only.so\0"
    offsets = [strings + value for tag, value in entries if tag == 1
               and original[strings + value:strings + value + len(name)] == name]
    assert len(offsets) == 1
    shutil.copyfile(directory / "plugins/relative-only.so", directory / "plugins/x.so")
    for filename, value in (("needed-relative", b"plugins/x.so\0"), ("needed-absolute", b"/plugins/x.so\0")):
        result = bytearray(original)
        result[offsets[0]:offsets[0] + len(name)] = value.ljust(len(name), b"\0")
        (directory / filename).write_bytes(result)
        (directory / filename).chmod(0o755)

pathname_dependencies(root)
pathname_dependencies(compatible)
def enter(directory=root):
    os.chroot(directory)
    os.chdir("/")

for name in ("rejected-source.so", "rejected-stack.so", "rejected-wx.so", "rejected-relro.so"):
    result = subprocess.run(["/pie"], env={"LD_PRELOAD": "/usr/lib/" + name},
                            preexec_fn=enter, capture_output=True, timeout=20, check=False)
    (work / (name + ".stderr")).write_bytes(result.stderr)
    good = name == "rejected-source.so"
    assert result.returncode == (0 if good else 127), (name, result.returncode, result.stderr)
    assert (root / "marker").exists() == good
    assert (root / "rejected-marker").exists() == good
    (root / "marker").unlink(missing_ok=True)
    (root / "rejected-marker").unlink(missing_ok=True)
for preload, status, marker in (("/usr/lib/missing.so", 0, True), ("usr/lib/rejected-source.so", 127, False)):
    result = subprocess.run(["/pie"], env={"LD_PRELOAD": preload},
                            preexec_fn=enter, capture_output=True, timeout=20, check=False)
    assert result.returncode == status, (preload, result.returncode, result.stderr)
    assert (root / "marker").exists() == marker
    assert not (root / "rejected-marker").exists()
    (root / "marker").unlink(missing_ok=True)
source = root / "usr/lib/rejected-source.so"
original = source.read_bytes()
for candidate in (None, "rejected-stack.so", "rejected-wx.so", "rejected-relro.so"):
    source.write_bytes(original if candidate is None else (root / "usr/lib" / candidate).read_bytes())
    result = subprocess.run(["/dependency"], env={}, preexec_fn=enter, capture_output=True, timeout=20, check=False)
    good = candidate is None
    assert result.returncode == (0 if good else 127), (candidate, result.returncode, result.stderr)
    assert (root / "marker").exists() == good
    assert (root / "rejected-marker").exists() == good
    (root / "marker").unlink(missing_ok=True)
    (root / "rejected-marker").unlink(missing_ok=True)
source.write_bytes(original)
loader = "/lib/ld-crabc-x86_64-hardened.so.1"
searches = (
    (["/search-env"], {"LD_LIBRARY_PATH": "plugins"}, 127),
    (["/search-env"], {"LD_LIBRARY_PATH": "/plugins"}, 0),
    (["/search-relative"], {}, 127),
    ([loader, "--library-path", "plugins", "/search-env"], {}, 127),
    ([loader, "--library-path", "/plugins", "/search-env"], {}, 0),
    ([loader, "search-origin"], {}, 127),
    ([loader, "/search-origin"], {}, 0),
    (["/needed-relative"], {}, 127),
    (["/needed-absolute"], {}, 0),
)
for arguments, environment, status in searches:
    result = subprocess.run(arguments, env=environment, preexec_fn=enter, capture_output=True, timeout=20, check=False)
    assert result.returncode == status, (arguments, result.returncode, result.stderr)
    assert (root / "marker").exists() == (status == 0)
    (root / "marker").unlink(missing_ok=True)
for paths, status in (("plugins", 127), ("/plugins", 0)):
    (root / "etc").mkdir(exist_ok=True)
    (root / "etc/ld-musl-x86_64.path").write_text(paths)
    result = subprocess.run(["/search-env"], env={}, preexec_fn=enter, capture_output=True, timeout=20, check=False)
    assert result.returncode == status, (paths, result.returncode, result.stderr)
    assert (root / "marker").exists() == (status == 0)
    (root / "marker").unlink(missing_ok=True)
(root / "etc/ld-musl-x86_64.path").unlink()
result = subprocess.run(["/pie"], env={"LD_PRELOAD": "/usr/lib/rejected-stack.so"},
                        preexec_fn=lambda: enter(compatible), capture_output=True, timeout=20, check=False)
assert result.returncode == 0, result.stderr
assert (compatible / "marker").exists() and (compatible / "rejected-marker").exists()
(compatible / "marker").unlink()
result = subprocess.run(["/search-relative"], env={}, preexec_fn=lambda: enter(compatible),
                        capture_output=True, timeout=20, check=False)
assert result.returncode == 0 and (compatible / "marker").exists(), result.stderr
(compatible / "marker").unlink()
(compatible / "etc").mkdir(exist_ok=True)
(compatible / "etc/ld-musl-x86_64.path").write_text("plugins")
result = subprocess.run(["/search-env"], env={}, preexec_fn=lambda: enter(compatible),
                        capture_output=True, timeout=20, check=False)
assert result.returncode == 0 and (compatible / "marker").exists(), result.stderr
(compatible / "marker").unlink()
result = subprocess.run(["/needed-relative"], env={}, preexec_fn=lambda: enter(compatible),
                        capture_output=True, timeout=20, check=False)
assert result.returncode == 0 and (compatible / "marker").exists(), result.stderr
PYTHON
printf 'hardened kernel entry: PASS; evidence: %s\n' "$work"
