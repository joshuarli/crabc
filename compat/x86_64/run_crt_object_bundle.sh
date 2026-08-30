#!/usr/bin/env bash
# Native Linux/x86-64 provenance for the private five-object Rust CRT bundle.
# This stages no sysroot, headers, libraries, compiler helpers, loader, or
# compiler driver.  It is deliberately not an application-linking interface.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    printf 'ERROR: x86 CRT object bundle: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in python3 rustup; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
if command -v llvm-objdump >/dev/null 2>&1; then
    objdump=llvm-objdump
else
    rustc_path="$(rustup run nightly-2026-07-24 rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-musl/bin/llvm-objdump"
    [ -x "$rustc_path" ] || fail "requires the pinned llvm-objdump component"
    objdump="$rustc_path"
fi

cd "$ROOT_DIR"
python3 crt/build_x86_64_bundle.py --llvm-objdump "$objdump" >/dev/null
manifest="$ROOT_DIR/target/crt-x86_64-object-bundle/manifest.json"
[ -f "$manifest" ] || fail "bundle manifest was not staged"
python3 - "$manifest" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
objects = manifest.get("objects", {})
expected = ("crt1.o", "Scrt1.o", "rcrt1.o", "crti.o", "crtn.o")
if set(objects) != set(expected) or len(objects) != len(expected):
    raise SystemExit("bundle manifest does not retain exactly five CRT objects")
if manifest.get("proof", {}).get("no_ambient_crt_or_compiler_runtime_input") is not True:
    raise SystemExit("bundle manifest does not prove producer closure")
for name in expected:
    if not (manifest_path.parent / objects[name]["path"]).is_file():
        raise SystemExit(f"bundle object is absent: {name}")
PY
printf '%s\n' 'x86 CRT object-bundle provenance: PASS (five Rust objects; two clean builds; not a sysroot)'
