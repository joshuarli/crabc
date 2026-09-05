#!/usr/bin/env bash
# Exercise the installed dynamic driver's bounded source-local input surface.
#
# This is a development-product boundary test. Unlike the libc-test leaf, an
# omitted product argument intentionally builds one fresh private product so a
# reviewed driver change can be exercised before it is used by an aggregate.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly oracle_cc=/usr/local/bin/crabc-x86_64-musl-gcc

usage() {
    printf 'usage: %s [DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

case "$#" in
    0) supplied_product='' ;;
    1)
        [ -n "$1" ] || usage
        case "$1" in -*) usage ;; esac
        supplied_product="$(realpath -e "$1")"
        ;;
    *) usage ;;
esac

[ "$(uname -sm)" = 'Linux x86_64' ]
python3 -B - "$ROOT" "${TMPDIR:-}" "$supplied_product" <<'PY'
from pathlib import Path
import sys

root, temporary = map(Path, sys.argv[1:3])
supplied_text = sys.argv[3]
if not temporary.is_dir() or temporary.resolve() != temporary or not temporary.is_relative_to(root / ".work"):
    raise SystemExit("dynamic driver source-input TMPDIR must be a physical checkout .work directory")
if supplied_text:
    supplied = Path(supplied_text)
    if not supplied.is_dir() or not supplied.is_relative_to(root / ".work"):
        raise SystemExit("dynamic driver source-input product must be a checkout .work directory")
PY

readonly work="$(mktemp -d "$TMPDIR/owned-dynamic-driver-source-inputs.XXXXXX")"
chmod a+rx "$work"
printf 'owned dynamic driver source inputs evidence: %s\n' "$work"

if [ -n "$supplied_product" ]; then
    readonly product="$supplied_product"
else
    readonly product="$work/installed"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$product" \
        >"$work/dynamic-product-build.json"
fi
readonly driver="$product/bin/crabc-cc-dynamic"

source_root="$work/source"
include_root="$source_root/quoted"
mkdir -p "$include_root"
cat >"$include_root/local.h" <<'HEADER'
#define OWNED_DRIVER_LOCAL_VALUE 41
HEADER
cat >"$include_root/stdio.h" <<'HEADER'
#error counterfeit angle header was selected
HEADER
cat >"$source_root/rounding.c" <<'SOURCE'
#pragma STDC FENV_ACCESS ON
#include "local.h"
#include <stdio.h>
#include <fenv.h>

int main(void)
{
	if (OWNED_DRIVER_LOCAL_VALUE != 41)
		return 10;
	if (fesetround(FE_UPWARD))
		return 11;
	/* GCC may constant-fold this to 1.0 without -frounding-math. */
	return (1.0 + 0x1p-53) == 1.0;
}
SOURCE

"$driver" --dynamic-pie --application-quote-include-dir "$include_root" \
    -frounding-math -O2 -std=c11 -c "$source_root/rounding.c" -o "$work/rounding.o"
[ -s "$work/rounding.o" ]
readelf -hW "$work/rounding.o" >"$work/rounding.object-header"
grep -Eq 'Type:[[:space:]]+REL' "$work/rounding.object-header"

# The installed driver owns target translation. The separately linked musl
# executable is solely the pinned runtime oracle for the resulting object, so
# the dynamic-rounding outcome demonstrates that the admitted flag reached GCC
# without claiming an ambient target compiler input.
"$oracle_cc" -fPIE -pie -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
    "$work/rounding.o" -o "$work/rounding-oracle"
oracle_root="$work/oracle-root"
mkdir -p "$oracle_root/lib" "$oracle_root/usr/lib"
cp -L --preserve=mode /opt/musl-1.2.6/lib/libc.so "$oracle_root/lib/ld-musl-x86_64.so.1"
cp -L --preserve=mode /opt/musl-1.2.6/lib/libc.so "$oracle_root/usr/lib/libc.so"
cp -L --preserve=mode "$work/rounding-oracle" "$oracle_root/rounding"
timeout 20 chroot "$oracle_root" /rounding >"$work/rounding.stdout" 2>"$work/rounding.stderr"
[ ! -s "$work/rounding.stdout" ]
[ ! -s "$work/rounding.stderr" ]

cat >"$source_root/export-main.c" <<'SOURCE'
#include <dlfcn.h>
#include <stdio.h>

int owned_driver_exported_main_value = 17;

int main(void)
{
	void *handle = dlopen(0, RTLD_NOW);
	int *value;
	if (!handle)
		return 20;
	value = dlsym(handle, "owned_driver_exported_main_value");
	if (value != &owned_driver_exported_main_value || *value != 17)
		return 21;
	puts("owned-dynamic-driver-export-ok");
	return 0;
}
SOURCE
"$driver" --dynamic-pie -rdynamic -std=c11 "$source_root/export-main.c" \
    -o "$work/export-main"
readelf --dyn-syms -W "$work/export-main" >"$work/export-main.dynsym"
awk '$5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "owned_driver_exported_main_value" { found = 1 }
     END { exit !found }' "$work/export-main.dynsym"

python3 -B - "$work/export-main.crabc-link.json" "$work/export-main" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

receipt_path, executable_path = map(Path, sys.argv[1:])
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
if receipt.get("schema") != 1 or receipt.get("format") != "crabc-x86-64-owned-dynamic-sysroot-v1":
    raise SystemExit("dynamic driver export receipt identity drifted")
if receipt.get("output_path") != str(executable_path.resolve()):
    raise SystemExit("dynamic driver export receipt output path drifted")
if receipt.get("output_sha256") != hashlib.sha256(executable_path.read_bytes()).hexdigest():
    raise SystemExit("dynamic driver export receipt output hash drifted")
command = receipt.get("link_command")
if not isinstance(command, list) or command.count("--export-dynamic") != 1:
    raise SystemExit("dynamic driver export receipt does not bind exactly one export flag")
PY

candidate_root="$work/candidate-root"
cp -a "$product" "$candidate_root"
cp -L --preserve=mode "$work/export-main" "$candidate_root/export-main"
timeout 20 chroot "$candidate_root" /export-main >"$work/export-main.stdout" 2>"$work/export-main.stderr"
printf 'owned-dynamic-driver-export-ok\n' >"$work/export-main.expected"
cmp "$work/export-main.expected" "$work/export-main.stdout"
[ ! -s "$work/export-main.stderr" ]

python3 -B - "$work/driver-source-inputs.json" "$product" "$work" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

record_path, product, work = map(Path, sys.argv[1:])
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
record = {
    "schema": "crabc.x86_64-owned-dynamic-driver-source-inputs/v1",
    "status": "passed",
    "campaign_complete": False,
    "public_support": False,
    "product": str(product),
    "product_manifest_sha256": digest(product / "share/crabc/manifest.json"),
    "driver": {"path": str(product / "bin/crabc-cc-dynamic"), "sha256": digest(product / "bin/crabc-cc-dynamic")},
    "checks": {
        "quoted_local_header": {"source": "source/rounding.c", "quoted_directory": "source/quoted", "object_sha256": digest(work / "rounding.o")},
        "angle_header_authority": "counterfeit source/quoted/stdio.h was not selected",
        "rounding_math": {"oracle": "rounding-oracle", "stdout_sha256": digest(work / "rounding.stdout")},
        "rdynamic": {"consumer": "export-main", "receipt": "export-main.crabc-link.json", "stdout_sha256": digest(work / "export-main.stdout")},
    },
}
record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

printf 'owned dynamic driver source inputs: PASS; evidence: %s\n' "$work"
