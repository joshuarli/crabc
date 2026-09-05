#!/usr/bin/env bash
# Prove that admitted GCC debug information stays linkable by the pinned LLD.
#
# The installed static helper owns this rule for both driver forms: `-g`
# retains DWARF but forces GCC's uncompressed representation.  This runner
# builds fresh private products, links a dynamic helper DSO and a static
# executable, and retains the ELF observations rather than treating debug
# stripping as a workaround.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly STATIC_BUILDER="$ROOT/scripts/build_x86_64_owned_sysroot.py"
readonly DYNAMIC_BUILDER="$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py"

fail() { printf 'owned driver debug information: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail 'requires Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
[ "$(id -u)" -eq 0 ] || fail 'requires the pinned root-capable evidence container'
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail 'requires repository-local TMPDIR'
python3 -B - "$ROOT" "$TMPDIR" <<'PY'
from pathlib import Path
import sys
root, temporary = map(lambda value: Path(value).resolve(), sys.argv[1:])
if not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned driver debug information: TMPDIR must remain below checkout .work')
PY

work="$(mktemp -d "$TMPDIR/owned-driver-debug-information.XXXXXX")"
chmod a+rx "$work"
printf 'owned driver debug information evidence: %s\n' "$work"

python3 -B "$STATIC_BUILDER" --output "$work/static-product" >"$work/static-product-build.json"
python3 -B "$DYNAMIC_BUILDER" --output "$work/dynamic-product" >"$work/dynamic-product-build.json"

cat >"$work/dso.c" <<'SOURCE'
int owned_debug_dso_value(void)
{
	return 17;
}
SOURCE
cat >"$work/static-main.c" <<'SOURCE'
int main(void)
{
	return 0;
}
SOURCE

# The dynamic DSO is the direct regression for the linker failure that
# motivated this contract.  The static executable proves the shared helper
# preserves the same source-translation representation in its other caller.
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-shared-object -g -c \
    "$work/dso.c" -o "$work/dynamic-debug.o"
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-shared-object \
    "$work/dynamic-debug.o" -o "$work/dynamic-debug.so"
"$work/static-product/bin/crabc-cc" --static-et-exec -g -c \
    "$work/static-main.c" -o "$work/static-debug.o"
"$work/static-product/bin/crabc-cc" --static-et-exec \
    "$work/static-debug.o" -o "$work/static-debug"
"$work/static-debug"

# No-debug invocation remains the ordinary compiler command shape: it has no
# DWARF sections and no injected compression policy.
"$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-shared-object -c \
    "$work/dso.c" -o "$work/dynamic-plain.o"

# An explicit request to compress DWARF is a clear source-build rejection, not
# an implicit override.  Capture the exact driver diagnostic in the evidence.
if "$work/dynamic-product/bin/crabc-cc-dynamic" --dynamic-shared-object -g -gz=zlib -c \
    "$work/dso.c" -o "$work/rejected.o" >"$work/rejected.stdout" 2>"$work/rejected.stderr"; then
    fail 'dynamic driver accepted compressed debug data'
fi
grep -Fq 'compressed debug data is unsupported' "$work/rejected.stderr" ||
    fail 'compressed-debug rejection diagnostic drifted'

readelf -hW "$work/dynamic-debug.o" >"$work/dynamic-debug.object-header.txt"
readelf -SW "$work/dynamic-debug.o" >"$work/dynamic-debug.sections.txt"
readelf --debug-dump=info "$work/dynamic-debug.o" >"$work/dynamic-debug.info.txt"
readelf -hW "$work/dynamic-debug.so" >"$work/dynamic-debug.dso-header.txt"
readelf -SW "$work/dynamic-debug.so" >"$work/dynamic-debug.dso-sections.txt"
readelf -dW "$work/dynamic-debug.so" >"$work/dynamic-debug.dso-dynamic.txt"
readelf --debug-dump=info "$work/dynamic-debug.so" >"$work/dynamic-debug.dso-info.txt"
readelf -hW "$work/static-debug.o" >"$work/static-debug.object-header.txt"
readelf -SW "$work/static-debug.o" >"$work/static-debug.sections.txt"
readelf --debug-dump=info "$work/static-debug.o" >"$work/static-debug.info.txt"
readelf -hW "$work/static-debug" >"$work/static-debug.executable-header.txt"
readelf -SW "$work/static-debug" >"$work/static-debug.executable-sections.txt"
readelf --debug-dump=info "$work/static-debug" >"$work/static-debug.executable-info.txt"
readelf -SW "$work/dynamic-plain.o" >"$work/dynamic-plain.sections.txt"

python3 -B - "$work" <<'PY'
import json
from pathlib import Path
import struct
import sys

work = Path(sys.argv[1])

def sections(path):
    data = path.read_bytes()
    if data[:7] != b'\x7fELF\x02\x01\x01':
        raise SystemExit(f'not an ELF64 little-endian object: {path}')
    section_offset = struct.unpack_from('<Q', data, 40)[0]
    section_size = struct.unpack_from('<H', data, 58)[0]
    section_count = struct.unpack_from('<H', data, 60)[0]
    string_index = struct.unpack_from('<H', data, 62)[0]
    if section_size != 64 or section_count == 0:
        raise SystemExit(f'unexpected section table: {path}')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, section_offset + index * section_size)
               for index in range(section_count)]
    string_header = headers[string_index]
    strings = data[string_header[4]:string_header[4] + string_header[5]]
    output = []
    for name_offset, kind, flags, address, offset, size, link, info, align, entry_size in headers:
        end = strings.find(b'\0', name_offset)
        name = strings[name_offset:end].decode('ascii', errors='replace') if end >= 0 else ''
        output.append({'name': name, 'flags': flags, 'size': size})
    return output

def inspect(name, expect_debug):
    path = work / name
    observed = sections(path)
    debug = [section for section in observed if section['name'].startswith('.debug')]
    if bool(debug) != expect_debug:
        raise SystemExit(f'{name}: debug-section presence drifted')
    compressed = [section['name'] for section in debug if section['flags'] & 0x800]
    if compressed:
        raise SystemExit(f'{name}: compressed DWARF remained: {compressed}')
    return {'path': str(path), 'debug_sections': debug, 'compressed_debug_sections': compressed}

record = {
    'schema': 'crabc.x86_64-owned-driver-debug-information/v1',
    'status': 'passed',
    'campaign_complete': False,
    'public_support': False,
    'checks': {
        'dynamic_debug_object': inspect('dynamic-debug.o', True),
        'dynamic_debug_dso': inspect('dynamic-debug.so', True),
        'static_debug_object': inspect('static-debug.o', True),
        'static_debug_executable': inspect('static-debug', True),
        'dynamic_plain_object': inspect('dynamic-plain.o', False),
    },
    'outputs': {
        'dynamic_dso': str(work / 'dynamic-debug.so'),
        'static_executable': str(work / 'static-debug'),
        'compressed_rejection_stderr': str(work / 'rejected.stderr'),
    },
}
(work / 'driver-debug-information.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY

grep -Fq 'DW_TAG_compile_unit' "$work/dynamic-debug.info.txt" || fail 'dynamic debug object lost DWARF'
grep -Fq 'DW_TAG_compile_unit' "$work/dynamic-debug.dso-info.txt" || fail 'dynamic debug DSO lost DWARF'
grep -Fq 'DW_TAG_compile_unit' "$work/static-debug.info.txt" || fail 'static debug object lost DWARF'
grep -Fq 'DW_TAG_compile_unit' "$work/static-debug.executable-info.txt" || fail 'static debug executable lost DWARF'
grep -Eq 'Type:[[:space:]]+DYN' "$work/dynamic-debug.dso-header.txt" || fail 'dynamic debug DSO is not ET_DYN'
grep -Eq 'Type:[[:space:]]+EXEC' "$work/static-debug.executable-header.txt" || fail 'static debug executable is not ET_EXEC'
printf 'owned driver debug information: PASS; evidence: %s\n' "$work"
