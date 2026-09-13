#!/usr/bin/env bash
# Bounded installed shared-libc placement proof for the owned helper archive.
#
# It accepts a supplied materialized dynamic product or builds one. The
# installed archive remains an ordinary GLOBAL DEFAULT provider for executable
# and application-DSO consumers; only the exact copy pulled into libc.so is
# local. The raw commands, source seal and installed artifacts remain below the
# caller-selected checkout-local work directory for host inspection.
set -euo pipefail
umask 002

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly WORK_DIR_REQUEST="${CRABC_COMPILER_HELPER_SHARED_WORK_DIR:-${ROOT_DIR}/.work/x86_64/compiler-helper-shared-placement}"
readonly IMAGE_ID="${CRABC_X86_COMPILER_HELPER_IMAGE:-}"
readonly READER="$ROOT_DIR/compat/x86_64/compiler_helper_evidence.py"
readonly BUILDER="$ROOT_DIR/scripts/build_x86_64_owned_dynamic_sysroot.py"
readonly DIRECT="$ROOT_DIR/builtins/fixtures/x86_64_compiler_helper_shared_direct.c"
readonly DSO="$ROOT_DIR/builtins/fixtures/x86_64_compiler_helper_shared_dso.c"
readonly DSO_CONSUMER="$ROOT_DIR/builtins/fixtures/x86_64_compiler_helper_shared_dso_consumer.c"
readonly INTERPOSE="$ROOT_DIR/builtins/fixtures/x86_64_compiler_helper_shared_interpose.c"

fail() { printf 'ERROR: native compiler-helper shared placement: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$#" -le 1 ] || fail "usage: $0 [ABSOLUTE_DYNAMIC_PRODUCT]"
readonly SUPPLIED_PRODUCT="${1:-}"
if [ -n "$SUPPLIED_PRODUCT" ]; then
    [[ "$SUPPLIED_PRODUCT" = /* ]] || fail "supplied dynamic product must use an absolute path"
fi
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)";; esac
[[ "$IMAGE_ID" =~ ^crabc-core-evidence@sha256:[0-9a-f]{64}$ ]] || fail "missing pinned image identity"
for tool in chroot nm objdump python3 readelf sha256sum timeout; do require_tool "$tool"; done
for input in "$READER" "$BUILDER" "$DIRECT" "$DSO" "$DSO_CONSUMER" "$INTERPOSE"; do
    [ -f "$input" ] || fail "missing input $input"
done
WORK_DIR="$(python3 -B "$READER" validate-work-dir --root "$ROOT_DIR" --work "$WORK_DIR_REQUEST")"
[ ! -e "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ] || fail "work directory must be fresh: $WORK_DIR"
mkdir -p "$WORK_DIR/raw"
readonly WORK_DIR

record() {
    local label="$1"
    shift
    local status
    printf '%q ' "$@" >"$WORK_DIR/raw/$label.argv"
    printf '\n' >>"$WORK_DIR/raw/$label.argv"
    set +e
    "$@" >"$WORK_DIR/raw/$label.stdout" 2>"$WORK_DIR/raw/$label.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK_DIR/raw/$label.status"
    return "$status"
}

python3 -B "$READER" capture-source --output "$WORK_DIR/source-before.json" >/dev/null
if [ -n "$SUPPLIED_PRODUCT" ]; then
    readonly PRODUCT="$SUPPLIED_PRODUCT"
else
    record product-build python3 -B "$BUILDER" --output "$WORK_DIR/product"
    readonly PRODUCT="$WORK_DIR/product"
fi

readonly LIBRARY="$PRODUCT/usr/lib"
readonly LIBC="$LIBRARY/libc.so"
readonly ARCHIVE="$LIBRARY/libcrabc-builtins.a"
readonly LOADER="$PRODUCT/lib/ld-crabc-x86_64.so.1"
readonly DRIVER="$PRODUCT/bin/crabc-cc-dynamic"
for artifact in "$LIBC" "$ARCHIVE" "$LOADER" "$DRIVER"; do [ -f "$artifact" ] || fail "missing installed artifact $artifact"; done
record product-admission-before python3 -B "$READER" validate-materialized-product --root "$ROOT_DIR" --product "$PRODUCT"

record archive-symbols nm --defined-only --extern-only "$ARCHIVE"
record libc-dynsym readelf --dyn-syms -W "$LIBC"
record libc-symtab readelf --symbols -W "$LIBC"
record libc-undefined nm --undefined-only "$LIBC"
record loader-undefined nm --undefined-only "$LOADER"
record libc-bitmap-caller objdump --disassemble=mi_bbitmap_try_find_and_clearNC "$LIBC"
python3 - "$ROOT_DIR/builtins/x86_64-helper-contract.toml" \
    "$PRODUCT/share/crabc/builtins.provenance.json" "$PRODUCT/share/crabc/libc-shared.provenance.json" \
    "$ARCHIVE" "$WORK_DIR/raw/archive-symbols.stdout" "$WORK_DIR/raw/libc-dynsym.stdout" \
    "$WORK_DIR/raw/libc-symtab.stdout" "$WORK_DIR/raw/libc-undefined.stdout" \
    "$WORK_DIR/raw/loader-undefined.stdout" "$WORK_DIR/raw/libc-bitmap-caller.stdout" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

(contract_path, archive_provenance_path, libc_provenance_path, archive_path, archive_symbols_path,
 dynsym_path, symtab_path, libc_undefined_path, loader_undefined_path, caller_path) = map(Path, sys.argv[1:])
contract = tomllib.loads(contract_path.read_text(encoding='utf-8'))
names = [row['name'] for row in contract['helpers']]
expected = set(names)
policy = contract['shared_libc']
archive_contract = json.loads(json.dumps(contract))
for helper in archive_contract['helpers']:
    helper['metadata']['version'] = None
archive_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
archive_provenance = json.loads(archive_provenance_path.read_text(encoding='utf-8'))
libc_provenance = json.loads(libc_provenance_path.read_text(encoding='utf-8'))
if archive_provenance['archive']['archive_sha256'] != archive_sha or archive_provenance['archive']['contract'] != archive_contract:
    raise SystemExit('installed archive provenance does not bind this exact helper contract and bytes')
expected_policy = {
    'source': libc_provenance.get('shared_compiler_helper_archive', {}).get('source'),
    'archive': 'libcrabc-builtins.a', 'member': 'crabc-builtins.o', **policy,
}
if libc_provenance.get('shared_compiler_helper_archive') != expected_policy:
    raise SystemExit('installed libc provenance helper placement differs')
if policy['linker_option'] not in libc_provenance.get('libc_shared_link_command', []):
    raise SystemExit('installed libc link command omits exact helper localization')
defined = {line.split()[-1] for line in archive_symbols_path.read_text(encoding='utf-8').splitlines()
           if len(line.split()) >= 2 and not line.endswith(':')}
if defined != expected:
    raise SystemExit('installed archive definition roster differs')
def rows(path):
    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(':'):
            result.append(fields)
    return result
if any(row[-1] in expected for row in rows(dynsym_path)):
    raise SystemExit('private libc helper copy leaked into dynsym')
local = [row for row in rows(symtab_path) if row[-1] in expected]
if (len(local) != len(expected) or {row[-1] for row in local} != expected
        or any(row[3:6] != ['FUNC', 'LOCAL', 'DEFAULT'] or row[6] in {'UND', 'ABS'} for row in local)):
    raise SystemExit('private libc helper symtab rows differ')
for path, label in ((libc_undefined_path, 'libc'), (loader_undefined_path, 'loader')):
    if any(line.split() and line.split()[-1] in expected for line in path.read_text(encoding='utf-8').splitlines()):
        raise SystemExit(label + ' has an unexpected helper import')
caller = caller_path.read_text(encoding='utf-8', errors='replace')
if re.search(r'call\S*\s+[^\n]*<__popcountdi2>', caller) is None:
    raise SystemExit('allocator bitmap caller does not retain its direct local __popcountdi2 transfer')
PY

record direct-link "$DRIVER" --dynamic-pie "$DIRECT" -o "$WORK_DIR/direct"
record dso-link "$DRIVER" --dynamic-shared-object "$DSO" -o "$WORK_DIR/libhelper.so"
record dso-consumer-link "$DRIVER" --dynamic-pie "$DSO_CONSUMER" \
    --application-dso "$WORK_DIR/libhelper.so" -o "$WORK_DIR/dso-consumer"
record interpose-link "$DRIVER" --dynamic-pie -rdynamic "$INTERPOSE" -o "$WORK_DIR/interpose"
record direct-symtab readelf --symbols -W "$WORK_DIR/direct"
record dso-symbols readelf --dyn-syms -W "$WORK_DIR/libhelper.so"
record interpose-symbols readelf --dyn-syms -W "$WORK_DIR/interpose"
python3 - "$ARCHIVE" "$WORK_DIR/direct.crabc-link.json" "$WORK_DIR/libhelper.so.crabc-link.json" \
    "$WORK_DIR/raw/direct-symtab.stdout" "$WORK_DIR/raw/dso-symbols.stdout" \
    "$WORK_DIR/raw/interpose-symbols.stdout" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

archive, direct_receipt, dso_receipt, direct_symbols, dso_symbols, interpose_symbols = map(Path, sys.argv[1:])
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
for receipt_path in (direct_receipt, dso_receipt):
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    if 'usr/lib/libcrabc-builtins.a' not in receipt.get('owned_runtime_inputs', []):
        raise SystemExit('installed dynamic driver omitted the helper archive role')
    if not any('libcrabc-builtins.a(crabc-builtins.o)' in line for line in receipt.get('link_trace', [])):
        raise SystemExit('installed dynamic driver did not extract the helper member')
    if not any(item.get('sha256') == digest and str(item.get('path', '')).endswith('/usr/lib/libcrabc-builtins.a')
               for item in receipt.get('input_receipts', [])):
        raise SystemExit('installed dynamic driver receipt does not bind the helper archive bytes')
def defines(path, name):
    return any(line.split()[3:6] == ['FUNC', 'GLOBAL', 'DEFAULT'] and line.split()[-1] == name
               for line in path.read_text(encoding='utf-8').splitlines() if len(line.split()) >= 8 and line.split()[0].endswith(':'))
if not defines(direct_symbols, '__popcountdi2') or not defines(dso_symbols, '__popcountdi2'):
    raise SystemExit('ordinary executable or application DSO did not receive its helper from the archive')
if not defines(interpose_symbols, '__popcountdi2'):
    raise SystemExit('interposition executable does not expose its strong helper definition')
PY

readonly EXECUTION_ROOT="$WORK_DIR/execution-root"
[ ! -e "$EXECUTION_ROOT" ] && [ ! -L "$EXECUTION_ROOT" ] || fail "execution root must be fresh: $EXECUTION_ROOT"
cp -a "$PRODUCT" "$EXECUTION_ROOT"
cp "$WORK_DIR/libhelper.so" "$EXECUTION_ROOT/usr/lib/libhelper.so"
cp "$WORK_DIR/direct" "$EXECUTION_ROOT/direct"
cp "$WORK_DIR/dso-consumer" "$EXECUTION_ROOT/dso-consumer"
cp "$WORK_DIR/interpose" "$EXECUTION_ROOT/interpose"
record direct-execute timeout 20 chroot "$EXECUTION_ROOT" /direct
record dso-execute timeout 20 chroot "$EXECUTION_ROOT" /dso-consumer
record interpose-execute timeout 20 chroot "$EXECUTION_ROOT" /interpose
record product-admission-after python3 -B "$READER" validate-materialized-product --root "$ROOT_DIR" --product "$PRODUCT"
record product-admission-unchanged cmp -s "$WORK_DIR/raw/product-admission-before.stdout" "$WORK_DIR/raw/product-admission-after.stdout"
python3 -B "$READER" validate-source-seal "$WORK_DIR/source-before.json" >/dev/null
sha256sum "$ARCHIVE" "$LIBC" "$LOADER" "$WORK_DIR/direct" "$WORK_DIR/libhelper.so" \
    "$WORK_DIR/dso-consumer" "$WORK_DIR/interpose" >"$WORK_DIR/artifacts.sha256"
printf 'native x86 compiler-helper shared placement: PASS (%s)\n' "$WORK_DIR"
