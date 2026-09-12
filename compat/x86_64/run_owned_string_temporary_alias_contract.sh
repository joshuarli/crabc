#!/usr/bin/env bash
# Focused native proof for musl's string and temporary-object weak aliases.
#
# One project-header object is linked unchanged by pinned musl, the installed
# static/static-PIE products, and installed dynamic PIE/non-PIE products. The
# ELF checks distinguish a true `.set` alias from a forwarding Rust wrapper.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly MUSL_LIB="$MUSL_ROOT/lib/libc.so"
readonly MUSL_ARCHIVE="$MUSL_ROOT/lib/libc.a"
readonly MUSL_LOADER="$MUSL_ROOT/lib/ld-musl-x86_64.so.1"
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_string_temporary_alias_contract_probe.c"
readonly OVERRIDE_SOURCE="$ROOT/compat/x86_64/owned_string_temporary_alias_override_probe.c"
readonly READER_DIR="$ROOT/compat/x86_64"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly STATIC_BUILDER="$ROOT/scripts/build_x86_64_owned_sysroot.py"
readonly DYNAMIC_BUILDER="$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py"

usage() {
    printf 'usage: %s [STATIC_SYSROOT DYNAMIC_SYSROOT]\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned string/temporary alias contract: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 0 ] || [ "$#" -eq 2 ] || usage
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
for tool in chroot cmp cp git python3 readelf realpath sha256sum timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] &&
    [ -f "$MUSL_LOADER" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE" \
    "$READER_DIR/owned_stdio_alias_contract_reader.py"; do
    [ -f "$source" ] || fail "missing source $source"
done

TMPDIR="$(python3 -B - "$ROOT" <<'PY'
import sys

sys.path.insert(0, sys.argv[1] + '/scripts')
from build_x86_64_owned_sysroot import deterministic_environment

print(deterministic_environment()['TMPDIR'])
PY
)"
export TMPDIR
python3 -B - "$ROOT" "$TMPDIR" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
temporary = Path(sys.argv[2]).resolve(strict=False)
if not temporary.is_relative_to(root / '.work'):
    raise SystemExit('owned string/temporary alias contract TMPDIR must remain below checkout .work')
temporary.mkdir(parents=True, exist_ok=True)
if temporary.resolve(strict=True) != temporary:
    raise SystemExit('owned string/temporary alias contract TMPDIR must be physical')
PY

readonly WORK="$(mktemp -d "$TMPDIR/owned-string-temporary-alias-contract.XXXXXX")"
chmod a+rx "$WORK"
trap 'chmod -R a+rX "$WORK"' EXIT
printf 'owned string/temporary alias contract evidence: %s\n' "$WORK"
git rev-parse HEAD >"$WORK/harness.commit"
git status --porcelain=v1 >"$WORK/harness.status"

run() {
    local stem="$1"
    shift
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    timeout 90 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
    status=$?
    set -e
    printf '%s\n' "$status" >"$WORK/$stem.status"
    [ "$status" -eq 0 ] || fail "$stem exited $status; evidence: $WORK"
}

same_transcript() {
    local expected="$1" actual="$2"
    cmp "$WORK/$expected.stdout" "$WORK/$actual.stdout" || fail "$actual stdout differs from $expected"
    cmp "$WORK/$expected.stderr" "$WORK/$actual.stderr" || fail "$actual stderr differs from $expected"
    cmp "$WORK/$expected.status" "$WORK/$actual.status" || fail "$actual status differs from $expected"
}

validate_product() {
    local product="$1" kind="$2" supplied="$3"
    python3 -B - "$ROOT" "$WORK" "$product" "$kind" "$supplied" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
work = Path(sys.argv[2]).resolve(strict=True)
product = Path(sys.argv[3]).resolve(strict=True)
kind = sys.argv[4]
supplied = sys.argv[5] == '1'
if not product.is_relative_to(work if not supplied else root / '.work'):
    boundary = 'checkout .work' if supplied else 'this retained disposable evidence product'
    raise SystemExit(f'{kind} product must remain below {boundary}')
sys.path.insert(0, str(root / 'compat/x86_64'))
from owned_posix_product_evidence import (
    ProductEvidenceError,
    _validate_dynamic_product,
    _validate_static_product,
)

try:
    if kind == 'static':
        _validate_static_product(product)
    elif kind == 'dynamic':
        _validate_dynamic_product(product)
    else:
        raise SystemExit(f'unknown product kind: {kind}')
except ProductEvidenceError as error:
    raise SystemExit(f'{kind} product does not satisfy the sealed owned-product contract: {error}') from error
PY
}

record_product_provenance() {
    local supplied="$1"
    python3 -B - "$WORK" "$STATIC_PRODUCT" "$DYNAMIC_PRODUCT" "$supplied" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys

work = Path(sys.argv[1]).resolve(strict=True)
static = Path(sys.argv[2]).resolve(strict=True)
dynamic = Path(sys.argv[3]).resolve(strict=True)
supplied = sys.argv[4] == '1'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

record = {
    'dynamic_product': {'path': str(dynamic), 'sha256': digest(dynamic / 'usr/lib/libc.so')},
    'static_product': {'path': str(static), 'sha256': digest(static / 'usr/lib/libc.a')},
}
if not supplied:
    record['runtime_build'] = {
        'commit': (work / 'harness.commit').read_text(encoding='utf-8').strip(),
        'harness_status_sha256': digest(work / 'harness.status'),
        'origin': 'fresh-current-checkout',
    }
else:
    evidence = static.parent
    source = evidence / 'source.commit'
    status = evidence / 'source.status'
    products = evidence / 'products.sha256'
    if dynamic.parent == evidence and source.is_file() and status.is_file() and products.is_file():
        commit = source.read_text(encoding='utf-8').strip()
        receipt_hashes = set(re.findall(r'^[0-9a-f]{64}', products.read_text(encoding='utf-8'), re.MULTILINE))
        if re.fullmatch(r'[0-9a-f]{40}', commit) and {
                record['static_product']['sha256'], record['dynamic_product']['sha256'],
        } <= receipt_hashes:
            record['runtime_build'] = {
                'commit': commit,
                'evidence': str(evidence),
                'source_status_sha256': digest(status),
                'origin': 'supplied-retained-product',
            }
    if 'runtime_build' not in record:
        record['runtime_build'] = {'origin': 'supplied-product-without-build-receipt'}

(work / 'runtime-product-provenance.json').write_text(
    json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8'
)
PY
}

if [ "$#" -eq 0 ]; then
    PRODUCTS_SUPPLIED=0
    STATIC_PRODUCT="$WORK/static-product"
    DYNAMIC_PRODUCT="$WORK/dynamic-product"
    run static-build python3 -B "$STATIC_BUILDER" --output "$STATIC_PRODUCT"
    run dynamic-build python3 -B "$DYNAMIC_BUILDER" --output "$DYNAMIC_PRODUCT"
else
    PRODUCTS_SUPPLIED=1
    STATIC_PRODUCT="$(realpath -e "$1")"
    DYNAMIC_PRODUCT="$(realpath -e "$2")"
fi
readonly STATIC_PRODUCT DYNAMIC_PRODUCT
validate_product "$STATIC_PRODUCT" static "$PRODUCTS_SUPPLIED"
validate_product "$DYNAMIC_PRODUCT" dynamic "$PRODUCTS_SUPPLIED"

sha256sum "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE" \
    "$READER_DIR/owned_stdio_alias_contract_reader.py" "$0" >"$WORK/harness.sha256"
sha256sum "$STATIC_PRODUCT/usr/lib/libc.a" "$DYNAMIC_PRODUCT/usr/lib/libc.so" \
    >"$WORK/products.sha256"
record_product_provenance "$PRODUCTS_SUPPLIED"

compile_object() {
    local stem="$1" source="$2"
    run "$stem-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -c "$source" -o "$WORK/$stem.o"
}

compile_object contract "$CONTRACT_SOURCE"
compile_object override "$OVERRIDE_SOURCE"
sha256sum "$WORK/contract.o" "$WORK/override.o" >"$WORK/consumer-objects.sha256"

for kind in contract override; do
    run "oracle-$kind-link" "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie \
        "$WORK/$kind.o" -o "$WORK/oracle-$kind"
    mkdir "$WORK/oracle-$kind-files"
    run "oracle-$kind" "$WORK/oracle-$kind" "$WORK/oracle-$kind-files"
done
[ "$(cat "$WORK/oracle-contract.stdout")" = owned-string-temporary-alias-contract-ok ] ||
    fail 'pinned-musl contract transcript drifted'
[ "$(cat "$WORK/oracle-override.stdout")" = owned-string-temporary-alias-override-ok ] ||
    fail 'pinned-musl override transcript drifted'

for mode in static static-pie; do
    for kind in contract override; do
        run "$mode-$kind-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
            "$WORK/$kind.o" -o "$WORK/$mode-$kind"
        mkdir "$WORK/$mode-$kind-files"
        run "$mode-$kind" "$WORK/$mode-$kind" "$WORK/$mode-$kind-files"
        same_transcript "oracle-$kind" "$mode-$kind"
    done
done

for mode in pie non-pie; do
    case "$mode" in
        pie) musl_mode=(-pie) ;;
        non-pie) musl_mode=(-no-pie) ;;
    esac
    for kind in contract override; do
        run "musl-shared-$mode-$kind-link" "$ORACLE_CC" -std=c11 "${musl_mode[@]}" \
            -rdynamic "$WORK/$kind.o" -o "$WORK/musl-shared-$mode-$kind"
    done
    root="$WORK/musl-shared-$mode-root"
    mkdir "$root" "$root/opt" "$root/opt/musl-1.2.6" "$root/scratch" \
        "$root/scratch/contract" "$root/scratch/contract-direct" \
        "$root/scratch/override" "$root/scratch/override-direct"
    cp -a "$MUSL_ROOT/." "$root/opt/musl-1.2.6"
    cp "$WORK/musl-shared-$mode-contract" "$root/contract"
    cp "$WORK/musl-shared-$mode-override" "$root/override"
    for kind in contract override; do
        run "musl-shared-$mode-$kind-kernel" chroot "$root" "/$kind" \
            "/scratch/$kind"
        same_transcript "oracle-$kind" "musl-shared-$mode-$kind-kernel"
        run "musl-shared-$mode-$kind-direct" chroot "$root" "$MUSL_LOADER" \
            "/$kind" "/scratch/$kind-direct"
        same_transcript "oracle-$kind" "musl-shared-$mode-$kind-direct"
    done
done

for mode in pie non-pie; do
    for kind in contract override; do
        run "dynamic-$mode-$kind-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" \
            "--dynamic-$mode" -rdynamic "$WORK/$kind.o" -o "$WORK/dynamic-$mode-$kind"
    done
    root="$WORK/dynamic-$mode-root"
    mkdir "$root" "$root/scratch" "$root/scratch/contract" \
        "$root/scratch/contract-direct" "$root/scratch/override" \
        "$root/scratch/override-direct"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$WORK/dynamic-$mode-contract" "$root/contract"
    cp "$WORK/dynamic-$mode-override" "$root/override"
    run "dynamic-$mode-contract-kernel" chroot "$root" /contract /scratch/contract
    same_transcript "musl-shared-$mode-contract-kernel" "dynamic-$mode-contract-kernel"
    run "dynamic-$mode-contract-direct" chroot "$root" "$INTERPRETER" /contract /scratch/contract-direct
    same_transcript "musl-shared-$mode-contract-direct" "dynamic-$mode-contract-direct"
    run "dynamic-$mode-override-kernel" chroot "$root" /override /scratch/override
    same_transcript "musl-shared-$mode-override-kernel" "dynamic-$mode-override-kernel"
    run "dynamic-$mode-override-direct" chroot "$root" "$INTERPRETER" /override /scratch/override-direct
    same_transcript "musl-shared-$mode-override-direct" "dynamic-$mode-override-direct"
done

assert_elf_type() {
    local stem="$1" expected="$2"
    run "$stem-elf-header" readelf --file-header --wide "$WORK/$stem"
    grep -Eq "^[[:space:]]*Type:[[:space:]]*$expected([[:space:]]|\\()" \
        "$WORK/$stem-elf-header.stdout" ||
        fail "$stem is not the expected ELF $expected product"
}

for kind in contract override; do
    assert_elf_type "oracle-$kind" EXEC
    assert_elf_type "static-$kind" EXEC
    assert_elf_type "static-pie-$kind" DYN
    for mode in pie non-pie; do
        expected=EXEC
        [ "$mode" = pie ] && expected=DYN
        assert_elf_type "musl-shared-$mode-$kind" "$expected"
        assert_elf_type "dynamic-$mode-$kind" "$expected"
    done
done

readelf --dyn-syms --wide "$MUSL_LIB" >"$WORK/musl-dynamic-symbols.txt"
readelf --dyn-syms --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-dynamic-symbols.txt"
readelf --symbols --wide "$MUSL_LIB" >"$WORK/musl-shared-symbols.txt"
readelf --symbols --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-shared-symbols.txt"
readelf --symbols --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-symbols.txt"
readelf --symbols --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-symbols.txt"
for binary in "$WORK"/dynamic-*-override; do
    readelf --dyn-syms --wide "$binary" >"$binary.symbols.txt"
done

python3 -B - "$WORK" "$READER_DIR" <<'PY'
from collections import defaultdict
from pathlib import Path
import sys

work = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from owned_stdio_alias_contract_reader import SymbolRow, same_definition

aliases = {
    'stpcpy': '__stpcpy',
    'stpncpy': '__stpncpy',
    'strchrnul': '__strchrnul',
    'memrchr': '__memrchr',
    'mkostemps': '__mkostemps',
}

def rows(path, wanted_tables):
    result = []
    member = ''
    table = ''
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.startswith('File: '):
            member = line[6:]
            table = ''
            continue
        if line.startswith("Symbol table '"):
            table = line.split("'", 2)[1]
            continue
        fields = line.split()
        if table in wanted_tables and len(fields) >= 8 and fields[0].endswith(':'):
            result.append(SymbolRow(
                member, fields[1], fields[3], fields[4], fields[5], fields[6],
                fields[7].split('@', 1)[0],
            ))
    return result

def defined_by_name(path, wanted_tables):
    result = defaultdict(list)
    for row in rows(path, wanted_tables):
        if row.section != 'UND':
            result[row.name].append(row)
    return result

def one(table, name, path):
    values = table.get(name, [])
    if len(values) != 1:
        raise SystemExit(f'{path}: expected one defined {name}, found {values}')
    return values[0]

def shape(row):
    return row.symbol_type, row.binding, row.visibility

def same_or_fail(alias, target, path):
    if not same_definition(alias, target):
        raise SystemExit(
            f'{path}: {alias.name} and {target.name} do not share one '
            f'defining member/value/type/section: {alias}, {target}'
        )

def alias_definitions(path, tables, providers):
    values = defined_by_name(path, tables)
    for name, target in aliases.items():
        alias = one(values, name, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        if providers:
            provider = one(values, target, path)
            same_or_fail(alias, provider, path)
        elif values.get(target):
            raise SystemExit(f'{path}: hidden provider leaked into dynsym: {values[target]}')
    return values

def compare_exact(name, musl, candidate, label):
    if shape(musl) != shape(candidate):
        raise SystemExit(f'{label}: {name} shape differs: musl {musl}, candidate {candidate}')

musl_dynamic = alias_definitions(work / 'musl-dynamic-symbols.txt', {'.dynsym'}, False)
candidate_dynamic = alias_definitions(work / 'candidate-dynamic-symbols.txt', {'.dynsym'}, False)
musl_shared = alias_definitions(work / 'musl-shared-symbols.txt', {'.symtab'}, True)
candidate_shared = alias_definitions(work / 'candidate-shared-symbols.txt', {'.symtab'}, True)
musl_static = alias_definitions(work / 'musl-static-symbols.txt', {'.symtab'}, True)
candidate_static = alias_definitions(work / 'candidate-static-symbols.txt', {'.symtab'}, True)

for name in aliases:
    compare_exact(name, one(musl_dynamic, name, 'musl dynamic'),
                  one(candidate_dynamic, name, 'candidate dynamic'), 'dynamic symbols')
    compare_exact(name, one(musl_shared, name, 'musl shared'),
                  one(candidate_shared, name, 'candidate shared'), 'shared symbols')
    compare_exact(name, one(musl_static, name, 'musl static'),
                  one(candidate_static, name, 'candidate static'), 'static symbols')
for name in aliases.values():
    musl_provider = one(musl_shared, name, 'musl shared')
    candidate_provider = one(candidate_shared, name, 'candidate shared')
    # The shared linker localizes each hidden source provider. Pinned musl's
    # final local symtab rows are DEFAULT while lld retains HIDDEN, but neither
    # form reaches dynsym; locality and same-definition aliases are the shared
    # product's public/private boundary.
    if (musl_provider.symbol_type, musl_provider.binding) != ('FUNC', 'LOCAL'):
        raise SystemExit(f'musl shared provider {name} is not local FUNC: {musl_provider}')
    if (candidate_provider.symbol_type, candidate_provider.binding) != ('FUNC', 'LOCAL'):
        raise SystemExit(f'candidate shared provider {name} is not local FUNC: {candidate_provider}')
    compare_exact(name, one(musl_static, name, 'musl static'),
                  one(candidate_static, name, 'candidate static'), 'static providers')

for path in sorted(work.glob('dynamic-*-override.symbols.txt')):
    table = defined_by_name(path, {'.dynsym'})
    for name in aliases:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
            raise SystemExit(f'{path}: application override {name} is not FUNC GLOBAL DEFAULT: {row}')
PY

printf '%s\n' \
    'owned string/temporary alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and dynamic PIE/non-PIE kernel/direct weak overrides, source-local strong-provider calls, fixed temporary-file transcripts); evidence:' \
    "$WORK"
