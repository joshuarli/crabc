#!/usr/bin/env bash
# Focused native proof for musl-shaped stdio aliases and interposition.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_stdio_alias_contract_probe.c"
readonly OVERRIDE_SOURCE="$ROOT/compat/x86_64/owned_stdio_alias_override_probe.c"
readonly PROTECTED_SOURCE="$ROOT/compat/x86_64/owned_stdio_protected_runtime_probe.c"
readonly READER="$ROOT/compat/x86_64/owned_stdio_alias_contract_reader.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned stdio alias contract: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
for tool in chroot cmp python3 readelf realpath timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE" "$PROTECTED_SOURCE" "$READER"; do
    [ -f "$source" ] || fail "missing source $source"
done

static_product="$(realpath -e "$1")"
dynamic_product="$(realpath -e "$2")"
python3 -B - "$ROOT" "$TMPDIR" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root, temporary, static, dynamic = (Path(value).resolve(strict=True) for value in sys.argv[1:])
for path, label in ((temporary, 'TMPDIR'), (static, 'static product'), (dynamic, 'dynamic product')):
    if not path.is_relative_to(root / '.work'):
        raise SystemExit(f'owned stdio alias contract {label} must remain below checkout .work')
for path, label in ((static / 'bin/crabc-cc', 'static compiler'),
                    (static / 'usr/lib/libc.a', 'static libc'),
                    (dynamic / 'bin/crabc-cc-dynamic', 'dynamic compiler'),
                    (dynamic / 'usr/lib/libc.so', 'dynamic libc')):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'owned stdio alias contract missing physical {label}: {path}')
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
readonly WORK="$(mktemp -d "$TMPDIR/owned-stdio-alias-contract.XXXXXX")"
chmod a+rx "$WORK"
printf 'owned stdio alias contract evidence: %s\n' "$WORK"

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
    timeout 45 "$@" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
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

compile_object() {
    local stem="$1" source="$2"
    run "$stem-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -pthread -c "$source" -o "$WORK/$stem.o"
}

compile_object contract "$CONTRACT_SOURCE"
compile_object override "$OVERRIDE_SOURCE"
compile_object protected "$PROTECTED_SOURCE"

run oracle-contract-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -pthread \
    "$WORK/contract.o" -o "$WORK/oracle-contract"
run oracle-contract "$WORK/oracle-contract"
[ "$(cat "$WORK/oracle-contract.stdout")" = 'owned-stdio-alias-contract-ok' ] ||
    fail 'pinned musl alias contract transcript drifted'
[ ! -s "$WORK/oracle-contract.stderr" ] || fail 'pinned musl alias contract emitted stderr'

run oracle-override-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie \
    "$WORK/override.o" -o "$WORK/oracle-override"
run oracle-override "$WORK/oracle-override" "$WORK/oracle-override-path"
[ "$(cat "$WORK/oracle-override.stdout")" = 'owned-stdio-alias-override-ok' ] ||
    fail 'pinned musl override transcript drifted'
[ ! -s "$WORK/oracle-override.stderr" ] || fail 'pinned musl override emitted stderr'

run oracle-protected-link "$ORACLE_CC" -std=c11 -pthread -Wl,--export-dynamic \
    -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
    "$WORK/protected.o" -ldl -o "$WORK/oracle-protected"
oracle_root="$WORK/oracle-protected-root"
mkdir -p "$oracle_root/lib" "$oracle_root/usr/lib"
cp "$MUSL_LIB" "$oracle_root/lib/ld-musl-x86_64.so.1"
cp "$MUSL_LIB" "$oracle_root/usr/lib/libc.so"
cp "$WORK/oracle-protected" "$oracle_root/protected"
run oracle-protected-kernel chroot "$oracle_root" /protected
run oracle-protected-direct chroot "$oracle_root" /lib/ld-musl-x86_64.so.1 /protected
same_transcript oracle-protected-kernel oracle-protected-direct

for mode in static static-pie; do
    run "$mode-contract-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" -pthread \
        "$WORK/contract.o" -o "$WORK/$mode-contract"
    run "$mode-contract" "$WORK/$mode-contract"
    same_transcript oracle-contract "$mode-contract"

    run "$mode-override-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
        "$WORK/override.o" -o "$WORK/$mode-override"
    run "$mode-override" "$WORK/$mode-override" "$WORK/$mode-override-path"
    same_transcript oracle-override "$mode-override"
done

for mode in pie non-pie; do
    run "dynamic-$mode-contract-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -pthread "$WORK/contract.o" -o "$WORK/dynamic-$mode-contract"
    run "dynamic-$mode-override-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -rdynamic "$WORK/override.o" -o "$WORK/dynamic-$mode-override"
    run "dynamic-$mode-protected-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -rdynamic "$WORK/protected.o" -o "$WORK/dynamic-$mode-protected"

    root="$WORK/dynamic-$mode-root"
    mkdir "$root" "$root/scratch"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$WORK/dynamic-$mode-contract" "$root/contract"
    cp "$WORK/dynamic-$mode-override" "$root/override"
    cp "$WORK/dynamic-$mode-protected" "$root/protected"
    run "dynamic-$mode-contract-kernel" chroot "$root" /contract
    same_transcript oracle-contract "dynamic-$mode-contract-kernel"
    run "dynamic-$mode-contract-direct" chroot "$root" "$INTERPRETER" /contract
    same_transcript oracle-contract "dynamic-$mode-contract-direct"
    run "dynamic-$mode-override-kernel" chroot "$root" /override /scratch/override
    same_transcript oracle-override "dynamic-$mode-override-kernel"
    run "dynamic-$mode-override-direct" chroot "$root" "$INTERPRETER" /override /scratch/override-direct
    same_transcript oracle-override "dynamic-$mode-override-direct"
    run "dynamic-$mode-protected-kernel" chroot "$root" /protected
    same_transcript oracle-protected-kernel "dynamic-$mode-protected-kernel"
    run "dynamic-$mode-protected-direct" chroot "$root" "$INTERPRETER" /protected
    same_transcript oracle-protected-direct "dynamic-$mode-protected-direct"
done

readelf --dyn-syms --wide "$MUSL_LIB" >"$WORK/musl-dynamic-symbols.txt"
readelf --dyn-syms --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-dynamic-symbols.txt"
readelf --symbols --wide "$MUSL_LIB" >"$WORK/musl-shared-symbols.txt"
readelf --symbols --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-shared-symbols.txt"
readelf --symbols --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-symbols.txt"
readelf --symbols --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-symbols.txt"
for binary in "$WORK"/dynamic-*-override "$WORK"/dynamic-*-protected; do
    readelf --dyn-syms --wide "$binary" >"$binary.symbols.txt"
done

python3 -B - "$WORK" "$(dirname "$READER")" <<'PY'
from collections import defaultdict
from pathlib import Path
import sys

work = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from owned_stdio_alias_contract_reader import SymbolRow, same_definition

aliases = {
    'fdopen': '__fdopen',
    'fgetc_unlocked': 'getc_unlocked',
    'fputc_unlocked': 'putc_unlocked',
    'fread_unlocked': 'fread',
    'fwrite_unlocked': 'fwrite',
    'fseeko': '__fseeko',
    'ftello': '__ftello',
    'fgetwc_unlocked': '__fgetwc_unlocked',
    'getwc_unlocked': '__fgetwc_unlocked',
    'fputwc_unlocked': '__fputwc_unlocked',
    'putwc_unlocked': '__fputwc_unlocked',
    'fgetws_unlocked': 'fgetws',
    'fputws_unlocked': 'fputws',
    'getwchar_unlocked': 'getwchar',
    'putwchar_unlocked': 'putwchar',
}
hidden = {'__fdopen', '__fseeko', '__ftello'}
protected = {'__uflow', '__overflow'}

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

def require_same_definition(alias, target, path):
    if not same_definition(alias, target):
        raise SystemExit(
            f'{path}: {alias.name} and {target.name} do not share one '
            f'defining member/value/type/section: {alias}, {target}'
        )

def dynamic(path):
    table = defined_by_name(path, {'.dynsym'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        if target not in hidden:
            target_row = one(table, target, path)
            if shape(target_row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
                raise SystemExit(f'{path}: {target} is not FUNC GLOBAL DEFAULT: {target_row}')
            require_same_definition(alias, target_row, path)
    for name in hidden:
        if table.get(name):
            raise SystemExit(f'{path}: hidden implementation leaked into dynamic symbols: {table[name]}')
    for name in protected:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'PROTECTED'):
            raise SystemExit(f'{path}: {name} is not FUNC GLOBAL PROTECTED: {row}')
    return table

def shared(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        if target in hidden:
            if target_row.symbol_type != 'FUNC' or target_row.visibility != 'HIDDEN':
                raise SystemExit(f'{path}: {target} is not a hidden FUNC body: {target_row}')
        elif shape(target_row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
            raise SystemExit(f'{path}: {target} is not FUNC GLOBAL DEFAULT: {target_row}')
        require_same_definition(alias, target_row, path)
    for name in protected:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'PROTECTED'):
            raise SystemExit(f'{path}: {name} is not FUNC GLOBAL PROTECTED: {row}')
    return table

def static(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        if target in hidden:
            expected = ('FUNC', 'GLOBAL', 'HIDDEN')
        else:
            expected = ('FUNC', 'GLOBAL', 'DEFAULT')
        if shape(target_row) != expected:
            raise SystemExit(f'{path}: {target} does not have expected archive binding: {target_row}')
        require_same_definition(alias, target_row, path)
    for name in hidden:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'HIDDEN'):
            raise SystemExit(f'{path}: {name} lacks a FUNC GLOBAL HIDDEN archive definition: {row}')
    for name in protected:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'PROTECTED'):
            raise SystemExit(f'{path}: static {name} is not FUNC GLOBAL PROTECTED: {row}')
    return table

musl_dynamic = dynamic(work / 'musl-dynamic-symbols.txt')
candidate_dynamic = dynamic(work / 'candidate-dynamic-symbols.txt')
for name in set(aliases) | protected:
    if shape(musl_dynamic[name]) != shape(candidate_dynamic[name]):
        raise SystemExit(f'dynamic binding/visibility mismatch for {name}')
musl_shared = shared(work / 'musl-shared-symbols.txt')
candidate_shared = shared(work / 'candidate-shared-symbols.txt')
musl_static = static(work / 'musl-static-symbols.txt')
candidate_static = static(work / 'candidate-static-symbols.txt')
for name in set(aliases) | set(aliases.values()) | protected:
    if shape(musl_shared[name]) != shape(candidate_shared[name]):
        raise SystemExit(f'shared symbol binding/visibility mismatch for {name}')
    if shape(musl_static[name]) != shape(candidate_static[name]):
        raise SystemExit(f'static symbol binding/visibility mismatch for {name}')

for path in sorted(work.glob('dynamic-*-override.symbols.txt')):
    table = defined_by_name(path, {'.dynsym'})
    for name in ('fdopen', 'fseeko', 'ftello'):
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
            raise SystemExit(f'{path}: application override is not dynamic GLOBAL DEFAULT: {row}')
for path in sorted(work.glob('dynamic-*-protected.symbols.txt')):
    table = defined_by_name(path, {'.dynsym'})
    for name in protected:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
            raise SystemExit(f'{path}: protected collision source is not dynamic GLOBAL DEFAULT: {row}')
PY

printf 'owned stdio alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and dynamic PIE/non-PIE public overrides, deterministic cookie lock observations, protected shared collision/lookup/callability); evidence: %s\n' "$WORK"
