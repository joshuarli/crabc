#!/usr/bin/env bash
# Focused native proof for musl-shaped syscall aliases and interposition.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_syscall_alias_contract_probe.c"
readonly OVERRIDE_SOURCE="$ROOT/compat/x86_64/owned_syscall_alias_override_probe.c"
readonly READER="$ROOT/compat/x86_64/owned_syscall_alias_contract_reader.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned syscall alias contract: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
for tool in chroot cmp python3 readelf realpath timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE" "$READER"; do
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
        raise SystemExit(f'owned syscall alias contract {label} must remain below checkout .work')
for path, label in ((static / 'bin/crabc-cc', 'static compiler'),
                    (static / 'usr/lib/libc.a', 'static libc'),
                    (dynamic / 'bin/crabc-cc-dynamic', 'dynamic compiler'),
                    (dynamic / 'usr/lib/libc.so', 'dynamic libc')):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'owned syscall alias contract missing physical {label}: {path}')
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
readonly WORK="$(mktemp -d "$TMPDIR/owned-syscall-alias-contract.XXXXXX")"
chmod a+rx "$WORK"
printf 'syscall alias regular file\n' >"$WORK/regular"
chmod a+r "$WORK/regular"
printf 'owned syscall alias contract evidence: %s\n' "$WORK"

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

compile_candidate_object() {
    local stem="$1" source="$2"
    run "$stem-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -c "$source" -o "$WORK/$stem.o"
}

compile_candidate_object contract "$CONTRACT_SOURCE"
compile_candidate_object override "$OVERRIDE_SOURCE"

run oracle-contract-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector "$CONTRACT_SOURCE" -o "$WORK/oracle-contract"
run oracle-contract "$WORK/oracle-contract" "$WORK/regular"
[ "$(cat "$WORK/oracle-contract.stdout")" = 'owned-syscall-alias-contract-ok' ] ||
    fail 'pinned musl normal alias transcript drifted'
[ ! -s "$WORK/oracle-contract.stderr" ] || fail 'pinned musl normal alias probe emitted stderr'

run oracle-override-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector "$OVERRIDE_SOURCE" -o "$WORK/oracle-override"
run oracle-override "$WORK/oracle-override" "$WORK/regular"
[ "$(cat "$WORK/oracle-override.stdout")" = 'owned-syscall-alias-override-ok' ] ||
    fail 'pinned musl override transcript drifted'
[ ! -s "$WORK/oracle-override.stderr" ] || fail 'pinned musl override probe emitted stderr'

for mode in static static-pie; do
    run "$mode-contract-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
        "$WORK/contract.o" -o "$WORK/$mode-contract"
    run "$mode-contract" "$WORK/$mode-contract" "$WORK/regular"
    same_transcript oracle-contract "$mode-contract"

    run "$mode-override-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
        "$WORK/override.o" -o "$WORK/$mode-override"
    run "$mode-override" "$WORK/$mode-override" "$WORK/regular"
    same_transcript oracle-override "$mode-override"
done

for mode in pie non-pie; do
    case "$mode" in
        pie) oracle_flags=(-fPIE -pie) ;;
        non-pie) oracle_flags=(-fno-pie -no-pie) ;;
    esac
    run "oracle-dynamic-$mode-contract-link" "$ORACLE_CC" -std=c11 \
        "${oracle_flags[@]}" -fno-builtin -fno-stack-protector "$CONTRACT_SOURCE" \
        -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$WORK/oracle-dynamic-$mode-contract"
    run "oracle-dynamic-$mode-override-link" "$ORACLE_CC" -std=c11 \
        "${oracle_flags[@]}" -fno-builtin -fno-stack-protector "$OVERRIDE_SOURCE" \
        -Wl,--export-dynamic -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
        -o "$WORK/oracle-dynamic-$mode-override"
    oracle_root="$WORK/oracle-dynamic-$mode-root"
    mkdir -p "$oracle_root/lib" "$oracle_root/usr/lib" "$oracle_root/scratch"
    cp "$MUSL_LIB" "$oracle_root/lib/ld-musl-x86_64.so.1"
    cp "$MUSL_LIB" "$oracle_root/usr/lib/libc.so"
    cp "$WORK/regular" "$oracle_root/scratch/regular"
    cp "$WORK/oracle-dynamic-$mode-contract" "$oracle_root/contract"
    cp "$WORK/oracle-dynamic-$mode-override" "$oracle_root/override"
    run "oracle-dynamic-$mode-contract-kernel" chroot "$oracle_root" /contract /scratch/regular
    same_transcript oracle-contract "oracle-dynamic-$mode-contract-kernel"
    run "oracle-dynamic-$mode-contract-direct" chroot "$oracle_root" /lib/ld-musl-x86_64.so.1 /contract /scratch/regular
    same_transcript oracle-contract "oracle-dynamic-$mode-contract-direct"
    run "oracle-dynamic-$mode-override-kernel" chroot "$oracle_root" /override /scratch/regular shared
    same_transcript oracle-override "oracle-dynamic-$mode-override-kernel"
    run "oracle-dynamic-$mode-override-direct" chroot "$oracle_root" /lib/ld-musl-x86_64.so.1 /override /scratch/regular shared
    same_transcript oracle-override "oracle-dynamic-$mode-override-direct"
done

for mode in pie non-pie; do
    run "dynamic-$mode-contract-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        "$WORK/contract.o" -o "$WORK/dynamic-$mode-contract"
    run "dynamic-$mode-override-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -rdynamic "$WORK/override.o" -o "$WORK/dynamic-$mode-override"

    root="$WORK/dynamic-$mode-root"
    mkdir "$root" "$root/scratch"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$WORK/regular" "$root/scratch/regular"
    cp "$WORK/dynamic-$mode-contract" "$root/contract"
    cp "$WORK/dynamic-$mode-override" "$root/override"
    run "dynamic-$mode-contract-kernel" chroot "$root" /contract /scratch/regular
    same_transcript oracle-contract "dynamic-$mode-contract-kernel"
    run "dynamic-$mode-contract-direct" chroot "$root" "$INTERPRETER" /contract /scratch/regular
    same_transcript oracle-contract "dynamic-$mode-contract-direct"
    run "dynamic-$mode-override-kernel" chroot "$root" /override /scratch/regular shared
    same_transcript oracle-override "dynamic-$mode-override-kernel"
    run "dynamic-$mode-override-direct" chroot "$root" "$INTERPRETER" /override /scratch/regular shared
    same_transcript oracle-override "dynamic-$mode-override-direct"
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

python3 -B - "$WORK" "$(dirname "$READER")" <<'PY'
from collections import defaultdict
from pathlib import Path
import sys

work = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from owned_syscall_alias_contract_reader import SymbolRow, same_definition

aliases = {
    'clock_gettime': '__clock_gettime',
    'clock_nanosleep': '__clock_nanosleep',
    'dup3': '__dup3',
    'fstat': '__fstat',
    'fstatat': '__fstatat',
    'fstatfs': '__fstatfs',
    'lseek': '__lseek',
    'madvise': '__madvise',
    'mmap': '__mmap',
    'mprotect': '__mprotect',
    'munmap': '__munmap',
    'statfs': '__statfs',
    'sysinfo': '__lsysinfo',
    'sigaction': '__sigaction',
}
archive_hidden = {
    '__clock_gettime', '__clock_nanosleep', '__dup3', '__fstat', '__fstatat',
    '__lseek', '__madvise', '__mmap', '__mprotect', '__munmap', '__lsysinfo',
    '__sigaction', '__libc_sigaction',
}
archive_local = {'__statfs', '__fstatfs'}
all_internal = archive_hidden | archive_local

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
    for name in aliases:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {row}')
    for name in all_internal:
        if table.get(name):
            raise SystemExit(f'{path}: implementation leaked into dynamic symbols: {table[name]}')
    return table

def shared(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        # Hidden source bodies are localized in the shared link. Pinned musl
        # records LOCAL DEFAULT while the Rust link may retain LOCAL HIDDEN;
        # dynsym absence above is the public export boundary.
        if target_row.symbol_type != 'FUNC' or target_row.binding != 'LOCAL':
            raise SystemExit(f'{path}: {target} is not a local FUNC body: {target_row}')
        if target_row.visibility not in {'DEFAULT', 'HIDDEN'}:
            raise SystemExit(f'{path}: {target} has unexpected local visibility: {target_row}')
        require_same_definition(alias, target_row, path)
    raw = one(table, '__libc_sigaction', path)
    if raw.symbol_type != 'FUNC' or raw.binding != 'LOCAL' or raw.visibility not in {'DEFAULT', 'HIDDEN'}:
        raise SystemExit(f'{path}: __libc_sigaction is not a local FUNC body: {raw}')
    return table

def static(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        expected = ('FUNC', 'LOCAL', 'DEFAULT') if target in archive_local else ('FUNC', 'GLOBAL', 'HIDDEN')
        if shape(target_row) != expected:
            raise SystemExit(f'{path}: {target} does not have expected archive shape: {target_row}')
        require_same_definition(alias, target_row, path)
    raw = one(table, '__libc_sigaction', path)
    if shape(raw) != ('FUNC', 'GLOBAL', 'HIDDEN'):
        raise SystemExit(f'{path}: __libc_sigaction lacks a FUNC GLOBAL HIDDEN archive definition: {raw}')
    return table

musl_dynamic = dynamic(work / 'musl-dynamic-symbols.txt')
candidate_dynamic = dynamic(work / 'candidate-dynamic-symbols.txt')
musl_shared = shared(work / 'musl-shared-symbols.txt')
candidate_shared = shared(work / 'candidate-shared-symbols.txt')
musl_static = static(work / 'musl-static-symbols.txt')
candidate_static = static(work / 'candidate-static-symbols.txt')

for name in aliases:
    if shape(one(musl_dynamic, name, 'musl dynamic symbols')) != shape(one(candidate_dynamic, name, 'candidate dynamic symbols')):
        raise SystemExit(f'dynamic binding/visibility mismatch for {name}')
    if shape(one(musl_shared, name, 'musl shared symbols')) != shape(one(candidate_shared, name, 'candidate shared symbols')):
        raise SystemExit(f'shared binding/visibility mismatch for {name}')
    if shape(one(musl_static, name, 'musl static symbols')) != shape(one(candidate_static, name, 'candidate static symbols')):
        raise SystemExit(f'static binding/visibility mismatch for {name}')

for path in sorted(work.glob('dynamic-*-override.symbols.txt')):
    table = defined_by_name(path, {'.dynsym'})
    for name in aliases:
        row = one(table, name, path)
        if shape(row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
            raise SystemExit(f'{path}: application override is not dynamic GLOBAL DEFAULT: {row}')
PY

printf 'owned syscall alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and shared PIE/non-PIE public overrides, source-shaped internal call paths); evidence: %s\n' "$WORK"
