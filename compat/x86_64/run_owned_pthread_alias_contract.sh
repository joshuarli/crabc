#!/usr/bin/env bash
# Focused native proof for musl-shaped pthread/C11 aliases and interposition.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_pthread_alias_contract_probe.c"
readonly READER="$ROOT/compat/x86_64/owned_pthread_alias_contract_reader.py"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

usage() {
    printf 'usage: %s STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned pthread alias contract: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -n "${TMPDIR:-}" ] || fail 'requires checkout-local TMPDIR'
for tool in chroot cmp python3 readelf realpath sha256sum timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$READER"; do
    [ -f "$source" ] || fail "missing source $source"
done

static_product="$(realpath -e "$1")"
dynamic_product="$(realpath -e "$2")"
python3 -B - "$ROOT" "$TMPDIR" "$static_product" "$dynamic_product" <<'PY'
import hashlib
import os
from pathlib import Path
import sys

root, temporary, static, dynamic = (Path(value).resolve(strict=True) for value in sys.argv[1:])
retained_value = os.environ.get("CRABC_RETAINED_640C0939_ROOT")
allowed = [root / ".work"]
if retained_value:
    retained = Path(retained_value).resolve(strict=True)
    expected_static = retained / "static/products/primary"
    expected_dynamic = retained / "dynamic"
    if static != expected_static or dynamic != expected_dynamic:
        raise SystemExit(
            "owned pthread alias contract retained inputs must be the sealed "
            "640c0939 primary static and dynamic products"
        )
    expected_hashes = {
        static / "usr/lib/libc.a": "ba36c1db3e38c97f50c02c4cdffae845221a1070192b9149e01825867f96f5c8",
        dynamic / "usr/lib/libc.so": "2d32042be95daf2ba65f3b2eb7e3d738e3a429444fdf45c46699137c04e8725a",
    }
    for path, expected in expected_hashes.items():
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        if observed != expected:
            raise SystemExit(f"sealed retained product hash drifted: {path}")
    allowed.append(retained)
for path, label in ((temporary, "TMPDIR"), (static, "static product"), (dynamic, "dynamic product")):
    if not any(path.is_relative_to(base) for base in allowed):
        raise SystemExit(f"owned pthread alias contract {label} must remain below checkout .work")
for path, label in ((static / "bin/crabc-cc", "static compiler"),
                    (static / "usr/lib/libc.a", "static libc"),
                    (dynamic / "bin/crabc-cc-dynamic", "dynamic compiler"),
                    (dynamic / "usr/lib/libc.so", "dynamic libc")):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"owned pthread alias contract missing physical {label}: {path}")
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
readonly WORK="$(mktemp -d "$TMPDIR/owned-pthread-alias-contract.XXXXXX")"
chmod a+rx "$WORK"
printf 'owned pthread alias contract evidence: %s\n' "$WORK"

python3 -B - "$WORK/input-identities.json" "$CONTRACT_SOURCE" "$READER" "$0" \
    "$MUSL_LIB" "$MUSL_ARCHIVE" "$STATIC_PRODUCT/bin/crabc-cc" \
    "$STATIC_PRODUCT/usr/lib/libc.a" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" \
    "$DYNAMIC_PRODUCT/usr/lib/libc.so" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
names = ("probe", "reader", "runner", "musl_shared", "musl_archive", "static_driver",
         "static_libc", "dynamic_driver", "dynamic_libc")
paths = [Path(value).resolve(strict=True) for value in sys.argv[2:]]
output.write_text(json.dumps({
    "format": "owned-pthread-alias-contract-inputs-v1",
    "inputs": {
        name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for name, path in zip(names, paths)
    },
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

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

assert_elf_type() {
    local label="$1" binary="$2" expected="$3"
    readelf --file-header --wide "$binary" >"$WORK/$label.file-header.txt"
    case "$expected" in
        exec)
            grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not ET_EXEC"
            ;;
        pie)
            grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not PIE ET_DYN"
            ;;
        *) fail "unknown ELF type expectation $expected for $label" ;;
    esac
}

compile_object() {
    run contract-compile "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -pthread -c "$CONTRACT_SOURCE" \
        -o "$WORK/contract.o"
}

compile_object

run oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -pthread \
    "$WORK/contract.o" -o "$WORK/oracle-contract"
run oracle "$WORK/oracle-contract"
[ "$(cat "$WORK/oracle.stdout")" = 'owned-pthread-alias-contract-ok' ] ||
    fail 'pinned musl alias contract transcript drifted'
[ ! -s "$WORK/oracle.stderr" ] || fail 'pinned musl alias contract emitted stderr'
assert_elf_type oracle-contract "$WORK/oracle-contract" exec

for mode in static static-pie; do
    run "$mode-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" -pthread \
        "$WORK/contract.o" -o "$WORK/$mode-contract"
    case "$mode" in
        static) assert_elf_type "$mode-contract" "$WORK/$mode-contract" exec ;;
        static-pie) assert_elf_type "$mode-contract" "$WORK/$mode-contract" pie ;;
    esac
    run "$mode" "$WORK/$mode-contract"
    same_transcript oracle "$mode"
done

for mode in pie non-pie; do
    case "$mode" in
        pie) oracle_mode=(-pie); oracle_type=pie ;;
        non-pie) oracle_mode=(-no-pie); oracle_type=exec ;;
    esac
    run "musl-dynamic-$mode-link" "$ORACLE_CC" -std=c11 -pthread -rdynamic \
        "${oracle_mode[@]}" -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 \
        "$WORK/contract.o" -o "$WORK/musl-dynamic-$mode-contract"
    assert_elf_type "musl-dynamic-$mode-contract" \
        "$WORK/musl-dynamic-$mode-contract" "$oracle_type"

    musl_root="$WORK/musl-dynamic-$mode-root"
    mkdir "$musl_root" "$musl_root/lib" "$musl_root/usr" "$musl_root/usr/lib"
    cp "$MUSL_LIB" "$musl_root/lib/ld-musl-x86_64.so.1"
    cp "$MUSL_LIB" "$musl_root/usr/lib/libc.so"
    cp "$WORK/musl-dynamic-$mode-contract" "$musl_root/contract"
    run "musl-dynamic-$mode-kernel" chroot "$musl_root" /contract
    run "musl-dynamic-$mode-direct" chroot "$musl_root" /lib/ld-musl-x86_64.so.1 /contract
    same_transcript "musl-dynamic-$mode-kernel" "musl-dynamic-$mode-direct"
done

for mode in pie non-pie; do
    run "dynamic-$mode-link" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" "--dynamic-$mode" \
        -pthread -rdynamic "$WORK/contract.o" -o "$WORK/dynamic-$mode-contract"
    case "$mode" in
        pie) assert_elf_type "dynamic-$mode-contract" "$WORK/dynamic-$mode-contract" pie ;;
        non-pie) assert_elf_type "dynamic-$mode-contract" "$WORK/dynamic-$mode-contract" exec ;;
    esac

    root="$WORK/dynamic-$mode-root"
    mkdir "$root" "$root/scratch"
    cp -a "$DYNAMIC_PRODUCT/." "$root"
    cp "$WORK/dynamic-$mode-contract" "$root/contract"
    run "dynamic-$mode-kernel" chroot "$root" /contract
    same_transcript "musl-dynamic-$mode-kernel" "dynamic-$mode-kernel"
    run "dynamic-$mode-direct" chroot "$root" "$INTERPRETER" /contract
    same_transcript "musl-dynamic-$mode-direct" "dynamic-$mode-direct"
done

readelf --dyn-syms --wide "$MUSL_LIB" >"$WORK/musl-dynamic-symbols.txt"
readelf --dyn-syms --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-dynamic-symbols.txt"
readelf --symbols --wide "$MUSL_LIB" >"$WORK/musl-shared-symbols.txt"
readelf --symbols --wide "$DYNAMIC_PRODUCT/usr/lib/libc.so" >"$WORK/candidate-shared-symbols.txt"
readelf --symbols --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-symbols.txt"
readelf --symbols --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-symbols.txt"
readelf --relocs --wide "$MUSL_ARCHIVE" >"$WORK/musl-static-relocations.txt"
readelf --relocs --wide "$STATIC_PRODUCT/usr/lib/libc.a" >"$WORK/candidate-static-relocations.txt"
for binary in "$WORK"/dynamic-*-contract; do
    readelf --dyn-syms --wide "$binary" >"$binary.symbols.txt"
done

python3 -B - "$WORK" "$(dirname "$READER")" <<'PY'
from collections import defaultdict
import re
from pathlib import Path
import sys

work = Path(sys.argv[1])
sys.path.insert(0, sys.argv[2])
from owned_pthread_alias_contract_reader import SymbolRow, same_definition

aliases = {
    'pthread_cond_timedwait': '__pthread_cond_timedwait',
    'pthread_create': '__pthread_create',
    'pthread_detach': '__pthread_detach',
    'pthread_exit': '__pthread_exit',
    'pthread_getspecific': '__pthread_getspecific',
    'pthread_join': '__pthread_join',
    'pthread_key_create': '__pthread_key_create',
    'pthread_key_delete': '__pthread_key_delete',
    'pthread_mutex_lock': '__pthread_mutex_lock',
    'pthread_mutex_timedlock': '__pthread_mutex_timedlock',
    'pthread_mutex_trylock': '__pthread_mutex_trylock',
    'pthread_mutex_unlock': '__pthread_mutex_unlock',
    'pthread_once': '__pthread_once',
    'pthread_setcancelstate': '__pthread_setcancelstate',
    'pthread_testcancel': '__pthread_testcancel',
    'thrd_detach': '__pthread_detach',
    'tss_get': '__pthread_getspecific',
}
archive_hidden = {
    '__pthread_cond_timedwait', '__pthread_create', '__pthread_exit', '__pthread_join',
    '__pthread_key_create', '__pthread_key_delete', '__pthread_mutex_lock',
    '__pthread_mutex_timedlock', '__pthread_mutex_trylock', '__pthread_mutex_unlock',
    '__pthread_once', '__pthread_setcancelstate', '__pthread_testcancel',
}
archive_local = {'__pthread_detach', '__pthread_getspecific'}

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
        alias = one(table, name, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
    for name in set(aliases.values()):
        if table.get(name):
            raise SystemExit(f'{path}: internal provider leaked into dynamic symbols: {table[name]}')
    return table

def shared(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        # The shared linker localizes both musl's hidden providers and its two
        # source-static providers. Visibility of the local symtab row is a
        # linker detail; the dynsym and same-definition checks are the ABI
        # boundary and alias proof.
        if target_row.symbol_type != 'FUNC' or target_row.binding != 'LOCAL':
            raise SystemExit(f'{path}: {target} is not a local FUNC body: {target_row}')
        require_same_definition(alias, target_row, path)
    return table

def static(path):
    table = defined_by_name(path, {'.symtab'})
    for name, target in aliases.items():
        alias = one(table, name, path)
        target_row = one(table, target, path)
        if shape(alias) != ('FUNC', 'WEAK', 'DEFAULT'):
            raise SystemExit(f'{path}: {name} is not FUNC WEAK DEFAULT: {alias}')
        expected = ('FUNC', 'GLOBAL', 'HIDDEN') if target in archive_hidden else ('FUNC', 'LOCAL', 'DEFAULT')
        if shape(target_row) != expected:
            raise SystemExit(f'{path}: {target} does not have expected archive binding: {target_row}')
        require_same_definition(alias, target_row, path)
    return table

def mq_notify_member(path):
    table = rows(path, {'.symtab'})
    definitions = [row for row in table if row.name == 'mq_notify' and row.section != 'UND']
    if len(definitions) != 1:
        raise SystemExit(f'{path}: expected one mq_notify archive definition, found {definitions}')
    return table, definitions[0].member

def relocation_blocks(path):
    blocks = []
    member = ''
    section = None
    contents = []
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.startswith('File: '):
            if section is not None:
                blocks.append((member, section, contents))
                section = None
                contents = []
            member = line[6:]
            continue
        if line.startswith("Relocation section '"):
            if section is not None:
                blocks.append((member, section, contents))
            section = line.split("'", 2)[1]
            contents = []
            continue
        if section is not None:
            contents.append(line)
    if section is not None:
        blocks.append((member, section, contents))
    return blocks

def symbol_relocations(path, member, name):
    token = re.compile(rf'(?:^|\s){re.escape(name)}(?:\s|\+|$)')
    return [
        (section, line)
        for block_member, section, contents in relocation_blocks(path)
        if block_member == member
        for line in contents
        if token.search(line)
    ]

def musl_mq_notify_public_detach_relocation(symbols, relocations):
    table, member = mq_notify_member(symbols)
    references = [
        row for row in table
        if row.member == member and row.name == 'pthread_detach' and row.section == 'UND'
    ]
    if len(references) != 1 or shape(references[0]) != ('NOTYPE', 'GLOBAL', 'DEFAULT'):
        raise SystemExit(
            f'{symbols}: mq_notify must retain one public undefined pthread_detach '
            f'reference, found {references}'
        )
    local_references = [
        row for row in table
        if row.member == member and row.name == '__pthread_detach' and row.section == 'UND'
    ]
    if local_references:
        raise SystemExit(
            f'{symbols}: mq_notify must not name source-local __pthread_detach: '
            f'{local_references}'
        )
    relocated = symbol_relocations(relocations, member, 'pthread_detach')
    if len(relocated) != 1:
        raise SystemExit(
            f'{relocations}: mq_notify must have one public pthread_detach relocation, '
            f'found {relocated}'
        )
    if symbol_relocations(relocations, member, '__pthread_detach'):
        raise SystemExit(
            f'{relocations}: mq_notify must not relocate source-local __pthread_detach'
        )
    return relocated[0]

def candidate_mq_notify_public_detach_relocation(symbols, relocations):
    _, member = mq_notify_member(symbols)
    relocated = symbol_relocations(relocations, member, 'pthread_detach')
    if len(relocated) != 1:
        raise SystemExit(
            f'{relocations}: candidate mq_notify must have one public pthread_detach '
            f'relocation, found {relocated}'
        )
    section, _ = relocated[0]
    if 'owned_message_queues12notify_start' not in section:
        raise SystemExit(
            f'{relocations}: candidate public pthread_detach relocation must originate '
            f'from mq notify_start, found {section}'
        )
    if symbol_relocations(relocations, member, '__pthread_detach'):
        raise SystemExit(
            f'{relocations}: candidate mq_notify must not relocate source-local '
            '__pthread_detach'
        )
    return relocated[0]

musl_dynamic = dynamic(work / 'musl-dynamic-symbols.txt')
candidate_dynamic = dynamic(work / 'candidate-dynamic-symbols.txt')
musl_shared = shared(work / 'musl-shared-symbols.txt')
candidate_shared = shared(work / 'candidate-shared-symbols.txt')
musl_static = static(work / 'musl-static-symbols.txt')
candidate_static = static(work / 'candidate-static-symbols.txt')
musl_mq_detach = musl_mq_notify_public_detach_relocation(
    work / 'musl-static-symbols.txt', work / 'musl-static-relocations.txt'
)
candidate_mq_detach = candidate_mq_notify_public_detach_relocation(
    work / 'candidate-static-symbols.txt', work / 'candidate-static-relocations.txt'
)
for name in aliases:
    for left, right, label in ((musl_dynamic, candidate_dynamic, 'dynamic'),
                               (musl_shared, candidate_shared, 'shared'),
                               (musl_static, candidate_static, 'static')):
        if shape(one(left, name, f'musl {label} symbols')) != shape(one(right, name, f'candidate {label} symbols')):
            raise SystemExit(f'{label} binding/visibility mismatch for {name}')

for path in sorted(work.glob('dynamic-*-contract.symbols.txt')):
    table = defined_by_name(path, {'.dynsym'})
    row = one(table, 'pthread_setcancelstate', path)
    if shape(row) != ('FUNC', 'GLOBAL', 'DEFAULT'):
        raise SystemExit(f'{path}: application override is not dynamic GLOBAL DEFAULT: {row}')
PY

printf 'owned pthread alias contract: PASS (pinned musl archive/shared aliases and matching static/shared execution matrix, exact executable ELF modes, strong public override, mq_notify public detach relocation, synchronous pthread_join hidden-provider route); evidence: %s\n' "$WORK"
