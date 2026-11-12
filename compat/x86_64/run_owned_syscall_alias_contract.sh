#!/usr/bin/env bash
# Focused native proof for musl-shaped syscall aliases and interposition.
set -euo pipefail
ulimit -c 0
umask 022

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_syscall_alias_contract_probe.c"
readonly OVERRIDE_SOURCE="$ROOT/compat/x86_64/owned_syscall_alias_override_probe.c"
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
for tool in chroot cmp python3 realpath timeout; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE"; do
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
                    (dynamic / 'usr/lib/libc.so', 'dynamic libc'),
                    (dynamic / 'share/crabc/producer-tools.json', 'dynamic producer tools')):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f'owned syscall alias contract missing physical {label}: {path}')
for path, label in ((root / 'libc/src/c_abi/x86_64/owned_dynamic.list', 'shared dynamic-list'),
                    (root / 'compat/x86_64/owned_shared_dynamic_list_probe.c', 'shared dynamic-list probe')):
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
    # Retain the exact Python program fed on stdin, then replay those bytes
    # below; other finite commands have an empty stdin boundary.
    if [ "$1" = python3 ] && [ "${2:-}" = -B ] && [ "${3:-}" = - ]; then
        cat >"$WORK/$stem.stdin"
    else
        : >"$WORK/$stem.stdin"
    fi
    python3 -B - "$WORK/$stem.argv.json" "$@" <<'PY'
import json
import os
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    'argv': sys.argv[2:],
    'timeout_seconds': 45,
    'execution_argv': ['timeout', '45', *sys.argv[2:]],
    'environment': {key: value for key, value in os.environ.items() if key not in {'PWD', 'SHLVL', '_'}},
    'cwd': os.getcwd(),
}, separators=(',', ':')) + '\n', encoding='utf-8')
PY
    local status
    set +e
    timeout 45 "$@" <"$WORK/$stem.stdin" >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
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

compile_probe_object() {
    local stem="$1" source="$2"
    run "$stem-compile" "$DYNAMIC_PRODUCT/bin/crabc-cc-dynamic" --dynamic-pie \
        -std=c11 -fno-builtin -fno-stack-protector -c "$source" -o "$WORK/$stem.o"
}

compile_probe_object contract "$CONTRACT_SOURCE"
compile_probe_object override "$OVERRIDE_SOURCE"

run oracle-contract-link "$ORACLE_CC" -static -no-pie \
    "$WORK/contract.o" -o "$WORK/oracle-contract"
run oracle-contract "$WORK/oracle-contract" "$WORK/regular"
[ "$(cat "$WORK/oracle-contract.stdout")" = 'owned-syscall-alias-contract-ok' ] ||
    fail 'pinned musl normal alias transcript drifted'
[ ! -s "$WORK/oracle-contract.stderr" ] || fail 'pinned musl normal alias probe emitted stderr'

run oracle-override-link "$ORACLE_CC" -static -no-pie \
    "$WORK/override.o" -o "$WORK/oracle-override"
run oracle-override "$WORK/oracle-override" "$WORK/regular"
[ "$(cat "$WORK/oracle-override.stdout")" = 'owned-syscall-alias-override-ok' ] ||
    fail 'pinned musl override transcript drifted'
[ ! -s "$WORK/oracle-override.stderr" ] || fail 'pinned musl override probe emitted stderr'

for mode in static static-pie; do
    run "$mode-contract-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
        "$WORK/contract.o" --link-receipt "${WORK#"$ROOT/"}/$mode-contract.link.json" \
        -o "$WORK/$mode-contract"
    run "$mode-contract" "$WORK/$mode-contract" "$WORK/regular"
    same_transcript oracle-contract "$mode-contract"

    run "$mode-override-link" "$STATIC_PRODUCT/bin/crabc-cc" "-$mode" \
        "$WORK/override.o" --link-receipt "${WORK#"$ROOT/"}/$mode-override.link.json" \
        -o "$WORK/$mode-override"
    run "$mode-override" "$WORK/$mode-override" "$WORK/regular"
    same_transcript oracle-override "$mode-override"
done

for mode in pie non-pie; do
    case "$mode" in
        pie) oracle_flags=(-pie) ;;
        non-pie) oracle_flags=(-no-pie) ;;
    esac
    run "oracle-dynamic-$mode-contract-link" "$ORACLE_CC" \
        "${oracle_flags[@]}" "$WORK/contract.o" \
        -Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1 -o "$WORK/oracle-dynamic-$mode-contract"
    run "oracle-dynamic-$mode-override-link" "$ORACLE_CC" \
        "${oracle_flags[@]}" "$WORK/override.o" \
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

printf 'owned syscall alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and shared PIE/non-PIE public overrides, source-shaped internal call paths); evidence: %s\n' "$WORK"
