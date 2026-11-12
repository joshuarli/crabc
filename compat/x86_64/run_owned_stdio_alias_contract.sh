#!/usr/bin/env bash
# Focused native proof for musl-shaped stdio aliases and interposition.
set -euo pipefail

# Explicit sealed receipt mode; the two-positional historical runner remains below.
if [ "${1:-}" = collect ] || [ "${1:-}" = validate-report ]; then
    exec python3 -B "$(dirname "${BASH_SOURCE[0]}")/owned_stdio_alias_contract_reader.py" "$@"
fi
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_stdio_alias_contract_probe.c"
readonly OVERRIDE_SOURCE="$ROOT/compat/x86_64/owned_stdio_alias_override_probe.c"
readonly PROTECTED_SOURCE="$ROOT/compat/x86_64/owned_stdio_protected_runtime_probe.c"
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
for tool in chroot cmp python3 realpath timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE" "$OVERRIDE_SOURCE" "$PROTECTED_SOURCE"; do
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
run oracle-contract "$WORK/oracle-contract" "$WORK/oracle-contract-path"
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
    run "$mode-contract" "$WORK/$mode-contract" "$WORK/$mode-contract-path"
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
    run "dynamic-$mode-contract-kernel" chroot "$root" /contract /scratch/contract-kernel
    same_transcript oracle-contract "dynamic-$mode-contract-kernel"
    run "dynamic-$mode-contract-direct" chroot "$root" "$INTERPRETER" /contract /scratch/contract-direct
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

printf 'owned stdio alias contract: PASS (pinned musl archive/shared aliases, static/static-PIE and dynamic PIE/non-PIE public overrides, deterministic cookie lock observations, protected shared collision/lookup/callability); evidence: %s\n' "$WORK"
