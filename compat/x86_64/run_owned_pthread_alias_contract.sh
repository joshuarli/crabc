#!/usr/bin/env bash
# Focused native proof for musl-shaped pthread/C11 aliases and interposition.
set -euo pipefail
ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_pthread_alias_contract_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1

cd "$ROOT"

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
for tool in chroot cmp python3 realpath timeout; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
[ -x "$ORACLE_CC" ] && [ -f "$MUSL_LIB" ] && [ -f "$MUSL_ARCHIVE" ] ||
    fail 'missing pinned musl 1.2.6 toolchain or artifacts'
for source in "$CONTRACT_SOURCE"; do
    [ -f "$source" ] || fail "missing source $source"
done

static_product="$(realpath -e "$1")"
dynamic_product="$(realpath -e "$2")"
python3 -B - "$ROOT" "$TMPDIR" "$static_product" "$dynamic_product" <<'PY'
from pathlib import Path
import sys

root, temporary, static, dynamic = (Path(value).resolve(strict=True) for value in sys.argv[1:])
for path, label in ((temporary, "TMPDIR"), (static, "static product"), (dynamic, "dynamic product")):
    if not path.is_relative_to(root / ".work"):
        raise SystemExit(f"owned pthread alias contract {label} must remain below checkout .work")
for path, label in ((static / "bin/crabc-cc", "static compiler"),
                    (static / "usr/lib/libc.a", "static libc"),
                    (dynamic / "bin/crabc-cc-dynamic", "dynamic compiler"),
                    (dynamic / "usr/lib/libc.so", "dynamic libc"),
                    (dynamic / "lib/ld-crabc-x86_64.so.1", "dynamic loader")):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"owned pthread alias contract missing physical {label}: {path}")


def overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


for product, label in ((static, "static product"), (dynamic, "dynamic product")):
    if overlaps(temporary, product):
        raise SystemExit(f"owned pthread alias contract TMPDIR overlaps {label}")
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
readonly WORK="$(mktemp -d "$TMPDIR/owned-pthread-alias-contract.XXXXXX")"
chmod a+rx "$WORK"
printf 'owned pthread alias contract evidence: %s\n' "$WORK"

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
        rel)
            grep -Eq 'Type:[[:space:]]+REL[[:space:]]+\(Relocatable file\)' \
                "$WORK/$label.file-header.txt" || fail "$label is not ET_REL"
            ;;
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
assert_elf_type contract.o "$WORK/contract.o" rel

run oracle-link "$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -pthread \
    "$WORK/contract.o" "-Wl,-Map,$WORK/oracle-contract.map" -o "$WORK/oracle-contract"
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
        "$WORK/contract.o" "-Wl,-Map,$WORK/musl-dynamic-$mode-contract.map" \
        -o "$WORK/musl-dynamic-$mode-contract"
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
        -pthread -rdynamic "$WORK/contract.o" \
        -o "$WORK/dynamic-$mode-contract"
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

printf 'owned pthread alias contract: PASS (pinned musl and matching candidate static/static-PIE and dynamic PIE/non-PIE kernel/direct execution matrix); evidence: %s\n' "$WORK"
