#!/usr/bin/env bash
# Focused native proof for the four musl-shaped x86 owned pthread timed aliases.
set -euo pipefail

umask 022

ulimit -c 0

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LIB=/opt/musl-1.2.6/lib/libc.so
readonly MUSL_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly CONTRACT_SOURCE="$ROOT/compat/x86_64/owned_pthread_timed_feature_contract_probe.c"
readonly INTERPRETER=/lib/ld-crabc-x86_64.so.1
readonly EXECUTION_PATH=/opt/cargo/bin:/opt/musl-1.2.6/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
readonly EXECUTION_TMPDIR="$ROOT/.work/x86_64/tmp"

# Every launched command reads EOF from /dev/null.
export PATH="$EXECUTION_PATH"
export HOME=/nonexistent
export LC_ALL=C
export LANG=C
export TZ=UTC
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=/workspace
export TMPDIR="$EXECUTION_TMPDIR"

cd "$ROOT"
mkdir -p "$TMPDIR"

usage() {
    printf 'usage: %s STATIC_SYSROOT DYNAMIC_SYSROOT\n' "$0" >&2
    exit 2
}

fail() {
    printf 'owned pthread timed feature contract: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
case "$TMPDIR" in
    "$ROOT"/.work/*) ;;
    *) fail 'internal TMPDIR escaped checkout .work' ;;
esac
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
        raise SystemExit(f"owned pthread timed feature contract {label} must remain below checkout .work")
for path, label in ((static / "bin/crabc-cc", "static compiler"),
                    (static / "usr/lib/libc.a", "static libc"),
                    (static / "usr/lib/crt1.o", "static entry object"),
                    (static / "usr/lib/rcrt1.o", "static PIE entry object"),
                    (static / "usr/lib/crti.o", "static prologue object"),
                    (static / "usr/lib/crtn.o", "static epilogue object"),
                    (static / "usr/lib/libcrabc-builtins.a", "static builtins archive"),
                    (dynamic / "bin/crabc-cc-dynamic", "dynamic compiler"),
                    (dynamic / "usr/lib/crt1.o", "dynamic entry object"),
                    (dynamic / "usr/lib/Scrt1.o", "dynamic PIE entry object"),
                    (dynamic / "usr/lib/crti.o", "dynamic prologue object"),
                    (dynamic / "usr/lib/crtn.o", "dynamic epilogue object"),
                    (dynamic / "usr/lib/crabc-dynamic-attach.o", "dynamic CRT attach object"),
                    (dynamic / "usr/lib/libcrabc-builtins.a", "dynamic builtins archive"),
                    (dynamic / "usr/lib/libc.so", "dynamic libc"),
                    (dynamic / "lib/ld-crabc-x86_64.so.1", "dynamic loader")):
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"owned pthread timed feature contract missing physical {label}: {path}")


def overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


for product, label in ((static, "static product"), (dynamic, "dynamic product")):
    if overlaps(temporary, product):
        raise SystemExit(f"owned pthread timed feature contract TMPDIR overlaps {label}")
PY

readonly STATIC_PRODUCT="$static_product"
readonly DYNAMIC_PRODUCT="$dynamic_product"
readonly WORK="$(mktemp -d "$TMPDIR/owned-pthread-timed-feature-contract.XXXXXX")"
chmod 0755 "$WORK"
printf 'owned pthread timed feature contract evidence: %s\n' "$WORK"


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
    timeout 45 "$@" </dev/null >"$WORK/$stem.stdout" 2>"$WORK/$stem.stderr"
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

normalize_runtime_root() {
    local root="$1" flavor="$2"
    python3 -B - "$root" "$flavor" <<'PY'
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1]).resolve(strict=True)
flavor = sys.argv[2]
if flavor not in {"musl", "dynamic"}:
    raise SystemExit("unknown pthread runtime-root flavor")
executables = {
    "contract",
    "lib/ld-musl-x86_64.so.1",
    "usr/lib/libc.so",
} if flavor == "musl" else {
    "contract",
    "bin/crabc-cc-dynamic",
    "lib/ld-crabc-x86_64.so.1",
    "usr/lib/libc.so",
}
for path in [root, *sorted(root.rglob("*"))]:
    if path.is_symlink():
        continue
    relative = "." if path == root else path.relative_to(root).as_posix()
    if path.is_dir():
        os.chmod(path, 0o755)
    elif path.is_file():
        os.chmod(path, 0o755 if relative in executables else 0o644)
    else:
        raise SystemExit(f"unsafe runtime-root entry: {relative}")
PY
}

assert_contract_output_modes() {
    python3 -B - "$WORK" <<'PY'
from pathlib import Path
import stat
import sys

work = Path(sys.argv[1]).resolve(strict=True)
expected = {
    "contract.o": 0o644,
    "oracle-contract": 0o755,
    "static-contract": 0o755,
    "static-pie-contract": 0o755,
    "musl-dynamic-pie-contract": 0o755,
    "musl-dynamic-non-pie-contract": 0o755,
    "dynamic-pie-contract": 0o755,
    "dynamic-non-pie-contract": 0o755,
}
for name, mode in expected.items():
    path = work / name
    if not path.is_file() or path.is_symlink() or stat.S_IMODE(path.stat().st_mode) != mode:
        raise SystemExit(f"pthread contract output mode differs: {name}")
PY
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
[ "$(cat "$WORK/oracle.stdout")" = 'owned-pthread-timed-feature-contract-ok' ] ||
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
    normalize_runtime_root "$musl_root" musl
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
    normalize_runtime_root "$root" dynamic
    run "dynamic-$mode-kernel" chroot "$root" /contract
    same_transcript "musl-dynamic-$mode-kernel" "dynamic-$mode-kernel"
    run "dynamic-$mode-direct" chroot "$root" "$INTERPRETER" /contract
    same_transcript "musl-dynamic-$mode-direct" "dynamic-$mode-direct"
done

assert_contract_output_modes

printf 'owned pthread timed feature contract: PASS (four pinned-musl-shaped timed aliases, exact source feature route, selected product bytes, final-link extraction, and bounded timeout/join behavior across five executable modes); evidence: %s\n' "$WORK"
