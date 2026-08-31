#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc posix_close evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true `-nostdlib -static` candidate linked only with crabc-libc.
# It proves musl's flag-ignored close spelling, normal/error errno behavior,
# and a closed archive/final-ELF boundary. It does not select generic
# descriptor I/O, close cancellation/AIO coordination, descriptor ownership,
# filesystem policy, libc.so, CRT, loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc posix_close: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_static_closure() {
    local candidate_path="$1"

    readelf --symbols --wide "$candidate_path" >"$candidate_symbols"
    readelf --program-headers --wide "$candidate_path" >"$candidate_program_headers"
    readelf --dynamic --wide "$candidate_path" >"$candidate_dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$candidate_relocations"
    objdump -d "$candidate_path" >"$candidate_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
        "$candidate_program_headers" "$candidate_dynamic"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
        "$candidate_symbols" "$candidate_disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "candidate errno does not use direct fs initial TLS"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_posix_close_header_abi.sh" >/dev/null
grep -Eq '^posix_close[[:space:]]+posix_close\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost posix_close ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-close.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-posix-close-reference"
candidate="$work_dir/crabc-static-posix-close-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-posix-close.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/candidate-errno-disassembly"
posix_close_disassembly="$work_dir/posix-close-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" posix_close.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]posix_close$' ||
    fail "pinned musl posix_close.lo lacks posix_close"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_close_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdint.h sys/syscall.h unistd.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_close_probe.c -o "$reference"
"$reference" || fail "pinned-musl posix_close fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap posix_close; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -DCRABC_POSIX_CLOSE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_posix_close_probe.c \
    compat/x86_64/libc_posix_close_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"

grep -Eq '[[:space:]]posix_close$' "$candidate_symbols" ||
    fail "candidate lacks posix_close"
if grep -Eq '[[:space:]](close|read|write|pread|pwrite|dup|dup2|dup3|pipe|pipe2|fsync|fdatasync)$' \
    "$candidate_symbols"; then
    fail "posix_close candidate exports an unselected descriptor entry"
fi
objdump -d --disassemble=posix_close "$candidate" >"$posix_close_disassembly"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$posix_close_disassembly" ||
    fail "posix_close lacks a direct Linux syscall"
grep -Eq '\$0x3,%e?ax' "$posix_close_disassembly" ||
    fail "posix_close lacks Linux x86-64 close=3"
if grep -Eq 'call.*<(close|read|write|pread|pwrite|dup|pipe)>' \
    "$posix_close_disassembly"; then
    fail "posix_close delegates to an unselected descriptor entry"
fi

"$candidate" || fail "freestanding posix_close fixture failed"

printf 'x86 static crabc-libc posix_close: PASS\n'
