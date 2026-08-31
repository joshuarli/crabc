#!/usr/bin/env bash
# Native Linux/x86-64 permanent-standard-stream feof_unlocked evidence.
#
# One GNU project-header fixture first runs against pinned musl 1.2.6 and then
# as a true `-nostdlib -static` candidate linked only through the selected
# archive. It proves musl's weak, same-address `feof_unlocked` alias of `feof`
# for permanent stdin observation only. It is not a lock-free FILE claim,
# another status alias, general FILE/path-stream I/O, or public-x86 evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly ORACLE_ARCHIVE=/opt/musl-1.2.6/lib/libc.a
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc permanent-stream feof_unlocked: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
       INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

assert_weak_same_address_alias() {
    local symbols_path="$1" alias_name="$2" target_name="$3" label="$4"
    local alias_value alias_type alias_bind target_value target_type target_bind

    read -r alias_value alias_type alias_bind < <(
        awk -v name="$alias_name" '$8 == name && $7 != "UND" { print $2, $4, $5; exit }' \
            "$symbols_path"
    )
    read -r target_value target_type target_bind < <(
        awk -v name="$target_name" '$8 == name && $7 != "UND" { print $2, $4, $5; exit }' \
            "$symbols_path"
    )
    [ -n "${alias_value:-}" ] || fail "$label lacks defined ${alias_name}"
    [ -n "${target_value:-}" ] || fail "$label lacks defined ${target_name}"
    [ "$alias_type" = FUNC ] || fail "$label ${alias_name} is not a function"
    [ "$target_type" = FUNC ] || fail "$label ${target_name} is not a function"
    [ "$alias_bind" = WEAK ] || fail "$label ${alias_name} is not weak"
    [ "$target_bind" = GLOBAL ] || fail "$label ${target_name} is not strong global"
    [ "$alias_value" = "$target_value" ] ||
        fail "$label ${alias_name}/${target_name} are not a same-address alias pair"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$ORACLE_ARCHIVE" ] || fail "missing pinned musl static archive"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_stdio_permanent_feof_unlocked_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-stdio-permanent-feof-unlocked.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-stdio-permanent-feof-unlocked-reference"
candidate="$work_dir/crabc-static-stdio-permanent-feof-unlocked-candidate"
trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
feof_disassembly="$work_dir/feof-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
oracle_archive_symbols="$work_dir/oracle-archive-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_stdio_permanent_feof_unlocked_probe.c >/dev/null 2>"$trace"
for header in stdio.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_stdio_permanent_feof_unlocked_probe.c \
    -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl permanent-stream feof_unlocked fixture failed"

nm -A --defined-only "$ORACLE_ARCHIVE" >"$oracle_archive_symbols" 2>/dev/null
grep -Eq "[[:space:]]T[[:space:]]feof$" "$oracle_archive_symbols" ||
    fail "pinned-musl archive omits strong feof"
grep -Eq "[[:space:]]W[[:space:]]feof_unlocked$" "$oracle_archive_symbols" ||
    fail "pinned-musl archive omits weak feof_unlocked"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    feof feof_unlocked fgetc close dup dup2 pipe; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq '[[:space:]][BDR][[:space:]]stdin$' "$archive_symbols" ||
    fail "archive does not define permanent stdin data"
grep -Eq "[[:space:]]W[[:space:]]feof_unlocked$" "$archive_symbols" ||
    fail "archive does not define weak feof_unlocked"
for unselected in ferror_unlocked clearerr_unlocked fgetc_unlocked getc_unlocked \
    getchar_unlocked fputc_unlocked putc_unlocked putchar_unlocked \
    fdopen freopen fopencookie popen pclose fmemopen open_memstream; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
for source_name in 'src/stdio/feof.c' 'weak_alias(feof, feof_unlocked)' \
    'pub unsafe extern "C" fn feof' '.weak feof_unlocked' \
    '.set feof_unlocked, feof'; do
    grep -Fq "$source_name" "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_standard.rs" ||
        fail "permanent-stream feof_unlocked implementation omits $source_name"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_STDIO_PERMANENT_FEOF_UNLOCKED_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_stdio_permanent_feof_unlocked_probe.c \
    compat/x86_64/libc_stdio_permanent_feof_unlocked_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=feof "$candidate" >"$feof_disassembly"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
for symbol in feof feof_unlocked fgetc close dup dup2 pipe stdin; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks ${symbol}"
done
assert_weak_same_address_alias "$candidate_symbols" feof_unlocked feof candidate
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if grep -Eq '[[:space:]]syscall$' "$feof_disassembly"; then
    fail "feof unexpectedly contains a syscall path"
fi
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_stdio_permanent_feof_unlocked_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
grep -Eq '[[:space:]]syscall$' "$candidate_disassembly" ||
    fail "candidate lacks a direct Linux syscall instruction"
timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding permanent-stream feof_unlocked fixture failed"

printf 'x86 static crabc-libc permanent-stream feof_unlocked: PASS\n'
