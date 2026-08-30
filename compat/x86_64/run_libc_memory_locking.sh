#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc per-range memory-locking gate.
#
# The same project-header C fixture executes through pinned musl 1.2.6 before
# a true -nostdlib -static candidate linked only with the selected archive.
# It is intentionally limited to mlock, munlock, and GNU
# mlock2(MLOCK_ONFAULT); lock availability is environment-dependent, while
# invalid flags and overflowing ranges have fixed Linux results. It does not
# select mlockall/munlockall, msync, mremap, mapping policy, allocator, CRT,
# loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc memory locking: %s\n' "$*" >&2
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local filesz
    local memsz
    local alignment

    read -r filesz memsz alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' \
            "$candidate_program_headers"
    )
    [ -n "${filesz:-}" ] || fail "candidate lacks parsable PT_TLS"
    (( filesz == 0 && memsz > 0 && memsz <= INITIAL_TLS_BYTES )) ||
        fail "PT_TLS exceeds fixture scratch"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT &&
        INITIAL_TLS_ALIGNMENT % alignment == 0 )) ||
        fail "PT_TLS alignment incompatible"
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks its Linux syscall instruction"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_memory_locking_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_mlock_reference.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-memory-locking.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-memory-locking-reference"
candidate="$work_dir/crabc-static-memory-locking-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_memory_locking_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdint.h features.h sys/mman.h sys/syscall.h sys/types.h \
    bits/mman.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_memory_locking_probe.c \
    -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location mlock mlock2 munlock; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MEMORY_LOCKING_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_memory_locking_probe.c \
    compat/x86_64/libc_memory_locking_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location mlock mlock2 munlock; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in mlockall munlockall msync mremap mmap mprotect munmap madvise \
    mincore shm_open shm_unlink memfd_create malloc free calloc realloc \
    pthread_create pthread_exit pthread_join; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "memory-locking candidate unexpectedly pulls ${unrelated}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

assert_named_syscall mlock 95
assert_named_syscall munlock 96
assert_named_syscall mlock2 145

"$candidate"

printf 'x86 static crabc-libc memory locking: PASS\n'
