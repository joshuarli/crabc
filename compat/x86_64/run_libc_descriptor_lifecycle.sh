#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc descriptor-lifecycle evidence.
#
# One project-header C body runs first with pinned musl, then as a true
# -nostdlib -static candidate through the selected archive.  It composes the
# selected descriptor-entry, fcntl-status, I/O, stat, duplication, and close
# surfaces only.  The fixture's raw Linux calls own a PID-specific temporary
# directory's entry and cleanup only; they are never substitutes for candidate
# C calls.  This is expressly non-promoting: it proves neither a general C
# runtime nor filesystem, cancellation, CRT, loader, sysroot, or public x86
# support.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ELF_CALL_CLOSURE="$ROOT_DIR/compat/x86_64/elf_call_closure.py"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc descriptor lifecycle: %s\n' "$*" >&2
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

# Each selected entry's call closure reaches its Linux syscall with the
# caller's first argument, and no syscall outside the stated numbers, whether
# Rust inlines the raw syscall leaf or keeps it out of line.
assert_named_syscall() {
    local symbol="$1" syscall_number="$2" allowed="${3:-}"

    python3 "$ELF_CALL_CLOSURE" check "$candidate" \
        --label 'x86 static libc descriptor lifecycle' --root "$symbol" \
        --syscall "nr=${syscall_number},a1=arg:rdi" \
        --syscalls-only "${syscall_number}${allowed:+,$allowed}" ||
        fail "${symbol} does not reach Linux syscall ${syscall_number}"
}

# fcntl dispatches on the command before entering Linux: every fcntl=72 it
# reaches passes the caller's descriptor and command. F_GETFD/F_GETFL supply
# a zero third word instead of reading a vararg; F_SETFD/F_SETFL pass the
# caller's scalar, with musl's command-path O_LARGEFILE rule for F_SETFL.
assert_fcntl_paths() {
    python3 "$ELF_CALL_CLOSURE" check "$candidate" \
        --label 'x86 static libc descriptor lifecycle' --root fcntl \
        --every-syscall 'nr=72,a1=arg:rdi,a2=arg:rsi' \
        --syscall 'nr=72,a3=0' \
        --syscall 'nr=72,a3=arg:rdx' \
        --instruction 'or[lq]? \$0x8000,' ||
        fail "fcntl does not reach its selected command paths"
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    if (( tls_filesz != 0 || tls_memsz == 0 || tls_memsz > INITIAL_TLS_BYTES )); then
        fail "fixture TLS scratch is incompatible with PT_TLS sizes"
    fi
    if (( tls_alignment == 0 || tls_alignment > INITIAL_TLS_ALIGNMENT ||
        INITIAL_TLS_ALIGNMENT % tls_alignment != 0 )); then
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cat cmp diff grep nm objdump readelf rustup sort wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_fcntl_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_stat_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-descriptor-lifecycle.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-descriptor-lifecycle-reference"
candidate="$work_dir/crabc-static-descriptor-lifecycle-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
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
    compat/x86_64/libc_descriptor_lifecycle_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h sys/stat.h sys/types.h unistd.h sys/syscall.h \
    bits/alltypes.h bits/fcntl.h bits/stat.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_descriptor_lifecycle_probe.c \
    -o "$reference"
if "$reference"; then :; else
    status=$?
    fail "pinned-musl descriptor-lifecycle fixture exited ${status}"
fi

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location __fstat __fstatat __lseek __dup3 open openat creat fcntl read write pread pwrite \
    lseek fstat fstatat dup dup2 dup3 ftruncate fsync fdatasync close; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_DESCRIPTOR_LIFECYCLE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_descriptor_lifecycle_probe.c \
    compat/x86_64/libc_descriptor_lifecycle_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __fstat __fstatat __lseek __dup3 open openat creat fcntl read write pread pwrite \
    lseek fstat fstatat dup dup2 dup3 ftruncate fsync fdatasync close; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

# Keep this one composed proof tied to the selected Linux entry points.
assert_named_syscall openat 0x101
assert_named_syscall __fstat 0x5
assert_named_syscall __fstatat 0x106
assert_fcntl_paths
assert_named_syscall close 0x3
assert_named_syscall read 0x0
assert_named_syscall write 0x1
assert_named_syscall pread 0x11
assert_named_syscall __lseek 0x8
assert_named_syscall ftruncate 0x4d
assert_named_syscall fsync 0x4a
assert_named_syscall fdatasync 0x4b
assert_named_syscall dup 0x20
assert_named_syscall dup2 0x21
# musl's dup3 falls back to dup2 when the kernel lacks dup3.
assert_named_syscall __dup3 0x124 0x21
# open applies FD_CLOEXEC through fcntl when the kernel ignores O_CLOEXEC.
assert_named_syscall open 0x2 0x48
# openat's optional mode is the fourth Linux word, carried in r10.
python3 "$ELF_CALL_CLOSURE" check "$candidate" \
    --label 'x86 static libc descriptor lifecycle' --root openat \
    --syscall 'nr=0x101,a1=arg:rdi,a2=arg:rsi' --instruction ',%r10d?$' ||
    fail "openat does not carry its mode in the fourth syscall word"

if "$candidate"; then :; else
    status=$?
    fail "freestanding descriptor-lifecycle fixture exited ${status}"
fi

printf 'x86 static crabc-libc descriptor lifecycle: PASS\n'
