#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc posix_fallocate evidence.
#
# This fixture uses raw Linux setup and inspection helpers over one unlinked
# regular file, so the candidate surface is only `posix_fallocate`: fixed
# mode-zero allocation over the half-open [4096, 8192) range, retained prefix bytes,
# zero-filled extension, stable position, direct POSIX error values, and
# unchanged errno. It is private evidence, not
# a general fallocate mode, pathname, CRT, pthread/TLS lifecycle, loader,
# sysroot, or public x86-64 C ABI support claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc posix_fallocate: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation" ;;
    esac
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static_c_abi_exports.txt"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "C ABI export closure drifted"
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

assert_posix_fallocate_syscall_path() {
    local disassembly="$work_dir/posix-fallocate-disassembly"

    objdump -d --disassemble=posix_fallocate "$candidate" >"$disassembly"
    grep -Eq '\$0x11d,%(e|r)ax' "$disassembly" ||
        fail "posix_fallocate lacks Linux fallocate syscall 285"
    grep -Eq '%r10(d)?' "$disassembly" ||
        fail "posix_fallocate does not place fallocate length in r10"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "posix_fallocate lacks syscall"
}

require_native_linux_x86_64
for tool in ar awk cargo cat cmp diff grep mapfile mkdir nm objdump readelf rustup sort wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_fcntl_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_posix_fallocate_reference.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-fallocate.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
candidate="$work_dir/crabc-static-posix-fallocate-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_fallocate_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h features.h stddef.h stdint.h sys/syscall.h sys/types.h unistd.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_fallocate_probe.c \
    -o "$work_dir/oracle"
"$work_dir/oracle"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit libc.a"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]posix_fallocate$' "$archive_symbols" ||
    fail "archive lacks posix_fallocate"
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive lacks initial TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_POSIX_FALLOCATE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_posix_fallocate_probe.c \
    compat/x86_64/libc_posix_fallocate_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
for symbol in __errno_location posix_fallocate; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks ${symbol}"
done
for unrelated in fallocate fcntl open openat close dup dup2 dup3 read write \
    pipe pipe2 splice copy_file_range sendfile; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls ${unrelated}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || fail "candidate retains unresolved symbols"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected dynamic runtime"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols"; then
    fail "candidate retains dynamic TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols"; then
    fail "candidate selects unowned dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks TLS"
assert_fixture_tls_capacity
assert_posix_fallocate_syscall_path

"$candidate"
printf 'x86 static crabc-libc posix_fallocate: PASS\n'
