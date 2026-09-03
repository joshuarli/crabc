#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc filesystem-capacity evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() { printf 'ERROR: x86 static libc filesystem capacity: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation" ;; esac
}
assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (cd "$members_path"; ar x "$archive_path" "${members[@]}"; nm -g --defined-only --format=posix "${members[@]}") |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" {print $1}' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static_c_abi_exports.txt"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    cmp -s "$expected_path" "$symbols_path" || { diff -u "$expected_path" "$symbols_path" >&2 || true; fail "C ABI export closure drifted"; }
}
assert_fixture_tls_capacity() {
    local filesz memsz alignment
    read -r filesz memsz alignment < <(awk '$1 == "TLS" {print $5,$6,$NF; exit}' "$candidate_program_headers")
    [ -n "${filesz:-}" ] || fail "candidate lacks parsable PT_TLS"
    (( filesz == 0 && memsz > 0 && memsz <= INITIAL_TLS_BYTES )) || fail "PT_TLS exceeds fixture scratch"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT && INITIAL_TLS_ALIGNMENT % alignment == 0 )) || fail "PT_TLS alignment incompatible"
}
assert_capacity_syscall_paths() {
    local statfs_disassembly="$work_dir/statfs-disassembly"
    local fstatfs_disassembly="$work_dir/fstatfs-disassembly"
    objdump -d --disassemble=statfs "$candidate" >"$statfs_disassembly"
    objdump -d --disassemble=fstatfs "$candidate" >"$fstatfs_disassembly"
    grep -Eq '\$0x89,%(e|r)ax' "$statfs_disassembly" || fail "statfs lacks Linux syscall 137"
    grep -Eq '\$0x8a,%(e|r)ax' "$fstatfs_disassembly" || fail "fstatfs lacks Linux syscall 138"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$statfs_disassembly" || fail "statfs lacks syscall"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$fstatfs_disassembly" || fail "fstatfs lacks syscall"
}

require_native_linux_x86_64
for tool in ar awk cargo cat cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_statfs_reference.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_filesystem_capacity_header_abi.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-filesystem-capacity.XXXXXX)"; trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"; archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
candidate="$work_dir/crabc-static-filesystem-capacity-candidate"; header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"; archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"; candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"; candidate_relocations="$work_dir/candidate-relocations"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_filesystem_capacity_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h stdint.h sys/statfs.h sys/statvfs.h sys/syscall.h bits/alltypes.h; do grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project $header"; done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" compat/x86_64/libc_filesystem_capacity_probe.c -o "$work_dir/oracle"
"$work_dir/oracle"
CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit libc.a"
nm -A --defined-only "$archive" >"$archive_symbols"; assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in statfs fstatfs statvfs fstatvfs; do grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive lacks ${symbol}"; done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" || fail "archive lacks initial TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then fail "archive selects dynamic TLS or unowned dependency"; fi
"$ORACLE_CC" -std=c11 -DCRABC_FILESYSTEM_CAPACITY_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined compat/x86_64/libc_filesystem_capacity_probe.c compat/x86_64/libc_filesystem_capacity_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"; readelf --program-headers --wide "$candidate" >"$candidate_program_headers"; readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true; readelf --relocs --wide "$candidate" >"$candidate_relocations"
for symbol in __errno_location statfs fstatfs statvfs fstatvfs; do grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || fail "candidate lacks ${symbol}"; done
for unrelated in stat lstat fstat fstatat open openat close dup dup2 dup3 read write sendfile posix_fadvise readahead; do grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols" && fail "candidate unexpectedly pulls ${unrelated}"; done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 {print}' "$candidate_symbols")"; [ -z "$unresolved_symbols" ] || fail "candidate retains unresolved symbols"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" || grep -Eq 'NEEDED' "$candidate_dynamic"; then fail "candidate selected dynamic runtime"; fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' "$candidate_relocations" "$candidate_symbols"; then fail "candidate retains dynamic TLS"; fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols"; then fail "candidate selects unowned dependency"; fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" || fail "candidate lacks TLS"; assert_fixture_tls_capacity; assert_capacity_syscall_paths
"$candidate"
printf 'x86 static crabc-libc filesystem capacity: PASS\n'
