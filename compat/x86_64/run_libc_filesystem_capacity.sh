#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc filesystem-capacity evidence.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

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
assert_direct_raw_syscall_path() {
    local symbol="$1"
    local disassembly="$2"
    local helper
    local helper_disassembly
    local index=0
    local -a helpers

    mapfile -t helpers < <(
        awk '
            /(call|jmp).*<[^>]*raw_syscall[^>]*>/ {
                helper = $0
                sub(/^.*</, "", helper)
                sub(/>.*/, "", helper)
                if (!seen[helper]++) {
                    print helper
                }
            }
        ' "$disassembly"
    )
    for helper in "${helpers[@]}"; do
        helper_disassembly="$work_dir/${symbol}-raw-syscall-${index}-disassembly"
        objdump -d --disassemble="$helper" "$candidate" >"$helper_disassembly"
        grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$helper_disassembly" ||
            fail "${symbol} direct raw-syscall helper lacks syscall instruction"
        index=$((index + 1))
    done
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        [ "${#helpers[@]}" -gt 0 ]; then
        return
    fi
    fail "${symbol} lacks a direct raw-syscall helper edge"
}

assert_local_weak_alias_body() {
    local public_symbol="$1"
    local body_symbol="$2"
    local disassembly="$3"
    local body_address body_size body_binding body_visibility body_section
    local public_address public_size public_binding public_visibility public_section
    local body_stop
    local -a body_rows public_rows

    mapfile -t body_rows < <(
        awk -v symbol="$body_symbol" '
            $4 == "FUNC" && $7 != "UND" && $NF == symbol {
                print $2, $3, $5, $6, $7
            }
        ' "$candidate_symbols"
    )
    [ "${#body_rows[@]}" -eq 1 ] ||
        fail "candidate must define exactly one local ${body_symbol} body"
    read -r body_address body_size body_binding body_visibility body_section \
        <<<"${body_rows[0]}"
    [ "$body_binding" = LOCAL ] && [ "$body_visibility" = DEFAULT ] &&
        [ "$body_size" -gt 0 ] ||
        fail "${body_symbol} is not a sized local default body"

    mapfile -t public_rows < <(
        awk -v symbol="$public_symbol" '
            $4 == "FUNC" && $7 != "UND" && $NF == symbol {
                print $2, $3, $5, $6, $7
            }
        ' "$candidate_symbols"
    )
    [ "${#public_rows[@]}" -eq 1 ] ||
        fail "candidate must define exactly one public ${public_symbol} alias"
    read -r public_address public_size public_binding public_visibility public_section \
        <<<"${public_rows[0]}"
    [ "$public_binding" = WEAK ] && [ "$public_visibility" = DEFAULT ] ||
        fail "${public_symbol} is not a weak default alias"
    [ "$public_address" = "$body_address" ] &&
        [ "$public_size" = "$body_size" ] &&
        [ "$public_section" = "$body_section" ] ||
        fail "${public_symbol} is not the same-address ${body_symbol} alias"

    body_stop=$((16#$body_address + body_size))
    objdump -d --start-address="0x$body_address" --stop-address="$body_stop" \
        "$candidate" >"$disassembly"
}

assert_capacity_syscall_paths() {
    local statfs_disassembly="$work_dir/__statfs-disassembly"
    local fstatfs_disassembly="$work_dir/__fstatfs-disassembly"

    assert_local_weak_alias_body statfs __statfs "$statfs_disassembly"
    assert_local_weak_alias_body fstatfs __fstatfs "$fstatfs_disassembly"
    grep -Eq '\$0x89,%(e|r)(ax|di)' "$statfs_disassembly" || fail "__statfs lacks Linux syscall 137"
    grep -Eq '\$0x8a,%(e|r)(ax|di)' "$fstatfs_disassembly" || fail "__fstatfs lacks Linux syscall 138"
    assert_direct_raw_syscall_path __statfs "$statfs_disassembly"
    assert_direct_raw_syscall_path __fstatfs "$fstatfs_disassembly"
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
build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
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
