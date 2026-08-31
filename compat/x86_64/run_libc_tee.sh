#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc tee evidence.
#
# The pinned-musl/project-header fixture proves only direct Linux pipe-buffer
# duplication: source bytes remain readable after an equal copy reaches a
# second pipe, zero length preserves errno, and a bad source descriptor maps
# to EBADF. Fixture-local pipe setup is evidence plumbing, not a selected
# pipe, descriptor, splice, cancellation, or I/O policy surface.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc tee: %s\n' "$*" >&2
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
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local filesz memsz alignment

    read -r filesz memsz alignment < <(awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers")
    [ -n "${filesz:-}" ] || fail "candidate lacks parsable PT_TLS"
    (( filesz == 0 && memsz > 0 && memsz <= INITIAL_TLS_BYTES )) ||
        fail "PT_TLS exceeds fixture scratch"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT && INITIAL_TLS_ALIGNMENT % alignment == 0 )) ||
        fail "PT_TLS alignment incompatible"
}

assert_tee_syscall_path() {
    objdump -d --disassemble=tee "$candidate" >"$tee_disassembly"
    grep -Eq '\$0x114,%(e|r)ax' "$tee_disassembly" ||
        fail "tee lacks Linux syscall 276"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tee_disassembly" ||
        fail "tee lacks a direct syscall"
}

assert_static_closure() {
    readelf --symbols --wide "$candidate" >"$candidate_symbols"
    readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
    readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
    readelf --relocs --wide "$candidate" >"$candidate_relocations"
    objdump -d "$candidate" >"$candidate_disassembly"

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
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$candidate_symbols" "$candidate_disassembly"; then
        fail "candidate selects an unowned runtime or panic dependency"
    fi
}

assert_candidate_excludes_descriptor_policy() {
    local symbol

    for symbol in fcntl open openat close dup dup2 dup3 read write pipe pipe2 \
        splice vmsplice sendfile copy_file_range readahead sync_file_range; do
        if awk -v symbol="$symbol" '$8 == symbol { found = 1 } END { exit !found }' \
            "$candidate_symbols"; then
            fail "candidate accidentally selects ${symbol}"
        fi
    done
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_tee_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-tee.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-tee-reference"
candidate="$work_dir/crabc-static-tee-candidate"
header_trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"; candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"; candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"; tee_disassembly="$work_dir/tee-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_tee_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h sys/types.h sys/syscall.h features.h bits/fcntl.h \
    bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_tee_probe.c -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" || fail "pinned-musl tee fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]__errno_location$' "$archive_symbols" ||
    fail "archive does not define __errno_location"
grep -Eq '[[:space:]][TW][[:space:]]tee$' "$archive_symbols" ||
    fail "archive does not define tee"
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive lacks initial TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TEE_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_tee_probe.c compat/x86_64/libc_tee_start.S \
    "$archive" -o "$candidate"
assert_static_closure
for symbol in __errno_location tee; do
    grep -Eq "[[:space:]]$symbol$" "$candidate_symbols" ||
        fail "candidate lacks $symbol"
done
assert_fixture_tls_capacity
assert_tee_syscall_path
assert_candidate_excludes_descriptor_policy
timeout "$EXECUTION_TIMEOUT" "$candidate" || fail "freestanding tee fixture failed"

printf 'x86 static crabc-libc tee: PASS\n'
