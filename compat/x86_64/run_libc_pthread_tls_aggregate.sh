#!/usr/bin/env bash
# Native Linux/x86-64 composed static crabc-libc pthread/TLS evidence.
#
# The same project-header C body runs against pinned musl 1.2.6 and then a
# true dependency-free `-nostdlib -static` candidate.  It composes selected
# worker/TLS, normal mutex/condition, rwlock, once, and TSD leaves without
# extending any of their deliberately bounded contracts.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() { printf 'ERROR: x86 static libc pthread/TLS aggregate: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)";; esac
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
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

extract_candidate_disassembly() {
    local symbol_pattern="$1"
    local destination="$2"

    awk -v symbol_pattern="$symbol_pattern" '
        $0 ~ "<.*" symbol_pattern ".*>:" { found = 1 }
        found { print }
        found && /^$/ { exit }
        END { exit !found }
    ' "$candidate_disassembly" >"$destination" ||
        fail "candidate lacks disassembly for ${symbol_pattern}"
}

assert_raw_syscall4_abi() {
    # The generic raw boundary may be out-of-line when this composition grows.
    # Check its exact Linux x86-64 ABI once rather than making each public
    # pthread entry's syscall proof depend on optimizer inlining.
    if [ -f "$raw_syscall4_disassembly" ]; then
        return
    fi
    extract_candidate_disassembly 'raw_syscall.*syscall4' "$raw_syscall4_disassembly"
    grep -Eq '\bsyscall\b' "$raw_syscall4_disassembly" ||
        fail "raw four-argument syscall boundary lacks syscall instruction"
    grep -Eq 'mov.*%rdi,%rax' "$raw_syscall4_disassembly" ||
        fail "raw four-argument syscall boundary does not route number to rax"
    grep -Eq 'mov.*%r8,%r10' "$raw_syscall4_disassembly" ||
        fail "raw four-argument syscall boundary does not route argument four to r10"
}

assert_futex_in_boundary() {
    local label="$1"
    local disassembly="$2"

    if grep -Eq '\bsyscall\b' "$disassembly"; then
        grep -Eq '\$0xca,%(eax|rax)' "$disassembly" ||
            fail "${label} direct futex boundary lacks futex=202"
        grep -Eq '%r10(d)?' "$disassembly" ||
            fail "${label} direct futex boundary lacks fourth-argument r10 evidence"
        return
    fi
    grep -Eq 'call.*raw_syscall.*syscall4' "$disassembly" ||
        fail "${label} does not reach a direct or generic futex syscall boundary"
    grep -Eq '\$0xca,%edi' "$disassembly" ||
        fail "${label} generic futex call lacks futex=202 in syscall-number argument"
    grep -Eq '%r8(d)?' "$disassembly" ||
        fail "${label} generic futex call lacks fourth-argument source evidence"
    assert_raw_syscall4_abi
}

assert_selected_futex_boundary() {
    local symbol="$1"
    local private_pattern="$2"
    local public_disassembly="$work_dir/${symbol}-disassembly"
    local private_disassembly="$work_dir/${symbol}-private-futex-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$public_disassembly"
    if grep -Eq '\bsyscall\b|call.*raw_syscall.*syscall4' "$public_disassembly"; then
        assert_futex_in_boundary "$symbol" "$public_disassembly"
        return
    fi

    # A selected public entry may retain only its C-object admission and call
    # an explicit private state-machine body. Follow that named edge, then
    # prove the body reaches the futex boundary with the same number/register
    # checks. This keeps the machine-code contract stable across legal
    # cross-item inlining decisions without accepting an arbitrary call graph.
    grep -Eq "call.*${private_pattern}" "$public_disassembly" ||
        fail "${symbol} no longer reaches its selected private futex state machine"
    extract_candidate_disassembly "$private_pattern" "$private_disassembly"
    assert_futex_in_boundary "${symbol} selected private state machine" "$private_disassembly"
}

require_native_linux_x86_64
for tool in ar cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-tls-aggregate.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-tls-aggregate-reference"
candidate="$work_dir/crabc-static-pthread-tls-aggregate-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
raw_syscall4_disassembly="$work_dir/raw-syscall4-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_tls_aggregate_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_tls_aggregate_probe.c -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    reference_status=$?
    fail "pinned-musl reference exited ${reference_status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap pthread_create pthread_join \
    pthread_mutex_lock pthread_mutex_unlock pthread_cond_wait pthread_cond_signal \
    pthread_cond_broadcast pthread_rwlock_rdlock pthread_rwlock_trywrlock \
    pthread_rwlock_wrlock pthread_rwlock_unlock pthread_once pthread_key_create \
    pthread_key_delete pthread_getspecific pthread_setspecific; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive does not define ${symbol}"
done
for unselected in pthread_cond_timedwait pthread_mutex_timedlock __tls_get_addr \
    malloc free calloc realloc; do
    ! grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols" || fail "archive exports unselected ${unselected}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" || fail "clone boundary is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_TLS_AGGREGATE_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_tls_aggregate_probe.c \
    compat/x86_64/libc_pthread_tls_aggregate_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __crabc_x86_static_tls_bootstrap pthread_create pthread_join pthread_once \
    pthread_cond_wait pthread_rwlock_trywrlock pthread_key_create; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
! grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" || fail "candidate selected dynamic interpreter"
! grep -Eq 'NEEDED' "$candidate_dynamic" || fail "candidate selected dynamic dependency"
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" || fail "candidate lacks initial TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects dynamic TLS or unowned runtime dependency"
fi
assert_selected_futex_boundary \
    pthread_mutex_lock 'pthread_mutex.*lock_selected_normal_mutex_record'
assert_selected_futex_boundary pthread_cond_wait 'pthread_cond.*wait_selected_private_cond'
assert_selected_futex_boundary pthread_join 'pthread_create_join.*join_selected_worker'
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" || fail "candidate errno lacks direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' compat/x86_64/libc_pthread_tls_aggregate_start.S || fail "start does not delegate TLS bootstrap to libc"

timeout "$EXECUTION_TIMEOUT" "$candidate" || fail "static candidate failed"
printf 'x86 static crabc-libc pthread/TLS aggregate: PASS\n'
