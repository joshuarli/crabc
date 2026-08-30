#!/usr/bin/env bash
# Native Linux/x86-64 static crabc-libc pthread read/write-lock evidence.
#
# The same project-header fixture first executes with pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked solely through the selected
# crabc archive.  It proves the complete rwlock and rwlockattr family,
# same-address weak aliases, timed status behavior, private reader/writer
# contention, and cross-process shared-futex wakeups.  It remains one private
# artifact within planned `libc.pthread-tls`, not full pthread/TLS, C runtime,
# sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=30s

fail() {
    printf 'ERROR: x86 static libc pthread rwlock: %s\n' "$*" >&2
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

symbol_value() {
    local symbols_path="$1"
    local symbol="$2"

    awk -v symbol="$symbol" '$NF == symbol && $4 == "FUNC" { print $2; exit }' \
        "$symbols_path"
}

assert_weak_hidden_alias_pair() {
    local symbols_path="$1"
    local hidden_symbol="$2"
    local public_symbol="$3"
    local hidden_value
    local public_value

    grep -Eq "GLOBAL +HIDDEN +.*${hidden_symbol}$" "$symbols_path" ||
        fail "${hidden_symbol} is not a hidden global function"
    grep -Eq "WEAK +DEFAULT +.*${public_symbol}$" "$symbols_path" ||
        fail "${public_symbol} is not a weak default function"
    hidden_value="$(symbol_value "$symbols_path" "$hidden_symbol")"
    public_value="$(symbol_value "$symbols_path" "$public_symbol")"
    [ -n "$hidden_value" ] || fail "${hidden_symbol} has no ELF value"
    [ "$hidden_value" = "$public_value" ] ||
        fail "${public_symbol} is not the same-address alias of ${hidden_symbol}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-rwlock.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-rwlock-reference"
candidate="$work_dir/crabc-static-pthread-rwlock-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
tryread_disassembly="$work_dir/rwlock-tryread-disassembly"
unlock_disassembly="$work_dir/rwlock-unlock-disassembly"
timedwait_disassembly="$work_dir/rwlock-timedwait-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_rwlock_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h time.h sys/mman.h sys/syscall.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_rwlock_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    reference_status=$?
    fail "pinned-musl reference execution exited ${reference_status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_join pthread_rwlock_init pthread_rwlock_destroy \
    pthread_rwlock_rdlock pthread_rwlock_tryrdlock pthread_rwlock_timedrdlock \
    pthread_rwlock_wrlock pthread_rwlock_trywrlock pthread_rwlock_timedwrlock \
    pthread_rwlock_unlock pthread_rwlockattr_init pthread_rwlockattr_destroy \
    pthread_rwlockattr_setpshared pthread_rwlockattr_getpshared \
    __pthread_rwlock_rdlock __pthread_rwlock_tryrdlock \
    __pthread_rwlock_timedrdlock __pthread_rwlock_wrlock \
    __pthread_rwlock_trywrlock __pthread_rwlock_timedwrlock \
    __pthread_rwlock_unlock; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for pair in \
    '__pthread_rwlock_rdlock pthread_rwlock_rdlock' \
    '__pthread_rwlock_tryrdlock pthread_rwlock_tryrdlock' \
    '__pthread_rwlock_timedrdlock pthread_rwlock_timedrdlock' \
    '__pthread_rwlock_wrlock pthread_rwlock_wrlock' \
    '__pthread_rwlock_trywrlock pthread_rwlock_trywrlock' \
    '__pthread_rwlock_timedwrlock pthread_rwlock_timedwrlock' \
    '__pthread_rwlock_unlock pthread_rwlock_unlock'; do
    set -- $pair
    assert_weak_hidden_alias_pair "$archive_elf_symbols" "$1" "$2"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_RWLOCK_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_rwlock_probe.c \
    compat/x86_64/libc_pthread_rwlock_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_join pthread_rwlock_init pthread_rwlock_destroy \
    pthread_rwlock_rdlock pthread_rwlock_tryrdlock pthread_rwlock_timedrdlock \
    pthread_rwlock_wrlock pthread_rwlock_trywrlock pthread_rwlock_timedwrlock \
    pthread_rwlock_unlock pthread_rwlockattr_init pthread_rwlockattr_destroy \
    pthread_rwlockattr_setpshared pthread_rwlockattr_getpshared \
    __pthread_rwlock_rdlock __pthread_rwlock_tryrdlock \
    __pthread_rwlock_timedrdlock __pthread_rwlock_wrlock \
    __pthread_rwlock_trywrlock __pthread_rwlock_timedwrlock \
    __pthread_rwlock_unlock __crabc_x86_pthread_clone; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for pair in \
    '__pthread_rwlock_rdlock pthread_rwlock_rdlock' \
    '__pthread_rwlock_tryrdlock pthread_rwlock_tryrdlock' \
    '__pthread_rwlock_timedrdlock pthread_rwlock_timedrdlock' \
    '__pthread_rwlock_wrlock pthread_rwlock_wrlock' \
    '__pthread_rwlock_trywrlock pthread_rwlock_trywrlock' \
    '__pthread_rwlock_timedwrlock pthread_rwlock_timedwrlock' \
    '__pthread_rwlock_unlock pthread_rwlock_unlock'; do
    set -- $pair
    assert_weak_hidden_alias_pair "$candidate_symbols" "$1" "$2"
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
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_pthread_rwlock_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pthread_rwlock_start.S; then
    fail "fixture start must not install a private FS base"
fi
objdump -d --disassemble=__pthread_rwlock_tryrdlock "$candidate" \
    >"$tryread_disassembly"
grep -Eq 'lock[[:space:]]+cmpxchg' "$tryread_disassembly" ||
    fail "pthread_rwlock_tryrdlock lacks its x86 atomic compare-exchange"
objdump -d --disassemble=__pthread_rwlock_unlock "$candidate" \
    >"$unlock_disassembly"
grep -Eq 'lock[[:space:]]+cmpxchg' "$unlock_disassembly" ||
    fail "pthread_rwlock_unlock lacks its x86 atomic compare-exchange"
grep -Eq '\$0xca,%eax|\$0xca,%rax|\$0x00000000000000ca,%rax' \
    "$unlock_disassembly" ||
    fail "pthread_rwlock_unlock lacks futex syscall number 202"
timedwait_symbol="$(nm -g --defined-only "$candidate" |
    awk '$3 ~ /pthread_rwlock16timed_futex_wait$/ { print $3; exit }')"
[ -n "$timedwait_symbol" ] || fail "candidate lacks the private timed-futex helper"
objdump -d --disassemble="$timedwait_symbol" "$candidate" >"$timedwait_disassembly"
grep -Eq '\$0xca,%eax|\$0xca,%rax|\$0x00000000000000ca,%rax' \
    "$timedwait_disassembly" ||
    fail "rwlock timed wait lacks futex syscall number 202"
grep -Eq '\$0xe4,%eax|\$0xe4,%rax|\$0x00000000000000e4,%rax' \
    "$timedwait_disassembly" ||
    fail "rwlock timed wait lacks clock_gettime syscall number 228"

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

printf 'x86 static crabc-libc pthread rwlock: PASS\n'
