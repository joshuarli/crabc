#!/usr/bin/env bash
# Native Linux/x86-64 bounded static crabc-libc pthread/C11 once evidence.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It proves only normal-return `pthread_once` and C11 `call_once`:
# four-byte zero/static flags, exactly one initializer, acquire publication of
# a relaxed payload, private-futex contention/wake, and errno preservation.
# It is not cancellation reset, initializer thread exit, recursive entry,
# fork/atfork, TSS, dynamic TLS, a general pthread/C11 runtime, family
# completion, CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc pthread/C11 once: %s\n' "$*" >&2
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

assert_private_once_futex_path() {
    local disassembly="$work_dir/pthread-once-disassembly"

    objdump -d --disassemble=pthread_once "$candidate" >"$disassembly"
    grep -Eq 'lock[[:space:]]+cmpxchg' "$disassembly" ||
        fail "pthread_once lacks its x86 atomic compare-exchange"
    grep -Eq 'xchg[[:space:]].*\(%r' "$disassembly" ||
        fail "pthread_once lacks its atomic exchange release"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "pthread_once lacks a raw x86 futex syscall"
    grep -Eq '\$0xca,%eax|\$0xca,%rax|\$0x00000000000000ca,%rax' \
        "$disassembly" || fail "pthread_once lacks futex syscall number 202"
    grep -Eq '\$0x80,%esi|\$0x80,%rsi' "$disassembly" ||
        fail "pthread_once lacks FUTEX_WAIT_PRIVATE"
    grep -Eq '\$0x81,%esi|\$0x81,%rsi' "$disassembly" ||
        fail "pthread_once lacks FUTEX_WAKE_PRIVATE"
    grep -Eq '\$0x7fffffff,%edx|\$0x7fffffff,%rdx' "$disassembly" ||
        fail "pthread_once does not normalize wake-all to INT_MAX"
    if grep -Eq '%fs:' "$disassembly"; then
        fail "pthread_once must not mutate errno TLS"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sed sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-c11-once.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-c11-once-reference"
candidate="$work_dir/crabc-static-pthread-c11-once-candidate"
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
call_once_disassembly="$work_dir/call-once-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_c11_once_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h threads.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_c11_once_probe.c \
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
    pthread_create pthread_join pthread_mutex_init pthread_mutex_destroy \
    pthread_mutex_lock pthread_mutex_unlock pthread_cond_init \
    pthread_cond_destroy pthread_cond_wait pthread_cond_signal \
    pthread_cond_broadcast pthread_once thrd_create thrd_join call_once; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" ||
    fail "archive pthread clone boundary is not hidden"
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
for unselected in mtx_timedlock cnd_timedwait pthread_mutexattr_init \
    pthread_mutexattr_destroy pthread_mutexattr_settype pthread_mutexattr_gettype \
    pthread_mutex_timedlock pthread_mutex_consistent pthread_condattr_init \
    pthread_condattr_destroy pthread_condattr_setclock pthread_condattr_getclock \
    pthread_condattr_setpshared pthread_condattr_getpshared \
    pthread_cond_timedwait malloc free calloc realloc __tls_get_addr; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

# C11 is a private shared state-machine caller, not an interposable call to
# the POSIX C entry point. Keep the musl source mapping and raw-futex shape
# ratcheted beside the native behavioral fixture.
for required in \
    'src/thread/pthread_once.c::{__pthread_once,__pthread_once_full}' \
    'src/thread/call_once.c' \
    'src/thread/__wait.c::__wait' \
    'src/internal/pthread_impl.h::__wake' \
    'ONCE_INITIALIZING' \
    'ONCE_COMPLETE' \
    'ONCE_WAITERS' \
    'FUTEX_WAIT_PRIVATE' \
    'FUTEX_WAKE_PRIVATE' \
    'c_int::MAX as i64' \
    'run_selected_once' \
    'x86_64_compare_exchange_acqrel_i32' \
    'x86_64_swap_acqrel_i32'; do
    grep -Fq "$required" libc/src/c_abi/x86_64/pthread_once.rs ||
        fail "pthread/C11 once source is missing ${required}"
done
call_once_source="$(sed -n '/pub unsafe extern "C" fn call_once(/,$p' \
    libc/src/c_abi/x86_64/pthread_once.rs)"
printf '%s\n' "$call_once_source" | grep -Fq 'run_selected_once(flag, function)' ||
    fail "call_once does not use the private shared once state machine"
if printf '%s\n' "$call_once_source" | grep -Eq '\bpthread_once[[:space:]]*\('; then
    fail "call_once crosses an interposable pthread C ABI"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_C11_ONCE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_pthread_c11_once_probe.c \
    compat/x86_64/libc_pthread_c11_once_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    pthread_create pthread_join pthread_mutex_init pthread_mutex_destroy \
    pthread_mutex_lock pthread_mutex_unlock pthread_cond_init \
    pthread_cond_destroy pthread_cond_wait pthread_cond_signal \
    pthread_cond_broadcast pthread_once thrd_create thrd_join call_once \
    __crabc_x86_pthread_clone; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
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
    compat/x86_64/libc_pthread_c11_once_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pthread_c11_once_start.S; then
    fail "fixture start must not install a private FS base"
fi
assert_private_once_futex_path
objdump -d --disassemble=call_once "$candidate" >"$call_once_disassembly"
if grep -Eq '(call|jmp).*pthread_once' "$call_once_disassembly"; then
    fail "call_once candidate crosses an interposable pthread C ABI"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

printf 'x86 static crabc-libc pthread/C11 once: PASS\n'
