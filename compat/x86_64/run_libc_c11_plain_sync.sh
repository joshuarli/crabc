#!/usr/bin/env bash
# Native Linux/x86-64 bounded static crabc-libc C11 plain-synchronization
# evidence.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It proves only mtx_plain init/destroy/lock/trylock/unlock and
# private cnd init/destroy/wait/signal/broadcast over the selected static
# worker, normal-mutex, and condition engines: held busy trylock, one signal,
# two-waiter broadcast, repeated predicate ping-pong, errno preservation, and
# quiescent destruction. It is not recursive/timed C11 behavior, cancellation,
# TSS, once, dynamic TLS, CRT, loader, sysroot, C11-family completion, or
# public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc C11 plain synchronization: %s\n' "$*" >&2
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

owned_helper_symbol() {
    local helper_leaf="$1"
    local -a helper_addresses
    local helper_symbol

    # `mtx_lock` validates its C11 record before it reaches the shared mutex
    # state-machine body. Resolve that exact outlined Rust body instead of
    # accepting a compare-exchange from an unrelated libc symbol.
    mapfile -t helper_addresses < <(
        nm --demangle --defined-only --numeric-sort "$candidate" |
            awk -v helper_leaf="$helper_leaf" \
                '$2 ~ /^[Tt]$/ && $3 ~ ("::" helper_leaf "$") { print $1 }'
    )
    [ "${#helper_addresses[@]}" -eq 1 ] ||
        fail "expected one owned helper ${helper_leaf}, found ${#helper_addresses[@]}"
    helper_symbol="$(
        nm --defined-only --numeric-sort "$candidate" |
            awk -v address="${helper_addresses[0]}" \
                '$1 == address && $2 ~ /^[Tt]$/ { print $3 }'
    )"
    [ -n "$helper_symbol" ] ||
        fail "cannot resolve ELF symbol for owned helper ${helper_leaf}"
    printf '%s\n' "$helper_symbol"
}

assert_public_reaches_owned_helper() {
    local public_symbol="$1"
    local helper_leaf="$2"
    local helper_symbol
    local disassembly="$work_dir/${public_symbol}-disassembly"

    helper_symbol="$(owned_helper_symbol "$helper_leaf")"
    objdump -d --disassemble="$public_symbol" "$candidate" >"$disassembly"
    if ! awk -v helper_symbol="$helper_symbol" '
        index($0, "<" helper_symbol ">") && $0 ~ /(call|jmp)/ { found = 1 }
        END { exit !found }
    ' "$disassembly"; then
        fail "${public_symbol} does not reach owned helper ${helper_leaf}"
    fi
}

assert_owned_helper_atomic() {
    local helper_leaf="$1"
    local helper_symbol
    local disassembly="$work_dir/${helper_leaf}-disassembly"

    helper_symbol="$(owned_helper_symbol "$helper_leaf")"
    objdump -d --disassemble="$helper_symbol" "$candidate" >"$disassembly"
    grep -Eq 'lock[[:space:]]+cmpxchg' "$disassembly" ||
        fail "owned helper ${helper_leaf} lacks x86 atomic compare-exchange"
    if grep -Eq '%fs:' "$disassembly"; then
        fail "owned helper ${helper_leaf} must not mutate errno TLS"
    fi
}

raw_syscall_helper_symbol() {
    local helper_leaf="$1"
    local -a helper_symbols

    mapfile -t helper_symbols < <(
        nm --defined-only --format=posix "$candidate" |
            awk -v helper_leaf="$helper_leaf" \
                '$1 ~ ("raw_syscall8" helper_leaf) && $2 ~ /^[Tt]$/ { print $1 }'
    )
    [ "${#helper_symbols[@]}" -eq 1 ] ||
        fail "expected one raw syscall helper for ${helper_leaf}, found ${#helper_symbols[@]}"
    printf '%s\n' "${helper_symbols[0]}"
}

# Rust may leave the raw syscall leaf outlined even when the mapped condition
# algorithm is inlined into the public C11 entry. Accept either direct code or
# the exact call to its named raw-syscall helper. This never scans unrelated
# candidate instructions for a futex word or a syscall instruction.
assert_public_or_bound_futex_path() {
    local public_symbol="$1"
    local operation="$2"
    local helper_leaf="$3"
    local public_disassembly="$work_dir/${public_symbol}-${operation}-disassembly"
    local helper_symbol
    local helper_disassembly
    local syscall_disassembly
    local argument_disassembly

    case "$operation" in
        wait)
            operation_direct='\$0x80,%e?si'
            operation_bound='\$0x80,%e?dx'
            ;;
        wake)
            operation_direct='\$0x81,%e?si'
            operation_bound='\$0x81,%e?dx'
            ;;
        requeue)
            operation_direct='\$0x83,%e?si'
            operation_bound='\$0x83,%e?dx'
            ;;
        *) fail "unknown private futex operation ${operation}" ;;
    esac

    objdump -d --disassemble="$public_symbol" "$candidate" >"$public_disassembly"
    if grep -Eq '\<syscall\>' "$public_disassembly"; then
        syscall_disassembly="$public_disassembly"
        argument_disassembly="$public_disassembly"
        grep -Eq '\$0xca,%e?ax' "$argument_disassembly" ||
            fail "${public_symbol} lacks futex syscall number 202"
        grep -Eq "$operation_direct" "$argument_disassembly" ||
            fail "${public_symbol} lacks ${operation} operation in the x86 syscall ABI"
    else
        helper_symbol="$(raw_syscall_helper_symbol "$helper_leaf")"
        if ! awk -v helper_symbol="$helper_symbol" '
            index($0, "<" helper_symbol ">") && $0 ~ /(call|jmp)/ { found = 1 }
            END { exit !found }
        ' "$public_disassembly"; then
            fail "${public_symbol} does not reach exact raw syscall helper ${helper_leaf}"
        fi
        helper_disassembly="$work_dir/${public_symbol}-${helper_leaf}-disassembly"
        objdump -d --disassemble="$helper_symbol" "$candidate" >"$helper_disassembly"
        grep -Eq '\<syscall\>' "$helper_disassembly" ||
            fail "${public_symbol}'s raw syscall helper lacks the x86 syscall instruction"
        syscall_disassembly="$helper_disassembly"
        argument_disassembly="$public_disassembly"
        grep -Eq '\$0xca,%e?di' "$argument_disassembly" ||
            fail "${public_symbol} does not pass futex syscall number 202 to ${helper_leaf}"
        grep -Eq "$operation_bound" "$argument_disassembly" ||
            fail "${public_symbol} does not pass the ${operation} operation to ${helper_leaf}"
    fi

    if [ "$operation" = requeue ]; then
        if [ "$argument_disassembly" = "$public_disassembly" ] &&
            grep -Eq '\<syscall\>' "$public_disassembly"; then
            grep -Eq '\$0x1,%r10(d)?' "$argument_disassembly" ||
                fail "${public_symbol} lacks requeue val2=1 in x86 r10"
        else
            grep -Eq '\$0x1,%r8(d)?' "$argument_disassembly" ||
                fail "${public_symbol} does not pass requeue val2=1 to ${helper_leaf}"
            grep -Eq '%r8' "$syscall_disassembly" ||
                fail "${public_symbol}'s raw syscall helper lacks x86 r10/r8 requeue handoff"
        fi
        grep -Eq '%r8' "$syscall_disassembly" ||
            fail "${public_symbol} lacks requeue uaddr2 handoff through x86 r8"
    fi

    if grep -Eq '%fs:' "$public_disassembly" "$syscall_disassembly"; then
        fail "${public_symbol} futex path must not mutate errno TLS"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_c11_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-c11-plain-sync.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-c11-plain-sync-reference"
candidate="$work_dir/crabc-static-c11-plain-sync-candidate"
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
mutex_unlock_disassembly="$work_dir/mtx-unlock-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_c11_plain_sync_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h threads.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_c11_plain_sync_probe.c \
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
    pthread_create pthread_exit pthread_join pthread_mutex_init \
    pthread_mutex_destroy pthread_mutex_lock pthread_mutex_trylock \
    pthread_mutex_unlock pthread_cond_init pthread_cond_destroy \
    pthread_cond_wait pthread_cond_signal pthread_cond_broadcast \
    thrd_create thrd_join cnd_init cnd_destroy cnd_wait cnd_signal \
    cnd_broadcast mtx_init mtx_destroy mtx_lock mtx_trylock mtx_unlock; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" ||
    fail "archive pthread clone boundary is not hidden"
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
for unselected in mtx_timedlock cnd_timedwait pthread_mutex_timedlock \
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

# The C11 wrapper must use private sibling seams, never exported pthread C
# symbols. Retain this source-level boundary alongside the native fixture.
for required in \
    'pthread_mutex::init_selected_normal_mutex' \
    'pthread_mutex::destroy_selected_normal_mutex' \
    'pthread_mutex::lock_selected_normal_mutex' \
    'pthread_mutex::try_lock_selected_normal_mutex' \
    'pthread_mutex::unlock_selected_normal_mutex' \
    'pthread_cond::init_selected_private_cond' \
    'pthread_cond::destroy_selected_private_cond' \
    'pthread_cond::wait_selected_private_cond' \
    'pthread_cond::signal_selected_private_cond' \
    'pthread_cond::broadcast_selected_private_cond' \
    'MTX_PLAIN' \
    'THRD_BUSY' \
    'mtx_unlock'; do
    grep -Fq "$required" libc/src/c_abi/x86_64/c11_sync.rs ||
        fail "C11 plain-sync source is missing ${required}"
done
if grep -Eq 'pthread_(mutex|cond)_(init|destroy|lock|trylock|unlock|wait|signal|broadcast)\(' \
    libc/src/c_abi/x86_64/c11_sync.rs; then
    fail "C11 plain-sync wrapper crosses an interposable pthread C ABI"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_C11_PLAIN_SYNC_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_c11_plain_sync_probe.c \
    compat/x86_64/libc_c11_plain_sync_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    thrd_create thrd_join cnd_init cnd_destroy cnd_wait cnd_signal \
    cnd_broadcast mtx_init mtx_destroy mtx_lock mtx_trylock mtx_unlock \
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
    compat/x86_64/libc_c11_plain_sync_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_c11_plain_sync_start.S; then
    fail "fixture start must not install a private FS base"
fi
assert_public_reaches_owned_helper mtx_lock lock_selected_normal_mutex_record
assert_owned_helper_atomic lock_selected_normal_mutex_record
objdump -d --disassemble=mtx_unlock "$candidate" \
    >"$mutex_unlock_disassembly"
grep -Eq 'xchg[[:space:]].*\(%r' "$mutex_unlock_disassembly" ||
    fail "mtx_unlock lacks its atomic exchange release"
assert_public_or_bound_futex_path cnd_wait wait syscall4
assert_public_or_bound_futex_path cnd_wait requeue syscall5
assert_public_or_bound_futex_path cnd_signal wake syscall4
assert_public_or_bound_futex_path cnd_broadcast wake syscall4

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

printf 'x86 static crabc-libc C11 plain synchronization: PASS\n'
