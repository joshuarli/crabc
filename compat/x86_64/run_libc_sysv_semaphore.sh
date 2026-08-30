#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc SysV-semaphore evidence.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` candidate linked only with the selected crabc
# archive.  It proves the bounded single-set semget/semop/semtimedop/semctl
# lifecycle, including SETVAL/GETVAL scalar unions, SETALL/GETALL array
# unions, IPC_STAT semid_ds output, direct Linux errno, stale errno after
# success, and explicit IPC_RMID cleanup.  It is not full SysV IPC,
# cross-process coordination, SEM_UNDO, IPC_SET, allocator, CRT, loader,
# sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc SysV semaphore: %s\n' "$*" >&2
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

    # Inspect crate-owned C object members only.  Compiler-builtins is
    # toolchain support, not a selected static C ABI export surface.
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

helper_symbol() {
    local fragment="$1"
    local symbols="$work_dir/${fragment}-symbols"
    local count

    nm --defined-only --format=posix "$candidate" |
        awk -v fragment="$fragment" 'index($1, fragment) && $2 ~ /^[Tt]$/ { print $1 }' \
        >"$symbols"
    count="$(awk 'END { print NR }' "$symbols")"
    [ "$count" -eq 1 ] || {
        awk '{ print }' "$symbols" >&2
        fail "expected exactly one ${fragment} helper symbol"
    }
    awk 'NR == 1 { print; exit }' "$symbols"
}

assert_semctl_dispatch_paths() {
    local dispatcher="$work_dir/semctl-dispatcher-disassembly"
    local no_argument_helper
    local no_argument_disassembly="$work_dir/semctl-no-argument-disassembly"
    local word_helper
    local word_disassembly="$work_dir/semctl-word-disassembly"

    # `semctl` itself is an ABI dispatcher.  SETVAL, GETALL, SETALL, IPC_SET,
    # IPC_INFO, SEM_INFO, IPC_STAT, SEM_STAT, and SEM_STAT_ANY retain the
    # supplied fourth C union word.  Every other command, including the five
    # known no-vararg commands and unknown values, takes the default branch.
    # That branch must occur before Linux so it never reads an unspecified C
    # register; the runtime seccomp regression below proves its r10 result.
    objdump -d --disassemble=semctl "$candidate" >"$dispatcher"
    for command in 0x10 0xd 0x11 0x1 0x3 0x13 0x2 0x12 0x14; do
        grep -Eq "\\\$${command},%edx" "$dispatcher" ||
            fail "semctl lacks union-word command ${command} dispatch"
    done
    grep -Fq 'semctl_no_argument' "$dispatcher" ||
        fail "semctl lacks its no-vararg helper path"
    grep -Fq 'semctl_word' "$dispatcher" ||
        fail "semctl lacks its union-word helper path"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$dispatcher"; then
        fail "semctl dispatcher must not enter Linux before argument dispatch"
    fi

    no_argument_helper="$(helper_symbol semctl_no_argument)"
    objdump -d --disassemble="$no_argument_helper" "$candidate" \
        >"$no_argument_disassembly"
    grep -Eq 'xor[[:space:]]+%ecx,%ecx|mov[[:space:]]+\\$0x0,%ecx' \
        "$no_argument_disassembly" ||
        fail "semctl no-vararg helper does not supply rcx=0"
    grep -Fq 'semctl_word' "$no_argument_disassembly" ||
        fail "semctl no-vararg helper does not reach the union-word helper"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$no_argument_disassembly"; then
        fail "semctl no-vararg helper must delegate its syscall boundary"
    fi

    word_helper="$(helper_symbol semctl_word)"
    objdump -d --disassemble="$word_helper" "$candidate" >"$word_disassembly"
    grep -Eq '\$0x42,%(e|r)ax' "$word_disassembly" ||
        fail "semctl union-word helper lacks Linux semctl=66"
    grep -Fq '%r10' "$word_disassembly" ||
        fail "semctl union-word helper lacks the x86 fourth-argument r10 path"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$word_disassembly" ||
        fail "semctl union-word helper lacks its Linux syscall"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sysv_semaphore_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sysv-semaphore.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-sysv-semaphore-reference"
candidate="$work_dir/crabc-static-sysv-semaphore-candidate"
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

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sysv_semaphore_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdint.h sys/ipc.h sys/sem.h sys/syscall.h sys/types.h \
    time.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_sysv_semaphore_probe.c \
    compat/x86_64/libc_sysv_semaphore_start.S \
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
    semget semop semtimedop semctl; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
for unselected in msgget msgsnd msgrcv msgctl shmget shmat shmdt shmctl \
    ftok sem_close sem_destroy sem_init sem_open sem_post sem_unlink sem_wait \
    sem_trywait sem_timedwait malloc free calloc realloc __tls_get_addr; do
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

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SYSV_SEMAPHORE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_sysv_semaphore_probe.c \
    compat/x86_64/libc_sysv_semaphore_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    semget semop semtimedop semctl; do
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
    compat/x86_64/libc_sysv_semaphore_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_sysv_semaphore_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_named_syscall semget 40
assert_named_syscall semop 41
assert_named_syscall semtimedop dc
assert_semctl_dispatch_paths

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "candidate execution exited ${candidate_status}"
fi

printf 'x86 static crabc-libc SysV semaphore: PASS\n'
