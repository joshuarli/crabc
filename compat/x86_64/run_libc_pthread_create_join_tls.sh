#!/usr/bin/env bash
# Native Linux/x86-64 bounded static crabc-libc pthread create/exit/join evidence.
#
# The same project-header fixture first runs with pinned musl 1.2.6, then as
# a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It proves one private create/explicit-exit/join worker/TLS lifecycle,
# not a general pthread implementation, C runtime, CRT, loader, or public x86
# support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc pthread create/exit/join TLS: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in ar cargo cmp diff grep mkdir nm objdump readelf rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_types_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-create-join-tls.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-create-join-tls-reference"
candidate="$work_dir/crabc-static-pthread-create-join-tls-candidate"
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
clone_disassembly="$work_dir/pthread-clone-disassembly"
join_disassembly="$work_dir/pthread-join-disassembly"
exit_disassembly="$work_dir/pthread-exit-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_create_join_tls_probe.c >/dev/null 2>"$header_trace"
for header in errno.h pthread.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -pthread -fno-builtin -fno-stack-protector \
    compat/x86_64/libc_pthread_create_join_tls_probe.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location pthread_create pthread_exit pthread_join; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$archive_elf_symbols" \
    || fail "archive pthread clone boundary is not hidden"
for unselected in clone __clone pthread_detach pthread_self pthread_equal \
    pthread_cancel pthread_setcancelstate pthread_setcanceltype pthread_testcancel \
    pthread_key_create pthread_setspecific pthread_getspecific pthread_mutex_init \
    pthread_mutex_lock pthread_mutex_unlock pthread_cond_wait pthread_sigmask \
    malloc free calloc realloc __tls_get_addr; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" \
    || fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PTHREAD_CREATE_JOIN_TLS_FREESTANDING \
    -DCRABC_PTHREAD_CREATE_JOIN_TLS_SELECTED_WORKER_LIMIT=64 \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_pthread_create_join_tls_probe.c \
    compat/x86_64/libc_pthread_create_join_tls_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location pthread_create pthread_exit pthread_join __crabc_x86_pthread_clone; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_pthread_clone$' "$candidate_symbols" \
    || fail "candidate pthread clone boundary is not hidden"
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
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" \
    || fail "candidate errno does not use direct fs initial TLS"
objdump -d --disassemble=__crabc_x86_pthread_clone "$candidate" >"$clone_disassembly"
grep -Eq '\bsyscall\b' "$clone_disassembly" \
    || fail "pthread clone boundary lacks an x86 syscall instruction"
grep -Eq '\$0x38,%al|\$0x0000000000000038,%rax|\$0x38,%rax' "$clone_disassembly" \
    || fail "pthread clone boundary lacks clone syscall number 56"
grep -Eq '0x8\(%rsp\),%r10' "$clone_disassembly" \
    || fail "pthread clone boundary lacks the seventh-argument child-tid shuffle"
grep -Eq '\$0x3c,%al|\$0x000000000000003c,%rax|\$0x3c,%rax' "$clone_disassembly" \
    || fail "pthread clone boundary lacks child exit syscall number 60"
objdump -d --disassemble=pthread_exit "$candidate" >"$exit_disassembly"
grep -Eq '\bsyscall\b' "$exit_disassembly" \
    || fail "pthread_exit lacks an x86 thread-exit syscall instruction"
# The bounded scan is an internal helper called by pthread_exit, so inspect
# the closed candidate rather than requiring the compiler to inline it into
# the public noreturn boundary.
grep -Eq '\$0xba,%al|\$0xba,%eax|\$0xba,%rax|\$0x00000000000000ba,%rax' "$candidate_disassembly" \
    || fail "candidate lacks gettid syscall number 186 identity validation"
grep -Eq '\$0x3c,%eax|\$0x3c,%rax|\$0x000000000000003c,%rax' "$exit_disassembly" \
    || fail "pthread_exit lacks thread exit syscall number 60"
objdump -d --disassemble=pthread_join "$candidate" >"$join_disassembly"
grep -Eq '\bsyscall\b' "$join_disassembly" \
    || fail "pthread_join lacks an x86 futex/munmap syscall instruction"
grep -Eq '\$0xca,%eax|\$0xca,%rax|\$0x00000000000000ca,%rax' "$join_disassembly" \
    || fail "pthread_join lacks futex syscall number 202"
grep -Eq '\$0xb,%eax|\$0xb,%rax|\$0x000000000000000b,%rax' "$join_disassembly" \
    || fail "pthread_join lacks munmap syscall number 11"

"$candidate"

printf 'x86 static crabc-libc pthread create/exit/join TLS: PASS\n'
