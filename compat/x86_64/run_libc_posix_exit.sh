#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc POSIX _exit evidence.
#
# The same project-header C fixture first runs against pinned musl, then as a
# true `-nostdlib -static` executable linked solely through the selected
# archive. Its local raw clone/wait plumbing observes `_exit` independently of
# ordinary-exit state and without selecting a process-supervision API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc POSIX _exit: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

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

assert_posix_exit_forwarding() {
    local posix_disassembly="$work_dir/posix-exit-disassembly"
    objdump -d --disassemble=_exit "$candidate" >"$posix_disassembly"
    grep -Eq '(call|jmp)[[:space:]].*<_Exit>' "$posix_disassembly" \
        || fail "_exit does not forward directly to _Exit"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$posix_disassembly"; then
        fail "_exit unexpectedly issues a raw syscall"
    fi
}

assert_named_syscall() {
    local syscall_word="$1" disassembly="$work_dir/immediate-termination-disassembly"
    objdump -d --disassemble=_Exit "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}" "$disassembly" \
        || fail "_Exit lacks the fixed syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" \
        || fail "_Exit lacks a Linux syscall instruction"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-exit.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-posix-exit-reference"; candidate="$work_dir/crabc-static-posix-exit-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"; disassembly="$work_dir/candidate-disassembly"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_exit_probe.c >/dev/null 2>"$trace"
for header in unistd.h signal.h bits/signal.h sys/types.h sys/wait.h sys/syscall.h bits/syscall.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" \
        || fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_posix_exit_probe.c -o "$reference"
"$reference" || fail "pinned-musl POSIX _exit fixture failed"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for selected in _exit _Exit; do
    grep -Eq "[[:space:]][TW][[:space:]]${selected}$" "$archive_symbols" \
        || fail "archive does not define ${selected}"
done
for unselected in abort at_quick_exit quick_exit vfork clone execve malloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
"$ORACLE_CC" -std=c11 -DCRABC_POSIX_EXIT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_posix_exit_probe.c \
    compat/x86_64/libc_posix_exit_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"; readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true; readelf --relocs --wide "$candidate" >"$relocs"; objdump -d "$candidate" >"$disassembly"
for selected in _exit _Exit; do
    grep -Eq "[[:space:]]${selected}$" "$symbols" \
        || fail "candidate lacks ${selected}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then fail "candidate has unresolved symbols"; fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then fail "candidate is dynamic"; fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' "$relocs" "$symbols" "$disassembly"; then fail "candidate retains a dynamic TLS model"; fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols" "$disassembly"; then fail "candidate selects unowned runtime symbols"; fi
for unselected in exit atexit __cxa_atexit __funcs_on_exit __cxa_finalize abort at_quick_exit quick_exit; do
    if grep -Eq "[[:space:]]${unselected}$" "$symbols"; then
        fail "candidate unexpectedly selects ordinary-exit state through ${unselected}"
    fi
done

# Musl's POSIX source only forwards to the separately selected C11 leaf. That
# sibling emits Linux exit_group=231 (0xe7), then preserves the defensive
# SYS_exit=60 (0x3c) loop only if whole-process termination returns.
assert_posix_exit_forwarding
assert_named_syscall e7
assert_named_syscall 3c
"$candidate" || fail "freestanding POSIX _exit fixture failed"
printf 'x86 static libc POSIX _exit: PASS\n'
