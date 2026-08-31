#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc child-reaping evidence.
#
# The same project-header C fixture first runs against pinned musl, then as a
# true `-nostdlib -static` executable linked solely through the selected
# crabc archive. Fixture-local raw clone/pipe/exit cleanup makes child state
# race-free without selecting fork/exec or a general process supervisor.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc child reaping: %s\n' "$*" >&2; exit 1; }
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

assert_named_syscall() {
    local symbol="$1" syscall_word="$2" disassembly="$work_dir/${symbol}-disassembly"
    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}" "$disassembly" \
        || fail "${symbol} lacks the fixed syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" \
        || fail "${symbol} lacks its named Linux syscall"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-child-reaping.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-child-reaping-reference"; candidate="$work_dir/crabc-static-child-reaping-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"; disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_child_reaping_probe.c >/dev/null 2>"$trace"
for header in errno.h signal.h sys/types.h sys/wait.h sys/syscall.h bits/syscall.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" \
        || fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_child_reaping_probe.c -o "$reference"
"$reference" || fail "pinned-musl child-reaping fixture failed"
CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in wait waitpid waitid; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not define $symbol"
done
for unselected in _Fork vfork clone execve wait4 syscall posix_spawn \
    wait3 malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_CHILD_REAPING_FREESTANDING -I"$ROOT_DIR/include" -nostdlib -static \
    -fno-pie -no-pie -ffreestanding -fno-builtin -fno-stack-protector \
    -Wl,-e,_start -Wl,--no-undefined compat/x86_64/libc_child_reaping_probe.c \
    compat/x86_64/libc_child_reaping_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"; readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true; readelf --relocs --wide "$candidate" >"$relocs"; objdump -d "$candidate" >"$disassembly"
for symbol in __errno_location wait waitpid waitid; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then fail "candidate has unresolved symbols"; fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then fail "candidate is dynamic"; fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" || fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' "$relocs" "$symbols" "$disassembly"; then fail "candidate retains a dynamic TLS model"; fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" || fail "candidate errno does not use direct fs initial TLS"
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols" "$disassembly"; then fail "candidate selects unowned runtime symbols"; fi

# wait/waitpid share Linux wait4 (#61, 0x3d). waitid is #247 (0xf7) and its
# direct five-argument ABI must retain the r10/r8 options/rusage path.
assert_named_syscall wait 3d
assert_named_syscall waitpid 3d
assert_named_syscall waitid f7
waitid_disassembly="$work_dir/waitid-disassembly"
objdump -d --disassemble=waitid "$candidate" >"$waitid_disassembly"
for register in '%r10' '%r8'; do
    grep -Fq "$register" "$waitid_disassembly" \
        || fail "waitid lacks the x86 ${register} argument path"
done
"$candidate" || fail "freestanding child-reaping fixture failed"
printf 'x86 static libc child reaping: PASS\n'
