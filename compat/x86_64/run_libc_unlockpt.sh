#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc unlockpt evidence.
#
# The pinned-musl/project-header fixture proves only the named fixed-request
# PTY lock release: raw EBADF/ENOTTY errors become -1 with errno, and success
# on one fresh devpts master preserves errno and permits a fixture-only peer
# observation. It selects no archive PTY opening, naming, session, terminal,
# or generic ioctl API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc unlockpt: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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

assert_static_closure() {
    local candidate_path="$1"

    readelf --symbols --wide "$candidate_path" >"$symbols"
    readelf --program-headers --wide "$candidate_path" >"$headers"
    readelf --dynamic --wide "$candidate_path" >"$dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$relocs"
    objdump -d "$candidate_path" >"$disassembly"
    objdump -d --disassemble=unlockpt "$candidate_path" >"$unlockpt_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs" "$symbols" "$disassembly"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
        "$symbols" "$disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols" "$disassembly"; then
        fail "candidate selects Rust panic machinery"
    fi
}

assert_candidate_excludes_pty_policy() {
    local symbol

    for symbol in ioctl grantpt posix_openpt ptsname ptsname_r openpty forkpty \
        login_tty vhangup ttyname ttyname_r tcgetattr tcsetattr tcgetpgrp \
        tcsetpgrp tcgetsid isatty open openat read write close; do
        if awk -v symbol="$symbol" '$8 == symbol { found = 1 } END { exit !found }' \
            "$symbols"; then
            fail "candidate accidentally selects ${symbol}"
        fi
    done
    if grep -Eq '(<(grantpt|posix_openpt|ptsname|ptsname_r|openpty|forkpty|login_tty|vhangup|ttyname|ttyname_r|tcgetattr|tcsetattr|tcgetpgrp|tcsetpgrp|tcgetsid|isatty|ioctl|open|read|write|close)>)' \
        "$disassembly"; then
        fail "unlockpt implementation retains an unselected PTY or terminal helper"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_unlockpt_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-unlockpt.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-unlockpt-reference"
candidate="$work_dir/crabc-static-unlockpt-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"; unlockpt_disassembly="$work_dir/unlockpt-disassembly"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_unlockpt_probe.c >/dev/null 2>"$trace"
for header in errno.h fcntl.h stdint.h stdlib.h sys/syscall.h features.h \
    bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_unlockpt_probe.c \
    -o "$reference"
timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl unlockpt fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]__errno_location$' "$archive_symbols" ||
    fail "archive does not define __errno_location"
grep -Eq '[[:space:]][TW][[:space:]]unlockpt$' "$archive_symbols" ||
    fail "archive does not define unlockpt"

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -DCRABC_UNLOCKPT_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_unlockpt_probe.c \
    compat/x86_64/libc_unlockpt_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"
grep -Eq '[[:space:]]unlockpt$' "$symbols" || fail "candidate lacks unlockpt"

grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$unlockpt_disassembly" ||
    fail "unlockpt lacks a direct ioctl syscall"
grep -Eq '\$0x40045431,%esi|\$0x40045431,%rsi' "$unlockpt_disassembly" ||
    fail "unlockpt lacks the fixed TIOCSPTLCK request"
grep -Eq '\$0x10,%eax' "$unlockpt_disassembly" ||
    fail "unlockpt lacks Linux x86-64 ioctl syscall 16"
grep -Eq 'movl[[:space:]]+\$0x0,.*\(%rsp\)' "$unlockpt_disassembly" ||
    fail "unlockpt lacks musl's private zero lock value"
if grep -Eq '\$0x80045430|\$0x5441|\$0x540e|\$0x540f|\$0x5410|\$0x5429' \
    "$unlockpt_disassembly"; then
    fail "unlockpt unexpectedly selects another terminal or PTY request"
fi
assert_candidate_excludes_pty_policy
timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding unlockpt fixture failed"

printf 'x86 static libc unlockpt: PASS\n'
