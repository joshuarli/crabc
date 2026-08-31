#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc timerfd evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static libc timerfd: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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

assert_fixture_tls_capacity() {
    local filesz memsz alignment
    read -r filesz memsz alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( filesz == 0 )) || fail "fixture TLS cannot initialize nonzero PT_TLS data"
    (( memsz > 0 && memsz <= INITIAL_TLS_BYTES )) || fail "fixture TLS scratch is too small"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT && INITIAL_TLS_ALIGNMENT % alignment == 0 )) ||
        fail "fixture TLS alignment is incompatible"
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall 0x${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks its Linux syscall instruction"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_timerfd_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-timerfd.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-timerfd-reference"
candidate="$work_dir/crabc-static-timerfd-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_timerfd_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h poll.h stddef.h stdint.h sys/syscall.h sys/timerfd.h \
    time.h unistd.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    compat/x86_64/libc_timerfd_probe.c -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then :; else status=$?; fail "pinned-musl fixture exited $status"; fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location timerfd_create timerfd_settime timerfd_gettime; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" || fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" || fail "archive errno lacks initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TIMERFD_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_timerfd_probe.c compat/x86_64/libc_timerfd_start.S \
    "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location timerfd_create timerfd_settime timerfd_gettime close fcntl poll read; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" || fail "candidate does not define ${symbol}"
done
for unrelated in timer_create timer_delete timer_getoverrun timer_gettime timer_settime \
    signalfd signalfd4 epoll_create epoll_wait eventfd inotify_init \
    pthread_create pthread_sigmask malloc free calloc realloc getauxval sysconf; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then fail "candidate unexpectedly pulls $unrelated"; fi
done
unresolved="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved" ] || { printf '%s\n' "$unresolved" >&2; fail "candidate retains unresolved symbols"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" || grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" || fail "candidate lacks errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" || fail "candidate errno is not direct initial TLS"

assert_named_syscall timerfd_create 11b
assert_named_syscall timerfd_settime 11e
assert_named_syscall timerfd_gettime 11f
timerfd_settime_disassembly="$work_dir/timerfd-settime-disassembly"
objdump -d --disassemble=timerfd_settime "$candidate" >"$timerfd_settime_disassembly"
grep -Fq '%r10' "$timerfd_settime_disassembly" || fail "timerfd_settime lacks fourth-argument r10 path"

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then :; else status=$?; fail "freestanding fixture exited $status"; fi
printf 'x86 static crabc-libc timerfd: PASS\n'
