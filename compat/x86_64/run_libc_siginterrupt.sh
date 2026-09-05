#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc siginterrupt evidence.
#
# One public XSI wrapper first runs through pinned musl 1.2.6, then through a
# true -nostdlib -static candidate. It toggles only SA_RESTART on an existing
# action; fixture-local raw queries are containment, not public sigaction or a
# general signal runtime. Its raw-syscall provider shares an archive member
# with the separately qualified `sigpending` leaf, so section garbage
# collection keeps that member co-residence from widening this candidate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc siginterrupt: %s\n' "$*" >&2
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
    (( memsz > 0 && memsz <= 4096 )) || fail "fixture TLS scratch is too small"
    (( alignment > 0 && alignment <= 64 && 64 % alignment == 0 )) ||
        fail "fixture TLS alignment is incompatible"
}

# Rust codegen may keep the selected raw leaf out of line. Prove the exact
# siginterrupt-to-syscall4 edge and the provider's instruction rather than
# requiring an implementation-detail inline copy.
assert_siginterrupt_raw_syscall() {
    local siginterrupt_disassembly="$work_dir/siginterrupt-syscall-disassembly"
    local raw_syscall_addresses
    local raw_syscall_address
    local raw_syscall_symbols
    local raw_syscall_symbol
    local raw_syscall_disassembly

    objdump -d --disassemble=siginterrupt "$candidate" >"$siginterrupt_disassembly"
    grep -Eq "\\\$0xd(,|[[:space:]]|\\\$)" "$siginterrupt_disassembly" ||
        fail "siginterrupt lacks Linux syscall 0xd"

    raw_syscall_addresses="$(
        nm -C --defined-only --format=posix "$candidate" |
            awk '$1 == "c::x86_64_static_c_abi::raw_syscall::syscall4" { print $3 }'
    )"
    [ "$(printf '%s\n' "$raw_syscall_addresses" | awk 'NF { count += 1 } END { print count }')" -eq 1 ] ||
        fail "candidate does not select exactly one raw_syscall::syscall4 provider"
    raw_syscall_address="$raw_syscall_addresses"
    raw_syscall_symbols="$(
        nm --defined-only --format=posix "$candidate" |
            awk -v address="$raw_syscall_address" '$3 == address { print $1 }'
    )"
    [ "$(printf '%s\n' "$raw_syscall_symbols" | awk 'NF { count += 1 } END { print count }')" -eq 1 ] ||
        fail "cannot resolve exactly one selected raw_syscall::syscall4 symbol"
    raw_syscall_symbol="$raw_syscall_symbols"

    if ! awk -v target="<${raw_syscall_symbol}>" '
        $0 ~ /[[:space:]](call|jmp[a-z]*)[[:space:]]/ && index($0, target) { found = 1 }
        END { exit !found }
    ' "$siginterrupt_disassembly"; then
        fail "siginterrupt does not call the selected raw_syscall::syscall4 provider"
    fi
    raw_syscall_disassembly="$work_dir/${raw_syscall_symbol}-disassembly"
    objdump -d --disassemble="$raw_syscall_symbol" "$candidate" >"$raw_syscall_disassembly"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$raw_syscall_disassembly" ||
        fail "selected raw_syscall::syscall4 lacks its Linux syscall instruction"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_siginterrupt_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-siginterrupt.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-siginterrupt-reference"
candidate="$work_dir/crabc-static-siginterrupt-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -U_GNU_SOURCE \
    -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_siginterrupt_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h signal.h stddef.h stdint.h sys/syscall.h bits/alltypes.h \
    bits/signal.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -U_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_siginterrupt_probe.c -o "$reference"
"$reference" || fail "pinned-musl siginterrupt fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap siginterrupt; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' \
    "$archive_elf_symbols" || fail "archive Static Initial TLS v1 bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -U_GNU_SOURCE \
    -DCRABC_SIGINTERRUPT_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_siginterrupt_probe.c \
    compat/x86_64/libc_siginterrupt_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap siginterrupt \
    crabc_x86_64_signal_restorer; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in sigaction signal sigemptyset sigfillset sigaddset sigdelset \
    sigismember sigprocmask sigpending sigsuspend sigpause sigtimedwait \
    sigwaitinfo sigwait kill killpg raise sigqueue signalfd signalfd4 \
    timerfd_create timerfd_settime timerfd_gettime pthread_create \
    pthread_sigmask malloc free calloc realloc getauxval sysconf; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls ${unrelated}"
    fi
done
unresolved="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved" ] || {
    printf '%s\n' "$unresolved" >&2
    fail "candidate retains an unresolved symbol"
}
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno is not direct initial TLS"
grep -Fq 'call __crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_siginterrupt_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_siginterrupt_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_siginterrupt_raw_syscall
siginterrupt_disassembly="$work_dir/siginterrupt-disassembly"
objdump -d --disassemble=siginterrupt "$candidate" >"$siginterrupt_disassembly"
grep -Eq '0x10000000|0xebffffff|0xffffffffefffffff' \
    "$siginterrupt_disassembly" ||
    fail "siginterrupt lacks its SA_RESTART set/clear bit path"

"$candidate"
printf 'x86 static crabc-libc siginterrupt: PASS\n'
