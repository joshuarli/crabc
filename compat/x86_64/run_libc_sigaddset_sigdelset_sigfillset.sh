#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc signal-set mutation evidence.
#
# The three-symbol POSIX project-header body first executes against pinned musl
# 1.2.6, then as a true `-nostdlib -static` candidate. It proves musl's exact
# first-word fill/add/delete behavior, reserved-signal EINVAL ordering, tail
# sentinels, stale errno, and no call or syscall in the helpers. The C++
# POSIX/GNU feature matrix retains all three C spellings and unmangled linkage.
# This does not select signal delivery, masks, actions, process signaling,
# waits, descriptors, timers, pthread policy, a general signal runtime, or
# public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly CXX_HEADER_PROBE="$ROOT_DIR/compat/x86_64/signal_set_mutation_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 static libc signal-set mutation: %s\n' "$*" >&2
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
    (( memsz > 0 && memsz <= 4096 )) || fail "fixture TLS scratch is too small"
    (( alignment > 0 && alignment <= 64 && 64 % alignment == 0 )) ||
        fail "fixture TLS alignment is incompatible"
}

assert_cxx_header_contract() {
    local profile oracle_object project_object cxx_header_trace undefined symbol
    local -a feature_args

    # C++ POSIX/GNU feature matrix: both profiles must retain the POSIX C
    # declarations, source project signal.h when requested, and emit unmangled
    # references to every selected symbol.
    for profile in posix gnu; do
        case "$profile" in
            posix) feature_args=(-D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE) ;;
            gnu) feature_args=(-D_GNU_SOURCE -U_POSIX_C_SOURCE) ;;
        esac
        oracle_object="$work_dir/oracle-sigset-mutation-${profile}-cxx.o"
        project_object="$work_dir/project-sigset-mutation-${profile}-cxx.o"
        cxx_header_trace="$work_dir/sigset-mutation-${profile}-cxx-header-trace"

        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
            -DCRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION -fno-builtin -fsyntax-only \
            "$CXX_HEADER_PROBE"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
            -DCRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION -fno-builtin -I"$ROOT_DIR/include" \
            -H -fsyntax-only "$CXX_HEADER_PROBE" >/dev/null 2>"$cxx_header_trace"
        grep -Fq "$ROOT_DIR/include/signal.h" "$cxx_header_trace" ||
            fail "${profile} C++ probe did not use the project signal header"

        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
            -DCRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION -fno-builtin -c "$CXX_HEADER_PROBE" \
            -o "$oracle_object"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
            -DCRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION -fno-builtin -I"$ROOT_DIR/include" \
            -c "$CXX_HEADER_PROBE" -o "$project_object"
        for object in "$oracle_object" "$project_object"; do
            undefined="$(nm --undefined-only "$object")"
            for symbol in sigaddset sigdelset sigfillset; do
                printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
                    fail "${profile} C++ probe did not retain unmangled ${symbol}"
                if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
                    fail "${profile} C++ probe retained a mangled ${symbol} reference"
                fi
            done
        done
    done
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$CXX_HEADER_PROBE" ] || fail "missing C++ signal-set mutation header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_signal_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sigset-mutation.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sigset-mutation-reference"
candidate="$work_dir/crabc-static-sigset-mutation-candidate"
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

assert_cxx_header_contract

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_probe.c >/dev/null 2>"$header_trace"
for header in errno.h signal.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_probe.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap sigaddset sigdelset sigfillset; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi
for symbol in sigaddset sigdelset sigfillset; do
    objdump -d --disassemble="$symbol" "$archive" >"$work_dir/archive-${symbol}-disassembly"
    if grep -Eq '[[:space:]](call|callq|syscall)([[:space:]]|$)' \
        "$work_dir/archive-${symbol}-disassembly"; then
        fail "archive ${symbol} must remain a direct no-call/no-syscall helper"
    fi
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -DCRABC_SIGSET_MUTATION_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_probe.c \
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_start.S "$archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap sigaddset sigdelset sigfillset; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in sigaction signal sigemptyset sigismember sigisemptyset sigandset \
    sigorset sigprocmask sigpending sigsuspend sigpause sigtimedwait sigwaitinfo \
    sigwait kill killpg raise sigqueue signalfd signalfd4 timerfd_create \
    timerfd_settime timerfd_gettime epoll_create epoll_wait eventfd inotify_init \
    pthread_create pthread_sigmask malloc free calloc realloc getauxval sysconf; do
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
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_sigaddset_sigdelset_sigfillset_start.S; then
    fail "fixture start must not install a private FS base"
fi
for symbol in sigaddset sigdelset sigfillset; do
    objdump -d --disassemble="$symbol" "$candidate" >"$work_dir/${symbol}-disassembly"
    if grep -Eq '[[:space:]](call|callq|syscall)([[:space:]]|$)' \
        "$work_dir/${symbol}-disassembly"; then
        fail "candidate ${symbol} must remain a direct no-call/no-syscall helper"
    fi
done

"$candidate"
printf 'x86 static crabc-libc signal-set mutation: PASS\n'
