#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc ftime evidence.
#
# The one-symbol project-header C body first runs through pinned musl 1.2.6,
# then as a true `-nostdlib -static` candidate. It proves only musl's legacy
# realtime snapshot adapter over the separately selected clock_gettime seam;
# it does not select calendar, timer, signal, or general time runtime policy.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc ftime: %s\n' "$*" >&2
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

assert_direct_raw_syscall_path() {
    local symbol="$1"
    local disassembly="$2"
    local helper
    local helper_disassembly
    local index=0
    local -a helpers

    mapfile -t helpers < <(
        awk '
            /(call|jmp).*<[^>]*raw_syscall[^>]*>/ {
                helper = $0
                sub(/^.*</, "", helper)
                sub(/>.*/, "", helper)
                if (!seen[helper]++) {
                    print helper
                }
            }
        ' "$disassembly"
    )
    for helper in "${helpers[@]}"; do
        helper_disassembly="$work_dir/${symbol}-raw-syscall-${index}-disassembly"
        objdump -d --disassemble="$helper" "$candidate" >"$helper_disassembly"
        grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$helper_disassembly" ||
            fail "${symbol} direct raw-syscall helper lacks syscall instruction"
        index=$((index + 1))
    done
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        [ "${#helpers[@]}" -gt 0 ]; then
        return
    fi
    fail "${symbol} lacks a direct raw-syscall helper edge"
}

assert_archive_public_clock_gettime_edge() {
    awk '
        /^[[:xdigit:]]+ <.*>:/ {
            in_ftime = $0 ~ /<ftime>:/
        }
        in_ftime && /R_X86_64_PLT32[[:space:]]+clock_gettime/ {
            found = 1
        }
        END { exit !found }
    ' "$archive_disassembly" ||
        fail "ftime archive body does not retain its public clock_gettime edge"
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall 0x${syscall_word}"
    assert_direct_raw_syscall_path "$symbol" "$disassembly"
}

assert_ftime_delegation() {
    local disassembly="$work_dir/ftime-disassembly"

    objdump -d --disassemble=ftime "$candidate" >"$disassembly"
    grep -Eq '(call|jmp).*<__clock_gettime>' "$disassembly" ||
        fail "ftime does not directly reach the selected __clock_gettime body"
    assert_named_syscall __clock_gettime e4
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_ftime_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ftime.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-ftime-reference"
candidate="$work_dir/crabc-static-ftime-candidate"
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
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_ftime_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdint.h sys/timeb.h features.h bits/alltypes.h time.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_ftime_probe.c -o "$reference"
"$reference"

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap ftime __clock_gettime clock_gettime; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
assert_archive_public_clock_gettime_edge
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -DCRABC_FTIME_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_ftime_probe.c compat/x86_64/libc_ftime_start.S \
    "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap ftime __clock_gettime clock_gettime; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in clock time timespec_get clock_getres clock_settime gettimeofday \
    difftime timegm gmtime gmtime_r localtime localtime_r mktime strftime strptime \
    asctime asctime_r ctime ctime_r sleep usleep alarm ualarm getitimer setitimer \
    timer_create timer_delete timer_getoverrun timer_gettime timer_settime \
    timerfd_create timerfd_settime timerfd_gettime sigaction signal sigemptyset \
    sigfillset sigaddset sigdelset sigismember sigisemptyset sigandset sigorset \
    sigprocmask sigpending sigsuspend sigpause sigtimedwait sigwaitinfo sigwait \
    kill killpg raise sigqueue signalfd signalfd4 psignal strsignal epoll_create \
    epoll_wait eventfd inotify_init pthread_create pthread_sigmask malloc free \
    calloc realloc getauxval sysconf; do
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
    compat/x86_64/libc_ftime_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_ftime_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_ftime_delegation

"$candidate"
printf 'x86 static crabc-libc ftime: PASS\n'
