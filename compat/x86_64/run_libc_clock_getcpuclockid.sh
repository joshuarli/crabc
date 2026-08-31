#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc clock_getcpuclockid evidence.
#
# The one-symbol public-header C body first executes through pinned musl 1.2.6
# and then through a true `-nostdlib -static` candidate. It selects only musl's
# process CPU-clock-ID formula and direct status return; it is not a general C
# clock runtime, scheduler, timer, pthread, or signal facility. The final ELF
# must have no PT_TLS/dynamic TLS because this positive-status boundary has no
# errno or bootstrap dependency.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc clock_getcpuclockid: %s\n' "$*" >&2
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

assert_named_syscall() {
    local symbol="$1" syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall 0x${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks its named Linux syscall instruction"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_clock_getcpuclockid_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-clock-getcpuclockid.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-clock-getcpuclockid-reference"
candidate="$work_dir/crabc-static-clock-getcpuclockid-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_clock_getcpuclockid_probe.c \
    >/dev/null 2>"$header_trace"
for header in limits.h stdint.h sys/syscall.h bits/syscall.h time.h features.h \
    bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_clock_getcpuclockid_probe.c -o "$reference"
"$reference" || fail "pinned-musl clock_getcpuclockid fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]clock_getcpuclockid$' "$archive_symbols" ||
    fail "archive does not define clock_getcpuclockid"

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -U_GNU_SOURCE \
    -DCRABC_CLOCK_GETCPUCLOCKID_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_clock_getcpuclockid_probe.c \
    compat/x86_64/libc_clock_getcpuclockid_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in clock_getcpuclockid; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for excluded in __errno_location __crabc_x86_static_tls_bootstrap clock clock_getres \
    clock_gettime clock_settime clock_nanosleep time gettimeofday timespec_get \
    difftime ftime timegm gmtime gmtime_r localtime localtime_r mktime strftime \
    strptime nanosleep sleep usleep alarm ualarm getitimer setitimer timer_create \
    timer_delete timer_getoverrun timer_gettime timer_settime timerfd_create \
    timerfd_settime timerfd_gettime pthread_getcpuclockid pthread_create \
    pthread_sigmask sched_getparam sched_setscheduler sched_yield getpid gettid \
    sigaction signal sigprocmask sigpending sigsuspend sigpause sigtimedwait \
    sigwaitinfo sigwait kill killpg raise sigqueue signalfd signalfd4 malloc free \
    calloc realloc getauxval sysconf; do
    if grep -Eq "[[:space:]]${excluded}$" "$candidate_symbols"; then
        fail "candidate unexpectedly pulls ${excluded}"
    fi
done
unresolved="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved" ] || {
    printf '%s\n' "$unresolved" >&2
    fail "candidate retains an unresolved symbol"
}
if grep -Eq 'Requesting program interpreter|INTERP|[[:space:]]TLS[[:space:]]' \
    "$candidate_program_headers" || grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic or TLS runtime"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains TLS or an unowned runtime dependency"
fi
if grep -Eq 'clock_getres|clock_gettime|clock_settime|clock_nanosleep|[[:space:]]getpid$|[[:space:]]gettid$|pthread_|sig(action|procmask|pending|suspend|wait)|timerfd_|timer_' \
    "$candidate_disassembly"; then
    fail "candidate selects an excluded C runtime seam"
fi
grep -Fq 'call __crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_clock_getcpuclockid_start.S &&
    fail "fixture start must not bootstrap C TLS"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_clock_getcpuclockid_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_named_syscall clock_getcpuclockid e5

"$candidate"
printf 'x86 static crabc-libc clock_getcpuclockid: PASS\n'
