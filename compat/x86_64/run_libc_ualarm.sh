#!/usr/bin/env bash
# Native Linux/x86-64 opt-in static crabc-libc ualarm evidence.
#
# The one-symbol project-header C body first runs through pinned musl 1.2.6,
# then as a true `-nostdlib -static` candidate linked through only the opt-in
# feature archive. It proves valid microsecond timer replacement/return paths
# and the invalid-field errno/state boundary without assigning a return value
# to musl's uninitialized-old-record failure path.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-ualarm
readonly MUSL_MEMBER=ualarm.lo
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_ualarm_header_abi.sh"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/signal_ualarm.rs"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_ualarm_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_ualarm_start.S"

fail() {
    printf 'ERROR: x86 static libc ualarm: %s\n' "$*" >&2
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

archive_members_for_symbol() {
    local archive_path="$1" symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' | LC_ALL=C sort -u
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

assert_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2" additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "${FEATURE} removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'ualarm\n') "$additions"; then
        diff -u <(printf 'ualarm\n') "$additions" >&2 || true
        fail "${FEATURE} changes more than the one ualarm export"
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

assert_named_syscall() {
    local symbol="$1" syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall 0x${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks its Linux syscall instruction"
}

assert_no_dynamic_tls_or_runtime() {
    local label="$1"
    shift
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$@"; then
        fail "${label} retains dynamic TLS or an unowned runtime dependency"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing default static C ABI export contract"
[ -f "$SOURCE" ] || fail "missing ualarm source owner"
[ -f "$PROBE" ] || fail "missing ualarm fixture"
[ -f "$START" ] || fail "missing ualarm fixture entry"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ualarm.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-ualarm-reference"
candidate="$work_dir/crabc-static-ualarm-candidate"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_object="$work_dir/musl-ualarm.o"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
owner_object="$work_dir/ualarm-owner.o"
owner_symbols="$work_dir/ualarm-owner-symbols"
owner_relocations="$work_dir/ualarm-owner-relocations"
owner_disassembly="$work_dir/ualarm-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" "$MUSL_MEMBER" >"$musl_object"
readelf --symbols --wide "$musl_object" >"$work_dir/musl-ualarm-symbols"
grep -Eq 'FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT.*[[:space:]]ualarm$' \
    "$work_dir/musl-ualarm-symbols" || fail "pinned musl ualarm.lo lacks ualarm"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in errno.h stddef.h unistd.h sys/time.h sys/select.h sys/syscall.h \
    bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture omitted project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" "$PROBE" -o "$reference"
"$reference"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl --features "$FEATURE" -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "baseline cargo build did not emit libc.a"
[ -f "$featured_archive" ] || fail "feature cargo build did not emit libc.a"
collect_global_surface "$baseline_archive" "$baseline_symbols" "$work_dir/baseline-members"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
if grep -Fqx ualarm "$STATIC_C_ABI_EXPORTS"; then
    fail "default static export ratchet absorbed opt-in ualarm"
fi

mapfile -t owner_members < <(archive_members_for_symbol "$featured_archive" ualarm)
[ "${#owner_members[@]}" -eq 1 ] || fail "feature archive has ambiguous ualarm ownership"
ar p "$featured_archive" "${owner_members[0]}" >"$owner_object"
readelf --symbols --wide "$owner_object" >"$owner_symbols"
readelf --relocs --wide "$owner_object" >"$owner_relocations"
objdump -dr "$owner_object" >"$owner_disassembly"
grep -Eq 'FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT.*[[:space:]]ualarm$' "$owner_symbols" ||
    fail "feature owner lacks global-default ualarm"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$owner_relocations" ||
    fail "feature owner lacks direct initial-TLS errno relocation"
assert_no_dynamic_tls_or_runtime "feature owner" \
    "$owner_relocations" "$owner_disassembly" "$owner_symbols"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_UALARM_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$PROBE" "$START" "$featured_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap ualarm; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in alarm getitimer setitimer timer_create timer_delete \
    timer_getoverrun timer_gettime timer_settime timerfd_create timerfd_settime \
    timerfd_gettime sigaction signal sigemptyset sigfillset sigaddset sigdelset \
    sigismember sigisemptyset sigandset sigorset sigprocmask sigpending \
    sigsuspend sigpause sigtimedwait sigwaitinfo sigwait kill killpg raise \
    sigqueue signalfd signalfd4 epoll_create epoll_wait eventfd inotify_init \
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
assert_no_dynamic_tls_or_runtime "candidate" \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno is not direct initial TLS"
grep -Fq 'call __crabc_x86_static_tls_bootstrap' "$START" ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' "$START"; then
    fail "fixture start must not install a private FS base"
fi

assert_named_syscall ualarm 26

"$candidate"
printf 'x86 opt-in static crabc-libc ualarm: PASS\n'
