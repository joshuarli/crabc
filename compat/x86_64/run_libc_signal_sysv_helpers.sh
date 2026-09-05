#!/usr/bin/env bash
# Native Linux/x86-64 opt-in SysV signal-helper evidence.
#
# The same project-header XSI fixture first runs through pinned musl 1.2.6,
# then through an opt-in `-nostdlib -static` crabc candidate. This private
# artifact can add exactly sighold, sigignore, sigrelse, and sigset. It does not select process.signal,
# a general signal-control API, pthread policy, or a public x86 support claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-signal-sysv-helpers
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXPECTED_ADDITIONS=(sighold sigignore sigrelse sigset)

fail() {
    printf 'ERROR: x86 static libc SysV signal helpers: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
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
    local disassembly="$work_dir/${symbol}-${syscall_word}-disassembly"
    local trampoline

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    if ! grep -Eq '\$0x'"$syscall_word"'(,|[[:space:]]|\$)' "$disassembly"; then
        grep -En 'syscall|0x[de]' "$disassembly" >&2 || true
        fail "$symbol lacks Linux syscall 0x${syscall_word}"
    fi
    if ! grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly"; then
        # LLVM may retain the existing private syscall4 leaf instead of
        # inlining it. Follow only that exact direct target; arbitrary calls
        # cannot substitute for the named Linux syscall proof.
        trampoline="$(sed -nE 's/.*call[[:space:]]+[[:xdigit:]]+ <([^>]*11raw_syscall8syscall4[^>]*)>.*/\1/p' "$disassembly" | sort -u)"
        [ -n "$trampoline" ] && [[ "$trampoline" != *$'\n'* ]] || {
            cat "$disassembly" >&2
            fail "$symbol has neither an inline syscall nor one private syscall4 target"
        }
        objdump -d --disassemble="$trampoline" "$candidate" >"$disassembly.trampoline"
        grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly.trampoline" ||
            fail "$symbol private syscall4 target lacks its Linux syscall instruction"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sed sort uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_signal_sysv_helpers_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-signal-sysv-helpers.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
base_target="$work_dir/base-target"
feature_target="$work_dir/feature-target"
base_archive="$base_target/x86_64-unknown-linux-musl/debug/libc.a"
archive="$feature_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-signal-sysv-helpers-reference"
candidate="$work_dir/crabc-static-signal-sysv-helpers-candidate"
header_trace="$work_dir/header-trace"
base_surface="$work_dir/base-surface"
feature_surface="$work_dir/feature-surface"
expected_surface="$work_dir/expected-surface"
expected_feature_surface="$work_dir/expected-feature-surface"
observed_additions="$work_dir/observed-additions"
expected_additions="$work_dir/expected-additions"
archive_symbols="$work_dir/archive-symbols"
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
    -I "$ROOT_DIR/include" -E -H compat/x86_64/libc_signal_sysv_helpers_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h signal.h stddef.h stdint.h sys/syscall.h bits/alltypes.h \
    bits/signal.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -U_GNU_SOURCE \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_signal_sysv_helpers_probe.c -o "$reference"
"$reference" || fail "pinned-musl SysV signal-helper fixture failed"

# The default archive is frozen. Only the opt-in feature may add this exact
# four-symbol legacy closure; it must not widen default selected-static ABI.
CARGO_TARGET_DIR="$base_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$base_archive" ] || fail "cargo did not emit unfeatured x86 archive"
collect_global_surface "$base_archive" "$base_surface" "$work_dir/base-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_surface"
if ! cmp -s "$expected_surface" "$base_surface"; then
    diff -u "$expected_surface" "$base_surface" >&2 || true
    fail "unfeatured selected-static C ABI export surface drifted"
fi
for symbol in "${EXPECTED_ADDITIONS[@]}"; do
    if grep -Fxq "$symbol" "$base_surface"; then
        fail "unfeatured archive unexpectedly exposes opt-in $symbol"
    fi
done

CARGO_TARGET_DIR="$feature_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit opt-in x86 archive"
collect_global_surface "$archive" "$feature_surface" "$work_dir/feature-members"
comm -13 "$base_surface" "$feature_surface" >"$observed_additions"
printf '%s\n' "${EXPECTED_ADDITIONS[@]}" | LC_ALL=C sort -u >"$expected_additions"
if ! cmp -s "$expected_additions" "$observed_additions"; then
    diff -u "$expected_additions" "$observed_additions" >&2 || true
    fail "opt-in SysV signal helpers changed more than their exact public closure"
fi
LC_ALL=C sort -u "$base_surface" "$expected_additions" >"$expected_feature_surface"
if ! cmp -s "$expected_feature_surface" "$feature_surface"; then
    diff -u "$expected_feature_surface" "$feature_surface" >&2 || true
    fail "opt-in SysV signal helpers did not preserve frozen export surface"
fi

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
for symbol in sighold sigignore sigrelse sigset; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define $symbol"
done
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "feature archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -U_GNU_SOURCE \
    -DCRABC_SIGNAL_SYSV_HELPERS_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_signal_sysv_helpers_probe.c \
    compat/x86_64/libc_signal_sysv_helpers_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in _start __errno_location __crabc_x86_static_tls_bootstrap \
    sighold sigignore sigrelse sigset crabc_x86_64_signal_restorer; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define required $symbol"
done
for unrelated in sigaction signal sigemptyset sigfillset sigaddset sigdelset \
    sigismember sigprocmask sigpending sigsuspend sigpause sigtimedwait \
    sigwaitinfo sigwait kill killpg raise sigqueue signalfd signalfd4 \
    pthread_sigmask pthread_kill malloc free calloc realloc getauxval sysconf; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "SysV signal-helper candidate unexpectedly pulls $unrelated"
    fi
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno initial TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an ambient runtime fallback"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno is not direct initial TLS"
grep -Fq 'call __crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_signal_sysv_helpers_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_signal_sysv_helpers_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_named_syscall sighold e
assert_named_syscall sigrelse e
assert_named_syscall sigignore d
assert_named_syscall sigset d
assert_named_syscall sigset e

"$candidate" || fail "freestanding SysV signal-helper candidate failed"
printf 'x86 static crabc-libc SysV signal helpers: PASS\n'
