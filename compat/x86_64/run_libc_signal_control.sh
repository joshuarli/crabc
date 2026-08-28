#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc signal-control evidence.
#
# The same project-header C fixture first runs against pinned musl, then as a
# true `-nostdlib -static` executable linked solely through the selected
# crabc `libc.a`. It proves only simple signal action/set/mask/pending behavior,
# including musl's partial output writes and `sigaction`'s exact hidden
# syscall-15 restorer relocation. It is not a process-signal capability,
# libc.so, general C runtime, CRT, pthread/TLS lifecycle, loader, or sysroot.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc signal control: %s\n' "$*" >&2
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
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    # `libc/Cargo.toml` fixes the Rust staticlib crate name to `c`. Its archive
    # also contains compiler-builtins members, which are toolchain support and
    # not crabc's C ABI surface. Inspect only the `c.*.rcgu.o` members so this
    # gate catches a new C export from the selected runtime. The signal
    # restorer is the one audited hidden frame-internal exception.
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff nm objdump readelf rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-signal-control.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-signal-control-reference"
candidate="$work_dir/crabc-static-signal-control-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
restorer_disassembly="$work_dir/restorer-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_signal_control_probe.c >/dev/null 2>"$header_trace"
for header in errno.h signal.h sys/syscall.h bits/syscall.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    compat/x86_64/libc_signal_control_probe.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location __libc_current_sigrtmax sigaction signal \
    sigemptyset sigfillset sigaddset sigdelset sigismember sigprocmask sigpending; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*crabc_x86_64_signal_restorer$' "$archive_elf_symbols" \
    || fail "archive restorer is not hidden from a public dynamic surface"
if grep -Eq '[[:space:]][TW][[:space:]]crabc_x86_64_signal_action_pack$' \
    "$archive_symbols"; then
    fail "archive accidentally exports the source-only signal packing bridge"
fi
# `sigsuspend` is owned by the separately selected readiness/signal-waits
# artifact in this shared archive; the remaining signal waits stay unselected.
for unselected in syscall malloc free calloc realloc pthread_create raise kill tgkill \
    sigtimedwait sigwaitinfo sigwait sigaltstack sigqueue pthread_sigmask \
    signalfd; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" \
    || fail "archive errno lacks an initial-TLS TPOFF relocation"
# Rust's static object retains a local DTPOFF link relocation for ERRNO. The
# final static candidate must resolve it, and rejects every TLS model below;
# an archive-level DTPOFF match alone is not dynamic TLS.
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi
# The shared `sigaction_impl` must materialize the exact hidden restorer
# address, rather than merely retaining an unrelated syscall-15 symbol in the
# archive. The candidate execution below then proves a delivered handler
# returns through that installed trampoline.
awk '
    /^[[:xdigit:]]+ <.*>:/ {
        in_sigaction_impl = $0 ~ /signal_control.*sigaction_impl/
    }
    in_sigaction_impl && /R_X86_64_32S[[:space:]]+crabc_x86_64_signal_restorer/ {
        found = 1
    }
    END { exit !found }
' "$archive_disassembly" \
    || fail "sigaction implementation does not install the hidden restorer"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SIGNAL_CONTROL_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_signal_control_probe.c \
    compat/x86_64/libc_signal_control_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __libc_current_sigrtmax sigaction signal \
    sigemptyset sigfillset sigaddset sigdelset sigismember sigprocmask sigpending \
    crabc_x86_64_signal_restorer; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate does not define ${symbol}"
done
grep -Eq 'GLOBAL +HIDDEN +.*crabc_x86_64_signal_restorer$' "$candidate_symbols" \
    || fail "candidate restorer is not hidden from a public dynamic surface"
if grep -Eq '[[:space:]]crabc_x86_64_signal_action_pack$' "$candidate_symbols"; then
    fail "candidate retains the source-only signal packing bridge"
fi
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" \
    || fail "candidate errno does not use direct fs initial TLS"
# The hidden frame trampoline must stay the fixed `mov rax, 15; syscall` path.
objdump -d --disassemble=crabc_x86_64_signal_restorer "$candidate" >"$restorer_disassembly"
grep -Eq '\$0xf,%rax|\$0x0*15,%rax' "$restorer_disassembly" \
    || fail "candidate restorer lacks rt_sigreturn syscall number 15"
grep -Eq '\bsyscall\b' "$restorer_disassembly" \
    || fail "candidate restorer lacks x86 syscall instruction"

"$candidate"

printf 'x86 static crabc-libc signal control: PASS\n'
