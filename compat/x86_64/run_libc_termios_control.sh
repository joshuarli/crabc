#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc termios-control evidence.
#
# The same project-header C fixture first runs against pinned musl, then as a
# true `-nostdlib -static` executable linked solely through the selected
# crabc `libc.a`. It proves only the closed termios record/ioctl boundary and
# its initial-TLS errno translation. It is not libc.so, generic ioctl, a PTY
# API, a CRT, pthread/TLS lifecycle, a loader, or a sysroot.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc termios control: %s\n' "$*" >&2
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
    # not crabc's C ABI surface. Inspect only `c.*.rcgu.o` members so a new
    # public C export must enter the closed manifest deliberately. The hidden
    # signal restorer remains the one audited frame-internal exception.
    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
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

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-termios-control.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-termios-control-reference"
candidate="$work_dir/crabc-static-termios-control-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
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
tcgetattr_disassembly="$work_dir/tcgetattr-disassembly"
tcsetattr_disassembly="$work_dir/tcsetattr-disassembly"
tcflush_disassembly="$work_dir/tcflush-disassembly"
tcflow_disassembly="$work_dir/tcflow-disassembly"
tcsendbreak_disassembly="$work_dir/tcsendbreak-disassembly"
tcgetwinsize_disassembly="$work_dir/tcgetwinsize-disassembly"
tcsetwinsize_disassembly="$work_dir/tcsetwinsize-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_termios_control_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h termios.h features.h sys/types.h bits/alltypes.h \
    sys/syscall.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    compat/x86_64/libc_termios_control_probe.c -o "$reference"
"$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location cfgetispeed cfgetospeed cfsetispeed cfsetospeed \
    cfsetspeed cfmakeraw tcgetattr tcsetattr tcflush tcflow tcsendbreak \
    tcgetwinsize tcsetwinsize; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" \
        || fail "archive does not define ${symbol}"
done
for unselected in syscall tcdrain tcgetsid \
    ttyname ttyname_r openpty forkpty login_tty posix_openpt \
    grantpt unlockpt ptsname ptsname_r malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" \
    || fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_TERMIOS_CONTROL_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_termios_control_probe.c \
    compat/x86_64/libc_termios_control_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location cfgetispeed cfgetospeed cfsetispeed cfsetospeed \
    cfsetspeed cfmakeraw tcgetattr tcsetattr tcflush tcflow tcsendbreak \
    tcgetwinsize tcsetwinsize; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate does not define ${symbol}"
done
if grep -Eq "[[:space:]][TW][[:space:]]ioctl$" "$candidate_symbols"; then
    fail "termios-control candidate unexpectedly pulls generic ioctl"
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
# Every selected named ioctl has its own emitted-code gate. The fixture proves
# behavior against a PTY; these checks additionally pin each Linux request
# word and its relevant argument register boundary instead of inferring them
# from a successful terminal operation.
objdump -d --disassemble=tcgetattr "$candidate" >"$tcgetattr_disassembly"
grep -Eq '\$0x5401' "$tcgetattr_disassembly" \
    || fail "tcgetattr lacks the fixed TCGETS request"
grep -Eq 'mov[[:alnum:]]*[[:space:]]+%rsi,%rdx' "$tcgetattr_disassembly" \
    || fail "tcgetattr does not pass its public termios pointer in ioctl arg3"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcgetattr_disassembly" \
    || fail "tcgetattr lacks its named ioctl syscall"

objdump -d --disassemble=tcsetattr "$candidate" >"$tcsetattr_disassembly"
grep -Eq 'cmp[[:alnum:]]*[[:space:]]+\$0x2,%esi|cmp[[:alnum:]]*[[:space:]]+\$0x3,%esi' "$tcsetattr_disassembly" \
    || fail "tcsetattr lacks the TCSANOW through TCSAFLUSH action bound"
grep -Eq 'ja(e)?[[:space:]]' "$tcsetattr_disassembly" \
    || fail "tcsetattr does not reject an out-of-range action before its ioctl"
grep -Eq 'add[[:alnum:]]*[[:space:]]+\$0x5402,%esi' "$tcsetattr_disassembly" \
    || fail "tcsetattr does not map actions onto TCSETS through TCSETSF"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcsetattr_disassembly" \
    || fail "tcsetattr lacks its named ioctl syscall"

objdump -d --disassemble=tcflush "$candidate" >"$tcflush_disassembly"
grep -Eq '\$0x540b' "$tcflush_disassembly" \
    || fail "tcflush lacks the fixed TCFLSH request"
grep -Eq 'movs[[:alpha:]]*[[:space:]]+%esi,%rdx' "$tcflush_disassembly" \
    || fail "tcflush does not pass its queue selector in ioctl arg3"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcflush_disassembly" \
    || fail "tcflush lacks its named ioctl syscall"

objdump -d --disassemble=tcflow "$candidate" >"$tcflow_disassembly"
grep -Eq '\$0x540a' "$tcflow_disassembly" \
    || fail "tcflow lacks the fixed TCXONC request"
grep -Eq 'movs[[:alpha:]]*[[:space:]]+%esi,%rdx' "$tcflow_disassembly" \
    || fail "tcflow does not pass its action in ioctl arg3"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcflow_disassembly" \
    || fail "tcflow lacks its named ioctl syscall"

# Musl's `tcsendbreak` discards every duration and issues TCSBRK with zero.
# The candidate's focused disassembly confirms its named wrapper preserves
# that fixed request/argument boundary rather than forwarding duration.
objdump -d --disassemble=tcsendbreak "$candidate" >"$tcsendbreak_disassembly"
grep -Eq '\$0x5409' "$tcsendbreak_disassembly" \
    || fail "tcsendbreak lacks the fixed TCSBRK request"
grep -Eq 'xor[[:space:]]+%edx,%edx|mov[[:alnum:]]*[[:space:]]+\$0x0+,%edx' \
    "$tcsendbreak_disassembly" \
    || fail "tcsendbreak does not discard duration for a zero ioctl argument"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcsendbreak_disassembly" \
    || fail "tcsendbreak lacks its named ioctl syscall"

objdump -d --disassemble=tcgetwinsize "$candidate" >"$tcgetwinsize_disassembly"
grep -Eq '\$0x5413' "$tcgetwinsize_disassembly" \
    || fail "tcgetwinsize lacks the fixed TIOCGWINSZ request"
grep -Eq 'mov[[:alnum:]]*[[:space:]]+%rsi,%rdx' "$tcgetwinsize_disassembly" \
    || fail "tcgetwinsize does not pass its winsize pointer in ioctl arg3"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcgetwinsize_disassembly" \
    || fail "tcgetwinsize lacks its named ioctl syscall"

objdump -d --disassemble=tcsetwinsize "$candidate" >"$tcsetwinsize_disassembly"
grep -Eq '\$0x5414' "$tcsetwinsize_disassembly" \
    || fail "tcsetwinsize lacks the fixed TIOCSWINSZ request"
grep -Eq 'mov[[:alnum:]]*[[:space:]]+%rsi,%rdx' "$tcsetwinsize_disassembly" \
    || fail "tcsetwinsize does not pass its winsize pointer in ioctl arg3"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcsetwinsize_disassembly" \
    || fail "tcsetwinsize lacks its named ioctl syscall"

"$candidate"

printf 'x86 static crabc-libc termios control: PASS\n'
