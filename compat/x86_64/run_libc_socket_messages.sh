#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc socket-message/options evidence.
#
# The same project-header C fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` candidate linked solely through the selected
# crabc archive. It proves exactly the padded `msghdr`/`mmsghdr` adapter,
# bounded outgoing ancillary copy, direct socket-option calls, and SIOCATMARK
# form. The selected archive has no general cancellation owner, so this is
# intentionally not pthread cancellation, a generic socket/runtime claim,
# libc.so, CRT, loader, sysroot, or public x86 support evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc socket messages: %s\n' "$*" >&2
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
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}" "$disassembly" ||
        fail "${symbol} lacks Linux syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks a direct Linux syscall"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_socket_messages_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-socket-messages.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-socket-messages-reference"
candidate="$work_dir/crabc-static-socket-messages-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_socket_messages_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h stdint.h sys/ioctl.h sys/socket.h \
    sys/syscall.h sys/types.h sys/uio.h time.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_socket_messages_probe.c \
    -o "$reference"
if "$reference"; then
    :
else
    status=$?
    fail "pinned-musl socket-message fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit libc.a"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location setsockopt getsockopt sendmsg recvmsg sendmmsg \
    recvmmsg sockatmark; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SOCKET_MESSAGES_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_socket_messages_probe.c \
    compat/x86_64/libc_socket_messages_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location setsockopt getsockopt sendmsg recvmsg sendmmsg \
    recvmmsg sockatmark; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
if grep -Eq "[[:space:]][TW][[:space:]]ioctl$" "$candidate_symbols"; then
    fail "socket-message candidate unexpectedly pulls generic ioctl"
fi
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || fail "candidate retains an unresolved symbol"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

# Direct option/message/syscall gates prove x86's r10/r8 five-argument path,
# the public-padding adapter, and the distinct direct recvmmsg form. The
# sendmmsg disassembly intentionally must use the musl-shaped sendmsg loop,
# never raw Linux SYS_sendmmsg=307.
assert_named_syscall setsockopt 36
assert_named_syscall getsockopt 37
assert_named_syscall sendmsg 2e
assert_named_syscall recvmsg 2f
assert_named_syscall recvmmsg 12b
assert_named_syscall sockatmark 10
sendmmsg_disassembly="$work_dir/sendmmsg-disassembly"
objdump -d --disassemble=sendmmsg "$candidate" >"$sendmmsg_disassembly"
grep -Eq '\$0x2e' "$sendmmsg_disassembly" ||
    fail "sendmmsg lacks its musl-shaped sendmsg syscall path"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$sendmmsg_disassembly" ||
    fail "sendmmsg lacks a direct sendmsg syscall path"
if grep -Eq '\$0x133' "$sendmmsg_disassembly"; then
    fail "sendmmsg incorrectly uses raw Linux SYS_sendmmsg"
fi

if "$candidate"; then
    :
else
    status=$?
    fail "freestanding socket-message fixture exited ${status}"
fi

printf 'x86 static crabc-libc socket messages: PASS\n'
