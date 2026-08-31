#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc tcgetpgrp evidence.
#
# The pinned-musl/project-header fixture proves only the read-only C ABI
# observation: TIOCGPGRP success returns the foreground pid and preserves
# errno, while raw EBADF/ENOTTY errors become -1. A child-only raw devpts
# session supplies the kernel precondition and selects no archive session or
# process-control API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc tcgetpgrp: %s\n' "$*" >&2
    exit 1
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

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/candidate-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned runtime dependency"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_tcgetpgrp_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-tcgetpgrp.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-tcgetpgrp-reference"
candidate="$work_dir/crabc-static-tcgetpgrp-candidate"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
header_trace="$work_dir/header-trace"

cd "$ROOT_DIR"
if ! "$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only compat/x86_64/libc_tcgetpgrp_probe.c \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project-header tcgetpgrp fixture contract drifted"
fi
for header in errno.h fcntl.h stdint.h unistd.h features.h sys/types.h \
    sys/syscall.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_tcgetpgrp_probe.c -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    reference_status=$?
    fail "pinned-musl tcgetpgrp fixture exited ${reference_status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location tcgetpgrp; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -DCRABC_TCGETPGRP_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_tcgetpgrp_probe.c \
    compat/x86_64/libc_tcgetpgrp_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"

tcgetpgrp_disassembly="$work_dir/tcgetpgrp-disassembly"
objdump -d --disassemble=tcgetpgrp "$candidate" >"$tcgetpgrp_disassembly"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$tcgetpgrp_disassembly" ||
    fail "tcgetpgrp lacks a direct ioctl syscall"
grep -Eq '\$0x540f,%esi|\$0x540f,%rsi' "$tcgetpgrp_disassembly" ||
    fail "tcgetpgrp lacks the fixed TIOCGPGRP request"
if grep -Eq '\$0x5401|\$0x5402|\$0x5403|\$0x5404|\$0x540e|\$0x5410|\$0x5429' \
    "$tcgetpgrp_disassembly"; then
    fail "tcgetpgrp unexpectedly selects a terminal-control request"
fi
if grep -Eq '[[:space:]](tcsetpgrp|tcgetsid|tcgetattr|tcsetattr|ttyname|ttyname_r|getpass|openpty|forkpty|login_tty|vhangup|posix_openpt|grantpt|unlockpt|ptsname|ptsname_r|setsid|setpgid|getpgid|getsid|getpgrp)$' \
    "$work_dir/candidate-symbols"; then
    fail "tcgetpgrp candidate selects an excluded session or terminal helper"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "freestanding tcgetpgrp fixture exited ${candidate_status}"
fi

printf 'x86 static crabc-libc tcgetpgrp: PASS\n'
