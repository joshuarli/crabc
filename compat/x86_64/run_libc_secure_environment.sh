#!/usr/bin/env bash
# Native Linux/x86-64 static GNU secure_getenv evidence.
#
# A pinned-musl normal-start reference establishes GNU secure_getenv behavior.
# The static candidate then proves the normal case and two synthetic validated
# auxv cases: a final AT_SECURE=1 and a UID/EUID mismatch. Raw __getauxval and
# weak getauxval remain the separately qualified auxv-observation artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc secure environment: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
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

build_candidate() {
    local output="$1"
    shift
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE "$@" -I"$ROOT_DIR/include" \
        -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
        -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
        compat/x86_64/libc_secure_environment_probe.c \
        compat/x86_64/libc_secure_environment_start.S "$archive" -o "$output"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
# The existing stdlib profile matrix owns the GNU C/C++ declaration and
# linkage evidence; direct raw auxv linkage remains a sibling artifact.
bash "$ROOT_DIR/compat/x86_64/run_stdlib_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-secure-environment.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-secure-environment-reference"
candidate="$work_dir/crabc-static-secure-environment-candidate"
synthetic_at_secure="$work_dir/crabc-static-secure-environment-at-secure"
synthetic_uid_mismatch="$work_dir/crabc-static-secure-environment-uid-mismatch"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_secure_environment_probe.c >/dev/null 2>"$work_dir/header-trace"
for header in errno.h stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$work_dir/header-trace" ||
        fail "fixture did not use project $header header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_secure_environment_probe.c \
    -o "$reference"
env -i OPEN=visible "$reference" || fail "pinned-musl secure-environment fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$work_dir/archive-symbols"
assert_selected_c_abi_surface "$archive" "$work_dir/selected-symbols" "$work_dir/expected-symbols"
grep -Eq '[[:space:]]secure_getenv$' "$work_dir/archive-symbols" ||
    fail "archive does not define secure_getenv"
readelf --relocs --wide "$archive" >"$work_dir/archive-relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$work_dir/archive-relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$work_dir/archive-relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

build_candidate "$candidate"
build_candidate "$synthetic_at_secure" \
    -DCRABC_SECURE_ENVIRONMENT_SYNTHETIC \
    -DCRABC_SECURE_ENVIRONMENT_SYNTHETIC_AT_SECURE
build_candidate "$synthetic_uid_mismatch" \
    -DCRABC_SECURE_ENVIRONMENT_SYNTHETIC \
    -DCRABC_SECURE_ENVIRONMENT_SYNTHETIC_UID_MISMATCH

readelf --symbols --wide "$candidate" >"$work_dir/candidate-symbols"
readelf --program-headers --wide "$candidate" >"$work_dir/candidate-program-headers"
readelf --dynamic --wide "$candidate" >"$work_dir/candidate-dynamic" || true
readelf --relocs --wide "$candidate" >"$work_dir/candidate-relocations"
objdump -d "$candidate" >"$work_dir/candidate-disassembly"
for symbol in secure_getenv __crabc_x86_static_tls_bootstrap __libc_start_main main; do
    grep -Eq "[[:space:]]$symbol$" "$work_dir/candidate-symbols" ||
        fail "candidate does not define $symbol"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$work_dir/candidate-symbols")"
[ -z "$unresolved_symbols" ] || { printf '%s\n' "$unresolved_symbols" >&2; fail "candidate retains unresolved symbol"; }
if grep -Eq 'Requesting program interpreter|INTERP' "$work_dir/candidate-program-headers" ||
    grep -Eq 'NEEDED' "$work_dir/candidate-dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$work_dir/candidate-program-headers" ||
    fail "candidate lacks selected errno TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$work_dir/candidate-relocations" "$work_dir/candidate-symbols" "$work_dir/candidate-disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$work_dir/candidate-symbols" "$work_dir/candidate-disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=secure_getenv "$candidate" >"$work_dir/secure-getenv-disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|call.*<(setuid|seteuid|setgid|setegid|setresuid|setresgid|open|openat|close|dup|dup2|dup3|execve|posix_spawn|fork|vfork|clone|sigaction|pthread_|__getauxval|getauxval)' \
    "$work_dir/secure-getenv-disassembly"; then
    fail "candidate selects a credential, descriptor, execution, signal, or raw-auxv dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" ||
    fail "candidate errno does not use direct initial TLS"

bootstrap_call_line="$(grep -nE 'call.*<__crabc_x86_static_tls_bootstrap>' "$work_dir/candidate-disassembly" | head -n 1 | cut -d: -f1)"
startup_call_line="$(grep -nE 'call.*<__libc_start_main>' "$work_dir/candidate-disassembly" | head -n 1 | cut -d: -f1)"
[ -n "$bootstrap_call_line" ] || fail "entry shim does not call the TLS bootstrap"
[ -n "$startup_call_line" ] || fail "entry shim does not call libc startup"
[ "$bootstrap_call_line" -lt "$startup_call_line" ] ||
    fail "TLS bootstrap does not precede secure-environment startup"

env -i OPEN=visible "$candidate" || fail "normal secure-environment candidate failed"
"$synthetic_at_secure" || fail "synthetic final-AT_SECURE candidate failed"
"$synthetic_uid_mismatch" || fail "synthetic UID/EUID-mismatch candidate failed"

printf 'x86 static crabc-libc secure environment: PASS\n'
