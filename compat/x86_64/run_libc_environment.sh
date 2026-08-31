#!/usr/bin/env bash
# Native Linux/x86-64 bounded static crabc-libc environment evidence.
#
# One project-header C fixture first runs its ordinary environment semantics
# through pinned musl 1.2.6, then runs through a true `-nostdlib -static`
# candidate. The candidate additionally proves its documented fixed-resource
# ENOMEM boundaries. This is not dynamic libc, secure execution, exec/spawn,
# a general process-environment lifecycle, CRT, loader, sysroot, or public x86
# support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc environment: %s\n' "$*" >&2
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

    # `libc/Cargo.toml` fixes the Rust staticlib crate name to `c`. Inspect
    # only crate-owned C object members so compiler-builtins cannot turn this
    # bounded environment contract into an accidental export claim.
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

symbol_value() {
    local symbols_path="$1"
    local symbol="$2"

    awk -v symbol="$symbol" '$8 == symbol && $7 != "UND" { print $2; exit }' \
        "$symbols_path"
}

require_native_linux_x86_64
for tool in ar cargo cmp diff nm objdump readelf rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-environment.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-environment-reference"
candidate="$work_dir/crabc-static-environment-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_environment_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdlib.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_environment_probe.c -o "$reference"
env -i CRABC_X86_INITIAL=entry "$reference"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __environ environ _environ ___environ getenv setenv putenv unsetenv clearenv; do
    grep -Eq "[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in secure_getenv __secure_getenv __putenv __env_rm_add; do
    if grep -Eq "[[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ENVIRONMENT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_environment_probe.c \
    compat/x86_64/libc_environment_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __environ environ _environ ___environ getenv setenv putenv unsetenv clearenv; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for symbol in __crabc_x86_static_tls_bootstrap __libc_start_main main; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define startup boundary ${symbol}"
done
environ_value="$(symbol_value "$candidate_symbols" __environ)"
[ -n "$environ_value" ] || fail "candidate has no __environ object value"
awk '$8 == "__environ" && $7 != "UND" && $3 == 8 && $4 == "OBJECT" && $5 == "GLOBAL" { found = 1 }
    END { exit !found }' "$candidate_symbols" ||
    fail "environment object does not have x86 LP64 size/type/binding"
for alias in environ _environ ___environ; do
    alias_value="$(symbol_value "$candidate_symbols" "$alias")"
    [ "$alias_value" = "$environ_value" ] ||
        fail "${alias} is not an ELF alias of __environ"
    awk -v alias="$alias" '$8 == alias && $7 != "UND" && $3 == 8 &&
        $4 == "OBJECT" && $5 == "WEAK" { found = 1 }
        END { exit !found }' "$candidate_symbols" ||
        fail "environment alias is not a weak x86 LP64 object: ${alias}"
done
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
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

bootstrap_call_line="$(grep -nE 'call.*<__crabc_x86_static_tls_bootstrap>' \
    "$candidate_disassembly" | head -n 1 | cut -d: -f1)"
startup_call_line="$(grep -nE 'call.*<__libc_start_main>' \
    "$candidate_disassembly" | head -n 1 | cut -d: -f1)"
[ -n "$bootstrap_call_line" ] || fail "entry shim does not call the TLS bootstrap"
[ -n "$startup_call_line" ] || fail "entry shim does not call libc startup"
[ "$bootstrap_call_line" -lt "$startup_call_line" ] ||
    fail "TLS bootstrap does not precede libc startup"

if env -i CRABC_X86_INITIAL=entry "$candidate"; then
    candidate_status=0
else
    candidate_status=$?
fi
case "$candidate_status" in
    0) ;;
    73) fail "non-reclaiming arena unexpectedly accepted a new value" ;;
    *) fail "candidate environment behavior failed with status $candidate_status" ;;
esac

printf 'x86 static crabc-libc environment: PASS\n'
