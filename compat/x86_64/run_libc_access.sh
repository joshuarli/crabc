#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc access evidence.
#
# One GNU-enabled project-header fixture first executes through pinned musl,
# then as a true -nostdlib -static candidate linked through the selected
# archive. It proves only access, faccessat, euidaccess, and musl's weak
# same-address eaccess alias. Fixture-local raw syscalls provision a
# root-owned record and contain a real-versus-effective UID transition; they
# do not select C descriptor, credential, process, or pathname-policy APIs.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc access: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
    [ "$(id -u)" -eq 0 ] || fail "requires root for the real/effective UID branch"
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_static_closure() {
    local candidate_path="$1"
    local label="$2"
    local symbols_path="$work_dir/${label}-symbols"
    local headers_path="$work_dir/${label}-program-headers"
    local dynamic_path="$work_dir/${label}-dynamic"
    local relocs_path="$work_dir/${label}-relocations"
    local disassembly_path="$work_dir/${label}-disassembly"
    local errno_disassembly="$work_dir/${label}-errno-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "${label} has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "${label} is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "${label} lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "${label} retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "${label} selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols_path" "$disassembly_path"; then
        fail "${label} selects Rust panic machinery"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "${label} errno does not use direct fs initial TLS"
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|$)" "$disassembly" ||
        fail "${symbol} lacks fixed syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks its named Linux syscall"
}

assert_musl_weak_alias() {
    local symbols_path="$1"
    local label="$2"
    local alias_value helper_value

    alias_value="$(awk '$8 == "eaccess" && $4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    helper_value="$(awk '$8 == "euidaccess" && $4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    [ -n "$alias_value" ] || fail "${label} lacks a weak eaccess symbol"
    [ -n "$helper_value" ] || fail "${label} lacks a strong euidaccess symbol"
    [ "$alias_value" = "$helper_value" ] ||
        fail "${label} eaccess is not musl's same-address weak alias"
}

assert_strong_eaccess_override() {
    local symbols_path="$1"
    local label="$2"

    awk '$8 == "eaccess" && $4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" { found = 1 } END { exit found ? 0 : 1 }' \
        "$symbols_path" || fail "${label} strong caller eaccess did not override the alias"
    if awk '$8 == "eaccess" && $5 == "WEAK" && $7 != "UND" { found = 1 } END { exit found ? 0 : 1 }' \
        "$symbols_path"; then
        fail "${label} retains the archive weak eaccess alias"
    fi
}

require_native_linux_x86_64
for tool in ar cargo cmp diff grep id ln mkdir nm objdump readelf rustup stat touch chmod sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_access_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-access.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-access-reference"
candidate="$work_dir/crabc-static-access-candidate"
candidate_override="$work_dir/crabc-static-access-override-candidate"
fixture_root="$work_dir/access-root"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
override_symbols="$work_dir/candidate-override-symbols"

mkdir "$fixture_root"
chmod 0755 "$fixture_root"
touch "$fixture_root/record"
chmod 0400 "$fixture_root/record"
ln -s missing-target "$fixture_root/dangling"
[ "$(stat -c '%u:%g:%a' "$fixture_root/record")" = '0:0:400' ] ||
    fail "runner did not provision a root-owned mode-0400 record"
[ -d "$fixture_root" ] && [ -L "$fixture_root/dangling" ] ||
    fail "runner did not provision the access fixture paths"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE "-DCRABC_ACCESS_ROOT=\"$fixture_root\"" \
    -I"$ROOT_DIR/include" -E -H compat/x86_64/libc_access_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h sys/syscall.h sys/types.h unistd.h features.h \
    bits/fcntl.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE "-DCRABC_ACCESS_ROOT=\"$fixture_root\"" \
    -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_access_probe.c -o "$reference"
"$reference" || fail "pinned-musl access fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location access faccessat euidaccess; do
    grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not strongly define ${symbol}"
done
grep -Eq '[[:space:]]W[[:space:]]eaccess$' "$archive_symbols" ||
    fail "archive does not weakly define eaccess"
if grep -Eq '[[:space:]]T[[:space:]]eaccess$' "$archive_symbols"; then
    fail "archive uses an eaccess wrapper instead of musl's weak alias"
fi
for unselected in fchmodat fchmod fchownat fchown lchmod chmod chown syscall; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
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

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ACCESS_FREESTANDING \
    "-DCRABC_ACCESS_ROOT=\"$fixture_root\"" -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_access_probe.c compat/x86_64/libc_access_start.S \
    "$archive" -o "$candidate"
assert_static_closure "$candidate" candidate
readelf --symbols --wide "$candidate" >"$candidate_symbols"
for symbol in __errno_location access faccessat euidaccess eaccess; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks ${symbol}"
done
assert_musl_weak_alias "$candidate_symbols" candidate
assert_named_syscall access 15
assert_named_syscall faccessat 10d
assert_named_syscall faccessat 1b7
faccessat_disassembly="$work_dir/faccessat-disassembly"
objdump -d --disassemble=faccessat "$candidate" >"$faccessat_disassembly"
grep -Fq '%r10' "$faccessat_disassembly" ||
    fail "faccessat lacks the x86 fourth-argument r10 path"
"$candidate" || fail "freestanding access fixture failed"

# The C strong definition must supersede the archive weak alias while the
# direct euidaccess call still extracts and proves the selected archive object.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_ACCESS_FREESTANDING \
    -DCRABC_ACCESS_OVERRIDE_EACCESS "-DCRABC_ACCESS_ROOT=\"$fixture_root\"" \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_access_probe.c compat/x86_64/libc_access_start.S \
    "$archive" -o "$candidate_override"
assert_static_closure "$candidate_override" candidate-override
readelf --symbols --wide "$candidate_override" >"$override_symbols"
assert_strong_eaccess_override "$override_symbols" candidate-override
"$candidate_override" || fail "freestanding eaccess override fixture failed"

printf 'x86 static crabc-libc access: PASS\n'
