#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc aux-vector evidence.
#
# One project-header fixture first runs through pinned musl 1.2.6, then as a
# true `-nostdlib -static` candidate through the selected archive. It proves
# only validated initial-vector getauxval lookup, musl's weak same-address
# private alias, constructor-before-main publication, and errno behavior. The
# fixture checks AT_PAGESZ/AT_PHENT/AT_PHNUM plus zero-valued AT_SECURE and
# absent AT_NULL/ENOENT behavior. It does not select loader state,
# secure-execution policy, environment storage, libc.so, CRT completion, C ABI
# closure, family promotion, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc auxv observation: %s\n' "$*" >&2
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_weak_same_address_alias() {
    local symbols_path="$1"
    local alias_name="$2"
    local target_name="$3"
    local label="$4"
    local alias_value alias_bind alias_type target_value target_type

    read -r alias_value alias_bind alias_type < <(
        awk -v name="$alias_name" '$8 == name && $7 != "UND" { print $2, $5, $4; exit }' \
            "$symbols_path"
    )
    read -r target_value target_type < <(
        awk -v name="$target_name" '$8 == name && $7 != "UND" { print $2, $4; exit }' \
            "$symbols_path"
    )
    [ -n "${alias_value:-}" ] || fail "$label lacks defined ${alias_name}"
    [ -n "${target_value:-}" ] || fail "$label lacks defined ${target_name}"
    [ "$alias_bind" = WEAK ] || fail "$label ${alias_name} is not weak"
    [ "$alias_type" = FUNC ] || fail "$label ${alias_name} is not a function"
    [ "$target_type" = FUNC ] || fail "$label ${target_name} is not a function"
    [ "$alias_value" = "$target_value" ] ||
        fail "$label ${alias_name}/${target_name} are not a same-address alias pair"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_machine_context_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-auxv-observation.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-auxv-observation-reference"
candidate="$work_dir/crabc-static-auxv-observation-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
reference_symbols="$work_dir/reference-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_file_header="$work_dir/candidate-file-header"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/candidate-errno-disassembly"
auxv_disassembly="$work_dir/candidate-auxv-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_auxv_observation_probe.c >/dev/null 2>"$header_trace"
for header in elf.h errno.h features.h sys/auxv.h bits/hwcap.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project ${header}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_auxv_observation_probe.c -o "$reference"
readelf --symbols --wide "$reference" >"$reference_symbols"
assert_weak_same_address_alias "$reference_symbols" getauxval __getauxval \
    "pinned-musl static reference"
"$reference" || fail "pinned-musl auxv-observation fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
readelf --relocs --wide "$archive" >"$archive_relocations"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]]T[[:space:]]__getauxval$' "$archive_symbols" ||
    fail "archive does not strongly define __getauxval"
grep -Eq '[[:space:]]W[[:space:]]getauxval$' "$archive_symbols" ||
    fail "archive does not weakly define getauxval"
assert_weak_same_address_alias "$archive_elf_symbols" getauxval __getauxval \
    "selected crabc archive"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive auxv errno path lacks an initial-TLS TPOFF relocation"
# `secure_getenv` is a separately selected archive member. It is not linked
# into this raw-auxv candidate and must not make archive-wide relocation
# closure look like an auxv dependency.
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS, a loader policy, or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_AUXV_OBSERVATION_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_auxv_observation_probe.c \
    compat/x86_64/libc_auxv_observation_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --file-header --wide "$candidate" >"$candidate_file_header"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
objdump -d --disassemble=__getauxval "$candidate" >"$auxv_disassembly"

grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
    "$candidate_file_header" || fail "candidate is not ET_EXEC"
for symbol in _start __crabc_x86_static_tls_bootstrap __libc_start_main \
    __errno_location __getauxval getauxval crabc_x86_64_auxv_observation_init main; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_weak_same_address_alias "$candidate_symbols" getauxval __getauxval candidate
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
if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT)|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic relocation or TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|[[:space:]](secure_getenv|__auxv|malloc|calloc|realloc|free)$' \
    "$candidate_symbols" || \
    grep -Eq '(call|jmp).*(<(secure_getenv|malloc|calloc|realloc|free)>|__auxv)' \
        "$candidate_disassembly"; then
    fail "candidate selects a loader, allocator, or unowned runtime dependency"
fi
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct x86 initial TLS"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
    "$auxv_disassembly"; then
    fail "__getauxval selects a syscall or Rust panic machinery"
fi

"$candidate" || fail "freestanding auxv-observation fixture failed"

printf 'x86 static crabc-libc auxv observation: PASS\n'
