#!/usr/bin/env bash
# Native Linux/x86-64 selected static c32rtomb C ABI evidence.
#
# The fixture first executes against pinned musl 1.2.6, then a true
# -nostdlib/-static candidate. The selected archive starts from one c32rtomb
# adapter member and retains only the linker-discovered closure needed by its
# direct existing wcrtomb dependency, named-profile selection, its existing
# CTYPE override read, and errno.
# This is a C11 UTF-32 encoder adapter, not a second locale core or a general
# text/locale runtime claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc c32rtomb: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        sort -u
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

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    if (( tls_filesz != 0 )); then
        fail "fixture TLS scratch cannot initialize nonzero PT_TLS data"
    fi
    if (( tls_memsz == 0 || tls_memsz > INITIAL_TLS_BYTES )); then
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    fi
    if (( tls_alignment == 0 || tls_alignment > INITIAL_TLS_ALIGNMENT ||
        INITIAL_TLS_ALIGNMENT % tls_alignment != 0 )); then
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
    fi
}

discovered_archive_members() {
    local map_path="$1"

    grep -F "${archive}(" "$map_path" |
        sed -n -E 's@.*libc\.a\(([^)]*\.o)\).*@\1@p' |
        sort -u
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_c32rtomb_header_abi.sh" >/dev/null

grep -Fqx $'c32rtomb\tc32rtomb.lo\tT\tGLOBAL\t0\t4' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost c32rtomb ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-c32rtomb.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-c32rtomb.a"
reference="$work_dir/musl-c32rtomb-reference"
discovery="$work_dir/crabc-static-c32rtomb-discovery"
candidate="$work_dir/crabc-static-c32rtomb-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
adapter_undefined="$work_dir/c32rtomb-undefined"
adapter_relocations="$work_dir/c32rtomb-relocations"
adapter_disassembly="$work_dir/c32rtomb-disassembly"
discovery_map="$work_dir/discovery.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_c32rtomb_probe.c >/dev/null 2>"$header_trace"
for header in errno.h locale.h uchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_c32rtomb_probe.c -o "$reference"
"$reference" || fail "pinned-musl c32rtomb fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in c32rtomb wcrtomb setlocale __errno_location; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

mapfile -t adapter_members < <(archive_member_for_symbol "$archive" c32rtomb)
mapfile -t wcrtomb_members < <(archive_member_for_symbol "$archive" wcrtomb)
mapfile -t setlocale_members < <(archive_member_for_symbol "$archive" setlocale)
mapfile -t errno_members < <(archive_member_for_symbol "$archive" __errno_location)
[ "${#adapter_members[@]}" -eq 1 ] ||
    fail "c32rtomb must have exactly one adapter object owner"
[ "${#wcrtomb_members[@]}" -eq 1 ] ||
    fail "wcrtomb must have exactly one established locale-core owner"
[ "${#setlocale_members[@]}" -eq 1 ] ||
    fail "setlocale must have exactly one established locale-core owner"
[ "${#errno_members[@]}" -eq 1 ] ||
    fail "errno must have exactly one static owner"
[ "${adapter_members[0]}" != "${wcrtomb_members[0]}" ] ||
    fail "c32rtomb unexpectedly shares the locale-core object"
[ "${adapter_members[0]}" != "${errno_members[0]}" ] ||
    fail "c32rtomb unexpectedly shares the errno object"
[ "${wcrtomb_members[0]}" = "${setlocale_members[0]}" ] ||
    fail "wcrtomb no longer shares the established fixed-profile owner"

mkdir "$work_dir/adapter"
(
    cd "$work_dir/adapter"
    ar x "$archive" "${adapter_members[0]}"
)
adapter_object="$work_dir/adapter/${adapter_members[0]}"
mapfile -t adapter_exports < <(
    nm -g --defined-only --format=posix "$adapter_object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${adapter_exports[*]}" != "c32rtomb" ]; then
    printf 'expected: %s\nactual:   %s\n' "c32rtomb" "${adapter_exports[*]}" >&2
    fail "c32rtomb adapter object export surface drifted"
fi
nm --undefined-only --format=posix "$adapter_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$adapter_undefined"
if ! diff -u <(printf '%s\n' wcrtomb) "$adapter_undefined"; then
    fail "c32rtomb adapter dependency closure drifted"
fi
readelf --relocs --wide "$adapter_object" >"$adapter_relocations"
objdump -dr "$adapter_object" >"$adapter_disassembly"
grep -Eq '[[:space:]]wcrtomb([[:space:]]|$)' "$adapter_relocations" ||
    fail "c32rtomb adapter lacks direct wcrtomb relocation"
grep -Eq '[[:space:]]jmp[[:space:]]' "$adapter_disassembly" ||
    fail "c32rtomb adapter lost its direct tail jump"
grep -Fq wcrtomb "$adapter_disassembly" ||
    fail "c32rtomb adapter tail jump does not target wcrtomb"

# Discover the real static closure with the full archive only once. The final
# evidence binary below links the reconstructed closure archive, never libc.a.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_C32RTOMB_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$discovery_map" compat/x86_64/libc_c32rtomb_probe.c \
    compat/x86_64/libc_c32rtomb_start.S "$archive" -o "$discovery"
mapfile -t closure_members < <(discovered_archive_members "$discovery_map")
[ "${#closure_members[@]}" -gt 0 ] || fail "static link map exposed no crabc closure members"
for member in "${adapter_members[0]}" "${wcrtomb_members[0]}" "${errno_members[0]}"; do
    if [[ " ${closure_members[*]} " != *" ${member} "* ]]; then
        fail "discovered closure omits required member $member"
    fi
done
mkdir "$work_dir/closure"
(
    cd "$work_dir/closure"
    ar x "$archive" "${closure_members[@]}"
    ar crs "$selected_archive" "${closure_members[@]}"
)

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_C32RTOMB_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$candidate_map" compat/x86_64/libc_c32rtomb_probe.c \
    compat/x86_64/libc_c32rtomb_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in c32rtomb wcrtomb setlocale __errno_location; do
    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
        fail "candidate lacks global $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '[[:space:]]callq?[[:space:]].*<(newlocale|duplocale|uselocale|freelocale)>' \
    "$candidate_disassembly"; then
    fail "candidate has a public locale-object API call"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$candidate_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq '[[:space:]](malloc|calloc|realloc|free|iconv|fgetwc|fputwc)$' \
    "$candidate_symbols" ||
    grep -Eq '<(malloc|calloc|realloc|free|iconv|fgetwc|fputwc)>:' \
        "$candidate_disassembly" ||
    grep -Eq 'crabc_core|mimalloc|sha_crypt' \
        "$candidate_symbols" "$candidate_disassembly"; then
    grep -E '([[:space:]](malloc|calloc|realloc|free|iconv|fgetwc|fputwc)$|<(malloc|calloc|realloc|free|iconv|fgetwc|fputwc)>:|crabc_core|mimalloc|sha_crypt)' \
        "$candidate_symbols" "$candidate_disassembly" >&2 || true
    fail "candidate selects an unowned runtime, allocator, iconv, or wide-stream dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

"$candidate" || fail "freestanding c32rtomb fixture failed"
printf 'x86 static libc c32rtomb: PASS\n'
