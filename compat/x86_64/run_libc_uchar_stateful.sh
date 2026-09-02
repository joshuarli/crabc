#!/usr/bin/env bash
# Native Linux/x86-64 selected static stateful <uchar.h> provider evidence.
#
# The fixture first executes against pinned musl 1.2.6, then a true
# -nostdlib/-static candidate reconstructed from the exact linker-discovered
# closure. The three providers are one source block whose only callable seams
# are the already selected mbrtowc/wcrtomb core and its fixed C/POSIX/C.UTF-8
# selection plus initial-TLS errno; the runner rejects ambient libc, dynamic
# TLS, allocator, iconv, wide-stream, and public locale-object expansion.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly -a PROVIDER_SYMBOLS=(c16rtomb mbrtoc16 mbrtoc32)

fail() {
    printf 'ERROR: x86 static libc uchar stateful: %s\n' "$*" >&2
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

require_provider_relocation() {
    local symbol="$1"

    grep -Eq "[[:space:]]${symbol}([[:space:]]|$)" "$provider_relocations" ||
        fail "provider object lacks a direct ${symbol} relocation"
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
bash "$ROOT_DIR/compat/x86_64/run_uchar_stateful_header_abi.sh" >/dev/null

grep -Fqx $'c16rtomb\tc16rtomb.lo\tT\tGLOBAL\t0\t9c' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost c16rtomb ownership"
grep -Fqx $'mbrtoc16\tmbrtoc16.lo\tT\tGLOBAL\t0\td4' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost mbrtoc16 ownership"
grep -Fqx $'mbrtoc32\tmbrtoc32.lo\tT\tGLOBAL\t0\t68' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost mbrtoc32 ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-uchar-stateful.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-uchar-stateful.a"
reference="$work_dir/musl-uchar-stateful-reference"
discovery="$work_dir/crabc-static-uchar-stateful-discovery"
candidate="$work_dir/crabc-static-uchar-stateful-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
provider_undefined="$work_dir/uchar-stateful-undefined"
provider_relocations="$work_dir/uchar-stateful-relocations"
provider_disassembly="$work_dir/uchar-stateful-disassembly"
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
    compat/x86_64/libc_uchar_stateful_probe.c >/dev/null 2>"$header_trace"
for header in errno.h locale.h uchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_uchar_stateful_probe.c -o "$reference"
"$reference" || { status=$?; fail "pinned-musl uchar stateful fixture failed with status $status"; }

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in "${PROVIDER_SYMBOLS[@]}" mbrtowc wcrtomb setlocale __errno_location; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

mapfile -t c16_members < <(archive_member_for_symbol "$archive" c16rtomb)
mapfile -t mbrtoc16_members < <(archive_member_for_symbol "$archive" mbrtoc16)
mapfile -t mbrtoc32_members < <(archive_member_for_symbol "$archive" mbrtoc32)
mapfile -t mbrtowc_members < <(archive_member_for_symbol "$archive" mbrtowc)
mapfile -t wcrtomb_members < <(archive_member_for_symbol "$archive" wcrtomb)
mapfile -t errno_members < <(archive_member_for_symbol "$archive" __errno_location)
[ "${#c16_members[@]}" -eq 1 ] || fail "c16rtomb must have exactly one crate object owner"
[ "${#mbrtoc16_members[@]}" -eq 1 ] || fail "mbrtoc16 must have exactly one crate object owner"
[ "${#mbrtoc32_members[@]}" -eq 1 ] || fail "mbrtoc32 must have exactly one crate object owner"
[ "${#mbrtowc_members[@]}" -eq 1 ] || fail "mbrtowc must have exactly one established decoder owner"
[ "${#wcrtomb_members[@]}" -eq 1 ] || fail "wcrtomb must have exactly one established encoder owner"
[ "${#errno_members[@]}" -eq 1 ] || fail "errno must have exactly one static owner"
[ "${c16_members[0]}" = "${mbrtoc16_members[0]}" ] ||
    fail "c16rtomb and mbrtoc16 must remain one stateful provider block"
[ "${c16_members[0]}" = "${mbrtoc32_members[0]}" ] ||
    fail "c16rtomb and mbrtoc32 must remain one stateful provider block"
[ "${c16_members[0]}" != "${mbrtowc_members[0]}" ] ||
    fail "stateful uchar providers unexpectedly share the decoder object"
[ "${c16_members[0]}" != "${wcrtomb_members[0]}" ] ||
    fail "stateful uchar providers unexpectedly share the encoder object"
[ "${c16_members[0]}" != "${errno_members[0]}" ] ||
    fail "stateful uchar providers unexpectedly share the errno object"

mkdir "$work_dir/provider"
(
    cd "$work_dir/provider"
    ar x "$archive" "${c16_members[0]}"
)
provider_object="$work_dir/provider/${c16_members[0]}"
for symbol in "${PROVIDER_SYMBOLS[@]}"; do
    nm -g --defined-only --format=posix "$provider_object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | grep -Fxq "$symbol" ||
        fail "provider object does not export $symbol"
done
nm --undefined-only --format=posix "$provider_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$provider_undefined"
if grep -Fxq mbrtowc "$provider_undefined"; then
    decoder_public_relocation=1
elif ! grep -Fq 'decode_mbrtowc' "$provider_undefined"; then
    cat "$provider_undefined" >&2
    fail "provider object does not retain the established mbrtowc decoder seam"
fi
grep -Fxq wcrtomb "$provider_undefined" || {
    cat "$provider_undefined" >&2
    fail "provider object does not retain its direct wcrtomb dependency"
}
if grep -Eq '(^|_)(malloc|calloc|realloc|free|iconv|fgetwc|fputwc|newlocale|duplocale|uselocale|freelocale)$' \
    "$provider_undefined"; then
    cat "$provider_undefined" >&2
    fail "provider object acquired an unowned runtime dependency"
fi
readelf --relocs --wide "$provider_object" >"$provider_relocations"
objdump -dr "$provider_object" >"$provider_disassembly"
[ "${decoder_public_relocation:-0}" -eq 0 ] || require_provider_relocation mbrtowc
require_provider_relocation wcrtomb
if grep -Eq '[[:space:]](syscall|callq?[[:space:]].*<(malloc|calloc|realloc|free|iconv|fgetwc|fputwc)>)' \
    "$provider_disassembly"; then
    fail "provider object acquired a syscall, allocator, iconv, or wide-stream call"
fi

# Discover the actual static closure once with libc.a. The evidence candidate
# below links only this reconstructed archive, never the full static library.
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_UCHAR_STATEFUL_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$discovery_map" compat/x86_64/libc_uchar_stateful_probe.c \
    compat/x86_64/libc_uchar_stateful_start.S "$archive" -o "$discovery"
mapfile -t closure_members < <(discovered_archive_members "$discovery_map")
[ "${#closure_members[@]}" -gt 0 ] || fail "static link map exposed no crabc closure members"
for member in "${c16_members[0]}" "${mbrtowc_members[0]}" "${wcrtomb_members[0]}" "${errno_members[0]}"; do
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
mapfile -t reconstructed_members < <(ar t "$selected_archive" | sort -u)
[ "${reconstructed_members[*]}" = "${closure_members[*]}" ] ||
    fail "reconstructed closure archive member set drifted"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_UCHAR_STATEFUL_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$candidate_map" compat/x86_64/libc_uchar_stateful_probe.c \
    compat/x86_64/libc_uchar_stateful_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in "${PROVIDER_SYMBOLS[@]}" mbrtowc wcrtomb setlocale __errno_location; do
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
    fail "candidate selects an unowned runtime, allocator, iconv, or wide-stream dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$work_dir/errno-disassembly"
grep -Eq '%fs:0x0|%fs:-' "$work_dir/errno-disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

"$candidate" || { status=$?; fail "freestanding uchar stateful fixture failed with status $status"; }
printf 'x86 static libc uchar stateful: PASS\n'
