#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc bcopy/bzero evidence.
#
# The fixture first runs through pinned musl 1.2.6, then through a true
# -nostdlib/-static candidate made from exactly two archive members: one
# legacy-adapter and one already-selected bulk-memory member. This is a bounded byte utility
# proof, not a general memory, allocator, or runtime claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc legacy memory: %s\n' "$*" >&2
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

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_byte_strings_header_abi.sh" >/dev/null

grep -Fqx $'bcopy\tbcopy.lo\tT\tGLOBAL\t0\t10' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost bcopy ownership"
grep -Fqx $'bzero\tbzero.lo\tT\tGLOBAL\t0\tc' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost bzero ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-legacy-memory.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-legacy-memory.a"
reference="$work_dir/musl-legacy-memory-reference"
candidate="$work_dir/crabc-static-legacy-memory-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
legacy_relocations="$work_dir/legacy-memory-relocations"
legacy_undefined="$work_dir/legacy-memory-undefined"
legacy_disassembly="$work_dir/legacy-memory-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_legacy_memory_probe.c >/dev/null 2>"$header_trace"
for header in string.h strings.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_legacy_memory_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl legacy-memory fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in bcopy bzero memmove memset; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

mapfile -t legacy_members < <(archive_member_for_symbol "$archive" bcopy)
mapfile -t bzero_members < <(archive_member_for_symbol "$archive" bzero)
mapfile -t memmove_members < <(archive_member_for_symbol "$archive" memmove)
mapfile -t memset_members < <(archive_member_for_symbol "$archive" memset)
[ "${#legacy_members[@]}" -eq 1 ] ||
    fail "bcopy must have exactly one crate object owner"
[ "${legacy_members[*]}" = "${bzero_members[*]}" ] ||
    fail "bcopy and bzero must share exactly one adapter object"
[ "${#memmove_members[@]}" -eq 1 ] ||
    fail "memmove must have exactly one bulk-memory owner"
[ "${memmove_members[*]}" = "${memset_members[*]}" ] ||
    fail "memmove and memset must share exactly one bulk-memory object"
[ "${legacy_members[0]}" != "${memmove_members[0]}" ] ||
    fail "legacy adapters unexpectedly share the bulk-memory object"

mkdir "$work_dir/owners"
(
    cd "$work_dir/owners"
    ar x "$archive" "${legacy_members[0]}" "${memmove_members[0]}"
    ar crs "$selected_archive" "${legacy_members[0]}" "${memmove_members[0]}"
)
legacy_object="$work_dir/owners/${legacy_members[0]}"
memory_object="$work_dir/owners/${memmove_members[0]}"

mapfile -t legacy_exports < <(
    nm -g --defined-only --format=posix "$legacy_object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${legacy_exports[*]}" != "bcopy bzero" ]; then
    printf 'expected: %s\nactual:   %s\n' "bcopy bzero" "${legacy_exports[*]}" >&2
    fail "legacy adapter object export surface drifted"
fi
mapfile -t memory_exports < <(
    nm -g --defined-only --format=posix "$memory_object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
for symbol in __memcpy_fwd bcmp memcmp memcpy memmove memset; do
    if [[ " ${memory_exports[*]} " != *" ${symbol} "* ]]; then
        fail "bulk-memory owner lacks ${symbol}"
    fi
done
nm --undefined-only --format=posix "$legacy_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$legacy_undefined"
if ! diff -u <(printf '%s\n' memmove memset) "$legacy_undefined"; then
    fail "legacy adapter dependency closure drifted"
fi
readelf --relocs --wide "$legacy_object" >"$legacy_relocations"
objdump -d "$legacy_object" >"$legacy_disassembly"
for symbol in memmove memset; do
    grep -Eq "[[:space:]]${symbol}([[:space:]]|$)" "$legacy_relocations" ||
        fail "legacy adapter lacks direct ${symbol} relocation"
done
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$legacy_disassembly"; then
    fail "legacy adapter unexpectedly performs a syscall"
fi
if grep -Eq '[[:space:]]call([[:space:]]|$)' "$legacy_disassembly"; then
    fail "legacy adapter must tail-transfer into the bulk-memory owner"
fi

"$ORACLE_CC" -std=c11 -D_BSD_SOURCE -DCRABC_LEGACY_MEMORY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_legacy_memory_probe.c \
    compat/x86_64/libc_legacy_memory_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in bcopy bzero memmove memset; do
    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
        fail "candidate lacks global ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers"; then
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|memccpy|mempcpy|explicit_bzero' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned allocator or memory utility"
fi

"$candidate" || fail "freestanding legacy-memory fixture failed"

printf 'x86 static libc legacy memory: PASS\n'
