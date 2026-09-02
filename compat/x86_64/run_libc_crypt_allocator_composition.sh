#!/usr/bin/env bash
# Native Linux/x86-64 private crypt/allocator provider-composition evidence.
#
# The named Cargo feature is the sole supported composition route: it joins
# the dependency-backed crypt adapter with the previously selected x86
# allocator wrapper/backend. This is a mixed static candidate, not allocator
# lifecycle, public x86 runtime, or capability-promotion evidence.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 static libc crypt/allocator composition: %s\n' "$*" >&2
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

assert_elf_function_binding() {
    local symbols_path="$1"
    local symbol="$2"
    local binding="$3"
    local owner="$4"

    awk -v symbol="$symbol" -v binding="$binding" '
        $4 == "FUNC" && $5 == binding && $6 == "DEFAULT" && $NF == symbol {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$symbols_path" \
        || fail "$owner must export ${symbol} as ${binding}/DEFAULT/FUNC"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo grep mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_crypt_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-crypt-allocator-composition.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
full_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_allocator_archive="$work_dir/libcrabc-allocator-runtime.a"
reference="$work_dir/pinned-musl-crypt-allocator-reference"
candidate="$work_dir/crabc-crypt-allocator-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
header_trace="$work_dir/header-trace"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
crypt_relocations="$work_dir/crypt-member-relocations"
wrapper_elf_symbols="$work_dir/wrapper-symbols"
combined_feature_log="$work_dir/combined-feature.log"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_crypt_allocator_composition_probe.c \
    >/dev/null 2>"$header_trace"
for header in crypt.h stdint.h stdlib.h string.h unistd.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_crypt_allocator_composition_probe.c \
    -o "$reference"
set +e
env -i LC_ALL=C TZ=UTC "$reference"
reference_status=$?
set -e
[ "$reference_status" -eq 0 ] \
    || fail "pinned-musl crypt/allocator reference failed with status $reference_status"

if CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-crypt,x86-allocator-runtime --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort \
    >"$combined_feature_log" 2>&1; then
    fail "manual x86-crypt/x86-allocator-runtime selection unexpectedly composed"
fi
grep -Fq 'x86-crypt and x86-allocator-runtime must be enabled through x86-crypt-allocator-composition' \
    "$combined_feature_log" || fail "manual crypt/allocator feature rejection drifted"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-crypt-allocator-composition --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$full_archive" ] || fail "cargo did not emit the composition libc archive"

mapfile -t crypt_members < <(archive_member_for_symbol "$full_archive" crypt)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$full_archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(archive_member_for_symbol "$full_archive" __errno_location)
mapfile -t backend_members < <(ar t "$full_archive" | grep -- '-static\.o$')
[ "${#crypt_members[@]}" -eq 1 ] || fail "crypt must have exactly one crate object owner"
[ "${#allocator_members[@]}" -eq 1 ] || fail "allocator wrapper must have exactly one crate object owner"
[ "${#errno_members[@]}" -eq 1 ] || fail "errno must have exactly one crate object owner"
[ "${#backend_members[@]}" -eq 1 ] || fail "allocator backend must have exactly one bundled static object"
[ "${crypt_members[0]}" != "${allocator_members[0]}" ] \
    || fail "crypt and allocator ownership unexpectedly collapsed"
[ "${crypt_members[0]}" != "${errno_members[0]}" ] \
    || fail "crypt and errno ownership unexpectedly collapsed"
[ "${crypt_members[0]}" != "${backend_members[0]}" ] \
    || fail "crypt and backend ownership unexpectedly collapsed"
[ "${allocator_members[0]}" != "${errno_members[0]}" ] \
    || fail "allocator and errno ownership unexpectedly collapsed"
[ "${allocator_members[0]}" != "${backend_members[0]}" ] \
    || fail "allocator and backend ownership unexpectedly collapsed"
[ "${errno_members[0]}" != "${backend_members[0]}" ] \
    || fail "errno and backend ownership unexpectedly collapsed"

selected_member_dir="$work_dir/selected-members"
mkdir "$selected_member_dir"
(
    cd "$selected_member_dir"
    ar x "$full_archive" "${crypt_members[0]}" "${allocator_members[0]}" \
        "${errno_members[0]}" "${backend_members[0]}"
    ar crs "$selected_allocator_archive" "${allocator_members[0]}" \
        "${errno_members[0]}" "${backend_members[0]}"
)
selected_crypt_member="$selected_member_dir/${crypt_members[0]}"
mapfile -t selected_allocator_members < <(ar t "$selected_allocator_archive")
if [ "${selected_allocator_members[*]}" != "${allocator_members[0]} ${errno_members[0]} ${backend_members[0]}" ]; then
    fail "selected allocator provider contains an unexpected archive member"
fi

readelf --relocs --wide "$selected_crypt_member" >"$crypt_relocations"
# The current RustCrypto closure emits one ordinary malloc relocation. The
# fixture directly exercises the paired free and aligned_alloc/free routes
# through the same selected wrapper, without claiming optimized-away Rust
# relocation sites as an executable fact.
for symbol in malloc; do
    nm --undefined-only "$selected_crypt_member" | grep -Eq "[[:space:]]${symbol}$" \
        || fail "selected crypt object does not request $symbol"
    grep -Eq "(^|[[:space:]])${symbol}([[:space:]]|$|@)" "$crypt_relocations" \
        || fail "selected crypt object has no relocation for $symbol"
done

readelf --symbols --wide "$selected_member_dir/${allocator_members[0]}" \
    >"$wrapper_elf_symbols"
for symbol in aligned_alloc free; do
    assert_elf_function_binding "$wrapper_elf_symbols" "$symbol" GLOBAL \
        "allocator wrapper"
done
assert_elf_function_binding "$wrapper_elf_symbols" malloc WEAK "allocator wrapper"
for symbol in mi_malloc_aligned mi_zalloc mi_realloc_aligned mi_free; do
    nm -g --defined-only "$selected_member_dir/${backend_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" \
        || fail "selected backend lacks $symbol"
done
for symbol in malloc_usable_size __crabc_x86_allocator_observability_v1; do
    if nm -g --defined-only "$selected_member_dir/${allocator_members[0]}" \
        "$selected_member_dir/${backend_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$"; then
        fail "selected provider leaked separate allocator-observability symbol $symbol"
    fi
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_X86_CRYPT_ALLOCATOR_COMPOSITION_CANDIDATE \
    -I"$ROOT_DIR/include" -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -Wl,--allow-multiple-definition -Wl,-Map,"$link_map" \
    compat/x86_64/libc_crypt_allocator_composition_probe.c \
    "$selected_crypt_member" "$selected_allocator_archive" "$musl_archive" \
    "$full_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in crypt crypt_r __crypt_sha256; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks $symbol"
done
for symbol in crypt __crypt_sha256; do
    assert_elf_function_binding "$candidate_symbols" "$symbol" GLOBAL "candidate"
done
assert_elf_function_binding "$candidate_symbols" crypt_r WEAK "candidate"
for symbol in malloc aligned_alloc free; do
    case "$symbol" in
        malloc) binding=WEAK ;;
        *) binding=GLOBAL ;;
    esac
    assert_elf_function_binding "$candidate_symbols" "$symbol" "$binding" "candidate"
done
for symbol in malloc_usable_size __crabc_x86_allocator_observability_v1; do
    if grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols"; then
        fail "candidate leaked separate allocator-observability symbol $symbol"
    fi
done
grep -Fq "$selected_crypt_member" "$link_map" \
    || fail "candidate did not link the selected crabc crypt object directly"
grep -Fq "$selected_allocator_archive" "$link_map" \
    || fail "candidate did not link the selected crabc allocator provider"
for member in strcmp.lo strlen.lo write.lo; do
    grep -Fq "libc.a($member)" "$link_map" \
        || fail "candidate did not select pinned-musl $member"
done
if grep -Eq 'libc\.a\((aligned_alloc|calloc|free|libc_calloc|lite_malloc|malloc|malloc_usable_size|memalign|posix_memalign|realloc|reallocarray|replaced|valloc)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl allocator implementation"
fi
if grep -F "$full_archive(" "$link_map" | grep -Eq -- '-static\.o\)'; then
    fail "candidate selected an additional backend from the full crabc archive"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|DTPOFF(32|64)?|GOTTPOFF' \
    "$candidate_relocations"; then
    fail "candidate retains a dynamic TLS relocation"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" \
    || fail "candidate lacks the allocator and errno static TLS image"
# Rust's static support closure may retain musl's resolver helper as code, but
# this candidate has no dynamic TLS relocation and establishes no resolver
# behavior. Keep the support owner explicit rather than mistaking it for the
# selected crabc allocator or a dynamic runtime claim.
grep -Fq 'libc.a(__tls_get_addr.lo)' "$link_map" \
    || fail "candidate did not attribute __tls_get_addr support to pinned musl"
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' "$candidate_headers" "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi

env -i LC_ALL=C TZ=UTC "$candidate" \
    || fail "crabc crypt/allocator composition candidate failed"

printf 'x86 static libc crypt/allocator composition: PASS\n'
