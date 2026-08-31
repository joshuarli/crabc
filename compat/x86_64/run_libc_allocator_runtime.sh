#!/usr/bin/env bash
# Native Linux/x86-64 opt-in crabc-libc allocator-wrapper evidence.
#
# This is deliberately a mixed-runtime differential: the candidate allocator
# entry points and active AArch64-equivalent libmimalloc-sys backend come from
# crabc-libc, while pinned musl supplies startup and the process primitives that
# the incomplete x86 runtime does not yet own. The link map must prove that no
# musl allocator object is selected. This admits the allocator ABI wrapper as a
# private artifact, not an owned runtime, allocator-port promotion, or public
# x86 platform.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 static libc allocator runtime: %s\n' "$*" >&2
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

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-allocator-runtime.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
full_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-allocator-runtime.a"
reference="$work_dir/pinned-musl-allocator-reference"
candidate="$work_dir/crabc-allocator-runtime-candidate"
header_trace="$work_dir/header-trace"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_allocator_runtime_probe.c >/dev/null 2>"$header_trace"
for header in errno.h stdint.h stdlib.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_allocator_runtime_probe.c -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" \
    || fail "pinned-musl allocator reference failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-allocator-runtime --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$full_archive" ] || fail "cargo did not emit the opt-in x86 libc archive"

mapfile -t allocator_members < <(
    archive_member_for_symbol "$full_archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(
    archive_member_for_symbol "$full_archive" __errno_location
)
mapfile -t backend_members < <(ar t "$full_archive" | grep -- '-static\.o$')
[ "${#allocator_members[@]}" -eq 1 ] \
    || fail "allocator wrapper must have exactly one crate object owner"
[ "${#errno_members[@]}" -eq 1 ] \
    || fail "errno must have exactly one crate object owner"
[ "${#backend_members[@]}" -eq 1 ] \
    || fail "allocator backend must have exactly one bundled static object"
[ "${allocator_members[0]}" != "${errno_members[0]}" ] \
    || fail "allocator and errno ownership unexpectedly collapsed"

mkdir "$work_dir/selected-members"
(
    cd "$work_dir/selected-members"
    ar x "$full_archive" "${allocator_members[0]}" "${errno_members[0]}" \
        "${backend_members[0]}"
    ar crs "$selected_archive" "${allocator_members[0]}" \
        "${errno_members[0]}" "${backend_members[0]}"
)

mapfile -t wrapper_symbols < <(
    nm -g --defined-only --format=posix \
        "$work_dir/selected-members/${allocator_members[0]}" |
        awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_wrapper_symbols=(
    __crabc_x86_allocator_runtime_v1
    aligned_alloc
    calloc
    free
    malloc
    posix_memalign
    realloc
)
if [ "${wrapper_symbols[*]}" != "${expected_wrapper_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_wrapper_symbols[*]}" \
        "${wrapper_symbols[*]}" >&2
    fail "allocator wrapper export surface drifted"
fi
for symbol in __errno_location ___errno_location; do
    nm -g --defined-only "$work_dir/selected-members/${errno_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" \
        || fail "selected errno owner lacks $symbol"
done
for symbol in mi_malloc_aligned mi_zalloc mi_realloc mi_free; do
    nm -g --defined-only "$work_dir/selected-members/${backend_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" \
        || fail "bundled AArch64-equivalent backend lacks $symbol"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_ALLOCATOR_RUNTIME_CANDIDATE -I"$ROOT_DIR/include" \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -Wl,-Map,"$link_map" compat/x86_64/libc_allocator_runtime_probe.c \
    "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"

for symbol in __crabc_x86_allocator_runtime_v1 aligned_alloc calloc free malloc \
    posix_memalign realloc; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks crabc allocator symbol $symbol"
done
if grep -Eq 'libc\.a\((aligned_alloc|calloc|free|malloc|posix_memalign|realloc)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl allocator implementation"
fi
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" \
    || fail "candidate lacks the allocator and errno static TLS image"
if grep -Eqi 'glibc|ld-linux|libc\.so\.6' "$candidate_program_headers" \
    "$candidate_dynamic" "$link_map"; then
    fail "candidate selected glibc"
fi

env -i LC_ALL=C TZ=UTC "$candidate" \
    || fail "crabc allocator wrapper candidate failed"

printf 'x86 static libc allocator runtime: PASS\n'
