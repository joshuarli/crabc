#!/usr/bin/env bash
# Native Linux/x86-64 opt-in crabc-libc C-string-duplication evidence.
#
# This is deliberately a mixed-runtime differential. The candidate owns only
# strdup/strndup plus the existing allocator wrapper, errno owner, and bundled
# mimalloc object. Pinned musl supplies startup/process primitives that remain
# outside the staged x86 runtime, but its duplicate and allocator objects must
# never enter the candidate link.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 static libc allocator string duplication: %s\n' "$*" >&2
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
for tool in ar awk cargo grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-allocator-string-duplication.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
full_archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-allocator-string-duplication.a"
reference="$work_dir/pinned-musl-string-duplication-reference"
candidate="$work_dir/crabc-string-duplication-candidate"
header_trace="$work_dir/header-trace"
link_map="$work_dir/candidate.map"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_allocator_string_duplication_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h stddef.h stdint.h stdlib.h string.h sys/mman.h \
    sys/syscall.h bits/alltypes.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_allocator_string_duplication_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" \
    || fail "pinned-musl string-duplication reference failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-allocator-string-duplication --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$full_archive" ] || fail "cargo did not emit the opt-in x86 libc archive"

mapfile -t duplication_members < <(
    archive_member_for_symbol "$full_archive" \
        __crabc_x86_allocator_string_duplication_v1
)
mapfile -t strdup_members < <(archive_member_for_symbol "$full_archive" strdup)
mapfile -t strndup_members < <(archive_member_for_symbol "$full_archive" strndup)
mapfile -t allocator_members < <(
    archive_member_for_symbol "$full_archive" __crabc_x86_allocator_runtime_v1
)
mapfile -t errno_members < <(archive_member_for_symbol "$full_archive" __errno_location)
mapfile -t backend_members < <(ar t "$full_archive" | grep -- '-static\.o$')
[ "${#duplication_members[@]}" -eq 1 ] \
    || fail "string-duplication witness must have exactly one crate object owner"
[ "${#strdup_members[@]}" -eq 1 ] && [ "${#strndup_members[@]}" -eq 1 ] \
    || fail "each duplication entry must have exactly one crate object owner"
[ "${duplication_members[0]}" = "${strdup_members[0]}" ] && \
    [ "${duplication_members[0]}" = "${strndup_members[0]}" ] \
    || fail "witness, strdup, and strndup must share one object owner"
[ "${#allocator_members[@]}" -eq 1 ] \
    || fail "allocator wrapper must have exactly one crate object owner"
[ "${#errno_members[@]}" -eq 1 ] \
    || fail "errno must have exactly one crate object owner"
[ "${#backend_members[@]}" -eq 1 ] \
    || fail "allocator backend must have exactly one bundled static object"
[ "${duplication_members[0]}" != "${allocator_members[0]}" ] \
    || fail "string duplication and allocation wrapper unexpectedly share one object"
[ "${duplication_members[0]}" != "${errno_members[0]}" ] \
    || fail "string duplication and errno ownership unexpectedly share one object"

mkdir "$work_dir/selected-members"
(
    cd "$work_dir/selected-members"
    ar x "$full_archive" "${duplication_members[0]}" "${allocator_members[0]}" \
        "${errno_members[0]}" "${backend_members[0]}"
    ar crs "$selected_archive" "${duplication_members[0]}" \
        "${allocator_members[0]}" "${errno_members[0]}" "${backend_members[0]}"
)

mapfile -t duplication_symbols < <(
    nm -g --defined-only --format=posix \
        "$work_dir/selected-members/${duplication_members[0]}" |
        awk '$2 ~ /^[TW]$/ && $1 !~ /^_R/ { print $1 }' | sort -u
)
expected_duplication_symbols=(
    __crabc_x86_allocator_string_duplication_v1
    strdup
    strndup
)
if [ "${duplication_symbols[*]}" != "${expected_duplication_symbols[*]}" ]; then
    printf 'expected: %s\nactual:   %s\n' "${expected_duplication_symbols[*]}" \
        "${duplication_symbols[*]}" >&2
    fail "string-duplication export surface drifted"
fi
for symbol in mi_malloc_aligned mi_free; do
    nm -g --defined-only "$work_dir/selected-members/${backend_members[0]}" |
        grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" \
        || fail "bundled AArch64-equivalent backend lacks $symbol"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_ALLOCATOR_STRING_DUPLICATION_CANDIDATE -I"$ROOT_DIR/include" \
    -static -fno-pie -no-pie -fno-builtin -fno-stack-protector \
    -Wl,-Map,"$link_map" compat/x86_64/libc_allocator_string_duplication_probe.c \
    "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"

for symbol in __crabc_x86_allocator_string_duplication_v1 strdup strndup malloc free; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate lacks crabc string-duplication symbol $symbol"
done
for symbol in strdup strndup; do
    awk -v symbol="$symbol" \
        '$4 == "FUNC" && $5 == "GLOBAL" && $8 == symbol { found = 1 }
         END { exit(found ? 0 : 1) }' "$candidate_symbols" \
        || fail "candidate $symbol is not a strong global function"
done
awk '$4 == "FUNC" && $5 == "WEAK" && $8 == "malloc" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" \
    || fail "candidate malloc lost the AArch64 weak binding"
if grep -Eq 'libc\.a\((strdup|strndup|aligned_alloc|calloc|free|malloc|memalign|posix_memalign|realloc|reallocarray|valloc)\.lo\)' \
    "$link_map"; then
    fail "candidate selected a pinned-musl duplication or allocator implementation"
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
    || fail "crabc string-duplication candidate failed"

printf 'x86 static libc allocator string duplication: PASS\n'
