#!/usr/bin/env bash
# Native Linux/x86-64 static crabc-libc explicit_bzero/swab evidence.
#
# The common project-header body first runs against pinned musl 1.2.6 and then
# an opt-in `-nostdlib -static` candidate. It proves exact range clearing and
# disjoint pair swaps; a separate O3 dead-local witness audits that
# explicit_bzero remains an observable wipe even without a later C read.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-memory-special
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/memory_special.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_memory_special_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_memory_special_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_memory_special_start.S"
readonly DEAD_WIPE_PROBE="$ROOT_DIR/compat/x86_64/libc_explicit_bzero_dead_wipe_probe.c"
readonly DEAD_WIPE_START="$ROOT_DIR/compat/x86_64/libc_explicit_bzero_dead_wipe_start.S"

fail() {
    printf 'ERROR: x86 static libc explicit_bzero/swab: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1" symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' | LC_ALL=C sort -u
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

assert_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2" additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "x86-memory-special removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'explicit_bzero\nswab\n') "$additions"; then
        diff -u <(printf 'explicit_bzero\nswab\n') "$additions" >&2 || true
        fail "x86-memory-special changes more than explicit_bzero/swab"
    fi
}

assert_dead_wipe_retained() {
    local binary="$1" output="$2" label="$3"

    objdump -d --disassemble=crabc_x86_64_explicit_bzero_dead_wipe "$binary" >"$output"
    if ! grep -Eq 'call.*explicit_bzero|rep[[:space:]]+stos|mov[bwlq][[:space:]].*\$0x0.*\(' "$output"; then
        fail "$label retains no optimized explicit_bzero call or zeroing stores"
    fi
}

assert_explicit_bzero_owner() {
    local binary="$1" output="$2" label="$3"

    objdump -d --disassemble=explicit_bzero "$binary" >"$output"
    if grep -Eq 'call.*memset' "$output"; then
        return
    fi
    # Rust may emit a statically resolved GOT-indirect call for an extern C
    # symbol even under static relocation. The owner object has already been
    # required to have exactly one memset relocation, and this selected archive
    # contains only that owner plus the established memory object.
    if grep -Eq 'call.*_GLOBAL_OFFSET_TABLE_' "$output" &&
        grep -Eq 'R_X86_64_.*[[:space:]]memset' "$special_relocations"; then
        return
    fi
    cat "$output" >&2
    fail "$label explicit_bzero calls no selected memset owner"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp comm diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-memory-special.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-memory-special.a"
reference="$work_dir/musl-memory-special-reference"
candidate="$work_dir/crabc-memory-special-candidate"
dead_reference="$work_dir/musl-explicit-bzero-dead-wipe"
dead_candidate="$work_dir/crabc-explicit-bzero-dead-wipe"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
expected_symbols="$work_dir/expected-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
archive_symbols="$work_dir/archive-symbols"
special_undefined="$work_dir/special-undefined"
special_relocations="$work_dir/special-relocations"
special_disassembly="$work_dir/special-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_link_map="$work_dir/candidate.map"
dead_candidate_symbols="$work_dir/dead-candidate-symbols"
dead_candidate_headers="$work_dir/dead-candidate-program-headers"
dead_candidate_dynamic="$work_dir/dead-candidate-dynamic"
dead_candidate_disassembly="$work_dir/dead-candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in string.h unistd.h sys/types.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" "$PROBE" -o "$reference"
"$reference" || fail "pinned-musl explicit_bzero/swab fixture failed"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "cargo did not emit the baseline x86 static libc archive"
collect_global_surface "$baseline_archive" "$baseline_symbols" "$work_dir/baseline-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_symbols"
if ! cmp -s "$expected_symbols" "$baseline_symbols"; then
    diff -u "$expected_symbols" "$baseline_symbols" >&2 || true
    fail "selected static C ABI export surface drifted"
fi
for symbol in explicit_bzero swab; do
    if grep -Fxq "$symbol" "$baseline_symbols"; then
        fail "baseline archive unexpectedly defines opt-in $symbol"
    fi
done

CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$SOURCE" ] || fail "missing explicit_bzero/swab source"
[ -f "$featured_archive" ] || fail "cargo did not emit the featured x86 static libc archive"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in explicit_bzero swab memset; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "featured archive does not define $symbol"
done
for marker in 'src/string/explicit_bzero.c::explicit_bzero' \
    'src/string/swab.c::swab' 'cleared = in(reg) cleared' \
    'pub unsafe extern "C" fn explicit_bzero' 'pub unsafe extern "C" fn swab'; do
    grep -Fq "$marker" "$SOURCE" || fail "source lacks $marker"
done

mapfile -t special_members < <(archive_member_for_symbol "$featured_archive" explicit_bzero)
[ "${#special_members[@]}" -eq 1 ] || fail "explicit_bzero must have exactly one crate object owner"
mapfile -t swab_members < <(archive_member_for_symbol "$featured_archive" swab)
[ "${#swab_members[@]}" -eq 1 ] || fail "swab must have exactly one crate object owner"
[ "${special_members[0]}" = "${swab_members[0]}" ] ||
    fail "explicit_bzero/swab must share their selected owner"
mapfile -t memset_members < <(archive_member_for_symbol "$featured_archive" memset)
[ "${#memset_members[@]}" -eq 1 ] || fail "memset must have exactly one selected owner"
[ "${special_members[0]}" != "${memset_members[0]}" ] ||
    fail "memory-special owner must retain the existing memset dependency"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$featured_archive" "${special_members[0]}" "${memset_members[0]}"
    ar crs "$selected_archive" "${special_members[0]}" "${memset_members[0]}"
)
special_object="$work_dir/owner/${special_members[0]}"
mapfile -t special_exports < <(
    nm -g --defined-only --format=posix "$special_object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | LC_ALL=C sort -u
)
if [ "${special_exports[*]}" != "explicit_bzero swab" ]; then
    printf 'expected: %s\nactual:   %s\n' "explicit_bzero swab" "${special_exports[*]}" >&2
    fail "memory-special owner export surface drifted"
fi
nm --undefined-only --format=posix "$special_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | LC_ALL=C sort -u >"$special_undefined"
if ! cmp -s <(printf 'memset\n') "$special_undefined"; then
    cat "$special_undefined" >&2
    fail "memory-special owner has an unexpected direct dependency"
fi
readelf --relocs --wide "$special_object" >"$special_relocations"
objdump -dr "$special_object" >"$special_disassembly"
grep -Eq 'R_X86_64_.*[[:space:]]memset' "$special_relocations" ||
    fail "explicit_bzero calls no selected memset owner"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$special_relocations" "$special_disassembly"; then
    fail "memory-special owner selects TLS, syscall, or an unowned runtime"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MEMORY_SPECIAL_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections -Wl,-Map,"$candidate_link_map" "$PROBE" "$START" \
    "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in explicit_bzero swab memset; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define $symbol"
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
    "$candidate_link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|errno' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned allocator or runtime dependency"
fi
assert_explicit_bzero_owner "$candidate" "$work_dir/candidate-explicit-bzero-disassembly" "candidate"
"$candidate" || fail "freestanding explicit_bzero/swab fixture failed"

# This deliberately has no post-wipe C read and uses no -fno-builtin flag.
# The retained call/stores are a disassembly proof for the ordinary O3 caller,
# not an LTO claim.
"$ORACLE_CC" -std=c11 -O3 -D_GNU_SOURCE -fno-stack-protector \
    -I "$ROOT_DIR/include" "$DEAD_WIPE_PROBE" -o "$dead_reference"
assert_dead_wipe_retained "$dead_reference" "$work_dir/reference-dead-wipe-disassembly" \
    "pinned-musl O3 dead-wipe witness"
"$dead_reference" || fail "pinned-musl O3 dead-wipe witness failed"

"$ORACLE_CC" -std=c11 -O3 -D_GNU_SOURCE \
    -DCRABC_EXPLICIT_BZERO_DEAD_WIPE_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-stack-protector \
    -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections "$DEAD_WIPE_PROBE" \
    "$DEAD_WIPE_START" "$selected_archive" -o "$dead_candidate"
readelf --symbols --wide "$dead_candidate" >"$dead_candidate_symbols"
readelf --program-headers --wide "$dead_candidate" >"$dead_candidate_headers"
readelf --dynamic --wide "$dead_candidate" >"$dead_candidate_dynamic" || true
objdump -d "$dead_candidate" >"$dead_candidate_disassembly"
if awk '$7 == "UND" && NF >= 8 { print }' "$dead_candidate_symbols" | grep -q .; then
    fail "dead-wipe candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED|[[:space:]]TLS[[:space:]]' \
    "$dead_candidate_headers" "$dead_candidate_dynamic"; then
    fail "dead-wipe candidate selects a dynamic runtime or TLS"
fi
assert_dead_wipe_retained "$dead_candidate" "$work_dir/candidate-dead-wipe-disassembly" \
    "candidate O3 dead-wipe witness"
assert_explicit_bzero_owner "$dead_candidate" "$work_dir/dead-candidate-explicit-bzero-disassembly" \
    "dead-wipe candidate"
"$dead_candidate" || fail "candidate O3 dead-wipe witness failed"

printf 'x86 static crabc-libc explicit_bzero/swab: PASS\n'
