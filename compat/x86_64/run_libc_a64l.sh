#!/usr/bin/env bash
# Native Linux/x86-64 opt-in static crabc-libc a64l evidence.
#
# One X/Open 700 project-header fixture first runs through pinned musl 1.2.6
# and then through a true `-nostdlib -static` candidate. The opt-in owner is
# the state-free a64l half of musl's shared a64l.c source. Its fixed local
# alphabet scan keeps this selected object independent of l64a, byte-string,
# and result-buffer owners.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-a64l
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/a64l.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_l64a_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_a64l_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_a64l_start.S"

fail() {
    printf 'ERROR: x86 static libc a64l: %s\n' "$*" >&2
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
        fail "x86-a64l removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'a64l\n') "$additions"; then
        diff -u <(printf 'a64l\n') "$additions" >&2 || true
        fail "x86-a64l changes more than a64l"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp comm diff grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null
grep -Fqx $'a64l\ta64l.lo\tT\tGLOBAL\t0\t64' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost a64l ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-a64l.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-a64l.a"
reference="$work_dir/musl-a64l-reference"
candidate="$work_dir/crabc-static-a64l-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-a64l.o"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
expected_symbols="$work_dir/expected-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
archive_symbols="$work_dir/archive-symbols"
a64l_undefined="$work_dir/a64l-undefined"
a64l_relocations="$work_dir/a64l-relocations"
a64l_disassembly="$work_dir/a64l-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" a64l.lo >"$musl_object"
for symbol in a64l l64a; do
    readelf --symbols --wide "$musl_object" | grep -Eq "[[:space:]]${symbol}$" ||
        fail "pinned musl a64l.lo lacks ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in stdlib.h features.h bits/alltypes.h errno.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" "$PROBE" -o "$reference"
"$reference" || fail "pinned-musl a64l fixture failed"

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
if grep -Fxq a64l "$baseline_symbols"; then
    fail "baseline archive unexpectedly defines opt-in a64l"
fi

CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$SOURCE" ] || fail "missing a64l source"
[ -f "$featured_archive" ] || fail "cargo did not emit the featured x86 static libc archive"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in a64l; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "featured archive does not define ${symbol}"
done
for marker in 'src/misc/a64l.c::a64l' 'for shift in (0..36).step_by(6)' \
    'while index < 64' 'pub unsafe extern "C" fn a64l'; do
    grep -Fq "$marker" "$SOURCE" || fail "source lacks $marker"
done

mapfile -t a64l_members < <(archive_member_for_symbol "$featured_archive" a64l)
[ "${#a64l_members[@]}" -eq 1 ] || fail "a64l must have exactly one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$featured_archive" "${a64l_members[0]}"
    ar crs "$selected_archive" "${a64l_members[0]}"
)
a64l_object="$work_dir/owner/${a64l_members[0]}"
mapfile -t a64l_exports < <(
    nm -g --defined-only --format=posix "$a64l_object" |
        awk '$2 ~ /^[TW]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ { print $1 }' |
        LC_ALL=C sort -u
)
if [ "${a64l_exports[*]}" != "a64l" ]; then
    printf 'expected: %s\nactual:   %s\n' "a64l" "${a64l_exports[*]}" >&2
    fail "a64l object export surface drifted"
fi
nm --undefined-only --format=posix "$a64l_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | LC_ALL=C sort -u >"$a64l_undefined"
if [ -s "$a64l_undefined" ]; then
    cat "$a64l_undefined" >&2
    fail "a64l owner has an unexpected direct dependency"
fi
readelf --relocs --wide "$a64l_object" >"$a64l_relocations"
objdump -dr "$a64l_object" >"$a64l_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$a64l_relocations" "$a64l_disassembly"; then
    fail "a64l owner selects a call, TLS, syscall, or an unowned runtime"
fi

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -DCRABC_A64L_FREESTANDING \
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
for symbol in a64l; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
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
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains errno or TLS"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$candidate_link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq '[[:space:]](l64a|strchr|index|memchr)$' "$candidate_symbols"; then
    fail "candidate accidentally selects an unowned radix-64 or byte-string helper"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|memset|strtol|strtoul|strtoimax' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

"$candidate" || fail "freestanding a64l fixture failed"

printf 'x86 static libc a64l: PASS\n'
