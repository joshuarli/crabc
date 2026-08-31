#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc rand_r evidence.
#
# The same project-header C fixture first runs through pinned musl 1.2.6 and
# then through a true -nostdlib/-static candidate made from exactly one rand_r
# archive member. It proves only the deterministic caller-owned unsigned seed
# transition and returned 31-bit value; it does not select global PRNG state,
# other random interfaces, entropy, TLS, syscalls, allocation, CRT, loader,
# sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc rand_r: %s\n' "$*" >&2
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
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_stdlib_header_abi.sh" >/dev/null

grep -Fqx $'rand_r\trand_r.lo\tT\tGLOBAL\t0\t44' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost rand_r ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-rand-r.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-rand-r.a"
reference="$work_dir/musl-rand-r-reference"
candidate="$work_dir/crabc-static-rand-r-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/rand-r-undefined"
object_relocations="$work_dir/rand-r-relocations"
object_disassembly="$work_dir/rand-r-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
rand_r_disassembly="$work_dir/rand-r-candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_rand_r_probe.c >/dev/null 2>"$header_trace"
for header in stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_rand_r_probe.c -o "$reference"
timeout 10s "$reference" || fail "pinned-musl rand_r fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq "[[:space:]][TW][[:space:]]rand_r$" "$archive_symbols" ||
    fail "archive does not define rand_r"

mapfile -t members < <(archive_member_for_symbol "$archive" rand_r)
[ "${#members[@]}" -eq 1 ] || fail "rand_r must have exactly one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${members[0]}"
    ar crs "$selected_archive" "${members[0]}"
)
object="$work_dir/owner/${members[0]}"

mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "rand_r" ]; then
    printf 'expected: %s\nactual:   %s\n' "rand_r" "${exports[*]}" >&2
    fail "rand_r object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    cat "$object_undefined" >&2
    fail "rand_r object unexpectedly depends on another symbol"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:' "$object_disassembly"; then
    fail "rand_r object unexpectedly calls, syscalls, or uses TLS"
fi

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -DCRABC_RAND_R_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_rand_r_probe.c \
    compat/x86_64/libc_rand_r_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=rand_r "$candidate" >"$rand_r_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "rand_r" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks global rand_r"
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
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:' "$rand_r_disassembly"; then
    fail "candidate rand_r unexpectedly calls, syscalls, or uses TLS"
fi
for unselected in rand srand random srandom random_r srandom_r initstate setstate \
    drand48 erand48 lrand48 mrand48 nrand48 arc4random arc4random_buf \
    getrandom getentropy malloc calloc realloc free; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate selects unowned ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

timeout 10s "$candidate" || fail "freestanding rand_r fixture failed"

printf 'x86 static libc rand_r: PASS\n'
