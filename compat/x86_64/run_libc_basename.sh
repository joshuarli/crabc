#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc basename evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then through a true one-member `-nostdlib -static` candidate. It selects only
# src/misc/basename.c's caller-owned mutable scan and its weak same-address
# __xpg_basename alias, translating the source's strlen call locally so the
# candidate imports no byte-string archive helper.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc basename: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_basename_header_abi.sh" >/dev/null

grep -Fqx $'basename\tbasename.lo\tT\tGLOBAL\t0\t78' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost basename ownership"
grep -Fqx $'__xpg_basename\tbasename.lo\tW\tWEAK\t0\t78' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost __xpg_basename ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-basename.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-basename.a"
reference="$work_dir/musl-basename-reference"
candidate="$work_dir/crabc-static-basename-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-basename.o"
musl_undefined="$work_dir/musl-basename-undefined"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/basename-undefined"
object_relocations="$work_dir/basename-relocations"
object_disassembly="$work_dir/basename-object-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" basename.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]basename$' ||
    fail "pinned musl basename.lo lacks basename"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]__xpg_basename$' ||
    fail "pinned musl basename.lo lacks __xpg_basename"
nm --undefined-only --format=posix "$musl_object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$musl_undefined"
if ! cmp -s <(printf '%s\n' strlen) "$musl_undefined"; then
    cat "$musl_undefined" >&2
    fail "pinned musl basename.lo has an unexpected helper boundary"
fi

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    -E -H compat/x86_64/libc_basename_probe.c >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/libgen.h" "$header_trace" ||
    fail "fixture did not use project libgen.h"

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_basename_probe.c -o "$reference"
"$reference" || fail "pinned-musl basename fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq "[[:space:]][TW][[:space:]]basename$" "$archive_symbols" ||
    fail "archive does not define basename"
grep -Eq "[[:space:]]W[[:space:]]__xpg_basename$" "$archive_symbols" ||
    fail "archive does not define weak __xpg_basename"

mapfile -t members < <(archive_member_for_symbol "$archive" basename)
[ "${#members[@]}" -eq 1 ] || fail "basename must have exactly one crate object owner"
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
if [ "${exports[*]}" != "__xpg_basename basename" ]; then
    printf 'expected: %s\nactual:   %s\n' "__xpg_basename basename" "${exports[*]}" >&2
    fail "basename object export surface drifted"
fi
if nm -S --defined-only --format=posix "$object" |
    awk '$2 ~ /^[BD]$/ { print }' | grep -q .; then
    fail "basename object unexpectedly retains mutable static storage"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    cat "$object_undefined" >&2
    fail "basename object unexpectedly depends on another symbol"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d --disassemble=basename "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$object_disassembly"; then
    fail "basename object unexpectedly performs a call or syscall"
fi

"$ORACLE_CC" -std=c11 -DCRABC_BASENAME_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_basename_probe.c \
    compat/x86_64/libc_basename_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "basename" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks global basename"
awk '$4 == "FUNC" && $5 == "WEAK" && $8 == "__xpg_basename" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks weak __xpg_basename"
basename_value="$(awk '$8 == "basename" { print $2; exit }' "$candidate_symbols")"
xpg_value="$(awk '$8 == "__xpg_basename" { print $2; exit }' "$candidate_symbols")"
[ -n "$basename_value" ] && [ "$basename_value" = "$xpg_value" ] ||
    fail "__xpg_basename is not a same-address basename alias"
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
    "$object_relocations" "$candidate_relocations" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "candidate unexpectedly retains errno or TLS"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$link_map" "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
for unselected in dirname strlen strrchr strspn strcspn strsep strtok strtok_r \
    getcwd realpath canonicalize_file_name open openat stat lstat fstatat \
    malloc calloc realloc free memcpy memmove memset; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

"$candidate" || fail "freestanding basename fixture failed"

printf 'x86 static libc basename: PASS\n'
