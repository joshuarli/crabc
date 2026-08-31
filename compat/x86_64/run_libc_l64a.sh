#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc l64a evidence.
#
# One X/Open 700 project-header fixture first runs through pinned musl 1.2.6
# and then through a true `-nostdlib -static` candidate made from exactly the
# one crate member defining `l64a`. It selects only the shared seven-byte
# result-buffer half of musl's a64l.c source, not a64l's stateless decoder.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc l64a: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
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

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            if nm -g --defined-only "$member" |
                grep -Eq '[[:space:]][TW][[:space:]]l64a$'; then
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "l64a must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_l64a_header_abi.sh" >/dev/null

grep -Fqx $'l64a\ta64l.lo\tT\tGLOBAL\t0\t34' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost l64a ownership"
grep -Fqx $'a64l\ta64l.lo\tT\tGLOBAL\t0\t64' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost shared a64l.lo provenance"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-l64a.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-l64a-reference"
candidate="$work_dir/crabc-static-l64a-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-a64l.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-l64a-members"
selected_member_names="$work_dir/selected-l64a-member-names"
owner_symbols="$work_dir/l64a-owner-symbols"
owner_storage="$work_dir/l64a-owner-storage"
owner_disassembly="$work_dir/l64a-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/l64a-disassembly"

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

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_l64a_probe.c >/dev/null 2>"$header_trace"
for header in stdlib.h features.h bits/alltypes.h errno.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_l64a_probe.c -o "$reference"
"$reference" || fail "pinned-musl l64a fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]l64a$' "$archive_symbols" ||
    fail "archive does not define l64a"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected l64a member is missing"

nm -g --defined-only --format=posix "$selected_member" >"$owner_symbols"
mapfile -t owner_exports < <(
    awk '$2 ~ /^[TW]$/ { print $1 }' "$owner_symbols" | sort -u
)
if [ "${owner_exports[*]}" != "l64a" ]; then
    printf 'expected: %s\nactual:   %s\n' "l64a" "${owner_exports[*]}" >&2
    fail "l64a object export surface drifted"
fi
nm -S --defined-only --format=posix "$selected_member" >"$owner_storage"
if ! awk '$2 ~ /^[bB]$/ && ($4 == "7" || $4 == "0000000000000007") { found = 1 }
         END { exit(found ? 0 : 1) }' "$owner_storage"; then
    cat "$owner_storage" >&2
    fail "l64a object lacks its seven-byte mutable static result buffer"
fi
objdump -d --disassemble=l64a "$selected_member" >"$owner_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$owner_disassembly"; then
    fail "l64a object unexpectedly performs a call or syscall"
fi

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -DCRABC_L64A_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_l64a_probe.c compat/x86_64/libc_l64a_start.S \
    "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d --disassemble=l64a "$candidate" >"$candidate_disassembly"
awk '$4 == "FUNC" && $5 == "GLOBAL" && $8 == "l64a" { found = 1 }
     END { exit(found ? 0 : 1) }' "$candidate_symbols" ||
    fail "candidate lacks global l64a"
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
    fail "candidate unexpectedly retains errno or TLS"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$candidate_disassembly"; then
    fail "candidate l64a calls an unselected runtime boundary"
fi
for unselected in a64l strchr strlen strspn strcspn strtol strtoul strtoimax \
    malloc calloc realloc free memcpy memmove memset memccpy mempcpy \
    explicit_bzero bcopy bzero inet_ntoa; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

"$candidate" || fail "freestanding l64a fixture failed"

printf 'x86 static libc l64a: PASS\n'
