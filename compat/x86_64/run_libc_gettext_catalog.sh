#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc gettext/catalog evidence.
#
# A project-header fixture first exercises the deterministic no-catalog subset
# against pinned musl 1.2.6, then links a true `-nostdlib -static` x86 archive
# candidate. The candidate-only tail ratchets the documented four permanent
# binding records plus catgets/catclose no-catalog behavior; musl's real
# catalog mapping is deliberately outside this selected profile.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc gettext/catalog: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_strong_function() {
    local symbols_path="$1" symbol="$2" label="$3"
    awk -v name="$symbol" \
        '$8 == name && $4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" { found = 1 } END { exit !found }' \
        "$symbols_path" || fail "$label lacks strong function $symbol"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_gettext_catalog_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-gettext-catalog.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/pinned-musl-gettext-catalog-reference"
candidate="$work_dir/crabc-static-gettext-catalog-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -E -H compat/x86_64/libc_gettext_catalog_probe.c >/dev/null 2>"$header_trace"
for header in errno.h libintl.h nl_types.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header> header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_gettext_catalog_probe.c -o "$reference"
if env -i "$reference"; then :; else
    status=$?
    fail "pinned-musl no-catalog fixture exited $status"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in bind_textdomain_codeset bindtextdomain catclose catgets catopen \
    dcgettext dcngettext dgettext dngettext gettext ngettext textdomain; do
    grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not strongly define $symbol"
done
for unselected in __gettextdomain malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' \
    "$archive_elf_symbols" || fail "archive TLS bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_GETTEXT_CATALOG_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    compat/x86_64/libc_gettext_catalog_probe.c \
    compat/x86_64/libc_gettext_catalog_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
    <(readelf --file-header --wide "$candidate") || fail "candidate is not ET_EXEC"
for symbol in bind_textdomain_codeset bindtextdomain catclose catgets catopen \
    dcgettext dcngettext dgettext dngettext gettext ngettext textdomain; do
    assert_strong_function "$candidate_symbols" "$symbol" candidate
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks selected errno TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'malloc|calloc|realloc|free|mmap|munmap|getenv|setenv|openat?|fopen|setlocale|newlocale|crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects allocator, catalog-file, environment, locale, or unowned state"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

if env -i "$candidate"; then :; else
    status=$?
    fail "freestanding gettext/catalog fixture exited $status"
fi

printf 'x86 static crabc-libc gettext/catalog no-catalog profile: PASS\n'
