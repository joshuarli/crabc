#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc hash-table evidence.
#
# Closed C/C++ feature profiles prove the exact musl <search.h> exposure and
# x86 ABI. One project-header fixture runs against pinned musl 1.2.6 and as a
# true freestanding candidate. The musl allocation call is wrapped; the
# candidate uses a temporary address-space ceiling plus mapping-liveness
# probes, so failure and ownership transitions are deterministic in both
# executions. This closes only the private search.hash-table capability, not
# general allocation or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc hash-table search: %s\n' "$*" >&2
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_strong_function() {
    local symbols_path="$1"
    local symbol="$2"
    local label="$3"

    awk -v name="$symbol" \
        '$8 == name && $4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" { found = 1 } END { exit !found }' \
        "$symbols_path" || fail "$label lacks strong function $symbol"
}

assert_weak_function() {
    local symbols_path="$1"
    local symbol="$2"
    local label="$3"

    awk -v name="$symbol" \
        '$8 == name && $4 == "FUNC" && $5 == "WEAK" && $7 != "UND" { found = 1 } END { exit !found }' \
        "$symbols_path" || fail "$label lacks weak function $symbol"
    if awk -v name="$symbol" \
        '$8 == name && $5 == "GLOBAL" && $7 != "UND" { found = 1 } END { exit !found }' \
        "$symbols_path"; then
        fail "$label unexpectedly strengthens $symbol"
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
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-search-hash-table.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
c_header="$ROOT_DIR/compat/x86_64/search_hash_table_header_abi_probe.c"
cxx_header="$ROOT_DIR/compat/x86_64/search_hash_table_header_abi_probe.cpp"
hidden_header="$ROOT_DIR/compat/x86_64/search_hash_table_header_hidden_probe.c"
runtime_fixture="$ROOT_DIR/compat/x86_64/libc_search_hash_table_probe.c"
runtime_start="$ROOT_DIR/compat/x86_64/libc_search_hash_table_start.S"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/pinned-musl-static-reference"
candidate="$work_dir/crabc-static-search-hash-table-candidate"
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-search-hash-table-cxx.o"
candidate_cxx_object="$work_dir/candidate-search-hash-table-cxx.o"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
reference_symbols="$work_dir/reference-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
candidate_hash_disassembly="$work_dir/candidate-hash-disassembly"

compile_visible_profile() {
    local profile="$1"
    shift
    local -a definitions=("$@")
    local variant

    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$c_header" ||
            fail "$profile C header contract failed ($variant)"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$cxx_header" ||
            fail "$profile C++ header contract failed ($variant)"
    done
}

assert_reentrant_hidden() {
    local profile="$1"
    shift
    local -a definitions=("$@")
    local variant

    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
            -U_GNU_SOURCE "${definitions[@]}" -fsyntax-only \
            "${include_args[@]}" "$hidden_header" >/dev/null 2>&1; then
            fail "$profile unexpectedly exposes GNU hsearch_data/_r ($variant)"
        fi
        if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
            "${definitions[@]}" -fsyntax-only "${include_args[@]}" \
            "$hidden_header" >/dev/null 2>&1; then
            fail "$profile unexpectedly exposes GNU hsearch_data/_r in C++ ($variant)"
        fi
    done
}

compile_visible_profile default
compile_visible_profile strict -D__STRICT_ANSI__
compile_visible_profile posix-2008 -D_POSIX_C_SOURCE=200809L
compile_visible_profile xopen-700 -D_XOPEN_SOURCE=700
compile_visible_profile bsd -D_BSD_SOURCE
compile_visible_profile gnu -D_GNU_SOURCE
assert_reentrant_hidden default
assert_reentrant_hidden strict -D__STRICT_ANSI__
assert_reentrant_hidden posix-2008 -D_POSIX_C_SOURCE=200809L
assert_reentrant_hidden xopen-700 -D_XOPEN_SOURCE=700
assert_reentrant_hidden bsd -D_BSD_SOURCE

"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_GNU_SOURCE -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_header" >/dev/null 2>"$header_trace"
for header in search.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "header probe did not use project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_GNU_SOURCE \
    -c "$cxx_header" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_GNU_SOURCE \
    -I "$ROOT_DIR/include" -c "$cxx_header" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in hcreate hdestroy hsearch hcreate_r hdestroy_r hsearch_r; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe does not retain C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*(hcreate|hdestroy|hsearch)'; then
        fail "C++ probe retained a mangled hash-table reference"
    fi
done

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    "$runtime_fixture" -Wl,--wrap=calloc -Wl,--wrap=free -o "$reference"
readelf --symbols --wide "$reference" >"$reference_symbols"
for symbol in hcreate hdestroy hsearch; do
    assert_strong_function "$reference_symbols" "$symbol" "pinned-musl static reference"
done
for symbol in hcreate_r hdestroy_r hsearch_r; do
    assert_weak_function "$reference_symbols" "$symbol" "pinned-musl static reference"
done
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    status=$?
    fail "pinned-musl static reference exited $status"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in hcreate hdestroy hsearch; do
    grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not strongly define $symbol"
done
for symbol in hcreate_r hdestroy_r hsearch_r; do
    grep -Eq "[[:space:]]W[[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not weakly define $symbol"
    if grep -Eq "[[:space:]]T[[:space:]]${symbol}$" "$archive_symbols"; then
        fail "archive unexpectedly strengthens $symbol"
    fi
done
for unselected in malloc calloc realloc free; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' \
    "$archive_elf_symbols" || fail "archive TLS bootstrap is not hidden"
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_SEARCH_HASH_TABLE_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined -Wl,--gc-sections \
    "$runtime_fixture" "$runtime_start" "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
    <(readelf --file-header --wide "$candidate") || fail "candidate is not ET_EXEC"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno TLS"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'malloc|calloc|realloc|free|mimalloc|crabc_core|sha_crypt|getenv|setenv|fopen|setlocale' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects allocator, process, stdio, locale, or unowned state"
fi
for symbol in hcreate hdestroy hsearch; do
    assert_strong_function "$candidate_symbols" "$symbol" candidate
done
for symbol in hcreate_r hdestroy_r hsearch_r; do
    assert_weak_function "$candidate_symbols" "$symbol" candidate
done
while read -r symbol; do
    objdump -d --disassemble="$symbol" "$candidate" >>"$candidate_hash_disassembly"
done < <(nm --defined-only "$candidate" | awk \
    '$3 ~ /search_hash_table/ || $3 ~ /^(hcreate|hcreate_r|hdestroy|hdestroy_r|hsearch|hsearch_r)$/ { print $3 }')
if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
    "$candidate_hash_disassembly"; then
    fail "selected hash-table call graph directly selects Rust panic machinery"
fi
if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding hash-table fixture exited $status"
fi

printf 'x86 static libc search.hash-table: PASS\n'
