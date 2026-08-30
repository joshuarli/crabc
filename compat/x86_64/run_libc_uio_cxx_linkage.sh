#!/usr/bin/env bash
# Native Linux/x86-64 freestanding C++ <sys/uio.h> archive-linkage evidence.
#
# The fixed C/C++ fixture first links and runs against pinned musl 1.2.6, then
# links only the selected static crabc-libc archive.  It proves one bounded
# C++ consumer reaches the four already-selected vector-I/O C spellings; it
# neither adds an export nor admits a C++ runtime or general header closure.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly C_PROBE="compat/x86_64/libc_uio_cxx_linkage_probe.c"
readonly CXX_PROBE="compat/x86_64/libc_uio_cxx_linkage_probe.cpp"
readonly START_SHIM="compat/x86_64/libc_uio_cxx_linkage_start.S"
readonly -a CXX_FLAGS=(
    -std=c++17 -x c++ -D_GNU_SOURCE -ffreestanding -fno-exceptions -fno-rtti
    -fno-threadsafe-statics -fno-use-cxa-atexit -fno-unwind-tables
    -fno-asynchronous-unwind-tables -fno-builtin -fno-stack-protector -fno-pie
    -nostdinc++
)

fail() {
    printf 'ERROR: x86 static libc C++ <sys/uio.h> linkage: %s\n' "$*" >&2
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

assert_cxx_c_linkage() {
    local object="$1" undefined="$2" defined="$3"
    local symbol

    nm --undefined-only "$object" >"$undefined"
    nm -g --defined-only "$object" >"$defined"
    grep -Eq '[[:space:]]crabc_x86_64_uio_cxx_linkage_probe$' "$defined" ||
        fail "C++ companion does not define its C-linkage entry"
    for symbol in __errno_location readv writev preadv pwritev; do
        grep -Eq "[[:space:]]${symbol}$" "$undefined" ||
            fail "C++ companion does not retain C linkage for ${symbol}"
    done
    if grep -Eq '[[:space:]]_Z|__gxx_personality_v0|__cxa(_guard)?_|_Unwind_|__stack_chk_fail|__tls_get_addr|_Zn|_Zd' "$undefined"; then
        fail "C++ companion retained a C++ runtime, mangled C reference, or dynamic TLS helper"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
        INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_vector_io_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-uio-cxx-linkage.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-uio-cxx-linkage-reference"
candidate="$work_dir/crabc-static-uio-cxx-linkage-candidate"
reference_c_object="$work_dir/reference-c.o"
reference_cxx_object="$work_dir/reference-cxx.o"
candidate_start_object="$work_dir/candidate-start.o"
candidate_c_object="$work_dir/candidate-c.o"
candidate_cxx_object="$work_dir/candidate-cxx.o"
candidate_cxx_undefined="$work_dir/candidate-cxx-undefined"
candidate_cxx_defined="$work_dir/candidate-cxx-defined"
candidate_cxx_sections="$work_dir/candidate-cxx-sections"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -fno-pie -c "$C_PROBE" -o "$reference_c_object"
"$ORACLE_CC" "${CXX_FLAGS[@]}" -c "$CXX_PROBE" -o "$reference_cxx_object"
"$ORACLE_CC" -fno-pie -no-pie "$reference_c_object" "$reference_cxx_object" \
    -o "$reference"
"$reference" || fail "pinned-musl C++ <sys/uio.h> fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location readv writev preadv pwritev socketpair close; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_UIO_CXX_LINKAGE_FREESTANDING -I"$ROOT_DIR/include" -ffreestanding \
    -fno-builtin -fno-stack-protector -fno-pie -c "$C_PROBE" -o "$candidate_c_object"
"$ORACLE_CC" "${CXX_FLAGS[@]}" -I"$ROOT_DIR/include" -c "$CXX_PROBE" \
    -o "$candidate_cxx_object"
"$ORACLE_CC" -c "$START_SHIM" -o "$candidate_start_object"
assert_cxx_c_linkage "$candidate_cxx_object" "$candidate_cxx_undefined" "$candidate_cxx_defined"
readelf --sections --wide "$candidate_cxx_object" >"$candidate_cxx_sections"
if grep -Eq '\.(init_array|fini_array|ctors|dtors|gcc_except_table)' "$candidate_cxx_sections"; then
    fail "C++ companion retains a constructor or exception section"
fi

"$ORACLE_CC" -nostdlib -static -fno-pie -no-pie -Wl,-e,_start \
    -Wl,--no-undefined "$candidate_start_object" "$candidate_c_object" \
    "$candidate_cxx_object" "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in crabc_x86_64_uio_cxx_linkage_entry \
    crabc_x86_64_uio_cxx_linkage_probe __errno_location readv writev preadv \
    pwritev socketpair close; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
[ -z "$unresolved_symbols" ] || fail "candidate retains an unresolved symbol"
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned runtime dependency"
fi
if grep -Eq '__gxx_personality_v0|__cxa(_guard)?_|_Unwind_|__stack_chk_fail|__tls_get_addr|_Zn|_Zd' \
    "$candidate_symbols" "$candidate_disassembly" ||
    grep -Eq '\.(init_array|fini_array|ctors|dtors)' "$candidate_sections"; then
    fail "candidate selected a C++ runtime, constructor, exception, or stack/TLS helper"
fi
"$candidate" || fail "freestanding C++ <sys/uio.h> archive fixture failed"

printf 'x86 static crabc-libc C++ <sys/uio.h> archive linkage: PASS\n'
