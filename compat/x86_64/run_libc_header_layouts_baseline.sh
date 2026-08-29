#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc header/layout baseline.
#
# The C fixture and separately compiled freestanding C++17 companion first
# execute through pinned musl 1.2.6, then through one -nostdlib -static
# candidate linked only with the existing selected crabc archive.  This joins
# the named C/C++ header ABI gates to existing record-bearing archive APIs; it
# adds neither a C export nor a header or runtime capability.  It is not
# installed-header closure, a general C ABI, libc.so, CRT, loader, sysroot,
# C++ runtime, pthread lifecycle, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc header/layout baseline: %s\n' "$*" >&2
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
    local archive_path="$1"
    local symbols_path="$2"
    local expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"
    local -a members

    # Keep the C ABI ratchet scoped to crate-owned `c.*.rcgu.o` members.
    # Compiler-builtins is toolchain support, not a selected crabc C export.
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

assert_fixture_tls_capacity() {
    local tls_filesz
    local tls_memsz
    local tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    if (( tls_filesz != 0 )); then
        fail "fixture TLS scratch cannot initialize nonzero PT_TLS data"
    fi
    if (( tls_memsz == 0 || tls_memsz > INITIAL_TLS_BYTES )); then
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    fi
    if (( tls_alignment == 0 || tls_alignment > INITIAL_TLS_ALIGNMENT ||
        INITIAL_TLS_ALIGNMENT % tls_alignment != 0 )); then
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
    fi
}

assert_cxx_c_linkage() {
    local object="$1"
    local undefined="$2"
    local defined="$3"
    local symbol

    nm --undefined-only "$object" >"$undefined"
    nm -g --defined-only "$object" >"$defined"
    grep -Eq "[[:space:]]crabc_x86_64_header_layouts_baseline_cxx_probe$" "$defined" ||
        fail "C++ companion does not define its C-linkage entry"
    for symbol in __errno_location fstat clock_gettime mmap munmap mprotect \
        madvise posix_madvise mincore getrlimit poll select socketpair close \
        sigemptyset cfmakeraw uname sysinfo getpagesize; do
        grep -Eq "[[:space:]]${symbol}$" "$undefined" ||
            fail "C++ companion does not retain C linkage for ${symbol}"
    done
    if grep -Eq '[[:space:]]_Z|__gxx_personality_v0|__cxa(_guard)?_|_Unwind_|__stack_chk_fail|__tls_get_addr|_Zn|_Zd' "$undefined"; then
        fail "C++ companion retained a C++ runtime, mangled C reference, or dynamic TLS helper"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
for gate in \
    run_types_header_abi.sh \
    run_stat_header_abi.sh \
    run_time_header_abi.sh \
    run_poll_header_abi.sh \
    run_select_header_abi.sh \
    run_fcntl_header_abi.sh \
    run_unistd_header_abi.sh \
    run_system_header_abi.sh \
    run_signal_header_abi.sh \
    run_termios_header_abi.sh \
    run_mman_header_abi.sh \
    run_resource_header_abi.sh \
    run_socket_header_abi.sh; do
    bash "$ROOT_DIR/compat/x86_64/$gate" >/dev/null
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-header-layouts-baseline.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-header-layouts-baseline-reference"
candidate="$work_dir/crabc-static-header-layouts-baseline-candidate"
header_trace_c="$work_dir/header-trace-c"
header_trace_cxx="$work_dir/header-trace-cxx"
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
errno_disassembly="$work_dir/errno-disassembly"

readonly C_PROBE="compat/x86_64/libc_header_layouts_baseline_probe.c"
readonly CXX_PROBE="compat/x86_64/libc_header_layouts_baseline_probe.cpp"
readonly START_SHIM="compat/x86_64/libc_header_layouts_baseline_start.S"
readonly -a PROJECT_HEADERS=(
    errno.h fcntl.h netinet/in.h poll.h signal.h sys/mman.h sys/resource.h
    sys/select.h sys/socket.h sys/stat.h sys/sysinfo.h sys/utsname.h termios.h
    time.h unistd.h
)
readonly -a CXX_FLAGS=(
    -std=c++17 -x c++ -D_GNU_SOURCE -ffreestanding -fno-exceptions -fno-rtti
    -fno-threadsafe-statics -fno-use-cxa-atexit -fno-unwind-tables
    -fno-asynchronous-unwind-tables -fno-builtin -fno-stack-protector -fno-pie
    -nostdinc++
)

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H "$C_PROBE" \
    >/dev/null 2>"$header_trace_c"
"$ORACLE_CC" "${CXX_FLAGS[@]}" -I"$ROOT_DIR/include" -E -H "$CXX_PROBE" \
    >/dev/null 2>"$header_trace_cxx"
for header in "${PROJECT_HEADERS[@]}"; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace_c" ||
        fail "C fixture did not use the project $header header"
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace_cxx" ||
        fail "C++ fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -fno-pie -c "$C_PROBE" -o "$reference_c_object"
"$ORACLE_CC" "${CXX_FLAGS[@]}" -c "$CXX_PROBE" -o "$reference_cxx_object"
"$ORACLE_CC" -fno-pie -no-pie "$reference_c_object" "$reference_cxx_object" \
    -o "$reference"
if "$reference"; then
    :
else
    status=$?
    fail "pinned-musl header/layout baseline fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location fstat clock_gettime mmap munmap mprotect \
    madvise posix_madvise mincore getrlimit poll select socketpair close \
    sigemptyset cfmakeraw uname sysinfo getpagesize; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_HEADER_LAYOUTS_BASELINE_FREESTANDING \
    -I"$ROOT_DIR/include" -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-pie -c "$C_PROBE" -o "$candidate_c_object"
"$ORACLE_CC" "${CXX_FLAGS[@]}" -I"$ROOT_DIR/include" -c "$CXX_PROBE" \
    -o "$candidate_cxx_object"
"$ORACLE_CC" -c "$START_SHIM" -o "$candidate_start_object"
assert_cxx_c_linkage "$candidate_cxx_object" "$candidate_cxx_undefined" \
    "$candidate_cxx_defined"
readelf --sections --wide "$candidate_cxx_object" >"$candidate_cxx_sections"
cxx_object_exception_sections="$(grep -E '\.(init_array|fini_array|ctors|dtors|gcc_except_table)' \
    "$candidate_cxx_sections" || true)"
if [ -n "$cxx_object_exception_sections" ]; then
    printf '%s\n' "$cxx_object_exception_sections" >&2
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
for symbol in crabc_x86_64_header_layouts_baseline_probe \
    crabc_x86_64_header_layouts_baseline_cxx_probe __errno_location fstat \
    clock_gettime mmap munmap mprotect madvise posix_madvise mincore getrlimit \
    poll select socketpair close sigemptyset cfmakeraw uname sysinfo getpagesize; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned runtime dependency"
fi
cxx_runtime_matches="$(grep -E '__gxx_personality_v0|__cxa(_guard)?_|_Unwind_|__stack_chk_fail|__tls_get_addr|_Zn|_Zd' \
    "$candidate_symbols" "$candidate_disassembly" || true)"
if [ -n "$cxx_runtime_matches" ]; then
    printf '%s\n' "$cxx_runtime_matches" >&2
    fail "candidate selected a C++ runtime, constructor, exception, or stack/TLS helper"
fi
cxx_constructor_sections="$(grep -E '\.(init_array|fini_array|ctors|dtors)' \
    "$candidate_sections" || true)"
if [ -n "$cxx_constructor_sections" ]; then
    printf '%s\n' "$cxx_constructor_sections" >&2
    fail "candidate selected a C++ runtime, constructor, exception, or stack/TLS helper"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

if "$candidate"; then
    :
else
    status=$?
    fail "freestanding C/C++ header/layout baseline fixture exited ${status}"
fi

printf 'x86 static crabc-libc C/C++ header/layout baseline: PASS\n'
