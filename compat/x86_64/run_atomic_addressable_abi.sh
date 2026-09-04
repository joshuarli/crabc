#!/usr/bin/env bash
# Native Linux/x86-64 project-only addressable C11 atomic ABI evidence.
#
# Musl 1.2.6 deliberately does not install <stdatomic.h>, so this is not a
# fabricated musl declaration or behavior comparison. It proves only the
# project header's six address-taken C entry points: a C consumer sees the
# actual macros before #undef, a C++ consumer spells the deliberately absent
# C++ surface as an explicit C ABI counterpart, and one -nostdlib static ELF
# resolves all six without a C++ or dynamic runtime.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s
readonly -a ATOMIC_SYMBOLS=(
    atomic_flag_clear
    atomic_flag_clear_explicit
    atomic_flag_test_and_set
    atomic_flag_test_and_set_explicit
    atomic_signal_fence
    atomic_thread_fence
)

fail() {
    printf 'ERROR: x86 project-only addressable stdatomic ABI: %s\n' "$*" >&2
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

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf sed sort timeout; do
    require_tool "$tool"
done
[ -x "$CC" ] || fail "missing pinned x86 compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export ratchet"

work_dir="$(mktemp -d /tmp/crabc-x86-64-atomic-addressable.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
c_probe="$work_dir/atomic-addressable-c.o"
cxx_probe="$work_dir/atomic-addressable-cxx.o"
start="$work_dir/atomic-addressable-start.o"
candidate="$work_dir/crabc-static-atomic-addressable"
c_header_trace="$work_dir/c-header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
cxx_undefined="$work_dir/cxx-undefined"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$CC" -std=c11 -D_GNU_SOURCE -nostdinc -I"$ROOT_DIR/include" -H \
    -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -ffunction-sections \
    -c compat/x86_64/atomic_addressable_abi_probe.c -o "$c_probe" \
    >/dev/null 2>"$c_header_trace"
for header in stdatomic.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$c_header_trace" ||
        fail "C fixture omitted project $header"
done
while IFS= read -r path; do
    case "$path" in
        "$ROOT_DIR/include"/*) ;;
        *) fail "C fixture header trace escaped the project tree: $path" ;;
    esac
done < <(trace_paths "$c_header_trace")

# The public project header deliberately exposes no C atomic vocabulary to
# C++17. This C++ companion instead checks the ABI of a consumer that declares the
# six C spellings itself; it must not pull a C++ runtime or mangle those names.
"$CC" -x c++ -std=c++17 -nostdinc -nostdinc++ -ffreestanding \
    -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-builtin \
    -fno-stack-protector -fno-pie -ffunction-sections \
    -c compat/x86_64/atomic_addressable_abi_probe.cpp -o "$cxx_probe"
nm --undefined-only "$cxx_probe" >"$cxx_undefined"
for symbol in "${ATOMIC_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$cxx_undefined" ||
        fail "C++ companion does not retain C ABI reference ${symbol}"
done
if grep -Eq '_Z|__gxx_personality_v0|__cxa|_Unwind_|operator (new|delete)|__stack_chk_fail|__tls_get_addr' \
    "$cxx_undefined"; then
    fail "C++ companion retains a C++ or dynamic-TLS runtime dependency"
fi

"$CC" -c compat/x86_64/atomic_addressable_abi_start.S -o "$start"
CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in "${ATOMIC_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

"$CC" -nostdlib -static -fno-pie -no-pie -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections "$start" "$c_probe" "$cxx_probe" "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in "${ATOMIC_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|[[:space:]]TLS[[:space:]]' \
    "$candidate_headers" || grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic or TLS runtime"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains TLS or an unowned runtime dependency"
fi
if grep -Eq '_Z|__gxx_personality_v0|__cxa|_Unwind_|operator (new|delete)|__stack_chk_fail' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a C++ runtime dependency"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding atomic fixture exited ${status}"
fi

printf 'x86 project-only addressable stdatomic ABI: PASS\n'
