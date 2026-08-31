#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc mktemp evidence.
#
# One GNU-enabled project-header C fixture runs against pinned musl 1.2.6 and
# then through a true dependency-free -nostdlib static crabc archive. The
# fixture owns disposable raw namespace setup solely to make ENOENT/ELOOP
# observable; the selected C surface remains legacy pathname generation, not
# file creation, a reservation, tmpnam/tempnam, or a handle authority API.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc mktemp: %s\n' "$*" >&2
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

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/candidate-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned runtime dependency"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_mktemp_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-mktemp.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-mktemp-reference"
candidate="$work_dir/crabc-static-mktemp-candidate"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_mktemp_probe.c -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    reference_status=$?
    fail "pinned-musl mktemp fixture exited ${reference_status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location mktemp; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_MKTEMP_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_mktemp_probe.c compat/x86_64/libc_mktemp_start.S \
    "$archive" -o "$candidate"
assert_static_closure "$candidate"

mktemp_disassembly="$work_dir/mktemp-disassembly"
objdump -d --disassemble=mktemp "$candidate" >"$mktemp_disassembly"
if grep -Eq '[[:space:]](tmpnam|tempnam|mkstemp|mkstemps|mkostemp|mkostemps|mkdtemp|tmpfile|name_to_handle_at|open_by_handle_at)$' \
    "$work_dir/candidate-symbols"; then
    fail "mktemp candidate selects an excluded temporary or handle API"
fi
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$mktemp_disassembly" ||
    fail "mktemp lacks direct Linux syscalls"
for word in 0xe4 0xba 0x106; do
    grep -Eq "\\\$${word},%(e|r)(ax|di)" "$mktemp_disassembly" ||
        fail "mktemp lacks Linux x86-64 syscall word ${word}"
done
if grep -Eq 'getrandom|openat|open_by_handle_at|name_to_handle_at' \
    "$mktemp_disassembly"; then
    fail "mktemp disassembly selects an excluded entropy or authority API"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    candidate_status=$?
    fail "freestanding mktemp fixture exited ${candidate_status}"
fi

printf 'x86 static crabc-libc mktemp: PASS\n'
