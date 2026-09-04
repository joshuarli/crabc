#!/usr/bin/env bash
# Native Linux/x86-64 selected-static file-handle ABI evidence.
#
# The candidate owns exactly name_to_handle_at/open_by_handle_at. Raw openat,
# openat and close provide setup only; the fixture pathname is confined to the
# runner's disposable working directories. Filesystem
# handle support and the privilege needed to reopen a raw handle are retained
# as kernel outcomes, so an unprivileged overlay runner may report the
# portable unsupported result without fabricating success.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc file handles: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/candidate-disassembly"
    local errno_disassembly="$work_dir/candidate-errno-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
        "$headers_path" "$dynamic_path"; then
        fail "candidate is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "candidate lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "candidate retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free' \
        "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned allocator/runtime dependency"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "candidate errno does not use direct fs initial TLS"
}

assert_feature_archive_surface() {
    local archive_path="$1"
    local symbols_path="$work_dir/archive-selected-symbols"
    local expected_path="$work_dir/archive-expected-symbols"
    local members_path="$work_dir/archive-members"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ &&
        $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    {
        grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS"
        printf '%s\n' name_to_handle_at open_by_handle_at
    } | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "file-handle feature archive export surface drifted"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_file_handles_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-file-handles.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-file-handles-reference"
candidate="$work_dir/crabc-static-file-handles-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
archive_symbols="$work_dir/archive-symbols"
mkdir "$reference_work" "$candidate_work"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_file_handles_probe.c -o "$reference"
(cd "$reference_work" && "$reference") ||
    fail "pinned-musl file-handle fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-file-handles --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
assert_feature_archive_surface "$archive"
nm -A --defined-only "$archive" >"$archive_symbols"

for symbol in __errno_location __crabc_x86_static_tls_bootstrap \
    name_to_handle_at open_by_handle_at; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_FILE_HANDLES_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_file_handles_probe.c \
    compat/x86_64/libc_file_handles_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"

objdump -d --disassemble=name_to_handle_at "$candidate" >"$work_dir/name-to-handle-disassembly"
objdump -d --disassemble=open_by_handle_at "$candidate" >"$work_dir/open-by-handle-disassembly"
grep -Eq '\$0x12f,%e?ax' "$work_dir/name-to-handle-disassembly" ||
    fail "name_to_handle_at lacks Linux x86-64 syscall 303"
grep -Eq '\$0x130,%e?ax' "$work_dir/open-by-handle-disassembly" ||
    fail "open_by_handle_at lacks Linux x86-64 syscall 304"
grep -Eq '%r10' "$work_dir/name-to-handle-disassembly" ||
    fail "name_to_handle_at lacks Linux fourth-word r10 transfer"
grep -Eq '%r8' "$work_dir/name-to-handle-disassembly" ||
    fail "name_to_handle_at lacks Linux fifth-word r8 transfer"
(cd "$candidate_work" && "$candidate") ||
    fail "freestanding file-handle fixture failed"

printf 'x86 static crabc-libc file handles: PASS\n'
