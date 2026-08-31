#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc sync_file_range evidence.
#
# One GNU project-header C fixture first runs through pinned musl 1.2.6 and
# then as a true `-nostdlib -static` candidate linked only with the selected
# crabc archive. It proves musl's direct `sync_file_range=277` descriptor
# request, not opening, read/write/seek, range validation, cancellation,
# writeback scheduling, storage-cache or power-loss durability, libc.so, CRT,
# loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc sync_file_range: %s\n' "$*" >&2
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

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" | grep -Eq '[[:space:]][TW][[:space:]]sync_file_range$'; then
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "sync_file_range must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/candidate-disassembly"
    local errno_disassembly="$work_dir/candidate-errno-disassembly"
    local range_disassembly="$work_dir/candidate-sync-file-range-disassembly"

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
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "candidate errno does not use direct fs initial TLS"
    objdump -d --disassemble=sync_file_range "$candidate_path" >"$range_disassembly"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$range_disassembly" ||
        fail "sync_file_range lacks a direct Linux syscall"
    grep -Eq '\$0x115,%e?ax' "$range_disassembly" ||
        fail "sync_file_range lacks Linux x86-64 sync_file_range=277"
    if grep -Eq 'call.*(sync|syncfs|fsync|fdatasync|copy_file_range|open|read|write|lseek|close|pthread_cancel|__syscall_cp)' \
        "$range_disassembly"; then
        fail "sync_file_range delegates to an unselected runtime boundary"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sync_file_range_header_abi.sh" >/dev/null

grep -Eq '^sync_file_range[[:space:]]+sync_file_range\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost sync_file_range ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sync-file-range.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sync-file-range-reference"
candidate="$work_dir/crabc-static-sync-file-range-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
selected_members="$work_dir/selected-members"
selected_member_names="$work_dir/selected-member-names"

cd "$ROOT_DIR"
mkdir "$reference_work" "$candidate_work"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sync_file_range_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stdint.h sys/syscall.h sys/types.h unistd.h \
    features.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_sync_file_range_probe.c \
    -o "$reference"
(cd "$reference_work" && "$reference") ||
    fail "pinned-musl sync_file_range fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap sync_file_range; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected sync_file_range member is missing"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SYNC_FILE_RANGE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_sync_file_range_probe.c \
    compat/x86_64/libc_sync_file_range_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate"

for unselected in fsync fdatasync copy_file_range open openat creat \
    read write lseek close pipe pipe2 fcntl mmap mprotect munmap malloc calloc \
    realloc free pthread_cancel __syscall_cp; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        grep -E "[[:space:]]${unselected}$" "$candidate_symbols" >&2 || true
        fail "sync_file_range candidate exports an unselected runtime entry"
    fi
done

(cd "$candidate_work" && "$candidate") ||
    fail "freestanding sync_file_range fixture failed"

printf 'x86 static crabc-libc sync_file_range: PASS\n'
