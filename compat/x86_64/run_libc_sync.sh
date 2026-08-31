#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc sync evidence.
#
# One project-header C fixture first runs through pinned musl 1.2.6 and then
# as a true `-nostdlib -static` candidate linked only with the one selected
# crabc archive member. It proves musl's void direct `sync=162` request, not
# a filesystem policy, writeback schedule, storage-cache or power-loss
# durability, syncfs/fsync/fdatasync, pathname opening, libc.so, CRT, loader,
# sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc sync: %s\n' "$*" >&2
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
    local member
    local definitions
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" | grep -Eq '[[:space:]][TW][[:space:]]sync$'; then
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "sync must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

assert_static_closure() {
    local candidate_path="$1"
    local symbols_path="$work_dir/candidate-symbols"
    local headers_path="$work_dir/candidate-program-headers"
    local dynamic_path="$work_dir/candidate-dynamic"
    local relocs_path="$work_dir/candidate-relocations"
    local disassembly_path="$work_dir/sync-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d --disassemble=sync "$candidate_path" >"$disassembly_path"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers_path" "$dynamic_path"; then
        fail "candidate is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path"; then
        fail "candidate unexpectedly selects TLS"
    fi
    if grep -Eq 'R_X86_64_TPOFF(32|64)?|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|__h_errno_location|%fs:' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "candidate selects errno, h_errno, or a TLS runtime"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols_path" "$disassembly_path"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly_path" ||
        fail "sync lacks its direct Linux syscall instruction"
    grep -Eq '\$0xa2' "$disassembly_path" ||
        fail "sync lacks Linux x86-64 sync=162"
    if grep -Eq '[[:space:]]call([[:space:]]|q)' "$disassembly_path"; then
        fail "sync implementation calls an unselected runtime boundary"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sync_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_sync_reference.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sync.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sync-reference"
candidate="$work_dir/crabc-static-sync-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-sync-members"
selected_member_names="$work_dir/selected-sync-member-names"
candidate_symbols="$work_dir/candidate-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sync_probe.c >/dev/null 2>"$header_trace"
for header in features.h stdint.h sys/syscall.h unistd.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_sync_probe.c -o "$reference"
"$reference" || fail "pinned-musl sync fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq "[[:space:]][TW][[:space:]]sync$" "$archive_symbols" ||
    fail "archive does not define sync"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected sync member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_SYNC_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--gc-sections \
    -Wl,--no-undefined compat/x86_64/libc_sync_probe.c \
    compat/x86_64/libc_sync_start.S "$selected_member" -o "$candidate"
assert_static_closure "$candidate"

for unselected in fsync fdatasync syncfs sync_file_range msync mlock mlock2 \
    munlock mlockall munlockall open openat close write read fcntl \
    setlocale uselocale newlocale duplocale freelocale malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "sync candidate unexpectedly selects ${unselected}"
    fi
done

"$candidate" || fail "freestanding sync fixture failed"

printf 'x86 static crabc-libc sync: PASS\n'
