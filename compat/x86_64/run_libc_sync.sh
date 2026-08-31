#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc sync evidence.
#
# One project-header X/Open C fixture runs through pinned musl 1.2.6 and then
# through a true dependency-free `-nostdlib -static` crabc archive. The
# adjacent pinned-musl/raw reference owns the disposable dirty-file and raw
# `sync=162` success observation; this leaf adds only the void C ABI boundary.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc sync: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
    local members_path="$work_dir/selected-c-abi-members"; local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_sync_syscall() {
    local disassembly="$work_dir/sync-disassembly"

    objdump -d --disassemble=sync "$candidate" >"$disassembly"
    grep -Eq '\$0xa2(,|[[:space:]]|$)' "$disassembly" ||
        fail "sync lacks fixed Linux sync syscall 162"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "sync lacks the Linux syscall instruction"
    if grep -Eq '%fs:|__errno_location' "$disassembly"; then
        fail "sync must not publish a raw result through errno TLS"
    fi
    if grep -Eq '[[:space:]]call([[:space:]]|q)' "$disassembly"; then
        fail "sync must retain its direct raw syscall boundary"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_sync_reference.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sync_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sync.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sync-reference"
candidate="$work_dir/crabc-static-sync-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sync_probe.c >/dev/null 2>"$trace"
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -fno-builtin -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_sync_probe.c -o "$reference"
"$reference" || fail "pinned-musl sync fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]sync$' "$archive_symbols" ||
    fail "archive does not define sync"
for marker in 'src/unistd/sync.c::sync' 'SYS_SYNC' \
    'raw_syscall::syscall0' 'without touching errno or TLS'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/sync.rs ||
        fail "sync source lacks ${marker}"
done

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -DCRABC_SYNC_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_sync_probe.c compat/x86_64/libc_sync_start.S \
    "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
grep -Eq '[[:space:]]sync$' "$symbols" || fail "candidate lacks sync"
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$headers" "$relocs" "$symbols" "$disassembly"; then
    fail "sync candidate unexpectedly retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols" "$disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
for unselected in fsync fdatasync syncfs sync_file_range open openat close \
    read write lseek sysconf sysinfo; do
    if grep -Eq "[[:space:]]${unselected}$" "$symbols"; then
        fail "sync candidate unexpectedly selects ${unselected}"
    fi
done
assert_sync_syscall
"$candidate" || fail "freestanding sync fixture failed"

printf 'x86 static libc sync: PASS\n'
