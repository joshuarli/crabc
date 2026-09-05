#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc fcntl record-lock evidence.
#
# The same project-header C fixture first runs through pinned musl, then as a
# true `-nostdlib -static` executable linked solely through the selected
# crabc archive. It proves only pointer-bearing F_GETLK/F_SETLK record locks:
# an unlocked query, a child observation/conflict against a parent lock,
# release, stale errno on success, and direct Linux errors. Fixture setup uses
# raw Linux syscalls, so no C descriptor lifecycle symbols are pulled in. This
# is not F_SETLKW cancellation, OFD locks, lockf, flock, generic fcntl, CRT,
# pthread/TLS lifecycle, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc fcntl record locks: %s\n' "$*" >&2
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

    # Inspect only crate-owned C object members. Compiler-builtins remains
    # toolchain support rather than a selected C ABI export surface.
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

helper_symbol() {
    local fragment="$1"
    local symbols="$work_dir/${fragment}-symbols"

    nm --defined-only --format=posix "$candidate" |
        awk -v fragment="$fragment" '$1 ~ /^_R/ && index($1, fragment) && $2 ~ /^[Tt]$/ { print $1 }' \
        >"$symbols"
    [ "$(wc -l <"$symbols")" -eq 1 ] || {
        cat "$symbols" >&2
        fail "expected exactly one ${fragment} helper symbol"
    }
    cat "$symbols"
}

assert_fcntl_record_lock_path() {
    local dispatcher="$work_dir/fcntl-disassembly"
    local helper
    local helper_disassembly="$work_dir/fcntl-record-lock-disassembly"

    objdump -d --disassemble=fcntl "$candidate" >"$dispatcher"
    grep -Eq '\$0x5,%esi' "$dispatcher" ||
        fail "fcntl lacks F_GETLK pointer-vararg dispatch"
    grep -Eq '\$0x6,%esi' "$dispatcher" ||
        fail "fcntl lacks F_SETLK pointer-vararg dispatch"
    grep -Fq 'fcntl_record_lock' "$dispatcher" ||
        fail "fcntl lacks its record-lock helper tail path"
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$dispatcher"; then
        fail "fcntl dispatcher must not enter Linux before command dispatch"
    fi
    helper="$(helper_symbol fcntl_record_lock)"
    objdump -d --disassemble="$helper" "$candidate" >"$helper_disassembly"
    grep -Eq '\$0x48,%(e|r)ax' "$helper_disassembly" ||
        fail "F_GETLK/F_SETLK helper lacks Linux fcntl=72"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$helper_disassembly" ||
        fail "F_GETLK/F_SETLK helper lacks its Linux syscall"
}

assert_fixture_tls_capacity() {
    local tls_filesz
    local tls_memsz
    local tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' \
            "$candidate_program_headers"
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

require_native_linux_x86_64
for tool in ar awk cargo cat cmp diff grep mkdir nm objdump readelf rustup wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_fcntl_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_x86_fcntl_getlk_reference.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-fcntl-record-locks.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-fcntl-record-locks-reference"
candidate="$work_dir/crabc-static-fcntl-record-locks-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_fcntl_record_locks_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h sys/types.h sys/syscall.h bits/fcntl.h \
    bits/syscall.h unistd.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_fcntl_record_locks_probe.c \
    -o "$reference"
if "$reference"; then
    :
else
    status=$?
    fail "pinned-musl fcntl record-lock fixture exited ${status}"
fi

# The instruction judge requires inlining the raw syscall adapter into each
# selected wrapper. One codegen unit makes that boundary deterministic.
CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort -C codegen-units=1
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location fcntl; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in fcntl64 lockf lockf64 fchown preadv2 pwritev2 \
    openat2 open_by_handle_at close_range _Fork \
    vfork clone execve syscall malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_FCNTL_RECORD_LOCKS_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -Wl,--gc-sections -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_fcntl_record_locks_probe.c \
    compat/x86_64/libc_fcntl_record_locks_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location fcntl; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
for unrelated in ioctl open openat creat close dup dup2 dup3 read write pread \
    pwrite pipe pipe2 flock lockf; do
    if grep -Eq "[[:space:]]${unrelated}$" "$candidate_symbols"; then
        fail "fcntl record-lock candidate unexpectedly pulls ${unrelated}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"

assert_fcntl_record_lock_path

if "$candidate"; then
    :
else
    status=$?
    fail "freestanding fcntl record-lock fixture exited ${status}"
fi

printf 'x86 static crabc-libc fcntl record locks: PASS\n'
