#!/usr/bin/env bash
# Native Linux/x86-64 archive-owned C timestamp-update composition evidence.
#
# One project-header body executes with pinned musl first, then as a true
# static PIE through Rust rcrt1/crti/crtn plus the selected crabc libc archive.
# It selects only the complete timestamp alias/conversion block. Raw syscalls
# create and clean the disposable fixture; they never perform the timestamp
# mutations or observations asserted by the C body. This remains private,
# non-promoting evidence rather than a general C runtime, dynamic libc, loader,
# sysroot, or public-x86 claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc timestamp updates: %s\n' "$*" >&2
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

assert_static_pie() {
    grep -Eq 'Type:[[:space:]]+DYN[[:space:]]+\(Position-Independent Executable file\)' \
        "$candidate_file_header" || fail "candidate is not an ET_DYN static PIE"
    if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
        grep -Eq 'NEEDED|JMPREL|PLTGOT' "$candidate_dynamic"; then
        fail "candidate selected an interpreter, dynamic dependency, or PLT"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
        fail "candidate lacks archive-owned errno PT_TLS"
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|$)" "$disassembly" ||
        fail "${symbol} lacks Linux syscall ${syscall_word}"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "${symbol} lacks a direct Linux syscall"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
if command -v ld.lld >/dev/null 2>&1; then
    link_editor=ld.lld
else
    toolchain_rustc="$(rustup which rustc)"
    toolchain_root="$(dirname "$(dirname "$toolchain_rustc")")"
    bundled_lld="$toolchain_root/lib/rustlib/x86_64-unknown-linux-musl/bin/gcc-ld/ld.lld"
    if [ -x "$bundled_lld" ]; then
        link_editor="$bundled_lld"
    elif command -v ld >/dev/null 2>&1; then
        link_editor=ld
    else
        fail "requires a native x86-64 linker"
    fi
fi

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_stat_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sys_time_direct_header_abi.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_utime_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-timestamp-updates.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
crt_dir="$work_dir/crt"
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-timestamp-updates-reference"
candidate="$work_dir/crabc-static-timestamp-updates-candidate"
probe_object="$work_dir/probe.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
candidate_symbols="$work_dir/candidate-symbols"
candidate_file_header="$work_dir/candidate-file-header"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_timestamp_updates_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h sys/stat.h sys/syscall.h sys/time.h time.h utime.h \
    bits/alltypes.h bits/stat.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project ${header}"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_timestamp_updates_probe.c -o "$reference"
if "$reference"; then :; else
    status=$?
    fail "pinned-musl timestamp fixture exited ${status}"
fi

mkdir "$crt_dir"
for object in rcrt1 crti crtn; do
    case "$object" in
        rcrt1) source_path=crt/src/x86_64_rcrt1.rs ;;
        crti) source_path=crt/src/x86_64_crti.rs ;;
        crtn) source_path=crt/src/x86_64_crtn.rs ;;
    esac
    rustup run nightly-2026-07-24 rustc --edition=2021 --crate-type=lib --emit=obj \
        --target x86_64-unknown-linux-musl -C panic=abort -C force-unwind-tables=no \
        -C debuginfo=0 -C opt-level=2 -C overflow-checks=off -C debug-assertions=off \
        -C relocation-model=pic -C code-model=small -C link-dead-code=no \
        --remap-path-prefix "$ROOT_DIR=/crabc" \
        --crate-name "crabc_x86_64_${object}" "$source_path" -o "$crt_dir/${object}.o"
done

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=pic -C code-model=small -C panic=abort -Ztls-model=initial-exec
[ -f "$archive" ] || fail "cargo did not emit the PIC x86 libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
readelf --relocs --wide "$archive" >"$archive_relocations"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap __libc_start_main \
    utimensat futimens futimes futimesat lutimes utimes utime fstat lstat; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
grep -Eq "[[:space:]]W[[:space:]]futimesat$" "$archive_symbols" ||
    fail "futimesat is not a weak archive alias"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fPIE -ffreestanding -fno-builtin \
    -fno-stack-protector -ftls-model=local-exec -I"$ROOT_DIR/include" \
    -c compat/x86_64/libc_timestamp_updates_probe.c -o "$probe_object"
"$link_editor" -pie -static --no-dynamic-linker --no-undefined -z relro -z now -e _start \
    "$crt_dir/rcrt1.o" "$crt_dir/crti.o" "$probe_object" "$archive" "$crt_dir/crtn.o" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --file-header --wide "$candidate" >"$candidate_file_header"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __crabc_x86_static_tls_bootstrap __libc_start_main main utimensat futimens \
    futimes futimesat lutimes utimes utime; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
grep -Eq 'WEAK +DEFAULT +.*futimesat$' "$candidate_symbols" ||
    fail "candidate does not retain weak futimesat"
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
assert_static_pie
if grep -Eq 'R_X86_64_(GLOB_DAT|JUMP_SLOT)' "$candidate_relocations" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic relocation or TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

assert_named_syscall utimensat 118
assert_named_syscall futimens 118
utimensat_disassembly="$work_dir/utimensat-disassembly"
objdump -d --disassemble=utimensat "$candidate" >"$utimensat_disassembly"
grep -Fq '%r10' "$utimensat_disassembly" ||
    fail "utimensat does not route flags through x86 syscall r10"

if "$candidate"; then :; else
    status=$?
    fail "static rcrt1/libc timestamp fixture exited ${status}"
fi

printf 'x86 static rcrt1/libc timestamp-update block: PASS\n'
