#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc pathname-lifecycle evidence.
#
# One project-header fixture first runs against pinned musl 1.2.6, then as a
# true `-nostdlib -static` candidate linked only with the selected crabc
# archive. It proves a bounded CWD/pathname/mode lifecycle, descriptor-relative
# namespace transitions, direct x86 syscall forms, and fchmod's O_PATH procfs
# fallback. It does not prove general
# filesystem policy, allocation, libc.so, CRT, loader, sysroot, family
# completion, promotion, or public x86 support.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s

fail() {
    printf 'ERROR: x86 static libc pathname lifecycle: %s\n' "$*" >&2
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
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_named_syscall() {
    local symbol="$1"
    local syscall_word="$2"
    local disassembly="$work_dir/${symbol}-disassembly"

    objdump -d --disassemble="$symbol" "$candidate" >"$disassembly"
    grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
        fail "$symbol lacks Linux syscall $syscall_word"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "$symbol lacks its Linux syscall instruction"
}

assert_remove_retry_path() {
    local disassembly="$work_dir/remove-disassembly"

    objdump -d --disassemble=remove "$candidate" >"$disassembly"
    grep -Eq '\$0x57(,|[[:space:]]|\$)' "$disassembly" ||
        fail "remove lacks Linux unlink=87"
    grep -Eq '\$0x54(,|[[:space:]]|\$)' "$disassembly" ||
        fail "remove lacks Linux rmdir=84 retry"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "remove lacks its Linux syscall instruction"
}

assert_fchmod_fallback_path() {
    local disassembly="$work_dir/fchmod-disassembly"

    objdump -d --disassemble=fchmod "$candidate" >"$disassembly"
    for syscall_word in 5b 48 5a; do
        grep -Eq "\\\$0x${syscall_word}(,|[[:space:]]|\\\$)" "$disassembly" ||
            fail "fchmod lacks Linux fallback syscall $syscall_word"
    done
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "fchmod lacks its Linux syscall instruction"
}

assert_renameat2_paths() {
    local disassembly="$work_dir/renameat2-disassembly"

    objdump -d --disassemble=renameat2 "$candidate" >"$disassembly"
    grep -Eq '\$0x108(,|[[:space:]]|\$)' "$disassembly" ||
        fail "renameat2 lacks zero-flag Linux renameat=264"
    grep -Eq '\$0x13c(,|[[:space:]]|\$)' "$disassembly" ||
        fail "renameat2 lacks flagged Linux renameat2=316"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "renameat2 lacks its Linux syscall instruction"
}

require_native_linux_x86_64
for tool in ar awk cargo chmod cmp cp diff grep mkdir nm objdump readelf rustup sha256sum sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pathname_lifecycle_header_abi.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64/tmp" "$ROOT_DIR/.work/x86_64/reports"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/tmp/libc-pathname-lifecycle.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pathname-lifecycle-reference"
candidate="$work_dir/crabc-static-pathname-lifecycle-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

mkdir "$reference_work" "$candidate_work"
cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pathname_lifecycle_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h stddef.h stdio.h sys/stat.h sys/syscall.h \
    sys/types.h unistd.h bits/alltypes.h bits/fcntl.h bits/stat.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pathname_lifecycle_probe.c \
    -o "$reference"
if (cd "$reference_work" && timeout "$EXECUTION_TIMEOUT" "$reference") \
    >"$work_dir/musl.stdout" 2>"$work_dir/musl.stderr"; then
    reference_status=0
else
    reference_status=$?
fi
printf '%s\n' "$reference_status" >"$work_dir/musl.status"
[ "$reference_status" -eq 0 ] ||
    fail "pinned-musl reference execution exited $reference_status"

build_source_runtime_libc "$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap chdir getcwd mkdir \
    unlink rmdir remove rename link symlink readlink chmod fchmod truncate \
    openat linkat readlinkat renameat2 unlinkat; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done
grep -Eq 'GLOBAL +HIDDEN +.*__crabc_x86_static_tls_bootstrap$' "$archive_elf_symbols" ||
    fail "archive Static Initial TLS v1 bootstrap is not hidden"
for unselected in chroot realpath renameat symlinkat \
    fchmodat scandir malloc free \
    calloc realloc __tls_get_addr; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected $unselected"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocations"
objdump -dr "$archive" >"$archive_disassembly"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_PATHNAME_LIFECYCLE_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections \
    compat/x86_64/libc_pathname_lifecycle_probe.c \
    compat/x86_64/libc_pathname_lifecycle_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap chdir getcwd mkdir \
    unlink rmdir remove rename link symlink readlink chmod fchmod truncate \
    openat linkat readlinkat renameat2 unlinkat; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define $symbol"
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
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_pathname_lifecycle_start.S ||
    fail "fixture start does not delegate first-thread TLS to libc"
if grep -Eqi 'arch_prctl|mov[[:space:]]+%rsi,[[:space:]]*%fs:0' \
    compat/x86_64/libc_pathname_lifecycle_start.S; then
    fail "fixture start must not install a private FS base"
fi

assert_named_syscall chdir 50
assert_named_syscall getcwd 4f
assert_named_syscall mkdir 53
assert_named_syscall unlink 57
assert_named_syscall rmdir 54
assert_remove_retry_path
assert_named_syscall rename 52
assert_named_syscall link 56
assert_named_syscall symlink 58
assert_named_syscall readlink 59
assert_named_syscall chmod 5a
assert_fchmod_fallback_path
assert_named_syscall truncate 4c
assert_named_syscall openat 101
assert_named_syscall linkat 109
assert_named_syscall readlinkat 10b
assert_named_syscall unlinkat 107
assert_renameat2_paths

if (cd "$candidate_work" && timeout "$EXECUTION_TIMEOUT" "$candidate") \
    >"$work_dir/crabc.stdout" 2>"$work_dir/crabc.stderr"; then
    candidate_status=0
else
    candidate_status=$?
fi
printf '%s\n' "$candidate_status" >"$work_dir/crabc.status"
[ "$candidate_status" -eq 0 ] ||
    fail "candidate execution exited $candidate_status"
cmp "$work_dir/musl.stdout" "$work_dir/crabc.stdout" ||
    fail "pinned-musl and candidate stdout differ"
cmp "$work_dir/musl.stderr" "$work_dir/crabc.stderr" ||
    fail "pinned-musl and candidate stderr differ"

report_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/reports/libc-pathname-lifecycle.XXXXXX")"
chmod 755 "$report_dir"
cp "$reference" "$report_dir/musl-reference.elf"
cp "$candidate" "$report_dir/crabc-candidate.elf"
cp "$header_trace" "$report_dir/project-header-trace.txt"
cp "$selected_c_abi_symbols" "$report_dir/selected-c-abi-symbols.txt"
cp "$candidate_symbols" "$report_dir/crabc-symbols.txt"
cp "$candidate_program_headers" "$report_dir/crabc-program-headers.txt"
cp "$work_dir"/{musl,crabc}.{stdout,stderr,status} "$report_dir/"
cp "$ROOT_DIR/compat/x86_64/libc_pathname_lifecycle_probe.c" \
    "$report_dir/libc_pathname_lifecycle_probe.c"
cp "$ROOT_DIR/compat/x86_64/run_libc_pathname_lifecycle.sh" \
    "$report_dir/run_libc_pathname_lifecycle.sh"
(
    cd "$report_dir"
    sha256sum musl-reference.elf crabc-candidate.elf project-header-trace.txt \
        selected-c-abi-symbols.txt crabc-symbols.txt crabc-program-headers.txt \
        libc_pathname_lifecycle_probe.c run_libc_pathname_lifecycle.sh \
        musl.stdout musl.stderr musl.status crabc.stdout crabc.stderr \
        crabc.status >sha256sums.txt
)

printf 'pathname lifecycle physical receipt: %s\n' "$report_dir"
printf 'x86 static crabc-libc pathname lifecycle: PASS\n'
