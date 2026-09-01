#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc issetugid evidence.
#
# One GNU project-header C fixture first executes through pinned musl 1.2.6 in
# the ordinary initial state, then through three true `-nostdlib -static`
# candidates. Synthetic initial vectors prove only the final-AT_SECURE and
# UID/EUID-mismatch cached secure cases; they are fixture inputs, not public
# auxv, credential, or process-control APIs.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc issetugid: %s\n' "$*" >&2
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

build_candidate() {
    local output="$1"
    shift
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE "$@" -I"$ROOT_DIR/include" \
        -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
        -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
        compat/x86_64/libc_issetugid_probe.c \
        compat/x86_64/libc_issetugid_start.S "$archive" -o "$output"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_issetugid_header_abi.sh" >/dev/null

grep -Eq '^issetugid[[:space:]]+issetugid\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost issetugid ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-issetugid.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-issetugid-reference"
candidate="$work_dir/crabc-static-issetugid-candidate"
synthetic_at_secure="$work_dir/crabc-static-issetugid-at-secure"
synthetic_uid_mismatch="$work_dir/crabc-static-issetugid-uid-mismatch"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-issetugid.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
issetugid_disassembly="$work_dir/issetugid-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" issetugid.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]issetugid$' ||
    fail "pinned musl issetugid.lo lacks issetugid"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_issetugid_probe.c >/dev/null 2>"$header_trace"
for header in errno.h unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_issetugid_probe.c -o "$reference"
env -i "$reference" || fail "pinned-musl ordinary issetugid fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]issetugid$' "$archive_symbols" ||
    fail "archive does not define issetugid"
readelf --relocs --wide "$archive" >"$archive_relocations"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocations" ||
    fail "archive lacks the selected initial-TLS errno boundary"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

build_candidate "$candidate"
build_candidate "$synthetic_at_secure" \
    -DCRABC_ISSETUGID_SYNTHETIC \
    -DCRABC_ISSETUGID_SYNTHETIC_AT_SECURE
build_candidate "$synthetic_uid_mismatch" \
    -DCRABC_ISSETUGID_SYNTHETIC \
    -DCRABC_ISSETUGID_SYNTHETIC_UID_MISMATCH

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" 2>/dev/null || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in issetugid __crabc_x86_static_tls_bootstrap __libc_start_main main; do
    grep -Eq "[[:space:]]$symbol$" "$candidate_symbols" ||
        fail "candidate does not define $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks selected initial TLS for the errno fixture"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

objdump -d --disassemble=issetugid "$candidate" >"$issetugid_disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|call.*<(setuid|seteuid|setgid|setegid|setresuid|setresgid|getauxval|__getauxval|secure_getenv|getenv|open|openat|close|execve|fork|vfork|clone|pthread_)' \
    "$issetugid_disassembly"; then
    fail "issetugid selects a credential, environment, auxv, process, or syscall path"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"

bootstrap_call_line="$(grep -nE 'call.*<__crabc_x86_static_tls_bootstrap>' "$candidate_disassembly" | head -n 1 | cut -d: -f1)"
startup_call_line="$(grep -nE 'call.*<__libc_start_main>' "$candidate_disassembly" | head -n 1 | cut -d: -f1)"
[ -n "$bootstrap_call_line" ] || fail "entry shim does not call the TLS bootstrap"
[ -n "$startup_call_line" ] || fail "entry shim does not call libc startup"
[ "$bootstrap_call_line" -lt "$startup_call_line" ] ||
    fail "TLS bootstrap does not precede issetugid startup"

env -i "$candidate" || fail "ordinary issetugid candidate failed"
"$synthetic_at_secure" || fail "synthetic final-AT_SECURE issetugid candidate failed"
"$synthetic_uid_mismatch" || fail "synthetic UID/EUID-mismatch issetugid candidate failed"

printf 'x86 static libc issetugid: PASS\n'
