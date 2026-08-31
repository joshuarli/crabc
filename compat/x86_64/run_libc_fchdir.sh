#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc fchdir evidence.
#
# One project-header fixture runs first through pinned musl 1.2.6 and then a
# true `-nostdlib -static` candidate. It proves exactly musl's live-O_PATH
# descriptor fallback and direct error behavior in isolated child processes;
# it does not select chdir/getcwd/open/fcntl, pathname policy, a procfs API,
# general descriptor handling, libc.so, CRT, loader, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc fchdir: %s\n' "$*" >&2
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
    local label="$2"
    local symbols_path="$work_dir/${label}-symbols"
    local headers_path="$work_dir/${label}-program-headers"
    local dynamic_path="$work_dir/${label}-dynamic"
    local relocs_path="$work_dir/${label}-relocations"
    local disassembly_path="$work_dir/${label}-disassembly"
    local errno_disassembly="$work_dir/${label}-errno-disassembly"

    readelf --symbols --wide "$candidate_path" >"$symbols_path"
    readelf --program-headers --wide "$candidate_path" >"$headers_path"
    readelf --dynamic --wide "$candidate_path" >"$dynamic_path" || true
    readelf --relocs --wide "$candidate_path" >"$relocs_path"
    objdump -d "$candidate_path" >"$disassembly_path"
    grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
        <(readelf --file-header --wide "$candidate_path") ||
        fail "${label} is not ET_EXEC"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols_path" | grep -q .; then
        fail "${label} has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
        "$headers_path" "$dynamic_path"; then
        fail "${label} is dynamic"
    fi
    grep -Eq '[[:space:]]TLS[[:space:]]' "$headers_path" ||
        fail "${label} lacks the selected errno TLS segment"
    if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$relocs_path" "$symbols_path" "$disassembly_path"; then
        fail "${label} retains a dynamic TLS model"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
        "$symbols_path" "$disassembly_path"; then
        fail "${label} selects an unowned runtime dependency"
    fi
    objdump -d --disassemble=__errno_location "$candidate_path" >"$errno_disassembly"
    grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
        fail "${label} errno does not use direct fs initial TLS"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort strings; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_fchdir_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-fchdir.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-fchdir-reference"
candidate="$work_dir/crabc-static-fchdir-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
fchdir_disassembly="$work_dir/fchdir-disassembly"
candidate_symbols="$work_dir/candidate-symbols"

cd "$ROOT_DIR"
mkdir "$reference_work" "$candidate_work"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_fchdir_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h sys/syscall.h unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header> header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_fchdir_probe.c -o "$reference"
(cd "$reference_work" && env -i "$reference") ||
    fail "pinned-musl fchdir fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap fchdir; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_FCHDIR_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_fchdir_probe.c \
    compat/x86_64/libc_fchdir_start.S "$archive" -o "$candidate"
assert_static_closure "$candidate" candidate
readelf --symbols --wide "$candidate" >"$candidate_symbols"
grep -Eq '[[:space:]]fchdir$' "$candidate_symbols" ||
    fail "candidate lacks fchdir"
if grep -Eq '[[:space:]](chdir|getcwd|fcntl|open|openat|readlink|mount|umount)$' \
    "$candidate_symbols"; then
    fail "candidate selects a broader C filesystem or descriptor entry"
fi
objdump -d --disassemble=fchdir "$candidate" >"$fchdir_disassembly"
grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$fchdir_disassembly" ||
    fail "fchdir lacks its raw Linux syscall path"
for syscall_word in 0x51 0x48 0x50; do
    grep -Eq "\\\$${syscall_word},%e?ax" "$fchdir_disassembly" ||
        fail "fchdir lacks Linux syscall ${syscall_word}"
done
strings "$candidate" | grep -Fx '/proc/self/fd/' >/dev/null ||
    fail "fchdir lacks musl's fixed procfd fallback spelling"
if grep -Eq 'call.*<(chdir|fcntl|open|openat|readlink|getcwd)(@plt)?($|\+)' \
    "$fchdir_disassembly"; then
    fail "fchdir delegates to a broader C ABI entry"
fi

(cd "$candidate_work" && env -i "$candidate") ||
    fail "freestanding fchdir fixture failed"

printf 'x86 static libc fchdir: PASS\n'
