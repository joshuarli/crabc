#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc ulimit evidence.
#
# One project-header fixture runs first through pinned musl 1.2.6 and then a
# true `-nostdlib -static` candidate. It proves exactly the historical
# RLIMIT_FSIZE 512-byte query/set adapter in disposable processes, not a
# general resource, accounting, scheduler, or file-size-policy boundary.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc ulimit: %s\n' "$*" >&2
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
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_ulimit_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ulimit.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-ulimit-reference"
candidate="$work_dir/crabc-static-ulimit-candidate"
reference_work="$work_dir/reference-work"
candidate_work="$work_dir/candidate-work"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
ulimit_disassembly="$work_dir/ulimit-disassembly"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
mkdir "$reference_work" "$candidate_work"
"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_ulimit_probe.c >/dev/null 2>"$header_trace"
for header in errno.h sys/resource.h sys/syscall.h ulimit.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header> header"
done
"$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_ulimit_probe.c -o "$reference"
(cd "$reference_work" && env -i "$reference") ||
    fail "pinned-musl ulimit fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap ulimit; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -DCRABC_ULIMIT_FREESTANDING -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_ulimit_probe.c compat/x86_64/libc_ulimit_start.S \
    "$archive" -o "$candidate"
assert_static_closure "$candidate" candidate
readelf --symbols --wide "$candidate" >"$candidate_symbols"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=ulimit "$candidate" >"$ulimit_disassembly"
grep -Eq '[[:space:]]ulimit$' "$candidate_symbols" ||
    fail "candidate lacks ulimit"
if grep -Eq '[[:space:]](getrlimit|setrlimit|prlimit|getrusage|getpriority|setpriority|nice|sysconf)$' \
    "$candidate_symbols"; then
    fail "candidate selects a broader C resource entry"
fi
grep -Eq 'cmp.*\$0x2,%edi' "$ulimit_disassembly" ||
    fail "ulimit does not distinguish UL_SETFSIZE before reading a vararg"
grep -Eq '[[:space:]]j(e|mp)[[:space:]]' "$ulimit_disassembly" ||
    fail "ulimit does not tail-route its no-vararg and set forms"
grep -Eq '\$0x12e,%e?ax' "$candidate_disassembly" ||
    fail "ulimit lacks Linux prlimit64=302"
if grep -Eq 'call.*<(getrlimit|setrlimit|prlimit|getrusage|getpriority|setpriority|nice)(@plt)?($|\+)' \
    "$candidate_disassembly"; then
    fail "ulimit delegates to a broader C resource entry"
fi

(cd "$candidate_work" && env -i "$candidate") ||
    fail "freestanding ulimit fixture failed"

printf 'x86 static libc ulimit: PASS\n'
