#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc qsort evidence.
#
# One project-header C fixture first runs against pinned musl 1.2.6 and then
# as a true `-nostdlib -static` executable linked through the selected archive.
# The candidate must extract qsort and its private smoothsort worker, not
# bsearch or the public/private qsort_r context ABI.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/source_runtime_libc.sh"

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc qsort: %s\n' "$*" >&2
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

assert_static_closure() {
    local candidate_path="$1"

    readelf --symbols --wide "$candidate_path" >"$symbols"
    readelf --program-headers --wide "$candidate_path" >"$headers"
    readelf --dynamic --wide "$candidate_path" >"$dynamic" || true
    readelf --relocs --wide "$candidate_path" >"$relocs"
    objdump -d "$candidate_path" >"$disassembly"
    objdump -d --disassemble=qsort "$candidate_path" >"$qsort_disassembly"
    if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep . >/dev/null; then
        fail "candidate has unresolved symbols"
    fi
    if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
        fail "candidate is dynamic"
    fi
    if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$headers" "$relocs" "$symbols" "$disassembly"; then
        fail "qsort candidate unexpectedly retains TLS"
    fi
    if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location' \
        "$symbols" "$disassembly"; then
        fail "candidate selects an unowned runtime dependency"
    fi
    if grep -Eq 'panic_(bounds_check|nounwind)|rust_begin_unwind|core9panicking' \
        "$symbols" "$disassembly"; then
        fail "candidate selects Rust panic machinery"
    fi
    if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$qsort_disassembly"; then
        fail "qsort unexpectedly performs a syscall"
    fi
    # The entry shim has one exit syscall. Any second syscall would be selected
    # by qsort or its private smoothsort worker, which has no kernel boundary.
    local syscall_count
    syscall_count="$(grep -Ec '[[:space:]]syscall([[:space:]]|$)' "$disassembly" || true)"
    [ "$syscall_count" -eq 1 ] ||
        fail "qsort candidate contains a syscall outside the test entry shim"
}

assert_candidate_excludes_context_abi() {
    local symbol

    for symbol in bsearch __qsort_r qsort_r lfind lsearch __tsearch_balance \
        tdelete tdestroy tfind tsearch twalk hcreate hcreate_r hdestroy \
        hdestroy_r hsearch hsearch_r; do
        if awk -v symbol="$symbol" '$8 == symbol { found = 1 } END { exit !found }' \
            "$symbols"; then
            fail "candidate accidentally selects ${symbol}"
        fi
    done
    if grep -Eq '(__qsort_r|qsort_r|bsearch|lfind|lsearch)' "$disassembly"; then
        fail "qsort implementation retains an unrelated callback/search ABI"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp cp diff grep mkdir mv nm objdump readelf rustup \
    sha256sum sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_qsort_header_abi.sh" >/dev/null

mkdir -p "$ROOT_DIR/.work/x86_64"
work_dir="$(mktemp -d "$ROOT_DIR/.work/x86_64/libc-qsort.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-qsort-reference"
candidate="$work_dir/crabc-static-qsort-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"
disassembly="$work_dir/candidate-disassembly"; qsort_disassembly="$work_dir/qsort-disassembly"
receipt="$work_dir/receipt"
report_dir="$ROOT_DIR/.work/x86_64/reports/libc-qsort"
mkdir "$receipt"
cd "$ROOT_DIR"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_qsort_probe.c >/dev/null 2>"$trace"
for header in stddef.h stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "fixture did not use project $header"
done
# The pinned compiler defaults to PIE; use an explicit static ET_EXEC reference.
"$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector \
    -I "$ROOT_DIR/include" compat/x86_64/libc_qsort_probe.c -o "$reference"
if "$reference" >"$receipt/musl.stdout" 2>"$receipt/musl.stderr"; then
    reference_status=0
else
    reference_status=$?
fi
printf '%s\n' "$reference_status" >"$receipt/musl.status"
[ "$reference_status" -eq 0 ] ||
    fail "pinned-musl qsort fixture failed with status $reference_status"

build_source_runtime_libc "$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]qsort$' "$archive_symbols" ||
    fail "archive does not define qsort"

"$ORACLE_CC" -std=c11 -DCRABC_QSORT_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_qsort_probe.c compat/x86_64/libc_qsort_start.S \
    "$archive" -o "$candidate"
assert_static_closure "$candidate"
grep -Eq '[[:space:]]qsort$' "$symbols" || fail "candidate lacks qsort"
assert_candidate_excludes_context_abi
if "$candidate" >"$receipt/crabc.stdout" 2>"$receipt/crabc.stderr"; then
    candidate_status=0
else
    candidate_status=$?
fi
printf '%s\n' "$candidate_status" >"$receipt/crabc.status"
[ "$candidate_status" -eq 0 ] ||
    fail "freestanding qsort fixture failed with status $candidate_status"
cmp "$receipt/musl.status" "$receipt/crabc.status" ||
    fail "qsort exit statuses differ"
cmp "$receipt/musl.stdout" "$receipt/crabc.stdout" ||
    fail "qsort stdout differs"
cmp "$receipt/musl.stderr" "$receipt/crabc.stderr" ||
    fail "qsort stderr differs"

cp "$reference" "$receipt/musl.elf"
cp "$candidate" "$receipt/crabc.elf"
cp "$archive.source-runtime.json" "$receipt/source-runtime.json"
cp compat/x86_64/libc_qsort_probe.c "$receipt/probe.c"
cp compat/x86_64/libc_qsort_start.S "$receipt/start.S"
cp compat/x86_64/run_libc_qsort.sh "$receipt/runner.sh"
cp libc/src/c_abi/x86_64/qsort.rs "$receipt/qsort.rs"
(
    cd "$receipt"
    sha256sum musl.elf crabc.elf musl.stdout musl.stderr musl.status \
        crabc.stdout crabc.stderr crabc.status source-runtime.json \
        probe.c start.S runner.sh qsort.rs >sha256sums.txt
)
mkdir -p "$(dirname "$report_dir")"
rm -rf -- "$report_dir"
mv "$receipt" "$report_dir"

printf 'x86 static libc qsort: PASS (receipt: %s)\n' "$report_dir"
