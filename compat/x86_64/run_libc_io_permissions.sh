#!/usr/bin/env bash
# Native Linux/x86-64 static crabc-libc iopl/ioperm negative-path evidence.
#
# The same project-header body first executes against pinned musl 1.2.6 and
# then a true `-nostdlib -static` candidate. It calls only invalid iopl/ioperm
# arguments that cannot make a valid permission change. It records Linux's
# EINVAL-versus-EPERM check ordering, so this gate never enables I/O
# permissions and never executes port I/O. The opt-in archive closure may add
# exactly iopl and ioperm to the frozen default C ABI.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly FEATURE=x86-io-permissions
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/io_permissions.rs"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly -a EXPECTED_ADDITIONS=(ioperm iopl)

fail() {
    printf 'ERROR: x86 static libc iopl/ioperm: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

collect_global_surface() {
    local archive_path="$1" output_path="$2" members_path="$3"
    local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        nm -g --defined-only --format=posix "${members[@]}"
    ) | awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        LC_ALL=C sort -u >"$output_path"
}

assert_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2" additions="$3" removed="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed"
    if [ -s "$removed" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "x86-io-permissions removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$additions"
    if ! cmp -s <(printf 'ioperm\niopl\n') "$additions"; then
        diff -u <(printf 'ioperm\niopl\n') "$additions" >&2 || true
        fail "x86-io-permissions changes more than iopl/ioperm"
    fi
}

assert_fixture_tls_capacity() {
    local filesz memsz alignment

    read -r filesz memsz alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( memsz > 0 && memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${memsz}"
    (( alignment > 0 && alignment <= INITIAL_TLS_ALIGNMENT &&
       INITIAL_TLS_ALIGNMENT % alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${alignment}"
}

assert_io_permissions_boundary() {
    local binary="$1" disassembly="$2" label="$3" symbol syscall_immediate symbol_disassembly

    : >"$disassembly"
    for symbol in iopl ioperm; do
        case "$symbol" in
            iopl) syscall_immediate='\$0xac(,|[[:space:]]|$)' ;;
            ioperm) syscall_immediate='\$0xad(,|[[:space:]]|$)' ;;
        esac
        symbol_disassembly="${disassembly}.${symbol}"
        objdump -d --disassemble="$symbol" "$binary" >"$symbol_disassembly"
        grep -Eq "[[:space:]]syscall([[:space:]]|$)" "$symbol_disassembly" ||
            fail "$label $symbol lacks a syscall instruction"
        grep -Eq "$syscall_immediate" "$symbol_disassembly" ||
            fail "$label $symbol does not issue its Linux syscall"
        cat "$symbol_disassembly" >>"$disassembly"
    done
    if grep -Eq '(^|[[:space:]])(in|out)([bwl])?([[:space:]]|$)|(^|[[:space:]])(ins|outs)[bwl]([[:space:]]|$)' "$disassembly"; then
        fail "$label unexpectedly contains a port-I/O instruction"
    fi
}

capture_invalid_probe_status() {
    local executable="$1" label="$2" status

    set +e
    env -i timeout "$EXECUTION_TIMEOUT" "$executable"
    status=$?
    set -e
    (( status <= 85 )) || fail "$label invalid-call fingerprint exited $status"
    printf '%s' "$status"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cat cmp comm diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sys_io_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-io-permissions.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target="$work_dir/cargo-baseline"
featured_target="$work_dir/cargo-featured"
baseline_archive="$baseline_target/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-io-permissions-reference"
candidate="$work_dir/crabc-io-permissions-candidate"
header_trace="$work_dir/header-trace"
baseline_symbols="$work_dir/baseline-symbols"
expected_symbols="$work_dir/expected-symbols"
featured_symbols="$work_dir/featured-symbols"
feature_additions="$work_dir/feature-additions"
feature_removed="$work_dir/feature-removed"
archive_symbols="$work_dir/archive-symbols"
archive_relocations="$work_dir/archive-relocations"
archive_disassembly="$work_dir/archive-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_io_permissions_probe.c >/dev/null 2>"$header_trace"
for header in errno.h sys/io.h sys/syscall.h features.h bits/io.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -static -fno-pie -no-pie -fno-builtin \
    -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_io_permissions_probe.c -o "$reference"
reference_status="$(capture_invalid_probe_status "$reference" "pinned-musl")"

CARGO_TARGET_DIR="$baseline_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "cargo did not emit the baseline x86 static libc archive"
collect_global_surface "$baseline_archive" "$baseline_symbols" "$work_dir/baseline-members"
grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_symbols"
if ! cmp -s "$expected_symbols" "$baseline_symbols"; then
    diff -u "$expected_symbols" "$baseline_symbols" >&2 || true
    fail "selected static C ABI export surface drifted"
fi
for symbol in "${EXPECTED_ADDITIONS[@]}"; do
    if grep -Fxq "$symbol" "$baseline_symbols"; then
        fail "baseline archive unexpectedly defines opt-in $symbol"
    fi
done

CARGO_TARGET_DIR="$featured_target" cargo rustc --locked -p crabc-libc --lib \
    --features "$FEATURE" --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$SOURCE" ] || fail "missing iopl/ioperm source"
[ -f "$featured_archive" ] || fail "cargo did not emit the featured x86 static libc archive"
collect_global_surface "$featured_archive" "$featured_symbols" "$work_dir/featured-members"
assert_feature_delta "$baseline_symbols" "$featured_symbols" "$feature_additions" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap iopl ioperm; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "featured archive does not define $symbol"
done
for marker in 'src/linux/iopl.c::iopl' 'src/linux/ioperm.c::ioperm' \
    'SYS_IOPL' 'SYS_IOPERM' 'pub unsafe extern "C" fn iopl' \
    'pub unsafe extern "C" fn ioperm'; do
    grep -Fq "$marker" "$SOURCE" || fail "source lacks $marker"
done
readelf --relocs --wide "$featured_archive" >"$archive_relocations"
objdump -dr "$featured_archive" >"$archive_disassembly"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocations" "$archive_disassembly"; then
    fail "featured archive selects dynamic TLS or an unowned runtime dependency"
fi
assert_io_permissions_boundary "$featured_archive" "$work_dir/archive-io-permissions-disassembly" "featured archive"

"$ORACLE_CC" -std=c11 -DCRABC_IO_PERMISSIONS_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_io_permissions_probe.c \
    compat/x86_64/libc_io_permissions_start.S "$featured_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap iopl ioperm; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
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
    fail "candidate lacks selected errno TLS"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains dynamic TLS or an unowned runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_io_permissions_start.S ||
    fail "fixture start does not bootstrap selected initial TLS"
assert_io_permissions_boundary "$candidate" "$work_dir/candidate-io-permissions-disassembly" "candidate"

candidate_status="$(capture_invalid_probe_status "$candidate" "candidate")"
[ "$candidate_status" = "$reference_status" ] ||
    fail "candidate invalid-call errno fingerprint differs from pinned musl ($candidate_status != $reference_status)"
printf 'x86 static crabc-libc iopl/ioperm negative-path: PASS (no port-I/O execution)\n'
