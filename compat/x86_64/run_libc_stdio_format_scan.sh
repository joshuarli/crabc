#!/usr/bin/env bash
# Native Linux/x86-64 selected static byte-string stdio evidence profiles.
#
# One project-header C fixture first executes against pinned musl 1.2.6, then
# as a true `-nostdlib -static` candidate linked only through crabc's selected
# archive. The default `integer` profile owns the bounded integer, count-store,
# and byte-string format/scan grammar. The closed `integer-scan` profile owns
# only musl's ULLONG_MAX source-overflow behavior for narrow `%d`/`%i`/`%u`/
# `%x` scans through the existing `sscanf`/`vsscanf` boundary. The separately
# closed `octal-hex-scan` profile owns only the matching `%o`/`%X` behavior,
# `fixed-percent-scan` owns only vfscanf's literal `%%` parser state,
# `fixed-format-whitespace-scan` owns only its top-level format-whitespace
# parser state, and `fixed-literal-scan` owns only its non-percent raw-literal
# parser state. `fixed-empty-format-scan` owns only the format-NUL termination
# state before vfscanf enters a format-directed scanner state or a variadic
# destination boundary. `fixed-suppressed-character-scan` owns only the
# no-destination non-wide `%*3c` raw-character conversion state.
# The sibling `float-hex-output` profile selects only binary64 `%a`/`%A`
# output, while the closed `errno-output` profile adds only bare GNU/musl `%m` C-locale
# errno-message output through that same formatter. None selects a general
# error-reporting, stream, locale, or ambient-formatting boundary, FILE
# streams, printf/fprintf, scanf/fscanf, decimal or long-double floats, wide
# text, scansets, positional arguments, pointer-valued %p, allocation, a
# dynamic libc, CRT, loader, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64
readonly EVIDENCE_PROFILE="${CRABC_STDIO_FORMAT_SCAN_PROFILE:-integer}"

case "$EVIDENCE_PROFILE" in
integer)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_format_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_format_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FORMAT_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="byte-string stdio format/scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(snprintf vsnprintf sprintf vsprintf sscanf vsscanf)
    ;;
integer-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_integer_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_integer_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_INTEGER_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="bounded stdio integer source scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
octal-hex-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_octal_hex_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_octal_hex_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_OCTAL_HEX_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="bounded stdio octal/uppercase-hex source scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
fixed-percent-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_fixed_percent_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_fixed_percent_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FIXED_PERCENT_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="sealed stdio literal-percent scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
fixed-format-whitespace-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_fixed_format_whitespace_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_fixed_format_whitespace_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FIXED_FORMAT_WHITESPACE_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="sealed stdio format-whitespace scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
fixed-literal-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_fixed_literal_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_fixed_literal_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FIXED_LITERAL_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="sealed stdio raw-literal scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
fixed-empty-format-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_fixed_empty_format_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_fixed_empty_format_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FIXED_EMPTY_FORMAT_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="sealed stdio empty-format scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
fixed-suppressed-character-scan)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_fixed_suppressed_character_scan_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_fixed_suppressed_character_scan_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FIXED_SUPPRESSED_CHARACTER_SCAN_FREESTANDING
    readonly EVIDENCE_LABEL="sealed stdio suppressed-character scan"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(sscanf vsscanf)
    ;;
float-hex-output)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_float_hex_output_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_float_hex_output_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_FLOAT_HEX_OUTPUT_FREESTANDING
    readonly EVIDENCE_LABEL="stdio binary64 hexadecimal output"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(snprintf vsnprintf sprintf vsprintf)
    ;;
errno-output)
    readonly FIXTURE_SOURCE=compat/x86_64/libc_stdio_errno_output_probe.c
    readonly START_SOURCE=compat/x86_64/libc_stdio_errno_output_start.S
    readonly FREESTANDING_DEFINE=CRABC_STDIO_ERRNO_OUTPUT_FREESTANDING
    readonly EVIDENCE_LABEL="errno-message stdio output"
    readonly -a REQUIRED_C_ABI_SYMBOLS=(snprintf vsnprintf sprintf vsprintf)
    ;;
*)
    printf 'ERROR: unknown x86 stdio format/scan evidence profile: %s\n' \
        "$EVIDENCE_PROFILE" >&2
    exit 2
    ;;
esac

fail() { printf 'ERROR: x86 static libc %s: %s\n' "$EVIDENCE_LABEL" "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment
    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize nonzero PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
        INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort timeout; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "/tmp/crabc-x86-64-libc-stdio-${EVIDENCE_PROFILE}.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"; archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-stdio-reference"; candidate="$work_dir/crabc-static-stdio-candidate"
trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"; selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"; symbols="$work_dir/candidate-symbols"; headers="$work_dir/candidate-program-headers"
dynamic="$work_dir/candidate-dynamic"; relocs="$work_dir/candidate-relocations"; disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"; archive_relocs="$work_dir/archive-relocations"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    "$FIXTURE_SOURCE" >/dev/null 2>"$trace"
project_headers=(errno.h limits.h stdarg.h stddef.h stdint.h stdio.h features.h bits/alltypes.h)
if [ "$EVIDENCE_PROFILE" = float-hex-output ]; then
    project_headers+=(fenv.h)
fi
for header in "${project_headers[@]}"; do
    grep -Fq "$ROOT_DIR/include/$header" "$trace" || fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" "$FIXTURE_SOURCE" -o "$reference"
timeout --foreground "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl ${EVIDENCE_LABEL} fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location "${REQUIRED_C_ABI_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in printf fprintf vprintf vfprintf dprintf vdprintf scanf fscanf vscanf vfscanf \
    asprintf vasprintf fwprintf swprintf fwide fgetwc fputwc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done
readelf --relocs --wide "$archive" >"$archive_relocs"
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$archive_relocs" ||
    fail "archive errno lacks an initial-TLS TPOFF relocation"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|__tls_get_addr|crabc_core|mimalloc|sha_crypt' \
    "$archive_relocs"; then
    fail "archive selects dynamic TLS or an unowned runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE "-D${FREESTANDING_DEFINE}" \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    "$FIXTURE_SOURCE" "$START_SOURCE" "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$symbols"
readelf --program-headers --wide "$candidate" >"$headers"
readelf --dynamic --wide "$candidate" >"$dynamic" || true
readelf --relocs --wide "$candidate" >"$relocs"
objdump -d "$candidate" >"$disassembly"
for symbol in "${REQUIRED_C_ABI_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$symbols" || fail "candidate lacks ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' "$headers" "$dynamic"; then
    fail "candidate is dynamic"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$headers" || fail "candidate lacks the selected errno TLS segment"
assert_fixture_tls_capacity
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$relocs" "$symbols" "$disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$symbols" "$disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if [ "$EVIDENCE_PROFILE" = float-hex-output ]; then
    grep -Fq 'unsafe fn write_hex_float' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "binary64 hexadecimal output no longer owns its spelling"
    grep -Eq "[[:space:]]fegetround$" "$symbols" ||
        fail "binary64 hexadecimal output candidate lacks the selected fenv reader"
    if grep -Eq '(^|[^[:alnum:]_])(log10|pow|floor)([^[:alnum:]_]|$)' \
        "$symbols" "$disassembly"; then
        fail "binary64 hexadecimal output selects a decimal libm formatting edge"
    fi
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Fq 'args.next_arg' "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
    fail "format/scan leaf no longer owns the x86 variadic boundary"
if [ "$EVIDENCE_PROFILE" = errno-output ]; then
    grep -Fq "b'm' if length == Length::None" \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "format/scan leaf no longer owns bare errno-message conversion"
    grep -Fq 'error_strings::error_message' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "errno-message conversion no longer uses the fixed C-locale table"
    grep -Fq 'errno::get_errno()' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "errno-message conversion no longer reads the selected TLS slot"
fi
if [ "$EVIDENCE_PROFILE" = integer-scan ]; then
    grep -Fq 'source-overflow path clears a negative sign' \
        "$ROOT_DIR/compat/x86_64/libc_stdio_integer_scan_probe.c" ||
        fail "integer scan fixture no longer records musl sign clearing"
    grep -Fq 'overflowed = true' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "integer scan implementation no longer tracks source overflow"
    grep -Fq 'u64::MAX' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "integer scan implementation no longer saturates at ULLONG_MAX"
fi
if [ "$EVIDENCE_PROFILE" = octal-hex-scan ]; then
    grep -Fq 'ScanBase::Octal' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "octal source overflow is no longer selected"
    grep -Fq 'ScanBase::HexUpper' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "uppercase-hex source overflow is no longer selected"
    grep -Fq 'complete `%X` consumption' \
        "$ROOT_DIR/compat/x86_64/libc_stdio_octal_hex_scan_probe.c" ||
        fail "octal/uppercase-hex fixture no longer records exact consumption"
fi
if [ "$EVIDENCE_PROFILE" = fixed-percent-scan ]; then
    grep -Fq "if unsafe { read_byte(directive) } == b'%'" \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "literal-percent scanner branch is no longer selected"
    grep -Fq 'cursor = unsafe { skip_input_space(cursor) };' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "literal-percent scanner no longer skips C-locale input whitespace"
    grep -Fq "if unsafe { read_byte(cursor) } != b'%'" \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "literal-percent scanner no longer matches exactly one percent"
    grep -Fq 'without an assignment' "$ROOT_DIR/$FIXTURE_SOURCE" ||
        fail "literal-percent fixture no longer records its assignment boundary"
fi
if [ "$EVIDENCE_PROFILE" = fixed-format-whitespace-scan ]; then
    grep -Fq 'if ascii_space(format_byte)' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "format-whitespace scanner branch is no longer selected"
    grep -Fq 'while ascii_space(unsafe { read_byte(directive) })' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "format-whitespace scanner no longer coalesces its format run"
    grep -Fq 'cursor = unsafe { skip_input_space(cursor) };' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "format-whitespace scanner no longer consumes C-locale input space"
    grep -Fq 'zero input whitespace' "$ROOT_DIR/$FIXTURE_SOURCE" ||
        fail "format-whitespace fixture no longer records zero-input-space admission"
fi
if [ "$EVIDENCE_PROFILE" = fixed-literal-scan ]; then
    grep -Fq "if format_byte != b'%'" \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "raw-literal scanner branch is no longer selected"
    grep -Fq 'if unsafe { read_byte(cursor) } == 0' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "raw-literal scanner no longer distinguishes input EOF"
    grep -Fq 'if unsafe { read_byte(cursor) } != format_byte' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "raw-literal scanner no longer distinguishes matching failure"
    grep -Fq 'zero-assignment raw literal' "$ROOT_DIR/$FIXTURE_SOURCE" ||
        fail "raw-literal fixture no longer records its assignment boundary"
fi
if [ "$EVIDENCE_PROFILE" = fixed-empty-format-scan ]; then
    grep -Fq 'if format_byte == 0' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "empty-format scanner termination is no longer selected"
    grep -Fq 'returns the existing assignment count without entering a scanner state' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "empty-format scanner no longer retains its sealed boundary"
    grep -Fq 'zero-assignment empty format' "$ROOT_DIR/$FIXTURE_SOURCE" ||
        fail "empty-format fixture no longer records its assignment boundary"
fi
if [ "$EVIDENCE_PROFILE" = fixed-suppressed-character-scan ]; then
    grep -Fq 'static-c-stdio-fixed-suppressed-character-scan artifact' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "suppressed-character scanner state is no longer selected"
    grep -Fq 'let suppress = if unsafe { read_byte(directive) } == b'\''*'\''' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "suppressed-character scanner no longer parses the star field"
    grep -Fq 'destination = if suppress' \
        "$ROOT_DIR/libc/src/c_abi/x86_64/stdio_format_scan.rs" ||
        fail "suppressed-character scanner no longer seals its null destination"
    grep -Fq 'zero-assignment suppressed character' "$ROOT_DIR/$FIXTURE_SOURCE" ||
        fail "suppressed-character fixture no longer records its assignment boundary"
fi
if timeout --foreground "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding ${EVIDENCE_LABEL} fixture failed with status ${status}"
fi
printf 'x86 static crabc-libc %s: PASS\n' "$EVIDENCE_LABEL"
