#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc psignal/psiginfo evidence.
#
# The same project-header fixture runs through pinned musl 1.2.6 and then a
# true `-nostdlib -static` candidate.  It first proves the default archive is
# unchanged, then permits exactly psignal/psiginfo in the opt-in featured
# archive. It captures only stderr's reporting bytes and errno result; it does
# not promote general diagnostics, formatted stdio, locale translation, or a
# signal-management runtime.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=20s
readonly INITIAL_TLS_BYTES=4096
readonly INITIAL_TLS_ALIGNMENT=64

fail() {
    printf 'ERROR: x86 static libc psignal: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

assert_selected_c_abi_surface() {
    local archive_path="$1" symbols_path="$2" expected_path="$3"
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

archive_c_abi_symbols() {
    local archive_path="$1" symbols_path="$2" members_path="$3"
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
}

assert_reporting_feature_delta() {
    local baseline_symbols="$1" featured_symbols="$2" delta_path="$3" removed_path="$4"

    comm -23 "$baseline_symbols" "$featured_symbols" >"$removed_path"
    if [ -s "$removed_path" ]; then
        diff -u "$baseline_symbols" "$featured_symbols" >&2 || true
        fail "x86-signal-reporting removes a default C ABI export"
    fi
    comm -13 "$baseline_symbols" "$featured_symbols" >"$delta_path"
    if ! cmp -s <(printf 'psiginfo\npsignal\n') "$delta_path"; then
        diff -u <(printf 'psiginfo\npsignal\n') "$delta_path" >&2 || true
        fail "x86-signal-reporting changes more than psignal/psiginfo"
    fi
}

assert_fixture_tls_capacity() {
    local tls_filesz tls_memsz tls_alignment

    read -r tls_filesz tls_memsz tls_alignment < <(
        awk '$1 == "TLS" { print $5, $6, $NF; exit }' "$candidate_program_headers"
    )
    [ -n "${tls_filesz:-}" ] || fail "candidate lacks a parsable PT_TLS segment"
    (( tls_filesz == 0 )) || fail "fixture TLS scratch cannot initialize PT_TLS data"
    (( tls_memsz > 0 && tls_memsz <= INITIAL_TLS_BYTES )) ||
        fail "fixture TLS scratch does not cover PT_TLS memsz ${tls_memsz}"
    (( tls_alignment > 0 && tls_alignment <= INITIAL_TLS_ALIGNMENT &&
       INITIAL_TLS_ALIGNMENT % tls_alignment == 0 )) ||
        fail "fixture TLS scratch is incompatible with PT_TLS alignment ${tls_alignment}"
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar awk cargo cmp comm diff grep mkdir nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_psignal_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-psignal.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
baseline_target_dir="$work_dir/cargo-baseline"
featured_target_dir="$work_dir/cargo-featured"
baseline_archive="$baseline_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
featured_archive="$featured_target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/pinned-musl-psignal-reference"
candidate="$work_dir/crabc-static-psignal-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
featured_symbols="$work_dir/featured-c-abi-symbols"
feature_delta="$work_dir/x86-signal-reporting-delta"
feature_removed="$work_dir/x86-signal-reporting-removed"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"
reference_stdout="$work_dir/reference-stdout"
reference_stderr="$work_dir/reference-stderr"
candidate_stdout="$work_dir/candidate-stdout"
candidate_stderr="$work_dir/candidate-stderr"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_psignal_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fcntl.h signal.h unistd.h features.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project <$header>"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_psignal_probe.c -o "$reference"
if env -i timeout "$EXECUTION_TIMEOUT" "$reference" >"$reference_stdout" 2>"$reference_stderr"; then :; else
    status=$?
    fail "pinned-musl psignal fixture exited $status"
fi
[ ! -s "$reference_stdout" ] || fail "pinned-musl fixture wrote stdout"
[ ! -s "$reference_stderr" ] || fail "pinned-musl fixture wrote stderr"

CARGO_TARGET_DIR="$baseline_target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$baseline_archive" ] || fail "cargo did not emit the baseline x86 static libc archive"
nm -A --defined-only "$baseline_archive" >"$archive_symbols"
assert_selected_c_abi_surface "$baseline_archive" "$selected_symbols" "$expected_symbols"
for unfeatured in psignal psiginfo; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unfeatured}$" "$archive_symbols"; then
        fail "baseline archive unexpectedly defines ${unfeatured}"
    fi
done

CARGO_TARGET_DIR="$featured_target_dir" cargo rustc --locked -p crabc-libc --lib \
    --features x86-signal-reporting --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$featured_archive" ] || fail "cargo did not emit the featured x86 static libc archive"
archive_c_abi_symbols "$featured_archive" "$featured_symbols" "$work_dir/featured-c-abi-members"
assert_reporting_feature_delta "$selected_symbols" "$featured_symbols" "$feature_delta" "$feature_removed"
nm -A --defined-only "$featured_archive" >"$archive_symbols"
for symbol in __errno_location __crabc_x86_static_tls_bootstrap psignal psiginfo strsignal; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "featured archive does not define ${symbol}"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -DCRABC_PSIGNAL_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_psignal_probe.c \
    compat/x86_64/libc_psignal_start.S "$featured_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location psignal psiginfo; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
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
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
unexpected_runtime="$(awk '$7 != "UND" && NF >= 8 { print $8 }' "$candidate_symbols" |
    grep -Ex 'perror|warn|warnx|vwarn|vwarnx|err|errx|verr|verrx|strerror|strerror_r|strerror_l|__strerror_l|gettext|catopen|malloc|calloc|realloc|free|pthread_create|fork|execve|syslog' || true)"
if [ -n "$unexpected_runtime" ]; then
    printf '%s\n' "$unexpected_runtime" >&2
    fail "candidate selects general diagnostics or an unowned runtime"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct initial TLS"
grep -Eq 'call.*__crabc_x86_static_tls_bootstrap' \
    compat/x86_64/libc_psignal_start.S ||
    fail "fixture start does not bootstrap selected initial TLS"

if env -i timeout "$EXECUTION_TIMEOUT" "$candidate" >"$candidate_stdout" 2>"$candidate_stderr"; then :; else
    status=$?
    fail "freestanding psignal fixture exited $status"
fi
if ! cmp -s "$reference_stdout" "$candidate_stdout" ||
    ! cmp -s "$reference_stderr" "$candidate_stderr"; then
    diff -u "$reference_stdout" "$candidate_stdout" >&2 || true
    diff -u "$reference_stderr" "$candidate_stderr" >&2 || true
    fail "candidate external output differs from pinned musl"
fi

printf 'x86 static crabc-libc psignal: PASS\n'
