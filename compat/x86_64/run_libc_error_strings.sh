#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc error-string evidence.
#
# The same project-header fixture runs first through pinned musl 1.2.6 and
# then through a true -nostdlib/-static executable linked only with the
# selected archive. Exact stdout compares every nonnegative Linux x86 errno
# index through one past the table, while direct assertions close truncation,
# NUL termination, and musl's weak same-address __xpg_strerror_r alias.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc error strings: %s\n' "$*" >&2
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

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_error_strings_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-error-strings.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-error-strings-reference"
candidate="$work_dir/crabc-static-error-strings-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
reference_stdout="$work_dir/reference-stdout"
reference_stderr="$work_dir/reference-stderr"
candidate_stdout="$work_dir/candidate-stdout"
candidate_stderr="$work_dir/candidate-stderr"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I"$ROOT_DIR/include" \
    -E -H compat/x86_64/libc_error_strings_probe.c \
    >/dev/null 2>"$header_trace"
for header in errno.h stdint.h string.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -fno-builtin \
    -fno-stack-protector -I"$ROOT_DIR/include" \
    compat/x86_64/libc_error_strings_probe.c -o "$reference"
if env -i "$reference" >"$reference_stdout" 2>"$reference_stderr"; then :; else
    status=$?
    fail "pinned-musl error-string fixture exited ${status}"
fi
[ ! -s "$reference_stderr" ] || fail "pinned-musl fixture wrote stderr"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]strerror$' "$archive_symbols" \
    || fail "archive does not define strong strerror"
grep -Eq '[[:space:]]T[[:space:]]strerror_r$' "$archive_symbols" \
    || fail "archive does not define strong strerror_r"
grep -Eq '[[:space:]]W[[:space:]]__xpg_strerror_r$' "$archive_symbols" \
    || fail "archive does not define weak __xpg_strerror_r"
# `__strerror_l`/`strerror_l` are a separately evidenced fixed-profile locale
# ABI sibling in the shared archive. This original error-string artifact neither
# invokes nor establishes them; its final candidate still excludes that leaf.
for unselected in abort syscall malloc calloc realloc free posix_memalign; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_ERROR_STRINGS_FREESTANDING -I"$ROOT_DIR/include" -nostdlib \
    -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_error_strings_probe.c \
    compat/x86_64/libc_error_strings_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in strerror strerror_r __xpg_strerror_r; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
        || fail "candidate does not define ${symbol}"
done
strerror_r_value="$(awk '$8 == "strerror_r" { print $2; exit }' "$candidate_symbols")"
xpg_value="$(awk '$8 == "__xpg_strerror_r" { print $2; exit }' "$candidate_symbols")"
[ -n "$strerror_r_value" ] && [ "$strerror_r_value" = "$xpg_value" ] \
    || fail "__xpg_strerror_r is not a same-address strerror_r alias"
awk '$8 == "__xpg_strerror_r" && $5 == "WEAK" { found=1 } END { exit !found }' \
    "$candidate_symbols" || fail "__xpg_strerror_r is not weak in final ELF"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers"; then
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|__strerror_l|strerror_l|malloc|free|syscall' \
    "$candidate_symbols"; then
    fail "candidate selects an unowned or excluded runtime symbol"
fi

if env -i "$candidate" >"$candidate_stdout" 2>"$candidate_stderr"; then :; else
    status=$?
    fail "freestanding error-string fixture exited ${status}"
fi
[ ! -s "$candidate_stderr" ] || fail "candidate wrote stderr"
if ! cmp -s "$reference_stdout" "$candidate_stdout"; then
    diff -u "$reference_stdout" "$candidate_stdout" >&2 || true
    fail "candidate output differs from pinned musl"
fi
grep -Eq '^strerror-domain-fnv1a64=[0-9a-f]{16}$' "$candidate_stdout" \
    || fail "candidate lacks the complete errno-domain digest"
grep -Fxq 'strerror-r-alias=weak-same-address' "$candidate_stdout" \
    || fail "candidate lacks the alias behavior witness"

printf 'x86 static crabc-libc error strings: PASS\n'
