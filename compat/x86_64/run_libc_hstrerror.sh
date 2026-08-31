#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc hstrerror evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# `-nostdlib -static` executable linked solely through the selected crabc
# archive. It selects exactly hstrerror's immutable C/POSIX/C.UTF-8 message
# strings, not h_errno storage, hosts/resolver configuration, DNS, network
# database, allocator, stdio, TLS, or syscall behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc hstrerror: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in ar cargo cmp diff grep nm objdump readelf rustup sort strings; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-hstrerror.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-hstrerror-reference"
candidate="$work_dir/crabc-static-hstrerror-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-hstrerror.o"
musl_strings="$work_dir/musl-hstrerror-strings"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" hstrerror.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]hstrerror$' ||
    fail "pinned musl archive lacks hstrerror.lo"
strings -a "$musl_object" >"$musl_strings"
for message in 'Host not found' 'Try again' 'Non-recoverable error' \
    'Address not available' 'Unknown error'; do
    grep -Fxq "$message" "$musl_strings" ||
        fail "pinned musl hstrerror message drifted: $message"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_hstrerror_probe.c >/dev/null 2>"$header_trace"
for header in errno.h netdb.h stddef.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_hstrerror_probe.c \
    -o "$reference"
for locale_name in C POSIX C.UTF-8; do
    if env -i LC_ALL="$locale_name" TZ=UTC "$reference"; then
        :
    else
        status=$?
        fail "pinned-musl ${locale_name} hstrerror fixture exited ${status}"
    fi
done

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]][TW][[:space:]]hstrerror$' "$archive_symbols" ||
    fail "archive does not define hstrerror"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_HSTRERROR_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--no-undefined compat/x86_64/libc_hstrerror_probe.c \
    compat/x86_64/libc_hstrerror_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d --disassemble=hstrerror "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]]hstrerror$' "$candidate_symbols" ||
    fail "candidate does not define hstrerror"
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic dependency"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers"; then
    grep -E '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" >&2 || true
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq 'R_X86_64_TPOFF(32|64)?|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects errno or a TLS runtime"
fi
if grep -Eq '\b(call|syscall)\b' "$candidate_disassembly"; then
    fail "hstrerror implementation calls an unselected runtime boundary"
fi
for unselected in __h_errno_location h_errno herror freeaddrinfo gai_strerror \
    getaddrinfo gethostbyaddr gethostbyname gethostbyname2 gethostent \
    getnameinfo getnetbyaddr getnetbyname getnetent getprotobyname \
    getprotobynumber getprotoent getservbyname getservbyport getservent \
    sethostent endhostent; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

for locale_name in C POSIX C.UTF-8; do
    if env -i LC_ALL="$locale_name" TZ=UTC "$candidate"; then
        :
    else
        status=$?
        fail "freestanding ${locale_name} hstrerror fixture exited ${status}"
    fi
done

printf 'x86 static crabc-libc hstrerror: PASS\n'
