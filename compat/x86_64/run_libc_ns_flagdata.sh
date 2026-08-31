#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc _ns_flagdata evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# true archive-free `-nostdlib -static` executable linked from exactly one
# extracted crabc object. It selects the immutable 16-record nameserver
# flag-accessor table in ns_parse.c without selecting that source object's
# parser code, name codecs, resolver state, DNS I/O, sockets, or netdb.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc _ns_flagdata: %s\n' "$*" >&2
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

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" |
                grep -Eq '[[:space:]][R][[:space:]]_ns_flagdata$'; then
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][TWDVBR][[:space:]](dn_expand|dn_skipname|ns_get16|ns_get32|ns_put16|ns_put32|ns_initparse|ns_parserr|ns_skiprr|ns_name_uncompress|__res_state)$'; then
                    fail "_ns_flagdata archive member also defines a resolver sibling"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "_ns_flagdata must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-ns-flagdata.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-ns-flagdata-reference"
candidate="$work_dir/crabc-static-ns-flagdata-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-ns-parse.o"
musl_symbols="$work_dir/musl-ns-parse-symbols"
musl_sections="$work_dir/musl-ns-parse-sections"
musl_relocations="$work_dir/musl-ns-parse-relocations"
musl_data="$work_dir/musl-ns-flagdata-bytes"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-ns-flagdata-members"
selected_member_names="$work_dir/selected-ns-flagdata-member-names"
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
ar p "$musl_archive" ns_parse.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
readelf --sections --wide "$musl_object" >"$musl_sections"
readelf --relocs --wide "$musl_object" >"$musl_relocations"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+ns_parse\.c$' "$musl_symbols" ||
    fail "pinned musl ns_parse object no longer maps to ns_parse.c"
grep -Eq '[[:space:]]128[[:space:]]+OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+_ns_flagdata$' "$musl_symbols" ||
    fail "pinned musl _ns_flagdata object layout drifted"
grep -Eq '\.rodata\._ns_flagdata[[:space:]]+PROGBITS.*[[:space:]]000080[[:space:]].*[[:space:]]A[[:space:]]' "$musl_sections" ||
    fail "pinned musl _ns_flagdata no longer occupies its read-only 128-byte section"
if grep -Fq '.rela.rodata._ns_flagdata' "$musl_relocations"; then
    fail "pinned musl _ns_flagdata section unexpectedly has a relocation"
fi
objdump -s -j .rodata._ns_flagdata "$musl_object" >"$musl_data"
grep -Eq '0000[[:space:]]+00800000[[:space:]]+0f000000[[:space:]]+00780000[[:space:]]+0b000000' "$musl_data" ||
    fail "pinned musl _ns_flagdata leading mask/shift pairs drifted"
grep -Eq '0040[[:space:]]+10000000[[:space:]]+04000000[[:space:]]+0f000000[[:space:]]+00000000' "$musl_data" ||
    fail "pinned musl _ns_flagdata trailing flag pairs drifted"
grep -Eq '0070[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000000[[:space:]]+00000000' "$musl_data" ||
    fail "pinned musl _ns_flagdata reserved records drifted"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_ns_flagdata_probe.c >/dev/null 2>"$header_trace"
for header in arpa/nameser.h stddef.h stdint.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project-header fixture did not include <$header>"
done

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_ns_flagdata_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference"; then
    :
else
    status=$?
    fail "pinned-musl _ns_flagdata fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]][R][[:space:]]_ns_flagdata$' "$archive_symbols" ||
    fail "archive does not define read-only _ns_flagdata"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected _ns_flagdata member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_NS_FLAGDATA_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined compat/x86_64/libc_ns_flagdata_probe.c \
    compat/x86_64/libc_ns_flagdata_start.S "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]][R][[:space:]]_ns_flagdata$' <(nm -g --defined-only "$candidate") ||
    fail "archive-free candidate does not retain read-only _ns_flagdata"
candidate_size="$(awk '$4 == "OBJECT" && $5 == "GLOBAL" && $6 == "DEFAULT" && $8 == "_ns_flagdata" { print $3; exit }' "$candidate_symbols")"
[ "$candidate_size" = 128 ] || fail "candidate _ns_flagdata does not retain its 128-byte ABI"
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "archive-free candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers"; then
    fail "archive-free candidate selected a dynamic interpreter"
fi
if grep -Eq 'NEEDED|Shared library' "$candidate_dynamic"; then
    fail "archive-free candidate selected DT_NEEDED"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|__h_errno_location|h_errno|%fs:' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects errno, h_errno, or TLS"
fi
for unselected in dn_comp dn_expand dn_skipname ns_get16 ns_get32 ns_put16 ns_put32 \
    ns_initparse ns_parserr ns_skiprr ns_name_uncompress __res_state res_init \
    res_query res_querydomain res_search res_mkquery res_send getaddrinfo freeaddrinfo \
    getnameinfo gethostbyaddr gethostbyname gethostbyname2 gethostent \
    getnetbyaddr getnetbyname getnetent getprotobyname getprotobynumber \
    getprotoent getservbyname getservbyport getservent h_errno hstrerror \
    inet_addr inet_aton inet_ntop inet_pton inet_ntoa inet_network \
    htonl htons ntohl ntohs if_indextoname if_nameindex if_nametoindex \
    if_freenameindex socket bind connect send recv malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "archive-free candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects an unowned runtime dependency"
fi

if env -i LC_ALL=C TZ=UTC "$candidate"; then
    :
else
    status=$?
    fail "freestanding _ns_flagdata fixture exited ${status}"
fi

printf 'x86 static crabc-libc _ns_flagdata: PASS\n'
