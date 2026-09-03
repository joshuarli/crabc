#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc nameserver message parser.
#
# A project-header fixture first runs through pinned musl 1.2.6 and then
# through one true `-nostdlib -static` candidate. The candidate begins with
# exactly one extracted parser-trio object and admits ordinary demand-driven
# libc.a closure only for dn_expand, ns_skiprr, ns_get16, ns_get32, and the
# selected initial-TLS errno support. It is caller-owned message parsing, not
# resolver state, DNS transport, a netdb database, or a general DNS runtime.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_TSV="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc nameser message parser: %s\n' "$*" >&2
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

assert_dn_expand_alias() {
    local symbols_path="$1"
    local label="$2"
    local alias_value helper_value

    alias_value="$(awk '$8 == "dn_expand" && $4 == "FUNC" && $5 == "WEAK" && $6 == "DEFAULT" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    helper_value="$(awk '$8 == "__dn_expand" && $4 == "FUNC" && $5 == "GLOBAL" && $6 == "HIDDEN" && $7 != "UND" { print $2; exit }' "$symbols_path")"
    [ -n "$alias_value" ] || fail "$label lacks weak default dn_expand"
    [ -n "$helper_value" ] || fail "$label lacks global hidden __dn_expand"
    [ "$alias_value" = "$helper_value" ] ||
        fail "$label dn_expand/__dn_expand are not a same-address alias pair"
}

extract_selected_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions symbol
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only "$member")"
            if printf '%s\n' "$definitions" | grep -Eq '[[:space:]][T][[:space:]]ns_initparse$'; then
                for symbol in ns_initparse ns_parserr ns_name_uncompress; do
                    printf '%s\n' "$definitions" | grep -Eq "[[:space:]][T][[:space:]]${symbol}$" ||
                        fail "parser selected object does not define ${symbol}"
                done
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][TW][[:space:]](dn_expand|dn_skipname|ns_get16|ns_get32|ns_put16|ns_put32|ns_skiprr|_ns_flagdata)$'; then
                    fail "nameser parser archive member also defines a selected helper"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "parser trio must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_TSV" ] || fail "missing pinned-musl AArch64 static inventory"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_nameser_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-nameser-message-parser.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-nameser-message-parser-reference"
candidate="$work_dir/crabc-static-nameser-message-parser-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-ns-parse.o"
musl_symbols="$work_dir/musl-ns-parse-symbols"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-nameser-parser-members"
selected_member_names="$work_dir/selected-nameser-parser-member-names"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
initparse_disassembly="$work_dir/ns-initparse-disassembly"
parserr_disassembly="$work_dir/ns-parserr-disassembly"
uncompress_disassembly="$work_dir/ns-name-uncompress-disassembly"
errno_disassembly="$work_dir/errno-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" ns_parse.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+ns_parse\.c$' "$musl_symbols" ||
    fail "pinned musl ns_parse object no longer maps to ns_parse.c"
for symbol in ns_initparse ns_parserr ns_name_uncompress; do
    grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+${symbol}$" "$musl_symbols" ||
        fail "pinned musl ns_parse object no longer defines ${symbol}"
    awk -F '\t' -v symbol="$symbol" '$1 == symbol && $2 == "ns_parse.lo" && $3 == "T" && $4 == "GLOBAL" { found = 1 } END { exit !found }' "$AARCH64_STATIC_TSV" ||
        fail "pinned-musl AArch64 static inventory no longer maps ${symbol} to ns_parse.lo"
done

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_nameser_message_parser_probe.c >/dev/null 2>"$header_trace"
for header in errno.h resolv.h arpa/nameser.h netinet/in.h stddef.h stdint.h \
    sys/socket.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "fixture unexpectedly used the project sys/types.h header"
fi

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_nameser_message_parser_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference"; then
    :
else
    status=$?
    fail "pinned-musl nameser message-parser fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in ns_initparse ns_parserr ns_name_uncompress; do
    grep -Eq "[[:space:]][T][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected nameser parser member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_NAMESER_MESSAGE_PARSER_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined \
    compat/x86_64/libc_nameser_message_parser_probe.c \
    compat/x86_64/libc_nameser_message_parser_start.S "$selected_member" "$archive" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d --disassemble=ns_initparse "$candidate" >"$initparse_disassembly"
objdump -d --disassemble=ns_parserr "$candidate" >"$parserr_disassembly"
objdump -d --disassemble=ns_name_uncompress "$candidate" >"$uncompress_disassembly"
for symbol in ns_initparse ns_parserr ns_name_uncompress __dn_expand dn_expand \
    ns_skiprr ns_get16 ns_get32 __errno_location __crabc_x86_static_tls_bootstrap; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
assert_dn_expand_alias "$candidate_symbols" candidate
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
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_program_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$initparse_disassembly" \
    "$parserr_disassembly" "$uncompress_disassembly"; then
    fail "candidate relocations retain a dynamic TLS model"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
grep -Eq 'call.*<ns_get16>' "$initparse_disassembly" ||
    fail "ns_initparse does not call its selected ns_get16 dependency"
grep -Eq 'call.*<ns_skiprr>' "$initparse_disassembly" ||
    fail "ns_initparse does not call its selected ns_skiprr dependency"
for symbol in ns_skiprr ns_name_uncompress ns_get16 ns_get32; do
    grep -Eq "call.*<${symbol}>" "$parserr_disassembly" ||
        fail "ns_parserr does not call its selected ${symbol} dependency"
done
grep -Eq 'call.*<(__)?dn_expand>' "$uncompress_disassembly" ||
    fail "ns_name_uncompress does not call its selected dn_expand dependency"
if grep -Eq '\bsyscall\b' "$initparse_disassembly" "$parserr_disassembly" \
    "$uncompress_disassembly"; then
    fail "nameser parser implementation unexpectedly performs a syscall"
fi
for unselected in __res_state res_init res_query res_querydomain res_search \
    res_mkquery res_send getaddrinfo freeaddrinfo getnameinfo gethostbyaddr \
    gethostbyname gethostbyname2 gethostent getnetbyaddr getnetbyname getnetent \
    getprotobyname getprotobynumber getprotoent getservbyname getservbyport \
    getservent endhostent endnetent endprotoent h_errno hstrerror inet_addr \
    inet_aton inet_ntop inet_pton inet_ntoa inet_network htonl htons ntohl ntohs \
    if_indextoname if_nameindex if_nametoindex if_freenameindex socket bind \
    connect send recv malloc free calloc realloc; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$initparse_disassembly" "$parserr_disassembly" \
    "$uncompress_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

if env -i LC_ALL=C TZ=UTC "$candidate"; then
    :
else
    status=$?
    fail "freestanding nameser message-parser fixture exited ${status}"
fi

printf 'x86 static crabc-libc nameser message parser: PASS\n'
