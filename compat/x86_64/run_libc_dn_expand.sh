#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc dn_expand evidence.
#
# The project-header fixture first runs against pinned musl 1.2.6, then as a
# true archive-free `-nostdlib -static` executable linked from exactly one
# extracted crabc object. It selects one caller-owned DNS wire-name expansion
# codec and its source-required hidden/weak alias pair; it does not select
# resolver state, `/etc/resolv.conf`, DNS packet I/O, sockets, netdb, or a
# complete parser.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc dn_expand: %s\n' "$*" >&2
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
    local symbols_path="$1" label="$2"
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
                grep -Eq '[[:space:]][W][[:space:]]dn_expand$'; then
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][TW][[:space:]](dn_skipname|ns_get16|ns_get32|ns_put16|ns_put32|ns_initparse|ns_parserr|ns_skiprr|ns_name_uncompress)$'; then
                    fail "dn_expand archive member also defines a nameserver sibling"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "dn_expand must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-dn-expand.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-dn-expand-reference"
candidate="$work_dir/crabc-static-dn-expand-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-dn-expand.o"
musl_symbols="$work_dir/musl-dn-expand-symbols"
musl_disassembly="$work_dir/musl-dn-expand-disassembly"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-dn-expand-members"
selected_member_names="$work_dir/selected-dn-expand-member-names"
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
ar p "$musl_archive" dn_expand.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+dn_expand\.c$' "$musl_symbols" ||
    fail "pinned musl dn_expand object no longer maps to dn_expand.c"
grep -Eq '[[:space:]]292[[:space:]]+FUNC[[:space:]]+GLOBAL[[:space:]]+HIDDEN[[:space:]]+[0-9]+[[:space:]]+__dn_expand$' "$musl_symbols" ||
    fail "pinned musl hidden __dn_expand object layout drifted"
grep -Eq '[[:space:]]292[[:space:]]+FUNC[[:space:]]+WEAK[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+dn_expand$' "$musl_symbols" ||
    fail "pinned musl weak dn_expand object layout drifted"
assert_dn_expand_alias "$musl_symbols" "pinned-musl static archive"
objdump -dr --disassemble=__dn_expand "$musl_object" >"$musl_disassembly"
if grep -Eq '\b(call|syscall)\b|R_X86_64_' "$musl_disassembly"; then
    fail "pinned musl dn_expand text unexpectedly depends on another boundary"
fi

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_dn_expand_probe.c >/dev/null 2>"$header_trace"
for header in resolv.h arpa/nameser.h netinet/in.h stddef.h stdint.h \
    sys/socket.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project-header fixture did not include <$header>"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "project-header fixture unexpectedly included <sys/types.h>"
fi

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_dn_expand_probe.c \
    -o "$reference"
if env -i LC_ALL=C TZ=UTC "$reference"; then
    :
else
    status=$?
    fail "pinned-musl dn_expand fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in __dn_expand dn_expand; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected dn_expand member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_DN_EXPAND_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined compat/x86_64/libc_dn_expand_probe.c \
    compat/x86_64/libc_dn_expand_start.S "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d --disassemble=__dn_expand "$candidate" >"$candidate_disassembly"
for symbol in __dn_expand dn_expand; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "archive-free candidate does not retain ${symbol}"
done
assert_dn_expand_alias "$candidate_symbols" candidate
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
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate unexpectedly selects TLS"
fi
if grep -Eq '__errno_location|__h_errno_location|h_errno' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects errno, h_errno, or a TLS runtime"
fi
if grep -Eq '\b(call|syscall)\b' "$candidate_disassembly"; then
    fail "dn_expand candidate calls an unselected runtime boundary"
fi
for unselected in dn_skipname ns_get16 ns_get32 ns_put16 ns_put32 ns_initparse \
    ns_parserr ns_skiprr ns_name_uncompress __res_state res_init \
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
    fail "freestanding dn_expand fixture exited ${status}"
fi

printf 'x86 static crabc-libc dn_expand: PASS\n'
