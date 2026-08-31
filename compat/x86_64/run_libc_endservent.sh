#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc endservent evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true archive-free `-nostdlib -static` candidate linked from one
# extracted crabc object. It proves musl's no-op legacy service-database
# terminator, not service enumeration, database files, resolver behavior,
# libc.so, CRT, loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc endservent: %s\n' "$*" >&2
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
                grep -Eq '[[:space:]][T][[:space:]]endservent$'; then
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][TWDVBR][[:space:]](getservent|setservent|getservbyname|getservbyport|endhostent|endnetent|endprotoent|sethostent|setnetent|setprotoent|res_init|res_query|getaddrinfo)$'; then
                    fail "endservent archive member also defines a service, netdb, or resolver sibling"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "endservent must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_endservent_header_abi.sh" >/dev/null
grep -Eq '^endservent[[:space:]]+serv\.lo[[:space:]]+T[[:space:]]+GLOBAL[[:space:]]+0[[:space:]]+4$' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost endservent ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-endservent.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-endservent-reference"
candidate="$work_dir/crabc-static-endservent-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-serv.o"
musl_symbols="$work_dir/musl-serv-symbols"
musl_disassembly="$work_dir/musl-endservent-disassembly"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-endservent-members"
selected_member_names="$work_dir/selected-endservent-member-names"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
endservent_disassembly="$work_dir/endservent-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" serv.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+serv\.c$' "$musl_symbols" ||
    fail "pinned musl serv object no longer maps to serv.c"
grep -Eq '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]endservent$' "$musl_symbols" ||
    fail "pinned musl serv object lacks endservent"
objdump -dr --disassemble=endservent "$musl_object" >"$musl_disassembly"
if grep -Eq '\b(call|syscall)\b|R_X86_64_' "$musl_disassembly"; then
    fail "pinned musl endservent text unexpectedly depends on another boundary"
fi

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_endservent_probe.c >/dev/null 2>"$header_trace"
for header in netdb.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project-header fixture did not include <$header>"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_endservent_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" ||
    fail "pinned-musl endservent fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]][T][[:space:]]endservent$' "$archive_symbols" ||
    fail "archive does not define endservent"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected endservent member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_ENDSERVENT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined compat/x86_64/libc_endservent_probe.c \
    compat/x86_64/libc_endservent_start.S "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=endservent "$candidate" >"$endservent_disassembly"
grep -Eq '[[:space:]]endservent$' "$candidate_symbols" ||
    fail "archive-free candidate does not retain endservent"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
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
if grep -Eq '\b(call|syscall)\b' "$endservent_disassembly"; then
    fail "endservent unexpectedly performs a call or syscall"
fi
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$endservent_disassembly" ||
    fail "endservent lacks its no-op return"
for unselected in getservent setservent getservbyname getservbyport \
    endhostent endnetent gethostent sethostent getnetent setnetent \
    endprotoent getprotoent setprotoent getprotobyname getprotobynumber \
    res_init res_query res_querydomain res_search res_mkquery res_send __res_state \
    dn_comp dn_expand dn_skipname ns_get16 ns_get32 ns_put16 ns_put32 \
    ns_initparse ns_parserr ns_skiprr ns_name_uncompress getaddrinfo freeaddrinfo \
    getnameinfo gethostbyaddr gethostbyname herror hstrerror \
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

env -i LC_ALL=C TZ=UTC "$candidate" ||
    fail "freestanding endservent fixture failed"

printf 'x86 static crabc-libc endservent: PASS\n'
