#!/usr/bin/env bash
# Native Linux/x86-64 complete musl proto.c static-provider evidence.
#
# One project-header fixture first executes through pinned musl 1.2.6 and then
# as a true `-nostdlib -static` candidate linked from exactly one extracted
# crabc object. It owns musl's fixed legacy protocol table plus its shared
# non-reentrant enumeration/result state. The block excludes /etc/protocols,
# aliases beyond the mandatory NULL slot, resolver/DNS/socket/filesystem
# behavior, allocation, errno/TLS, libc.so, CRT, loader, sysroot, family
# promotion, and public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"
readonly WORK_PACKAGE="$ROOT_DIR/compat/x86_64/protocol-database-provider.toml"
readonly SOURCE="$ROOT_DIR/libc/src/c_abi/x86_64/protocol_database.rs"
readonly HEADER_RUNNER="$ROOT_DIR/compat/x86_64/run_protocol_database_header_abi.sh"
readonly PROBE="$ROOT_DIR/compat/x86_64/libc_protocol_database_probe.c"
readonly START="$ROOT_DIR/compat/x86_64/libc_protocol_database_start.S"
readonly -a PROTOCOL_SYMBOLS=(
    endprotoent
    getprotobyname
    getprotobynumber
    getprotoent
    setprotoent
)

fail() {
    printf 'ERROR: x86 static libc protocol database: %s\n' "$*" >&2
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

validate_work_package() {
    python3 - "$WORK_PACKAGE" <<'PY'
from pathlib import Path
import sys
import tomllib


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"ERROR: x86 static libc protocol database: {message}")


path = Path(sys.argv[1])
try:
    with path.open("rb") as stream:
        document = tomllib.load(stream)
except (OSError, tomllib.TOMLDecodeError) as error:
    raise SystemExit(
        f"ERROR: x86 static libc protocol database: cannot load {path}: {error}"
    ) from error

require(
    set(document) == {"schema", "target", "platform", "oracle", "work_package"},
    "protocol-database provider contract has an unexpected top-level shape",
)
require(
    document["schema"] == "crabc.x86_64-protocol-database-provider/v1",
    "protocol-database provider contract schema drifted",
)
require(
    document["target"] == "x86_64-unknown-linux-musl"
    and document["platform"] == "Linux/x86-64 little-endian"
    and document["oracle"] == "Pinned musl 1.2.6",
    "protocol-database provider target or oracle drifted",
)

work = document["work_package"]
require(isinstance(work, dict), "protocol-database provider work package is not a table")
expected_work_keys = {
    "target_family",
    "target_obligations",
    "target_verified_slice",
    "blocker",
    "prerequisites",
    "dependent_work",
    "baseline_contract",
    "source_owners",
    "focused_evidence_command",
    "family_aggregate_command",
    "product_command",
    "negative_scope",
    "expected_transition",
    "evidence",
}
require(
    set(work) == expected_work_keys,
    "protocol-database provider work package fields drifted",
)
require(
    work["target_family"] == "libc.headers-layouts"
    and work["target_obligations"]
    == ["unlisted-public-callables", "current-static-c-exports"]
    and work["target_verified_slice"] == "static-c-protocol-database",
    "protocol-database provider target obligation drifted",
)

expected_source_owners = [
    "compat/x86_64/protocol-database-provider.toml",
    "libc/src/c_abi/x86_64/static_c_abi.rs",
    "libc/src/c_abi/x86_64/protocol_database.rs",
    "include/netdb.h",
    "compat/x86_64/protocol_database_header_abi_probe.c",
    "compat/x86_64/protocol_database_header_abi_probe.cpp",
    "compat/x86_64/run_protocol_database_header_abi.sh",
    "compat/x86_64/libc_protocol_database_probe.c",
    "compat/x86_64/libc_protocol_database_start.S",
    "compat/x86_64/run_libc_protocol_database.sh",
    "compat/x86_64/static_c_abi_exports.txt",
    "compat/x86_64/header_callable_inventory.json",
    "compat/x86_64/headers-layouts-foundation.toml",
    "compat/x86_64/parity.toml",
    "compat/x86_64/validate_parity_ledger.py",
    "compat/x86_64/tests/test_header_callable_inventory.py",
    "compat/x86_64/tests/test_parity_ledger.py",
    "compat/x86_64/tests/test_runner.py",
    "compat/x86_64/aarch64_parity_inventory.py",
    "compat/x86_64/aarch64_parity_inventory.json",
    "compat/x86_64/README.md",
    "scripts/dev-x86_64.sh",
]
require(
    work["source_owners"] == expected_source_owners,
    "protocol-database provider source ownership drifted",
)
require(
    work["focused_evidence_command"]
    == "./scripts/dev-x86_64.sh libc-protocol-database"
    and work["family_aggregate_command"]
    == "./scripts/dev-x86_64.sh campaign-family libc.headers-layouts"
    and work["product_command"] == "./scripts/dev-x86_64.sh campaign-static",
    "protocol-database provider evidence routing drifted",
)
require(
    work["prerequisites"] == ["oracle.musl-toolchain"]
    and work["dependent_work"]
    == [
        "libc.headers-layouts callable-provider complement closure",
        "libc.c-abi-compat C ABI closure",
        "libc.resolver bounded resolver profile",
    ],
    "protocol-database provider prerequisite/dependent-work contract drifted",
)
for name in (
    "endprotoent",
    "getprotobyname",
    "getprotobynumber",
    "getprotoent",
    "setprotoent",
):
    require(name in work["blocker"], f"provider blocker no longer names {name}")
for required in (
    "src/network/proto.c",
    "proto.lo",
    "immutable built-in protocol table",
    "shared index",
    "shared protoent result",
    "NULL alias slot",
    "strlen/strcmp",
    "network_databases_exports.rs",
    "/etc/protocols",
):
    require(required in work["baseline_contract"], f"baseline contract omits {required}")
for required in (
    "/etc/protocols",
    "case folding",
    "errno/TLS",
    "allocation",
    "DNS",
    "resolver configuration",
    "public x86 support",
):
    require(required in work["negative_scope"], f"negative scope omits {required}")
for required in (
    "1079 to 1084",
    "387 to 382",
    "1513",
    "libc.headers-layouts",
    "libc.resolver",
    "libc.c-abi-compat",
):
    require(required in work["expected_transition"], f"expected transition omits {required}")
require(
    work["evidence"]
    == [
        "pinned-musl/project netdb C/C++ declaration matrix",
        "pinned-musl versus static crabc proto.c state-machine differential",
        "header callable provider linkage audit",
        "AArch64 static ABI ownership parity inventory",
    ],
    "protocol-database provider evidence set drifted",
)
PY
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
        LC_ALL=C sort -u >"$symbols_path"
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_musl_proto_oracle() {
    local symbols_path="$1"
    local defined_path="$2"
    local expected_defined_path="$3"
    local undefined_path="$4"
    local expected_undefined_path="$5"
    local symbol

    readelf --symbols --wide "$musl_object" >"$symbols_path"
    grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+proto\.c$' \
        "$symbols_path" || fail "pinned musl proto object no longer maps to proto.c"
    for symbol in "${PROTOCOL_SYMBOLS[@]}"; do
        grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]${symbol}$" \
            "$symbols_path" || fail "pinned musl proto.lo lacks strong ${symbol}"
    done
    nm -g --defined-only --format=posix "$musl_object" |
        awk '$2 ~ /^[TWDVBR]$/ { print $1 }' | LC_ALL=C sort -u >"$defined_path"
    printf '%s\n' "${PROTOCOL_SYMBOLS[@]}" | LC_ALL=C sort -u >"$expected_defined_path"
    if ! cmp -s "$expected_defined_path" "$defined_path"; then
        diff -u "$expected_defined_path" "$defined_path" >&2 || true
        fail "pinned musl proto.lo public definition surface drifted"
    fi
    nm --undefined-only --format=posix "$musl_object" |
        awk '$2 == "U" { print $1 }' | LC_ALL=C sort -u >"$undefined_path"
    printf '%s\n' strcmp strlen | LC_ALL=C sort -u >"$expected_undefined_path"
    if ! cmp -s "$expected_undefined_path" "$undefined_path"; then
        diff -u "$expected_undefined_path" "$undefined_path" >&2 || true
        fail "pinned musl proto.lo import surface drifted"
    fi
}

extract_protocol_member() {
    local archive_path="$1"
    local members_path="$2"
    local matches_path="$3"
    local member definitions symbol selected_count
    local -a members matches

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
        for member in "${members[@]}"; do
            definitions="$(nm -g --defined-only --format=posix "$member" | awk '$2 ~ /^[TWDVBR]$/ { print $1 }')"
            selected_count=0
            for symbol in "${PROTOCOL_SYMBOLS[@]}"; do
                if printf '%s\n' "$definitions" | grep -Fqx "$symbol"; then
                    selected_count=$((selected_count + 1))
                fi
            done
            if [ "$selected_count" -eq 0 ]; then
                continue
            fi
            if [ "$selected_count" -ne "${#PROTOCOL_SYMBOLS[@]}" ]; then
                fail "${member} defines only a strict subset of the proto.c provider block"
            fi
            printf '%s\n' "$member"
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] ||
        fail "proto.c provider block must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in ar awk cargo cmp diff env grep mapfile mkdir mktemp nm objdump python3 readelf rustup sort strings; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"
[ -f "$WORK_PACKAGE" ] || fail "missing protocol-database provider contract"
[ -f "$SOURCE" ] || fail "missing target-local protocol-database provider source"
[ -f "$HEADER_RUNNER" ] || fail "missing protocol-database header runner"
[ -f "$PROBE" ] || fail "missing protocol-database fixture"
[ -f "$START" ] || fail "missing protocol-database static entry"
grep -Fq 'src/network/proto.c' "$SOURCE" ||
    fail "target-local source no longer records pinned musl proto.c provenance"
grep -Fq 'network_databases_exports.rs' "$SOURCE" ||
    fail "target-local source no longer guards against the generic protocol database path"
validate_work_package

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$HEADER_RUNNER" >/dev/null
for symbol in "${PROTOCOL_SYMBOLS[@]}"; do
    grep -Eq "^${symbol}[[:space:]]+proto\\.lo[[:space:]]+T[[:space:]]+GLOBAL" \
        "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost ${symbol} ownership"
done

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-protocol-database.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-protocol-database-reference"
candidate="$work_dir/crabc-static-protocol-database-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-proto.o"
musl_symbols="$work_dir/musl-proto-symbols"
musl_defined="$work_dir/musl-proto-defined"
expected_musl_defined="$work_dir/expected-musl-proto-defined"
musl_undefined="$work_dir/musl-proto-undefined"
expected_musl_undefined="$work_dir/expected-musl-proto-undefined"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-protocol-database-members"
selected_member_names="$work_dir/selected-protocol-database-member-names"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
getprotoent_disassembly="$work_dir/getprotoent-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" proto.lo >"$musl_object"
assert_musl_proto_oracle "$musl_symbols" "$musl_defined" "$expected_musl_defined" \
    "$musl_undefined" "$expected_musl_undefined"

"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -E -H "$PROBE" \
    >/dev/null 2>"$header_trace"
for header in netdb.h features.h stddef.h stdint.h sys/socket.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project-header fixture did not include <$header>"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    "$PROBE" -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" ||
    fail "pinned-musl protocol-database fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
for symbol in "${PROTOCOL_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]][T][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
selected_member="$(extract_protocol_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected proto.c provider member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_PROTOCOL_DATABASE_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--gc-sections \
    -Wl,--no-undefined "$PROBE" "$START" "$selected_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=getprotoent "$candidate" >"$getprotoent_disassembly"
for symbol in "${PROTOCOL_SYMBOLS[@]}"; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "archive-free candidate does not retain ${symbol}"
done
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
if grep -Eq '[[:space:]]\.plt([.[:space:]]|$)' "$candidate_sections"; then
    fail "archive-free candidate retains a PLT"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|malloc|calloc|realloc|free|memcpy|memset|strcmp|strlen' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects an unowned runtime or byte-string dependency"
fi
if strings "$candidate" | grep -Fq '/etc/protocols'; then
    fail "archive-free candidate embeds an unselected /etc/protocols dependency"
fi
for unselected in \
    endhostent endnetent gethostent sethostent getnetent setnetent \
    gethostbyaddr gethostbyname getnetbyaddr getnetbyname \
    endservent getservent setservent getservbyname getservbyport \
    getaddrinfo freeaddrinfo getnameinfo herror hstrerror \
    res_init res_query res_querydomain res_search res_mkquery res_send __res_state \
    dn_comp dn_expand dn_skipname ns_get16 ns_get32 ns_put16 ns_put32 \
    ns_initparse ns_parserr ns_skiprr ns_name_uncompress \
    socket bind connect accept listen send sendto sendmsg recv recvfrom recvmsg shutdown \
    open openat read close fopen fdopen fclose; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "archive-free candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$getprotoent_disassembly"; then
    fail "getprotoent unexpectedly performs a syscall"
fi

env -i LC_ALL=C TZ=UTC "$candidate" ||
    fail "freestanding protocol-database fixture failed"

printf 'x86 static crabc-libc proto.c providers: PASS\n'
