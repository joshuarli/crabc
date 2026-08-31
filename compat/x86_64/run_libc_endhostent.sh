#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc endhostent/endnetent evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true `-nostdlib -static` candidate linked only with crabc-libc. It
# proves musl's no-op legacy host-database terminator and its weak same-address
# endnetent alias, not host/network enumeration, resolver behavior, files,
# state, libc.so, CRT, loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc endhostent: %s\n' "$*" >&2
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_endhostent_header_abi.sh" >/dev/null
grep -Eq '^endhostent[[:space:]]+ent\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost endhostent ownership"
grep -Eq '^endnetent[[:space:]]+ent\.lo[[:space:]]+W[[:space:]]+WEAK' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost endnetent alias ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-endhostent.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-endhostent-reference"
candidate="$work_dir/crabc-static-endhostent-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-ent.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
endhostent_disassembly="$work_dir/endhostent-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" ent.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]endhostent$' ||
    fail "pinned musl ent.lo lacks strong endhostent"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+WEAK[[:space:]].*[[:space:]]endnetent$' ||
    fail "pinned musl ent.lo lacks weak endnetent alias"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_endhostent_probe.c >/dev/null 2>"$header_trace"
for header in netdb.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_endhostent_probe.c -o "$reference"
"$reference" || fail "pinned-musl endhostent fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in endhostent endnetent; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define $symbol"
done

"$ORACLE_CC" -std=c11 -DCRABC_ENDHOSTENT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_endhostent_probe.c \
    compat/x86_64/libc_endhostent_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=endhostent "$candidate" >"$endhostent_disassembly"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_program_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "endhostent candidate unexpectedly retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if grep -Eq '[[:space:]](gethostent|sethostent|getnetent|setnetent|getaddrinfo|getnameinfo|res_init)$' \
    "$candidate_symbols"; then
    fail "candidate exports an unselected netdb enumeration or resolver entry"
fi
host_address="$(nm -g --defined-only --format=posix "$candidate" | awk '$1 == "endhostent" && $2 == "T" { print $3; exit }')"
net_address="$(nm -g --defined-only --format=posix "$candidate" | awk '$1 == "endnetent" && $2 == "W" { print $3; exit }')"
[ -n "$host_address" ] || fail "candidate lacks strong endhostent"
[ -n "$net_address" ] || fail "candidate lacks weak endnetent"
[ "$host_address" = "$net_address" ] ||
    fail "candidate endnetent is not the same-address weak endhostent alias"
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$endhostent_disassembly" ||
    fail "endhostent lacks its no-op return"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$endhostent_disassembly"; then
    fail "endhostent unexpectedly performs a call or syscall"
fi

"$candidate" || fail "freestanding endhostent fixture failed"

printf 'x86 static crabc-libc endhostent/endnetent: PASS\n'
