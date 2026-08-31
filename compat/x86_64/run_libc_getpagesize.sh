#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc getpagesize evidence.
#
# The implementation remains the existing musl-mapped system-configuration
# source owner. This fixture proves that `--gc-sections` retains only its
# no-argument getpagesize entry in the final true-static candidate; it does
# not select the neighboring sysconf/pathconf/getdtablesize ABI surface.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc getpagesize: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1"
    local symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' |
        sort -u
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

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_getpagesize_header_abi.sh" >/dev/null

grep -Fqx $'getpagesize\tgetpagesize.lo\tT\tGLOBAL\t0\tc' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost getpagesize ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-getpagesize.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-getpagesize-reference"
candidate="$work_dir/crabc-static-getpagesize-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
owner_symbols="$work_dir/getpagesize-owner-symbols"
owner_disassembly="$work_dir/getpagesize-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
getpagesize_disassembly="$work_dir/getpagesize-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_getpagesize_probe.c >/dev/null 2>"$header_trace"
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_getpagesize_probe.c -o "$reference"
"$reference" || fail "pinned-musl getpagesize fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]getpagesize$' "$archive_symbols" ||
    fail "archive does not define strong getpagesize"

mapfile -t members < <(archive_member_for_symbol "$archive" getpagesize)
[ "${#members[@]}" -eq 1 ] ||
    fail "getpagesize must have exactly one existing archive source owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${members[0]}"
)
owner="$work_dir/owner/${members[0]}"
nm -g --defined-only --format=posix "$owner" >"$owner_symbols"
grep -Eq '^getpagesize[[:space:]]+T[[:space:]]' "$owner_symbols" ||
    fail "existing source owner does not define getpagesize"
objdump -d --disassemble=getpagesize "$owner" >"$owner_disassembly"
grep -Eq '\$0x1000(,|[[:space:]]|$)' "$owner_disassembly" ||
    fail "existing source getpagesize does not retain the x86 4096-byte result"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$owner_disassembly"; then
    fail "existing source getpagesize unexpectedly performs a call or syscall"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_GETPAGESIZE_FREESTANDING \
    -O2 -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_getpagesize_probe.c \
    compat/x86_64/libc_getpagesize_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=getpagesize "$candidate" >"$getpagesize_disassembly"

grep -Eq '[[:space:]]getpagesize$' "$candidate_symbols" ||
    fail "candidate lacks getpagesize"
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
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
if grep -Eq '(/opt/musl-|libc\.a\(|glibc|ld-linux|libc\.so\.6)' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected an ambient libc runtime"
fi
if grep -Eq '[[:space:]](__errno_location|sysconf|confstr|fpathconf|pathconf|getdtablesize|getauxval)$' \
    "$candidate_symbols"; then
    fail "candidate retained broad system-configuration C ABI symbols"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|prlimit64|SYS_PRLIMIT64|statfs|fstatfs' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime or system-configuration path"
fi
grep -Eq '\$0x1000(,|[[:space:]]|$)' "$getpagesize_disassembly" ||
    fail "candidate getpagesize does not retain the x86 4096-byte result"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' "$getpagesize_disassembly"; then
    fail "candidate getpagesize unexpectedly performs a call or syscall"
fi

"$candidate" || fail "freestanding getpagesize fixture failed"

printf 'x86 static libc getpagesize: PASS\n'
