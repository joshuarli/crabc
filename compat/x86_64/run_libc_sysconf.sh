#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc sysconf evidence.
#
# The existing musl-mapped system-configuration source owner is linked only
# with `--gc-sections`. The final true-static candidate retains `sysconf` and
# its initial-TLS errno seam, but not neighboring configuration entry points,
# wider source-table closures, or a runtime closure.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc sysconf: %s\n' "$*" >&2
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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sed sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sysconf_header_abi.sh" >/dev/null

grep -Fqx $'sysconf\tsysconf.lo\tT\tGLOBAL\t0\t21c' "$AARCH64_STATIC_ABI" ||
    fail "AArch64 musl ABI oracle lost sysconf ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sysconf.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sysconf-reference"
candidate="$work_dir/crabc-static-sysconf-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
owner_symbols="$work_dir/sysconf-owner-symbols"
owner_disassembly="$work_dir/sysconf-owner-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
sysconf_disassembly="$work_dir/sysconf-disassembly"
errno_disassembly="$work_dir/errno-location-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sysconf_probe.c >/dev/null 2>"$header_trace"
for header in errno.h limits.h unistd.h features.h sys/types.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_sysconf_probe.c -o "$reference"
"$reference" || fail "pinned-musl sysconf fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]]T[[:space:]]sysconf$' "$archive_symbols" ||
    fail "archive does not define strong sysconf"

mapfile -t members < <(archive_member_for_symbol "$archive" sysconf)
[ "${#members[@]}" -eq 1 ] ||
    fail "sysconf must have exactly one existing archive source owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${members[0]}"
)
owner="$work_dir/owner/${members[0]}"
nm -g --defined-only --format=posix "$owner" >"$owner_symbols"
grep -Eq '^sysconf[[:space:]]+T[[:space:]]' "$owner_symbols" ||
    fail "existing source owner does not define sysconf"
objdump -d --disassemble=sysconf "$owner" >"$owner_disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$owner_disassembly"; then
    fail "existing source sysconf unexpectedly performs a syscall"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_SYSCONF_FREESTANDING \
    -O2 -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_sysconf_probe.c \
    compat/x86_64/libc_sysconf_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=sysconf "$candidate" >"$sysconf_disassembly"
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"

for symbol in sysconf __errno_location; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate lacks $symbol"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks the required initial-TLS errno segment"
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
if grep -Eq '[[:space:]](confstr|pathconf|fpathconf|getpagesize|getdtablesize|getauxval|getrlimit|setrlimit|prlimit|getrusage|getpriority|setpriority|nice|get_nprocs_conf|get_nprocs|get_phys_pages|get_avphys_pages)$' \
    "$candidate_symbols"; then
    fail "candidate retained neighboring system-configuration or resource C ABI symbols"
fi
if grep -Eq '[[:space:]](snprintf|memcpy|memmove|memset|strcpy|strncpy|strlen|malloc|calloc|realloc|free|aligned_alloc|memalign|valloc)$' \
    "$candidate_symbols"; then
    fail "candidate retained an unselected text or allocator dependency"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|alloc::|__rust_' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an allocator or unowned runtime dependency"
fi
if grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$sysconf_disassembly"; then
    fail "candidate sysconf unexpectedly performs a syscall"
fi
if awk '/[[:space:]]call/ && $0 !~ /<__errno_location>/ { exit 1 }' \
    "$sysconf_disassembly"; then
    :
else
    fail "candidate sysconf calls outside its explicit errno seam"
fi
grep -Eq '%fs:' "$errno_disassembly" ||
    fail "candidate errno accessor does not use direct initial-TLS FS access"

"$candidate" || fail "freestanding sysconf fixture failed"

printf 'x86 static libc sysconf: PASS\n'
