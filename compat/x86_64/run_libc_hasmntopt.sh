#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc hasmntopt evidence.
#
# One project-header caller-buffer fixture first runs through pinned musl 1.2.6
# and then through a true `-nostdlib -static` candidate. It admits only musl's
# option-token scan; mount-table access, mounting, stdio, and filesystem I/O
# are explicitly outside the artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc hasmntopt: %s\n' "$*" >&2
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

archive_member_for_symbol() {
    local archive_path="$1" symbol="$2"

    nm -A --defined-only "$archive_path" |
        awk -v symbol="$symbol" '
            $NF == symbol {
                member = $1
                sub(/^.*\.a:/, "", member)
                sub(/:.*$/, "", member)
                print member
            }
        ' | sort -u
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
for tool in ar awk cargo cmp diff grep mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_hasmntopt_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-hasmntopt.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-hasmntopt-reference"
candidate="$work_dir/crabc-static-hasmntopt-candidate"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/hasmntopt-undefined"
object_relocations="$work_dir/hasmntopt-relocations"
object_disassembly="$work_dir/hasmntopt-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
hasmntopt_disassembly="$work_dir/final-hasmntopt-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -E -H compat/x86_64/libc_hasmntopt_probe.c >/dev/null 2>"$header_trace"
for header in mntent.h stdio.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project <$header> header"
done
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -static -fno-pie -no-pie \
    -fno-builtin -fno-stack-protector -I "$ROOT_DIR/include" \
    compat/x86_64/libc_hasmntopt_probe.c -o "$reference"
env -i "$reference" || fail "pinned-musl hasmntopt fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]hasmntopt$' "$archive_symbols" ||
    fail "archive does not define hasmntopt"

mapfile -t members < <(archive_member_for_symbol "$archive" hasmntopt)
[ "${#members[@]}" -eq 1 ] || fail "hasmntopt must have exactly one crate object owner"
mkdir "$work_dir/hasmntopt-owner"
(
    cd "$work_dir/hasmntopt-owner"
    ar x "$archive" "${members[0]}"
)
object="$work_dir/hasmntopt-owner/${members[0]}"
mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "hasmntopt" ]; then
    printf 'expected: %s\nactual:   %s\n' "hasmntopt" "${exports[*]}" >&2
    fail "hasmntopt object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    cat "$object_undefined" >&2
    fail "hasmntopt object must have no ambient C ABI dependency"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:|__errno_location' \
    "$object_disassembly"; then
    fail "hasmntopt object must remain a pure caller-buffer scan"
fi

for marker in 'src/misc/mntent.c::hasmntopt' 'strlen' 'strncmp' 'strchr' \
    'pub unsafe extern "C" fn hasmntopt' 'no mount, unmount, filesystem'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/hasmntopt.rs ||
        fail "hasmntopt source lacks ${marker}"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_HASMNTOPT_FREESTANDING -I "$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_hasmntopt_probe.c \
    compat/x86_64/libc_hasmntopt_start.S "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq 'Type:[[:space:]]+EXEC[[:space:]]+\(Executable file\)' \
    <(readelf --file-header --wide "$candidate") || fail "candidate is not ET_EXEC"
grep -Eq '[[:space:]]hasmntopt$' "$candidate_symbols" ||
    fail "candidate lacks hasmntopt"
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
if grep -Eq '[[:space:]](setmntent|endmntent|getmntent|getmntent_r|addmntent|mount|umount|umount2|fopen|fclose)$' \
    "$candidate_symbols"; then
    fail "candidate selects mntent I/O or mount behavior"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location|strchr|strncmp|strlen' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects a runtime, errno, or external string helper"
fi
objdump -d --disassemble=hasmntopt "$candidate" >"$hasmntopt_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:|__errno_location' \
    "$hasmntopt_disassembly"; then
    fail "hasmntopt must remain a pure caller-buffer scan"
fi

env -i "$candidate" || fail "freestanding hasmntopt fixture failed"

printf 'x86 static libc hasmntopt: PASS\n'
