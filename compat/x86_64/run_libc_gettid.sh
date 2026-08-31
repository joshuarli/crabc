#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc gettid evidence.
#
# One GNU project-header C fixture first executes through pinned musl 1.2.6
# and then through a true one-member `-nostdlib -static` candidate. It proves
# only the current task's ordinary positive Linux identifier through direct
# and function-pointer calls, not scheduler or aggregate process behavior.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc gettid: %s\n' "$*" >&2
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
    grep -Ev '^(#|$)' "$STATIC_C_ABI_EXPORTS" | LC_ALL=C sort -u >"$expected_path"
    if ! cmp -s "$expected_path" "$symbols_path"; then
        diff -u "$expected_path" "$symbols_path" >&2 || true
        fail "selected static C ABI export surface drifted"
    fi
}

assert_gettid_syscall_path() {
    local disassembly="$1"

    objdump -d --disassemble=gettid "$candidate" >"$disassembly"
    grep -Eq '\$0xba(,|[[:space:]]|\$)' "$disassembly" ||
        fail "gettid lacks Linux syscall 186"
    grep -Eq '[[:space:]]syscall([[:space:]]|$)' "$disassembly" ||
        fail "gettid lacks its Linux syscall instruction"
    if grep -Eq '[[:space:]]call(q)?([[:space:]]|$)|__pthread_self|%fs:' "$disassembly"; then
        fail "gettid unexpectedly selects a TCB, TLS, or helper-call path"
    fi
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_gettid_header_abi.sh" >/dev/null

grep -Eq '^gettid[[:space:]]+gettid\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost gettid ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-gettid.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
selected_archive="$work_dir/libcrabc-gettid.a"
reference="$work_dir/musl-gettid-reference"
candidate="$work_dir/crabc-static-gettid-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-gettid.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/gettid-undefined"
object_relocations="$work_dir/gettid-relocations"
object_disassembly="$work_dir/gettid-object-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_sections="$work_dir/candidate-sections"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
gettid_disassembly="$work_dir/gettid-disassembly"
link_map="$work_dir/candidate.map"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" gettid.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq '[[:space:]]gettid$' ||
    fail "pinned musl gettid.lo lacks gettid"

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_gettid_probe.c >/dev/null 2>"$header_trace"
for header in unistd.h features.h sys/types.h stdint.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_gettid_probe.c -o "$reference"
"$reference" || fail "pinned-musl gettid fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]gettid$' "$archive_symbols" ||
    fail "archive does not define gettid"

mapfile -t gettid_members < <(archive_member_for_symbol "$archive" gettid)
[ "${#gettid_members[@]}" -eq 1 ] ||
    fail "gettid must have exactly one crate object owner"
mkdir "$work_dir/owner"
(
    cd "$work_dir/owner"
    ar x "$archive" "${gettid_members[0]}"
    ar crs "$selected_archive" "${gettid_members[0]}"
)
object="$work_dir/owner/${gettid_members[0]}"

mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "gettid" ]; then
    printf 'expected: %s\nactual:   %s\n' "gettid" "${exports[*]}" >&2
    fail "gettid object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if [ -s "$object_undefined" ]; then
    cat "$object_undefined" >&2
    fail "gettid object retains an unresolved helper"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '__pthread_self|__errno_location|__tls_get_addr|pthread_|crabc_core|mimalloc|sha_crypt' \
    "$object_relocations" "$object_disassembly"; then
    fail "gettid object selects a forbidden runtime dependency"
fi

"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_GETTID_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,-Map,"$link_map" compat/x86_64/libc_gettid_probe.c \
    compat/x86_64/libc_gettid_start.S "$selected_archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --sections --wide "$candidate" >"$candidate_sections"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq '[[:space:]]gettid$' "$candidate_symbols" ||
    fail "candidate does not define gettid"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic runtime"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location' \
    "$candidate_program_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "gettid candidate unexpectedly retains TLS or errno"
fi
if grep -Eq '[[:space:]](getpid|getppid|sched_yield|sched_getscheduler|pthread_create|pthread_self|__pthread_self|fork|clone|syscall)$' \
    "$candidate_symbols"; then
    fail "candidate selects process, scheduler, or pthread behavior"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|libc\.a\(' \
    "$candidate_symbols" "$candidate_disassembly" "$link_map"; then
    fail "candidate selects an unowned or ambient runtime dependency"
fi
if grep -Eq '[[:space:]]\.plt([[:space:]]|$)' "$candidate_sections"; then
    fail "candidate retains a PLT"
fi
assert_gettid_syscall_path "$gettid_disassembly"

"$candidate" || fail "freestanding gettid fixture failed"

printf 'x86 static libc gettid: PASS\n'
