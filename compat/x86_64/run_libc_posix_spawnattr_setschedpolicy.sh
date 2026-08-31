#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc posix_spawnattr_setschedpolicy evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true `-nostdlib -static` candidate linked only with crabc-libc.
# It proves musl's fixed scheduler-policy compatibility failure without
# selecting spawn execution, child lifecycle, file actions, attribute state,
# real scheduler policy, libc.so, a CRT, a loader, a sysroot, or public x86
# support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc posix_spawnattr_setschedpolicy: %s\n' "$*" >&2
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
bash "$ROOT_DIR/compat/x86_64/run_posix_spawnattr_setschedpolicy_header_abi.sh" >/dev/null
grep -Eq '^posix_spawnattr_setschedpolicy[[:space:]]+posix_spawnattr_sched\.lo[[:space:]]+T[[:space:]]+GLOBAL' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost posix_spawnattr_setschedpolicy ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-posix-spawnattr-setschedpolicy.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-posix-spawnattr-setschedpolicy-reference"
candidate="$work_dir/crabc-static-posix-spawnattr-setschedpolicy-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-posix-spawnattr-sched.o"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"
expected_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
posix_spawnattr_setschedpolicy_disassembly="$work_dir/posix-spawnattr-setschedpolicy-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" posix_spawnattr_sched.lo >"$musl_object"
readelf --symbols --wide "$musl_object" | grep -Eq \
    '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]].*[[:space:]]posix_spawnattr_setschedpolicy$' ||
    fail "pinned musl posix_spawnattr_sched.lo lacks strong posix_spawnattr_setschedpolicy"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_posix_spawnattr_setschedpolicy_probe.c >/dev/null 2>"$header_trace"
for header in spawn.h features.h sys/types.h bits/alltypes.h errno.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use project $header"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_posix_spawnattr_setschedpolicy_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl posix_spawnattr_setschedpolicy fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq '[[:space:]][TW][[:space:]]posix_spawnattr_setschedpolicy$' "$archive_symbols" ||
    fail "archive does not define posix_spawnattr_setschedpolicy"

"$ORACLE_CC" -std=c11 -DCRABC_POSIX_SPAWNATTR_SETSCHEDPOLICY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections \
    compat/x86_64/libc_posix_spawnattr_setschedpolicy_probe.c \
    compat/x86_64/libc_posix_spawnattr_setschedpolicy_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=posix_spawnattr_setschedpolicy "$candidate" \
    >"$posix_spawnattr_setschedpolicy_disassembly"
grep -Eq '[[:space:]]posix_spawnattr_setschedpolicy$' "$candidate_symbols" ||
    fail "candidate lacks posix_spawnattr_setschedpolicy"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_program_headers" "$candidate_dynamic"; then
    fail "candidate is dynamic"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_program_headers" "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "posix_spawnattr_setschedpolicy candidate unexpectedly retains TLS"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt' "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi
if grep -Eq '[[:space:]](posix_spawn|posix_spawnp|posix_spawnattr_init|posix_spawnattr_destroy|posix_spawnattr_setflags|posix_spawnattr_getflags|posix_spawnattr_setpgroup|posix_spawnattr_getpgroup|posix_spawnattr_setsigmask|posix_spawnattr_getsigmask|posix_spawnattr_setsigdefault|posix_spawnattr_getsigdefault|posix_spawnattr_setschedparam|posix_spawnattr_getschedparam|posix_spawnattr_getschedpolicy|posix_spawn_file_actions_init|posix_spawn_file_actions_destroy|posix_spawn_file_actions_addopen|posix_spawn_file_actions_addclose|posix_spawn_file_actions_adddup2)$' \
    "$candidate_symbols"; then
    fail "candidate exports an unselected spawn entry"
fi
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$posix_spawnattr_setschedpolicy_disassembly" ||
    fail "posix_spawnattr_setschedpolicy lacks its ENOSYS return"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)' \
    "$posix_spawnattr_setschedpolicy_disassembly"; then
    fail "posix_spawnattr_setschedpolicy unexpectedly performs a call or syscall"
fi

"$candidate" || fail "freestanding posix_spawnattr_setschedpolicy fixture failed"

printf 'x86 static crabc-libc posix_spawnattr_setschedpolicy: PASS\n'
