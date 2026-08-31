#!/usr/bin/env bash
# Native Linux/x86-64 private stack-check-failure archive evidence.
#
# The same narrow fixture runs through pinned musl first and then through one
# dependency-free `-nostdlib -static` crabc archive.  It proves only musl's
# terminal x86 `__stack_chk_fail` entry and its hidden weak same-address local
# alias; it deliberately rejects guard storage, canary initialization, CRT,
# TLS, loader, and public-support claims.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() { printf 'ERROR: x86 static libc stack-check failure: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

expect_sigsegv() {
    local binary="$1" label="$2" status

    set +e
    "$binary"
    status=$?
    set -e
    [ "$status" -eq 139 ] ||
        fail "${label} did not terminate with SIGSEGV (status ${status})"
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
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

assert_stack_check_failure_owner() {
    local archive_path="$1"
    local members_path="$work_dir/stack-check-failure-members"
    local member_symbols="$work_dir/stack-check-failure-member-symbols"
    local strong_value local_value
    local -a members failure_members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    (
        cd "$members_path"
        ar x "$archive_path" "${members[@]}"
    )
    mapfile -t failure_members < <(
        (
            cd "$members_path"
            nm -A -g --defined-only --format=posix "${members[@]}"
        ) | awk '$2 == "__stack_chk_fail" && $3 == "T" { name = $1; sub(/:$/, "", name); print name }' | sort -u
    )
    [ "${#failure_members[@]}" = 1 ] ||
        fail "archive does not retain one stack-check failure owner: ${failure_members[*]:-(none)}"

    readelf --symbols --wide "$members_path/${failure_members[0]}" >"$member_symbols"
    awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" && $8 == "__stack_chk_fail" { found = 1 } END { exit found ? 0 : 1 }' \
        "$member_symbols" || fail "archive owner lost musl strong __stack_chk_fail"
    awk '$4 == "FUNC" && $5 == "WEAK" && $6 == "HIDDEN" && $7 != "UND" && $8 == "__stack_chk_fail_local" { found = 1 } END { exit found ? 0 : 1 }' \
        "$member_symbols" || fail "archive owner lost musl hidden weak __stack_chk_fail_local alias"
    strong_value="$(awk '$4 == "FUNC" && $8 == "__stack_chk_fail" { print $2 }' "$member_symbols")"
    local_value="$(awk '$4 == "FUNC" && $8 == "__stack_chk_fail_local" { print $2 }' "$member_symbols")"
    [ -n "$strong_value" ] && [ "$strong_value" = "$local_value" ] ||
        fail "archive stack-check failure aliases do not share one address"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-stack-chk-fail.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-stack-check-failure-reference"
candidate="$work_dir/crabc-static-stack-check-failure-candidate"
candidate_local="$work_dir/crabc-static-stack-check-failure-local-candidate"
archive_symbols="$work_dir/archive-symbols"
archive_elf_symbols="$work_dir/archive-elf-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
failure_disassembly="$work_dir/stack-check-failure-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -static -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_stack_chk_fail_probe.c -o "$reference"
expect_sigsegv "$reference" "pinned-musl __stack_chk_fail"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
readelf --symbols --wide "$archive" >"$archive_elf_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" "$expected_c_abi_symbols"
assert_stack_check_failure_owner "$archive"
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__stack_chk_fail$' "$archive_elf_symbols" ||
    fail 'archive does not define musl __stack_chk_fail'
grep -Eq 'FUNC +WEAK +HIDDEN +.*__stack_chk_fail_local$' "$archive_elf_symbols" ||
    fail 'archive does not define musl hidden weak __stack_chk_fail_local'

"$ORACLE_CC" -std=c11 -DCRABC_STACK_CHK_FAIL_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_stack_chk_fail_probe.c \
    compat/x86_64/libc_stack_chk_fail_start.S "$archive" -o "$candidate"
"$ORACLE_CC" -std=c11 -DCRABC_STACK_CHK_FAIL_FREESTANDING \
    -DCRABC_STACK_CHK_FAIL_LOCAL_CALL -I"$ROOT_DIR/include" \
    -nostdlib -static -fno-pie -no-pie -ffreestanding -fno-builtin \
    -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_stack_chk_fail_probe.c \
    compat/x86_64/libc_stack_chk_fail_start.S "$archive" -o "$candidate_local"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
grep -Eq 'FUNC +GLOBAL +DEFAULT +.*__stack_chk_fail$' "$candidate_symbols" ||
    fail 'candidate lacks musl __stack_chk_fail'
grep -Eq 'FUNC +WEAK +HIDDEN +.*__stack_chk_fail_local$' "$candidate_symbols" ||
    fail 'candidate lacks musl hidden weak __stack_chk_fail_local'
candidate_primary_value="$(awk '$4 == "FUNC" && $8 == "__stack_chk_fail" { print $2 }' "$candidate_symbols")"
candidate_local_value="$(awk '$4 == "FUNC" && $8 == "__stack_chk_fail_local" { print $2 }' "$candidate_symbols")"
[ -n "$candidate_primary_value" ] && [ "$candidate_primary_value" = "$candidate_local_value" ] ||
    fail "candidate stack-check failure aliases do not share one address"
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate has unresolved symbols"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED|JMPREL|PLTGOT' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a TLS resolver or dynamic TLS model"
fi
for unselected in __stack_chk_guard __init_ssp abort raise _Exit exit dlopen dlsym \
    pthread_create __tls_get_addr; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "candidate accidentally selects ${unselected}"
    fi
done
objdump -d --disassemble=__stack_chk_fail "$candidate" >"$failure_disassembly"
grep -Eq '[[:space:]]hlt([[:space:]]|$)' "$failure_disassembly" ||
    fail '__stack_chk_fail does not retain musl x86 hlt termination'
if grep -Eq '[[:space:]]call[a-z]*[[:space:]]' "$failure_disassembly"; then
    fail '__stack_chk_fail selected an ambient failure handler'
fi
expect_sigsegv "$candidate" "freestanding __stack_chk_fail"
expect_sigsegv "$candidate_local" "freestanding __stack_chk_fail_local"
printf 'x86 static libc stack-check failure: PASS\n'
