#!/usr/bin/env bash
# Native Linux/x86-64 selected static pthread spin-destruction evidence.
#
# One project-header C fixture first executes through pinned musl 1.2.6 and
# then as a true archive-free `-nostdlib -static` candidate linked from one
# extracted crabc object. It proves only musl's source-closed successful
# return and non-observation of caller storage, not a spin-lock lifecycle,
# synchronization, thread runtime, CRT, loader, sysroot, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly AARCH64_STATIC_ABI="$ROOT_DIR/compat/abi/musl-1.2.6/aarch64/libc.a.static.tsv"

fail() {
    printf 'ERROR: x86 static libc pthread_spin_destroy: %s\n' "$*" >&2
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
                grep -Eq '[[:space:]][T][[:space:]]pthread_spin_destroy$'; then
                if printf '%s\n' "$definitions" |
                    grep -Eq '[[:space:]][TWDVBR][[:space:]](pthread_spin_init|pthread_spin_lock|pthread_spin_trylock|pthread_spin_unlock|pthread_mutex_|pthread_cond_|pthread_rwlock_|pthread_create|pthread_join|pthread_cancel)$'; then
                    fail "pthread_spin_destroy archive member also defines a synchronization or thread sibling"
                fi
                printf '%s\n' "$member"
            fi
        done
    ) >"$matches_path"
    mapfile -t matches <"$matches_path"
    [ "${#matches[@]}" = 1 ] || fail "pthread_spin_destroy must have exactly one selected archive member"
    printf '%s/%s\n' "$members_path" "${matches[0]}"
}

require_native_linux_x86_64
for tool in ar awk cargo cmp diff grep mapfile mkdir mktemp nm objdump readelf rustup sort uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -f "$AARCH64_STATIC_ABI" ] || fail "missing AArch64 musl static ABI oracle"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_spin_destroy_header_abi.sh" >/dev/null
grep -Eq '^pthread_spin_destroy[[:space:]]+pthread_spin_destroy\.lo[[:space:]]+T[[:space:]]+GLOBAL[[:space:]]+0[[:space:]]+8$' \
    "$AARCH64_STATIC_ABI" || fail "AArch64 musl ABI oracle lost pthread_spin_destroy ownership"

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-spin-destroy.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-pthread-spin-destroy-reference"
candidate="$work_dir/crabc-static-pthread-spin-destroy-candidate"
musl_archive="$("$ORACLE_CC" -print-file-name=libc.a)"
musl_object="$work_dir/musl-pthread-spin-destroy.o"
musl_symbols="$work_dir/musl-pthread-spin-destroy-symbols"
musl_disassembly="$work_dir/musl-pthread-spin-destroy-disassembly"
header_trace="$work_dir/header-trace"
archive_symbols="$work_dir/archive-symbols"
selected_c_abi_symbols="$work_dir/selected-c-abi-symbols"
expected_c_abi_symbols="$work_dir/expected-c-abi-symbols"
selected_members="$work_dir/selected-pthread-spin-destroy-members"
selected_member_names="$work_dir/selected-pthread-spin-destroy-member-names"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
spin_destroy_disassembly="$work_dir/pthread-spin-destroy-disassembly"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
ar p "$musl_archive" pthread_spin_destroy.lo >"$musl_object"
readelf --symbols --wide "$musl_object" >"$musl_symbols"
grep -Eq '[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+pthread_spin_destroy\.c$' "$musl_symbols" ||
    fail "pinned musl spin-destroy object no longer maps to pthread_spin_destroy.c"
grep -Eq '[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]pthread_spin_destroy$' "$musl_symbols" ||
    fail "pinned musl spin-destroy object lacks pthread_spin_destroy"
objdump -dr --disassemble=pthread_spin_destroy "$musl_object" >"$musl_disassembly"
if grep -Eq '\b(call|syscall)\b|R_X86_64_' "$musl_disassembly"; then
    fail "pinned musl pthread_spin_destroy text unexpectedly depends on another boundary"
fi
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$musl_disassembly" ||
    fail "pinned musl pthread_spin_destroy lacks its successful return"

"$ORACLE_CC" -std=c11 -I"$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_pthread_spin_destroy_probe.c >/dev/null 2>"$header_trace"
for header in pthread.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project-header fixture did not include <$header>"
done
"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_spin_destroy_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC "$reference" ||
    fail "pinned-musl pthread_spin_destroy fixture failed"

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_c_abi_symbols" \
    "$expected_c_abi_symbols"
grep -Eq '[[:space:]][T][[:space:]]pthread_spin_destroy$' "$archive_symbols" ||
    fail "archive does not define pthread_spin_destroy"
selected_member="$(extract_selected_member "$archive" "$selected_members" \
    "$selected_member_names")"
[ -f "$selected_member" ] || fail "selected pthread_spin_destroy member is missing"

"$ORACLE_CC" -std=c11 -DCRABC_PTHREAD_SPIN_DESTROY_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined \
    compat/x86_64/libc_pthread_spin_destroy_probe.c \
    compat/x86_64/libc_pthread_spin_destroy_start.S "$selected_member" \
    -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
objdump -d --disassemble=pthread_spin_destroy "$candidate" >"$spin_destroy_disassembly"
grep -Eq '[[:space:]]pthread_spin_destroy$' "$candidate_symbols" ||
    fail "archive-free candidate does not retain pthread_spin_destroy"
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
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr|__errno_location|%fs:' \
        "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects errno or TLS"
fi
if grep -Eq '\b(call|syscall)\b' "$spin_destroy_disassembly"; then
    fail "pthread_spin_destroy unexpectedly performs a call or syscall"
fi
grep -Eq '[[:space:]]ret([[:space:]]|$)' "$spin_destroy_disassembly" ||
    fail "pthread_spin_destroy lacks its successful return"
for unselected in pthread_spin_init pthread_spin_lock pthread_spin_trylock \
    pthread_spin_unlock pthread_mutex_init pthread_mutex_destroy pthread_mutex_lock \
    pthread_mutex_trylock pthread_mutex_unlock pthread_cond_init pthread_cond_destroy \
    pthread_cond_wait pthread_cond_signal pthread_cond_broadcast pthread_rwlock_init \
    pthread_rwlock_destroy pthread_create pthread_join pthread_detach pthread_cancel \
    thrd_create thrd_join thrd_detach; do
    if grep -Eq "[[:space:]]${unselected}$" "$candidate_symbols"; then
        fail "archive-free candidate accidentally selects ${unselected}"
    fi
done
if grep -Eq 'crabc_core|mimalloc|sha_crypt' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "archive-free candidate selects an unowned runtime dependency"
fi

env -i LC_ALL=C TZ=UTC "$candidate" ||
    fail "freestanding pthread_spin_destroy fixture failed"

printf 'x86 static crabc-libc pthread_spin_destroy: PASS\n'
