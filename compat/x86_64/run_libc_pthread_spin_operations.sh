#!/usr/bin/env bash
# Native Linux/x86-64 private pthread spin-operation evidence.
#
# The project-header fixture executes against pinned musl and then as a true
# -nostdlib -static candidate linked from only the selected init/operations
# objects. The feature remains opt-in and the default archive must retain its
# frozen export surface.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static libc pthread spin operations: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
for tool in ar cargo grep mkdir mktemp nm objdump readelf sort timeout uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_pthread_spin_operations_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-pthread-spin-operations.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-reference"
candidate="$work_dir/crabc-candidate"
archive_symbols="$work_dir/archive-symbols"
default_archive_symbols="$work_dir/default-archive-symbols"
default_public_symbols="$work_dir/default-public-symbols"
feature_public_symbols="$work_dir/feature-public-symbols"
feature_delta_symbols="$work_dir/feature-delta-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
candidate_disassembly="$work_dir/candidate-disassembly"
operations_disassembly="$work_dir/operations-disassembly"
musl_archive="$($ORACLE_CC -print-file-name=libc.a)"
musl_objects="$work_dir/musl-objects"
musl_symbols="$work_dir/musl-symbols"
members_dir="$work_dir/members"
mkdir "$members_dir"
mkdir "$musl_objects"

cd "$ROOT_DIR"
case "$musl_archive" in
    /*) ;;
    *) fail "pinned musl compiler did not report an absolute libc.a path" ;;
esac
[ -f "$musl_archive" ] || fail "pinned musl static archive is missing"
for symbol in pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    object="$musl_objects/${symbol}.o"
    ar p "$musl_archive" "${symbol}.lo" >"$object"
    readelf --symbols --wide "$object" >"$musl_symbols-${symbol}"
    grep -Eq "[[:space:]]FILE[[:space:]]+LOCAL[[:space:]]+DEFAULT[[:space:]]+ABS[[:space:]]+${symbol}\\.c$" \
        "$musl_symbols-${symbol}" ||
        fail "pinned musl ${symbol} object lost its source mapping"
    grep -Eq "[[:space:]]FUNC[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]].*[[:space:]]${symbol}$" \
        "$musl_symbols-${symbol}" || fail "pinned musl object lacks ${symbol}"
done
objdump -dr --disassemble=pthread_spin_lock "$musl_objects/pthread_spin_lock.o" \
    >"$work_dir/musl-lock-disassembly"
grep -Eq 'pause' "$work_dir/musl-lock-disassembly" ||
    fail "pinned musl lock source lost its x86 pause"
grep -Eq 'cmpxchg' "$work_dir/musl-lock-disassembly" ||
    fail "pinned musl lock source lost its atomic compare-exchange"

"$ORACLE_CC" -std=c11 -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_spin_operations_probe.c \
    -o "$reference"
env -i LC_ALL=C TZ=UTC timeout "$EXECUTION_TIMEOUT" "$reference" ||
    fail "pinned-musl pthread spin-operation fixture failed"

# The feature must not widen the frozen default archive.
CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
nm -A --defined-only "$archive" >"$default_archive_symbols"
nm -g --defined-only "$archive" |
    awk '$2 ~ /^[TWDVBR]$/ && $3 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ { print $3 }' |
    sort -u >"$default_public_symbols"
for symbol in pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    if grep -Eq "[[:space:]]${symbol}$" "$default_archive_symbols"; then
        fail "default archive unexpectedly defines ${symbol}"
    fi
done

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --features x86-pthread-spin-operations \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the feature archive"
nm -A --defined-only "$archive" >"$archive_symbols"
nm -g --defined-only "$archive" |
    awk '$2 ~ /^[TWDVBR]$/ && $3 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ { print $3 }' |
    sort -u >"$feature_public_symbols"
comm -13 "$default_public_symbols" "$feature_public_symbols" >"$feature_delta_symbols"
expected_delta="$work_dir/expected-feature-delta"
printf '%s\n' pthread_spin_lock pthread_spin_trylock pthread_spin_unlock |
    sort -u >"$expected_delta"
cmp -s "$expected_delta" "$feature_delta_symbols" || {
    diff -u "$expected_delta" "$feature_delta_symbols" >&2 || true
    fail "spin-operation feature widened the archive by more than its exact three-name roster"
}
for symbol in pthread_spin_init pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "feature archive does not define ${symbol}"
done

mapfile -t members < <(ar t "$archive" | grep -E '^c\..+\.rcgu\.o$')
[ "${#members[@]}" -gt 0 ] || fail "feature archive has no crabc-libc members"
(
    cd "$members_dir"
    ar x "$archive" "${members[@]}"
    for member in "${members[@]}"; do
        definitions="$(nm -g --defined-only "$member")"
        if printf '%s\n' "$definitions" | grep -Eq \
            '[[:space:]][T][[:space:]]pthread_spin_lock$'; then
            printf '%s\n' "$member"
        fi
    done
) >"$work_dir/operations-member"
mapfile -t operation_members <"$work_dir/operations-member"
[ "${#operation_members[@]}" = 1 ] ||
    fail "spin operations are not owned by one archive member"
operation_member="$members_dir/${operation_members[0]}"

(
    cd "$members_dir"
    for member in "${members[@]}"; do
        definitions="$(nm -g --defined-only "$member")"
        if printf '%s\n' "$definitions" | grep -Eq \
            '[[:space:]][T][[:space:]]pthread_spin_init$'; then
            printf '%s\n' "$member"
        fi
    done
) >"$work_dir/init-member"
mapfile -t init_members <"$work_dir/init-member"
[ "${#init_members[@]}" = 1 ] || fail "spin init is not owned by one archive member"
init_member="$members_dir/${init_members[0]}"

"$ORACLE_CC" -std=c11 -DCRABC_PTHREAD_SPIN_OPERATIONS_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie \
    -ffreestanding -fno-builtin -fno-stack-protector -Wl,-e,_start \
    -Wl,--gc-sections -Wl,--no-undefined \
    compat/x86_64/libc_pthread_spin_operations_probe.c \
    compat/x86_64/libc_pthread_spin_operations_start.S \
    "$init_member" "$operation_member" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    objdump -d --disassemble="$symbol" "$candidate" >>"$operations_disassembly"
done
for symbol in pthread_spin_init pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not retain ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "archive-free candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_program_headers" ||
    grep -Eq 'NEEDED|Shared library' "$candidate_dynamic"; then
    fail "archive-free candidate selected a dynamic runtime"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD|DTPOFF|__tls_get_addr|__errno_location|%fs:' \
    "$candidate_program_headers" "$candidate_relocations" "$candidate_symbols" \
    "$candidate_disassembly"; then
    fail "archive-free candidate selected TLS or errno"
fi
grep -Eq 'pause' "$operations_disassembly" || fail "lock path lacks x86 pause"
grep -Eq 'cmpxchg' "$operations_disassembly" || fail "lock path lacks atomic compare-exchange"
if grep -Eq '\b(call|syscall)\b' "$operations_disassembly"; then
    fail "spin operations unexpectedly call another runtime boundary"
fi

env -i LC_ALL=C TZ=UTC timeout "$EXECUTION_TIMEOUT" "$candidate" ||
    fail "freestanding pthread spin-operation fixture failed"

printf 'x86 static crabc-libc pthread spin operations: PASS (private opt-in)\n'
