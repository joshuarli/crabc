#!/usr/bin/env bash
# Native Linux/x86-64 selected static crabc-libc sleep evidence.
#
# The same project-header C fixture first executes through pinned musl 1.2.6,
# then as a true -nostdlib/-static candidate. It proves only musl's one-call
# `sleep(unsigned)` wrapper over the already selected nanosleep boundary; its
# raw timer and selected signal setup merely make EINTR deterministic.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"

fail() {
    printf 'ERROR: x86 static libc sleep: %s\n' "$*" >&2
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
    local members_path="$work_dir/selected-c-abi-members"; local -a members

    mapfile -t members < <(ar t "$archive_path" | grep -E '^c\..+\.rcgu\.o$')
    [ "${#members[@]}" -gt 0 ] || fail "archive has no crabc-libc object members"
    mkdir "$members_path"
    ( cd "$members_path"; ar x "$archive_path" "${members[@]}"; \
      nm -g --defined-only --format=posix "${members[@]}" ) |
        awk '$2 ~ /^[TWDVBR]$/ && $1 !~ /^(_R|_ZN|DW\.ref\.|anon\.)/ && $1 != "crabc_x86_64_signal_restorer" && $1 != "__crabc_x86_pthread_clone" { print $1 }' |
        sort -u >"$symbols_path"
    [ -f "$STATIC_C_ABI_EXPORTS" ] || fail "missing static C ABI export contract"
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

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_sleep_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-libc-sleep.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
target_dir="$work_dir/cargo-target"
archive="$target_dir/x86_64-unknown-linux-musl/debug/libc.a"
reference="$work_dir/musl-sleep-reference"
candidate="$work_dir/crabc-static-sleep-candidate"
header_trace="$work_dir/header-trace"; archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-c-abi-symbols"; expected_symbols="$work_dir/expected-c-abi-symbols"
object_undefined="$work_dir/sleep-undefined"; object_relocations="$work_dir/sleep-relocations"
object_disassembly="$work_dir/sleep-disassembly"; candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"; candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"; candidate_disassembly="$work_dir/candidate-disassembly"
errno_disassembly="$work_dir/errno-disassembly"; sleep_disassembly="$work_dir/final-sleep-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" -E -H \
    compat/x86_64/libc_sleep_probe.c >/dev/null 2>"$header_trace"
for header in errno.h signal.h unistd.h features.h sys/syscall.h \
    bits/alltypes.h bits/signal.h bits/syscall.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "fixture did not use the project $header header"
done
"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -fno-builtin \
    -fno-stack-protector -I "$ROOT_DIR/include" compat/x86_64/libc_sleep_probe.c \
    -o "$reference"
"$reference" || fail "pinned-musl sleep fixture failed"

CARGO_TARGET_DIR="$target_dir" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"
nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
for symbol in __errno_location nanosleep sleep; do
    grep -Eq "[[:space:]][TW][[:space:]]${symbol}$" "$archive_symbols" ||
        fail "archive does not define ${symbol}"
done
for unselected in timer_create setitimer ualarm malloc free calloc realloc; do
    if grep -Eq "[[:space:]][TW][[:space:]]${unselected}$" "$archive_symbols"; then
        fail "archive accidentally exports unselected ${unselected}"
    fi
done

mapfile -t members < <(archive_member_for_symbol "$archive" sleep)
[ "${#members[@]}" -eq 1 ] || fail "sleep must have exactly one crate object owner"
mkdir "$work_dir/sleep-owner"
(
    cd "$work_dir/sleep-owner"
    ar x "$archive" "${members[0]}"
)
object="$work_dir/sleep-owner/${members[0]}"
mapfile -t exports < <(
    nm -g --defined-only --format=posix "$object" |
        awk '$2 ~ /^[TW]$/ { print $1 }' | sort -u
)
if [ "${exports[*]}" != "sleep" ]; then
    printf 'expected: %s\nactual:   %s\n' "sleep" "${exports[*]}" >&2
    fail "sleep object export surface drifted"
fi
nm --undefined-only --format=posix "$object" |
    awk '$1 != "_GLOBAL_OFFSET_TABLE_" { print $1 }' | sort -u >"$object_undefined"
if ! grep -Fxq nanosleep "$object_undefined" || [ "$(wc -l <"$object_undefined")" -ne 1 ]; then
    cat "$object_undefined" >&2
    fail "sleep object must depend only on nanosleep"
fi
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|%fs:|__errno_location' "$object_disassembly"; then
    fail "sleep object must delegate without a direct syscall or errno TLS"
fi
grep -Eq 'nanosleep' "$object_relocations" ||
    fail "sleep object lacks its nanosleep delegation relocation"

for marker in 'src/unistd/sleep.c::sleep' 'nanosleep(&tv, &tv)' \
    'initial-TLS `errno`' 'pub extern "C" fn sleep'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/sleep.rs ||
        fail "sleep source lacks ${marker}"
done

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -DCRABC_SLEEP_FREESTANDING \
    -I "$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    compat/x86_64/libc_sleep_probe.c compat/x86_64/libc_sleep_start.S \
    "$archive" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
objdump -d "$candidate" >"$candidate_disassembly"
for symbol in __errno_location nanosleep sleep; do
    grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" ||
        fail "candidate does not define ${symbol}"
done
if awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols" | grep -q .; then
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP|NEEDED' \
    "$candidate_headers" "$candidate_dynamic"; then
    fail "candidate selects a dynamic dependency"
fi
grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    fail "candidate lacks the selected errno TLS segment"
if grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
    "$candidate_relocations" "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate retains a dynamic TLS model"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|clock_nanosleep|usleep|timer_create|timer_settime' \
    "$candidate_symbols" "$candidate_disassembly"; then
    fail "candidate selects an unowned time or runtime dependency"
fi
objdump -d --disassemble=__errno_location "$candidate" >"$errno_disassembly"
grep -Eq '%fs:0x0|%fs:-' "$errno_disassembly" ||
    fail "candidate errno does not use direct fs initial TLS"
objdump -d --disassemble=sleep "$candidate" >"$sleep_disassembly"
grep -Eq '[[:space:]]call([[:space:]]|q).*<nanosleep>' "$sleep_disassembly" ||
    fail "final sleep wrapper lost its nanosleep delegation"
if grep -Eq '[[:space:]]syscall([[:space:]]|$)|%fs:|__errno_location' "$sleep_disassembly"; then
    fail "final sleep wrapper must not emit a direct syscall or errno TLS path"
fi

"$candidate" || fail "freestanding sleep fixture failed"

printf 'x86 static libc sleep: PASS\n'
