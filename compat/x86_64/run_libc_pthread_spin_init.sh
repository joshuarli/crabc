#!/usr/bin/env bash
# Native Linux/x86-64 bounded static pthread_spin_init evidence.
#
# The same project-header fixture first runs against pinned musl 1.2.6, then
# as a true `-nostdlib -static` executable linked only with the selected crabc
# archive. It proves one source-faithful zero-store over valid caller-owned
# four-byte pthread_spinlock_t storage, for arbitrary input and pshared words.
# It does not select any other spin API, process sharing, synchronization,
# threads, TLS, errno, runtime, promotion, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly STATIC_C_ABI_EXPORTS="$ROOT_DIR/compat/x86_64/static_c_abi_exports.txt"
readonly EXECUTION_TIMEOUT=10s

fail() {
    printf 'ERROR: x86 static pthread_spin_init: %s\n' "$*" >&2
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
for tool in ar awk cargo cmp diff grep mkdir mktemp nm objdump readelf rustup sort timeout; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_pthread_spin_init_header_abi.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-pthread-spin-init.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cargo_target="$work_dir/cargo-target"
reference="$work_dir/musl-pthread-spin-init-reference"
candidate="$work_dir/crabc-static-pthread-spin-init-candidate"
archive="$cargo_target/x86_64-unknown-linux-musl/debug/libc.a"
archive_symbols="$work_dir/archive-symbols"
selected_symbols="$work_dir/selected-symbols"
expected_symbols="$work_dir/expected-symbols"
candidate_symbols="$work_dir/candidate-symbols"
candidate_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_relocations="$work_dir/candidate-relocations"
spin_disassembly="$work_dir/pthread-spin-init-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -pthread -fno-builtin -fno-stack-protector \
    -I"$ROOT_DIR/include" compat/x86_64/libc_pthread_spin_init_probe.c \
    -o "$reference"
if timeout "$EXECUTION_TIMEOUT" "$reference"; then
    :
else
    status=$?
    fail "pinned-musl pthread_spin_init fixture exited ${status}"
fi

CARGO_TARGET_DIR="$cargo_target" cargo rustc --locked -p crabc-libc --lib \
    --target x86_64-unknown-linux-musl -- \
    -C relocation-model=static -C code-model=small -C panic=abort
[ -f "$archive" ] || fail "cargo did not emit the x86 static libc archive"

nm -A --defined-only "$archive" >"$archive_symbols"
assert_selected_c_abi_surface "$archive" "$selected_symbols" "$expected_symbols"
grep -Eq "[[:space:]][TW][[:space:]]pthread_spin_init$" "$archive_symbols" ||
    fail "archive does not define pthread_spin_init"
for sibling in pthread_spin_destroy pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    if grep -Eq "[[:space:]]${sibling}$" "$archive_symbols"; then
        fail "archive unexpectedly defines unselected ${sibling}"
    fi
done
for marker in \
    'src/thread/pthread_spin_init.c::pthread_spin_init' \
    'return *s = 0;' \
    'shared argument is deliberately ignored' \
    'spin acquisition/release, destruction'; do
    grep -Fq "$marker" libc/src/c_abi/x86_64/pthread_spin_init.rs ||
        fail "pthread_spin_init source lacks ${marker}"
done
if grep -Eq 'use super|raw_syscall::|static_tls::|errno::|atomic::' \
    libc/src/c_abi/x86_64/pthread_spin_init.rs; then
    fail "pthread_spin_init source must not import a runtime seam"
fi

"$ORACLE_CC" -std=c11 -pthread -DCRABC_PTHREAD_SPIN_INIT_FREESTANDING \
    -I"$ROOT_DIR/include" -nostdlib -static -fno-pie -no-pie -ffreestanding \
    -fno-builtin -fno-stack-protector -Wl,-e,_start -Wl,--no-undefined \
    -Wl,--gc-sections compat/x86_64/libc_pthread_spin_init_probe.c \
    compat/x86_64/libc_pthread_spin_init_start.S "$archive" -o "$candidate"

readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic" || true
readelf --relocs --wide "$candidate" >"$candidate_relocations"
grep -Eq "[[:space:]]pthread_spin_init$" "$candidate_symbols" ||
    fail "candidate does not define pthread_spin_init"
for sibling in pthread_spin_destroy pthread_spin_lock pthread_spin_trylock pthread_spin_unlock; do
    if grep -Eq "[[:space:]]${sibling}$" "$candidate_symbols"; then
        fail "candidate pulled unselected ${sibling}"
    fi
done
unresolved_symbols="$(awk '$7 == "UND" && NF >= 8 { print }' "$candidate_symbols")"
if [ -n "$unresolved_symbols" ]; then
    printf '%s\n' "$unresolved_symbols" >&2
    fail "candidate retains an unresolved symbol"
fi
if grep -Eq 'Requesting program interpreter|INTERP' "$candidate_headers" ||
    grep -Eq 'NEEDED' "$candidate_dynamic"; then
    fail "candidate selected a dynamic runtime"
fi
if grep -Eq '[[:space:]]TLS[[:space:]]' "$candidate_headers" ||
    grep -Eq 'TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD(64)?|DTPOFF(32|64)?|__tls_get_addr' \
        "$candidate_relocations" "$candidate_symbols"; then
    fail "candidate must remain TLS-free"
fi
objdump -d --disassemble=pthread_spin_init "$candidate" >"$spin_disassembly"
if grep -Eq '[[:space:]](call|syscall)([[:space:]]|$)|%fs:' "$spin_disassembly"; then
    fail "pthread_spin_init must remain a direct helper-free record store"
fi
if grep -Eq 'crabc_core|mimalloc|sha_crypt|__errno_location' \
    "$candidate_symbols" "$spin_disassembly"; then
    fail "candidate selects an unowned runtime dependency"
fi

if timeout "$EXECUTION_TIMEOUT" "$candidate"; then
    :
else
    status=$?
    fail "freestanding pthread_spin_init fixture exited ${status}"
fi

printf 'x86 static crabc-libc pthread_spin_init: PASS\n'
