#!/usr/bin/env bash
# Source-only native Linux/x86-64 opaque `%fs:0` thread-pointer evidence.
#
# One fixed fixture runs against pinned musl 1.2.6's direct inline read and an
# isolated private Rust leaf. It proves only that opaque identity snapshot; it
# never selects `crabc-libc`, a public C ABI, pthread/TLS lifecycle, an ldso,
# CRT, or sysroot artifact.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly MUSL_LOADER=/opt/musl-1.2.6/lib/ld-musl-x86_64.so.1

fail() {
    printf 'ERROR: x86 thread-pointer source-only probe: %s\n' "$*" >&2
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

require_native_linux_x86_64
for tool in readelf objdump rustup; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-thread-pointer.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
object="$work_dir/thread-pointer.o"
reference="$work_dir/musl-thread-pointer-reference"
candidate="$work_dir/crabc-thread-pointer-candidate"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
object_disassembly="$work_dir/object-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_program_headers="$work_dir/candidate-program-headers"
candidate_dynamic="$work_dir/candidate-dynamic"
candidate_dynamic_symbols="$work_dir/candidate-dynamic-symbols"
candidate_disassembly="$work_dir/candidate-disassembly"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -no-pie -pthread -DCRABC_THREAD_POINTER_ORACLE \
    compat/x86_64/libc_thread_pointer_probe.c -o "$reference"
env -u LD_LIBRARY_PATH -u LD_PRELOAD "$reference"

rustup run nightly-2026-07-24 rustc --edition=2021 \
    --target x86_64-unknown-linux-musl \
    --crate-type=lib \
    --emit=obj \
    -C relocation-model=static \
    -C code-model=small \
    -C panic=abort \
    compat/x86_64/libc_thread_pointer_probe.rs \
    -o "$object"

# Save evidence before searching it so `pipefail` cannot turn an early grep
# close into a harmless producer SIGPIPE failure.
readelf --symbols --wide "$object" >"$object_symbols"
readelf --relocs --wide "$object" >"$object_relocations"
objdump -dr --disassemble=crabc_x86_64_thread_pointer_probe "$object" \
    >"$object_disassembly"

grep -Eq '[[:space:]]crabc_x86_64_thread_pointer_probe$' "$object_symbols" \
    || fail "object does not define its private fixture bridge"
if grep -Eq '(__tls_get_addr|__pthread_self|pthread_[[:alnum:]_]*|pthread_self|__errno_location|crabc_core|crabc_libc)' \
    "$object_symbols" "$object_relocations"; then
    fail "object depends on public pthread/errno, runtime, or TLS resolver state"
fi
if grep -Eq 'R_X86_64_(TPOFF|TLSGD|TLSLD|TLSDESC|GOTTPOFF|DTPMOD|DTPOFF)' \
    "$object_relocations"; then
    fail "object selected a TLS relocation instead of a literal FS word read"
fi
grep -Eq '%fs:0x0' "$object_disassembly" \
    || fail "object bridge does not directly read the x86 %fs:0 identity word"
if grep -Eq 'R_X86_64_|[[:space:]](call|callq|syscall|rdfsbase|wrfsbase|swapgs)([[:space:]]|$)' \
    "$object_disassembly"; then
    fail "object bridge has a relocation, call, syscall, or FS-base operation"
fi
if grep -Eq '[[:space:]](push|pop)[[:space:]]|[[:space:]](sub|add)[[:space:]].*%rsp' \
    "$object_disassembly"; then
    fail "object bridge unexpectedly uses stack storage"
fi

"$ORACLE_CC" -std=c11 -no-pie -pthread \
    compat/x86_64/libc_thread_pointer_probe.c "$object" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --program-headers --wide "$candidate" >"$candidate_program_headers"
readelf --dynamic --wide "$candidate" >"$candidate_dynamic"
readelf --dyn-syms --wide "$candidate" >"$candidate_dynamic_symbols"
objdump -dr --disassemble=crabc_x86_64_thread_pointer_probe "$candidate" \
    >"$candidate_disassembly"

grep -Eq '[[:space:]]crabc_x86_64_thread_pointer_probe$' "$candidate_symbols" \
    || fail "candidate does not define its private fixture bridge"
if grep -Eq '[[:space:]]crabc_x86_64_thread_pointer_probe$' "$candidate_dynamic_symbols"; then
    fail "candidate exposes its private fixture bridge dynamically"
fi
interpreter="$(sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p' "$candidate_program_headers")"
[ "$interpreter" = "$MUSL_LOADER" ] \
    || fail "candidate interpreter is ${interpreter:-missing}, not pinned musl"
grep -Fq 'Shared library: [libc.so]' "$candidate_dynamic" \
    || fail "candidate does not require pinned musl libc.so"
if grep -Eq 'libc\.so\.6|ld-linux|\((RPATH|RUNPATH)\)' "$candidate_dynamic"; then
    fail "candidate permits a glibc or search-path runtime dependency"
fi
if grep -Eq '(__tls_get_addr|__pthread_self|pthread_self|__errno_location)' \
    "$candidate_dynamic_symbols"; then
    fail "candidate dynamically depends on resolver, pthread-self, or errno state"
fi
grep -Eq '%fs:0x0' "$candidate_disassembly" \
    || fail "linked bridge does not directly read the x86 %fs:0 identity word"
if grep -Eq '[[:space:]](call|callq|syscall|rdfsbase|wrfsbase|swapgs)([[:space:]]|$)' \
    "$candidate_disassembly"; then
    fail "linked bridge has a call, syscall, or FS-base operation"
fi
if grep -Eq '[[:space:]](push|pop)[[:space:]]|[[:space:]](sub|add)[[:space:]].*%rsp' \
    "$candidate_disassembly"; then
    fail "linked bridge unexpectedly uses stack storage"
fi

env -u LD_LIBRARY_PATH -u LD_PRELOAD "$candidate"
printf 'x86 opaque thread-pointer source-only probe: PASS\n'
