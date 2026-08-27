#!/usr/bin/env bash
# Source-only native Linux/x86-64 C-runtime primitive-composition evidence.
#
# The same focused fixture runs against pinned musl 1.2.6 and a single
# isolated crabc object. It proves only the narrow syscall-to-errno composition
# plus coexistence of the independently-proved memory/fenv leaves; it never
# selects crabc-libc, an ldso, CRT, sysroot, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
	printf 'ERROR: x86 C runtime foundation probe: %s\n' "$*" >&2
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
require_tool cc
require_tool readelf
require_tool objdump
require_tool rustup
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-c-foundation.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
object="$work_dir/foundation.o"
reference="$work_dir/musl-foundation-reference"
candidate="$work_dir/crabc-foundation-candidate"
header_trace="$work_dir/header-trace"
object_symbols="$work_dir/object-symbols"
object_relocations="$work_dir/object-relocations"
object_disassembly="$work_dir/object-disassembly"
candidate_symbols="$work_dir/candidate-symbols"
candidate_dynamic_symbols="$work_dir/candidate-dynamic-symbols"

cd "$ROOT_DIR"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_FOUNDATION_ORACLE=1 -fno-builtin \
	compat/x86_64/libc_foundation_probe.c -o "$reference"
"$reference"

cc -E -H -D_GNU_SOURCE -I"$ROOT_DIR/include" \
	compat/x86_64/libc_foundation_probe.c >/dev/null 2>"$header_trace"
for header in errno.h fenv.h string.h sys/syscall.h; do
	grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
		|| fail "candidate fixture did not use the project $header header"
done

rustup run nightly-2026-07-24 rustc --edition=2021 \
	--target x86_64-unknown-linux-musl \
	--crate-type=lib \
	--emit=obj \
	-C relocation-model=static \
	-C code-model=small \
	-C panic=abort \
	compat/x86_64/libc_foundation_probe.rs \
	-o "$object"

# Save tables before searches so pipefail cannot turn a harmless producer
# SIGPIPE into a flaky assertion failure.
readelf --symbols --wide "$object" >"$object_symbols"
readelf --relocs --wide "$object" >"$object_relocations"
objdump -d "$object" >"$object_disassembly"

for symbol in crabc_x86_64_foundation_syscall6 __errno_location memcpy memmove memset feclearexcept \
	feraiseexcept fegetenv fesetenv fetestexcept; do
	grep -Eq "[[:space:]]${symbol}$" "$object_symbols" \
		|| fail "object does not define ${symbol}"
done
if grep -Eq '[[:space:]]syscall$' "$object_symbols"; then
	fail "foundation object must not export the public variadic syscall symbol"
fi
grep -Eq 'R_X86_64_TPOFF(32|64)?' "$object_relocations" \
	|| fail "foundation errno does not use initial-TLS TPOFF relocation"
if grep -Eq 'crabc_core|crabc_libc|__tls_get_addr' "$object_relocations"; then
	fail "foundation object depends on a runtime artifact or dynamic TLS"
fi
for instruction in syscall fnstenv; do
	grep -Eq "[[:space:]]${instruction}([[:space:]]|$)" "$object_disassembly" \
		|| fail "object lacks ${instruction}"
done
for instruction in 'rep[[:space:]]+movs' 'rep[[:space:]]+stos'; do
	grep -Eq "$instruction" "$object_disassembly" \
		|| fail "object lacks ${instruction}"
done

cc -no-pie -fno-builtin -D_GNU_SOURCE -I"$ROOT_DIR/include" \
	compat/x86_64/libc_foundation_probe.c "$object" -o "$candidate"
readelf --symbols --wide "$candidate" >"$candidate_symbols"
readelf --dyn-syms --wide "$candidate" >"$candidate_dynamic_symbols"
for symbol in crabc_x86_64_foundation_syscall6 __errno_location memcpy memmove memset feclearexcept \
	feraiseexcept fegetenv fesetenv fetestexcept; do
	grep -Eq "[[:space:]]${symbol}$" "$candidate_symbols" \
		|| fail "candidate does not define ${symbol}"
done
if grep -Eq '[[:space:]]UND[[:space:]].*(crabc_x86_64_foundation_syscall6|__errno_location|memcpy|memmove|memset|feclear|feraise|feget|feset|fetest)' \
	"$candidate_dynamic_symbols"; then
	fail "candidate leaves a foundation symbol to the ambient C runtime"
fi
"$candidate"

printf 'x86 C runtime foundation probe: PASS\n'
