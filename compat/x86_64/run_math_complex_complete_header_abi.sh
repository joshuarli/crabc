#!/usr/bin/env bash
# Native Linux/x86-64 complete math.complex C++ declaration/linkage evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SYMBOLS=(
	cabs cabsf cabsl cacos cacosf cacosh cacoshf cacoshl cacosl carg cargf
	cargl casin casinf casinh casinhf casinhl casinl catan catanf catanh
	catanhf catanhl catanl ccos ccosf ccosh ccoshf ccoshl ccosl cexp cexpf
	cexpl cimag cimagf cimagl clog clogf clogl conj conjf conjl cpow cpowf
	cpowl cproj cprojf cprojl creal crealf creall csin csinf csinh csinhf
	csinhl csinl csqrt csqrtf csqrtl ctan ctanf ctanh ctanhf ctanhl ctanl
)

fail() { printf 'ERROR: x86 math.complex complete header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in grep mktemp nm; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-math-complex-complete-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$ROOT_DIR/compat/x86_64/math_complex_complete_header_abi_probe.cpp"

for mode in sse x87; do
	case "$mode" in sse) arguments=() ;; x87) arguments=(-mfpmath=387) ;; esac
	reference="$work_dir/musl-${mode}.o"
	candidate="$work_dir/project-${mode}.o"
	trace="$work_dir/project-${mode}-headers"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -c "$probe" -o "$reference"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -c "$probe" -o "$candidate"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$probe" \
		>/dev/null 2>"$trace" || fail "project ${mode} header provenance check failed"
	for header in complex.h float.h math.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
			fail "project ${mode} probe did not use <$header>"
	done
	for object in "$reference" "$candidate"; do
		undefined="$(nm --undefined-only "$object")"
		for symbol in "${SYMBOLS[@]}"; do
			printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
				fail "C++ ${mode} probe does not retain unmangled ${symbol}"
		done
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(cabs|cacos|carg|casin|catan|ccos|cexp|clog|conj|cpow|cproj|creal|csin|csqrt|ctan)'; then
			fail "C++ ${mode} probe retained a mangled math.complex reference"
		fi
	done
done

printf 'x86 pinned-musl/project complete math.complex header ABI: PASS\n'
