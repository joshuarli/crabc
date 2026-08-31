#!/usr/bin/env bash
# Native Linux/x86-64 complete math.special C++ declaration/linkage evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SYMBOLS=(
	__fpclassify __fpclassifyf __fpclassifyl __lgammal_r __signbit __signbitf
	__signbitl drem dremf erf erfc erfcf erfcl erff erfl finite finitef frexp
	frexpf frexpl ilogb ilogbf ilogbl j0 j0f j1 j1f jn jnf ldexp ldexpf
	ldexpl lgamma lgamma_r lgammaf lgammaf_r lgammal lgammal_r llrint llrintf
	llrintl llround llroundf llroundl logb logbf logbl lrint lrintf lrintl
	lround lroundf lroundl modf modff modfl nan nanf nanl nextafter nextafterf
	nextafterl nexttoward nexttowardf nexttowardl remainder remainderf
	remainderl remquo remquof remquol scalb scalbf scalbln scalblnf scalblnl
	scalbn scalbnf scalbnl significand significandf tgamma tgammaf tgammal y0
	y0f y1 y1f yn ynf signgam
)

fail() { printf 'ERROR: x86 math.special header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in grep mktemp nm; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-math-special-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$ROOT_DIR/compat/x86_64/math_special_header_abi_probe.cpp"

for mode in sse x87; do
	case "$mode" in sse) arguments=() ;; x87) arguments=(-mfpmath=387) ;; esac
	reference="$work_dir/musl-${mode}.o"
	candidate="$work_dir/project-${mode}.o"
	trace="$work_dir/project-${mode}-headers"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -c "$probe" -o "$reference"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -c "$probe" -o "$candidate"
	if ! "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$probe" \
		>/dev/null 2>"$trace"; then
		cat "$trace" >&2
		fail "project ${mode} header provenance check failed"
	fi
	for header in float.h math.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
			fail "project ${mode} probe did not use <$header>"
	done
	for object in "$reference" "$candidate"; do
		undefined="$(nm --undefined-only "$object")"
		for symbol in "${SYMBOLS[@]}"; do
			printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
				fail "C++ ${mode} probe does not retain unmangled ${symbol}"
		done
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(erf|lgamma|tgamma|nexttoward|remquo|scalbn|j[01n]|y[01n])'; then
			fail "C++ ${mode} probe retained a mangled math.special reference"
		fi
	done
done

printf 'x86 pinned-musl/project math.special header ABI: PASS\n'
