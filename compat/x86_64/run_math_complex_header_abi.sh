#!/usr/bin/env bash
# Native Linux/x86-64 <math.h>/<complex.h>/<tgmath.h> ABI-header evidence.
#
# Pinned musl 1.2.6 is the declaration, feature-macro, type-generic, and C++
# linkage oracle. Project headers are first in the candidate pass, but both
# executables intentionally link pinned musl's math runtime: this closes only
# header semantics, not crabc-libc math implementation or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
	printf 'ERROR: x86 math/complex header ABI: %s\n' "$*" >&2
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
for tool in grep mktemp nm; do
	require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-math-complex-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
c_probe="$ROOT_DIR/compat/x86_64/math_complex_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/math_complex_header_abi_probe.cpp"

for mode in sse x87; do
	case "$mode" in
		sse) arguments=() ;;
		x87) arguments=(-mfpmath=387) ;;
	esac
	reference="$work_dir/musl-${mode}"
	candidate="$work_dir/project-${mode}"
	oracle_cxx="$work_dir/musl-${mode}.o"
	candidate_cxx="$work_dir/project-${mode}.o"
	header_trace="$work_dir/project-${mode}-headers"
	cxx_header_trace="$work_dir/project-${mode}-cxx-headers"

	"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin "${arguments[@]}" \
		"$c_probe" -lm -o "$reference"
	"$reference" || fail "pinned musl ${mode} C header behavior drifted"
	"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin "${arguments[@]}" \
		-I "$ROOT_DIR/include" "$c_probe" -lm -o "$candidate"
	"$candidate" || fail "project ${mode} C header behavior diverged from pinned musl"

	if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin "${arguments[@]}" \
		-I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
		>/dev/null 2>"$header_trace"; then
		cat "$header_trace" >&2
		fail "project ${mode} C header provenance check failed"
	fi
	for header in complex.h float.h math.h tgmath.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
			fail "project ${mode} C probe did not use <$header>"
	done

	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -c "$cxx_probe" -o "$oracle_cxx"
	"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -c "$cxx_probe" \
		-o "$candidate_cxx"
	if ! "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
		"${arguments[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$cxx_probe" \
		>/dev/null 2>"$cxx_header_trace"; then
		cat "$cxx_header_trace" >&2
		fail "project ${mode} C++ header provenance check failed"
	fi
	for header in complex.h float.h math.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$cxx_header_trace" ||
			fail "project ${mode} C++ probe did not use <$header>"
	done
	for object in "$oracle_cxx" "$candidate_cxx"; do
		undefined="$(nm --undefined-only "$object")"
		for symbol in __fpclassify __fpclassifyf __fpclassifyl __signbit \
			__signbitf __signbitl creal crealf creall cimag cimagf cimagl \
			conj conjf conjl acosl asinl atanl atan2l ceill exp2l expl expm1l \
			fabsl floorl fmodl log10l log1pl log2l logl lrintl llrintl rintl \
			remainderl remquol sqrtl truncl; do
			printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
				fail "C++ ${mode} probe does not retain unmangled ${symbol}"
		done
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(creal|cimag|conj|fpclassifyl|signbitl|acosl|exp2l|remquol|sqrtl)'; then
			fail "C++ ${mode} probe retained a mangled math/complex reference"
		fi
	done
done

printf 'x86 pinned-musl/project math, complex, and tgmath header ABI: PASS\n'
