#!/usr/bin/env bash
# Native Linux/x86-64 C++17 GNU declaration/linkage evidence for binary80
# fdiml/exp10l/pow10l. Pinned musl is the declaration oracle; project headers
# are first only in the candidate pass.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SYMBOLS=(fdiml exp10l pow10l)

fail() { printf 'ERROR: x86 binary80 fdiml/exp10l/pow10l header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in grep mktemp nm; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-math-long-double-completion-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$ROOT_DIR/compat/x86_64/math_long_double_completion_header_abi_probe.cpp"

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
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(fdiml|exp10l|pow10l)'; then
			fail "C++ ${mode} probe retained a mangled binary80 math reference"
		fi
	done
done

printf 'x86 pinned-musl/project GNU binary80 fdiml/exp10l/pow10l header ABI: PASS\n'
