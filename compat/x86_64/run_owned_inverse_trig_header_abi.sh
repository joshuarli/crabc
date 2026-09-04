#!/usr/bin/env bash
# Native Linux/x86-64 C++ declaration/linkage evidence for owned inverse trig.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly SYMBOLS=(asin acos atan atan2 asinf acosf atanf atan2f)

fail() { printf 'ERROR: x86 owned inverse-trig header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in grep mktemp nm realpath; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] || fail "requires repository-local TMPDIR"
checkout_physical="$(realpath -e "$ROOT_DIR")" || fail "cannot resolve checkout root"
tmpdir_physical="$(realpath -e "$TMPDIR")" || fail "cannot resolve TMPDIR"
case "$tmpdir_physical" in
	"$checkout_physical"/.work/*) ;;
	*) fail "TMPDIR physically escapes checkout .work: $tmpdir_physical" ;;
esac
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d "$TMPDIR/crabc-x86-owned-inverse-trig-header.XXXXXX")"
cleanup() {
	local status=$?
	trap - EXIT
	if [ "$status" -eq 0 ]; then
		rm -rf -- "$work_dir"
	else
		printf 'x86 owned inverse-trig header ABI: retained failure evidence at %s\n' "$work_dir" >&2
	fi
	exit "$status"
}
trap cleanup EXIT
probe="$ROOT_DIR/compat/x86_64/owned_inverse_trig_header_abi_probe.cpp"

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
		>/dev/null 2>"$trace" || { cat "$trace" >&2; fail "project ${mode} header provenance failed"; }
	for header in fenv.h float.h math.h features.h bits/alltypes.h; do
		grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
			fail "project ${mode} probe did not use <$header>"
	done
	for object in "$reference" "$candidate"; do
		undefined="$(nm --undefined-only "$object")"
		for symbol in "${SYMBOLS[@]}"; do
			printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
				fail "C++ ${mode} probe does not retain unmangled ${symbol}"
		done
		if printf '%s\n' "$undefined" | grep -Eq '_Z.*(asin|acos|atan)'; then
			fail "C++ ${mode} probe retained a mangled inverse-trigonometry reference"
		fi
	done
done

printf 'x86 pinned-musl/project owned inverse-trig header ABI: PASS\n'
