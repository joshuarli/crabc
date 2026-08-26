#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <sys/syscall.h> header slice.
#
# The project include tree is first. The pinned musl 1.2.6 compiler is the
# source-only declaration oracle: preprocessing must expose precisely the
# same complete __NR_* and SYS_* macro sets. No object is linked and this
# runner never selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly PROBE="$ROOT_DIR/compat/x86_64/x86_syscall_header_probe.c"

fail() {
	printf 'ERROR: x86 syscall header: %s\n' "$*" >&2
	exit 1
}

require_native_linux_x86_64() {
	[ "$(uname -s)" = Linux ] || fail "requires native Linux"
	case "$(uname -m)" in
		x86_64|amd64) ;;
		*) fail "refuses emulation on $(uname -m)" ;;
	esac
}

macro_surface() {
	awk '
		/^#define (__NR_|SYS_)/ {
			name = $2
			$1 = ""
			$2 = ""
			sub(/^[[:space:]]+/, "")
			print name "\t" $0
		}
	'
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

# Establish that this compiler, headers, loader, and libc come from the
# SHA-verified musl 1.2.6 tree before it is used as a declaration oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-syscall-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
reference_macros="$work_dir/musl-macros"
project_macros="$work_dir/project-macros"

# -H proves the angle-bracket include resolved both staged project headers;
# -fsyntax-only makes the source-only/no-libc boundary explicit.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$PROBE" \
	>/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/sys/syscall.h" "$header_trace" || {
	fail "probe did not use the project <sys/syscall.h>"
}
grep -Fq "$ROOT_DIR/include/bits/syscall.h" "$header_trace" || {
	fail "probe did not use the project x86 bits/syscall.h"
}

"$ORACLE_CC" -std=c11 -dM -E "$PROBE" | macro_surface | LC_ALL=C sort \
	>"$reference_macros"
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -dM -E "$PROBE" \
	| macro_surface | LC_ALL=C sort >"$project_macros"

[ "$(wc -l < "$reference_macros")" -eq 768 ] || {
	fail "pinned musl macro surface is not the expected 384 __NR_* plus 384 SYS_* names"
}
[ "$(wc -l < "$project_macros")" -eq 768 ] || {
	fail "project macro surface is not the expected 384 __NR_* plus 384 SYS_* names"
}
diff -u "$reference_macros" "$project_macros" || {
	fail "project x86 syscall macro surface diverges from pinned musl 1.2.6"
}

printf 'x86 pinned-musl <sys/syscall.h> macro header: PASS\n'
