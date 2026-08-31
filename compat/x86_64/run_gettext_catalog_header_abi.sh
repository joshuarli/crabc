#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <libintl.h>/<nl_types.h> ABI declaration evidence.
#
# Pinned musl 1.2.6 is the declaration oracle. All twelve selected declarations
# are unconditional under musl's default, strict, POSIX, XOPEN, BSD, and GNU
# profiles. The C++ object check ratchets unmangled C linkage for both header
# families, including the catalog declarations in <nl_types.h>.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 gettext/catalog header ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/gettext_catalog_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/gettext_catalog_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-gettext-catalog-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_profile() {
    local -a definitions=("$@")
    local variant
    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$cxx_probe"
    done
}

compile_profile
compile_profile -D__STRICT_ANSI__
compile_profile -D_POSIX_C_SOURCE=200809L
compile_profile -D_XOPEN_SOURCE=700
compile_profile -D_BSD_SOURCE
compile_profile -D_GNU_SOURCE

"$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"
for header in libintl.h nl_types.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-gettext-catalog-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
        "${include_args[@]}" -c "$cxx_probe" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    for symbol in bind_textdomain_codeset bindtextdomain catclose catgets catopen \
        dcgettext dcngettext dgettext dngettext gettext ngettext textdomain; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "C++ probe does not retain C linkage for ${symbol} (${variant})"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*(gettext|textdomain|catopen|catclose|catgets)'; then
        fail "C++ probe retained a mangled gettext/catalog reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ gettext/catalog header ABI: PASS\n'
