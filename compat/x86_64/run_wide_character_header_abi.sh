#!/usr/bin/env bash
# Native Linux/x86-64 selected <wchar.h>/<wctype.h> C11/C++17 ABI gate.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/wide_character_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/wide_character_header_abi_probe.cpp"
readonly -a SYMBOLS=(
    wcslen wcsnlen wcscpy wcsncpy wcpcpy wcpncpy wcscat wcsncat
    wcscmp wcsncmp wcschr wcsrchr wcsstr wcscspn wcsspn wcspbrk
    wcsxfrm wcscoll wcstok wcscasecmp wcsncasecmp
    wmemchr wmemcmp wmemcpy wmemmove wmemset wcwidth wcswidth
    iswalnum iswalpha iswblank iswcntrl iswdigit iswgraph iswlower
    iswprint iswpunct iswspace iswupper iswxdigit iswctype wctype
    towlower towupper towctrans wctrans
)

fail() { printf 'ERROR: x86 wide-character header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }
run_compiler() {
    local compiler="$1"; shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$compiler" "$@"
}

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in awk env grep mktemp nm realpath sed uname; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
builtin_include="$(realpath "$builtin_include")"
[ -d "$builtin_include" ] || fail "missing compiler builtin include directory"
work_dir="$(mktemp -d /tmp/crabc-x86-64-wide-character-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for tree in reference candidate; do
    if [ "$tree" = reference ]; then
        compiler="$ORACLE_CC"
        include_root="$MUSL_ROOT/include"
    else
        compiler="$CANDIDATE_CC"
        include_root="$ROOT_DIR/include"
    fi
    c_trace="$work_dir/$tree-c.trace"
    cxx_trace="$work_dir/$tree-cxx.trace"
    cxx_object="$work_dir/$tree-cxx.o"
    run_compiler "$compiler" -x c -std=c11 -D_XOPEN_SOURCE=700 -nostdinc \
        -I "$include_root" -isystem "$builtin_include" -H -fno-builtin \
        -fsyntax-only "$C_PROBE" >/dev/null 2>"$c_trace" || {
            sed -n '1,160p' "$c_trace" >&2
            fail "$tree C11 declaration probe failed"
        }
    run_compiler "$compiler" -x c++ -std=c++17 -D_XOPEN_SOURCE=700 \
        -nostdinc -nostdinc++ -I "$include_root" -isystem "$builtin_include" \
        -H -fno-builtin -c "$CXX_PROBE" -o "$cxx_object" \
        >/dev/null 2>"$cxx_trace" || {
            sed -n '1,160p' "$cxx_trace" >&2
            fail "$tree C++17 declaration probe failed"
        }
    for trace in "$c_trace" "$cxx_trace"; do
        for header in wchar.h wctype.h features.h bits/alltypes.h; do
            grep -Fq "$include_root/$header" "$trace" ||
                fail "$tree did not preprocess $include_root/$header"
        done
        if sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$trace" |
            grep -Ev "^($include_root|$builtin_include)/" | grep -q .; then
            fail "$tree trace escaped its declared header roots"
        fi
    done
    undefined="$(nm --undefined-only "$cxx_object" | awk '{print $NF}')"
    for symbol in "${SYMBOLS[@]}"; do
        printf '%s\n' "$undefined" | grep -Fxq "$symbol" ||
            fail "$tree C++ object lost C linkage for $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '^_Z.*(wcs|wmem|isw|tow|wct)'; then
        fail "$tree C++ object retains a mangled selected reference"
    fi
    printf 'PASS: %s/C11+C++17\n' "$tree"
done

printf 'x86 wide-character header ABI: PASS\n'
