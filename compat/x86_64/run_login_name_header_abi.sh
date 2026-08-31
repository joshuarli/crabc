#!/usr/bin/env bash
# Native Linux/x86-64 <unistd.h> login-name header ABI gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 login-name header ABI: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-login-name-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
c_probe="$ROOT_DIR/compat/x86_64/login_name_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/login_name_header_abi_probe.cpp"

for project in oracle project; do
    include_args=()
    [ "$project" = oracle ] || include_args=(-I "$ROOT_DIR/include")
    for profile in strict posix gnu bsd; do
        case "$profile" in
            strict) feature_args=(-U_GNU_SOURCE) ;;
            posix) feature_args=(-U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L) ;;
            gnu) feature_args=(-D_GNU_SOURCE) ;;
            bsd) feature_args=(-U_GNU_SOURCE -D_BSD_SOURCE) ;;
        esac
        "$ORACLE_CC" -std=c11 "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" -fno-builtin \
            "${include_args[@]}" -fsyntax-only "$cxx_probe"
    done

    object="$work_dir/$project.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
        -U_GNU_SOURCE -fno-builtin "${include_args[@]}" -c "$cxx_probe" \
        -o "$object"
    undefined="$(nm --undefined-only "$object")"
    for symbol in getlogin getlogin_r; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$project C++ witness lacks unmangled $symbol"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*getlogin'; then
        fail "$project C++ witness retained a mangled login-name reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ login-name header ABI: PASS\n'
