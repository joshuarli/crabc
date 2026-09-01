#!/usr/bin/env bash
# Native Linux/x86-64 C11/C++17 fixed-locale narrow text ABI gate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/locale_narrow_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/locale_narrow_header_abi_probe.cpp"

fail() { printf 'ERROR: x86 narrow-locale header ABI: %s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null 2>&1 || fail "requires $1"; }

[ "$#" -eq 0 ] || fail "usage: $0"
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
for tool in c++ grep mktemp nm sort; do require_tool "$tool"; done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-locale-narrow-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

oracle_c="$work_dir/oracle-c.o"
project_c="$work_dir/project-c.o"
oracle_cxx="$work_dir/oracle-cxx.o"
project_cxx="$work_dir/project-cxx.o"

"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -nostdinc \
    -isystem /opt/musl-1.2.6/include -c "$C_PROBE" -o "$oracle_c"
"$ORACLE_CC" -std=c11 -D_XOPEN_SOURCE=700 -nostdinc \
    -isystem "$ROOT_DIR/include" -c "$C_PROBE" -o "$project_c"
c++ -std=c++17 -D_XOPEN_SOURCE=700 -nostdinc -nostdinc++ \
    -isystem /opt/musl-1.2.6/include -c "$CXX_PROBE" -o "$oracle_cxx"
c++ -std=c++17 -D_XOPEN_SOURCE=700 -nostdinc -nostdinc++ \
    -isystem "$ROOT_DIR/include" -c "$CXX_PROBE" -o "$project_cxx"

for object in "$oracle_cxx" "$project_cxx"; do
    undefined="$work_dir/$(basename "$object").undefined"
    nm -u "$object" | awk '{ print $NF }' | sort -u >"$undefined"
    for symbol in isalnum_l isalpha_l isblank_l iscntrl_l isdigit_l \
        isgraph_l islower_l isprint_l ispunct_l isspace_l isupper_l \
        isxdigit_l tolower_l toupper_l strcasecmp strcasecmp_l strncasecmp \
        strncasecmp_l strcoll strcoll_l strxfrm strxfrm_l; do
        grep -Fxq "$symbol" "$undefined" || fail "C++ object lacks unmangled $symbol"
    done
    if grep -Eq '^_Z' "$undefined"; then
        fail "C++ narrow-locale probe retained a mangled reference"
    fi
done

# Pinned musl keeps only the two narrow string `_l` declarations visible in
# strict C/C++; the broader locale-object and ctype vocabulary remains gated.
# Exercise that exact small strict profile without falsely widening this
# X/Open aggregate probe.
strict_oracle_c="$work_dir/strict-oracle-c.o"
strict_project_c="$work_dir/strict-project-c.o"
strict_oracle_cxx="$work_dir/strict-oracle-cxx.o"
strict_project_cxx="$work_dir/strict-project-cxx.o"
"$ORACLE_CC" -std=c11 -DCRABC_REQUIRE_STRICT_STRING_LOCALE -nostdinc \
    -isystem /opt/musl-1.2.6/include -c "$C_PROBE" -o "$strict_oracle_c"
"$ORACLE_CC" -std=c11 -DCRABC_REQUIRE_STRICT_STRING_LOCALE -nostdinc \
    -isystem "$ROOT_DIR/include" -c "$C_PROBE" -o "$strict_project_c"
c++ -std=c++17 -DCRABC_REQUIRE_STRICT_STRING_LOCALE -nostdinc -nostdinc++ \
    -isystem /opt/musl-1.2.6/include -c "$CXX_PROBE" -o "$strict_oracle_cxx"
c++ -std=c++17 -DCRABC_REQUIRE_STRICT_STRING_LOCALE -nostdinc -nostdinc++ \
    -isystem "$ROOT_DIR/include" -c "$CXX_PROBE" -o "$strict_project_cxx"
for object in "$strict_oracle_cxx" "$strict_project_cxx"; do
    undefined="$work_dir/$(basename "$object").undefined"
    nm -u "$object" | awk '{ print $NF }' | sort -u >"$undefined"
    for symbol in strcasecmp_l strncasecmp_l; do
        grep -Fxq "$symbol" "$undefined" ||
            fail "strict C++ object lacks unmangled $symbol"
    done
    if grep -Eq '^_Z' "$undefined"; then
        fail "strict C++ narrow-locale probe retained a mangled reference"
    fi
done

printf 'x86 pinned-musl/project fixed-locale narrow text header ABI: PASS\n'
