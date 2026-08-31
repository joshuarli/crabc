#!/usr/bin/env bash
# Native Linux/x86-64 usleep C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The candidate
# pass puts project headers first. This compile-only boundary proves only the
# historical `int usleep(unsigned int)` spelling and its GNU/BSD/XOPEN<700
# selectors; it selects no sleep policy, timer state, or signal delivery.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 unistd.h usleep ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/usleep_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/usleep_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-usleep-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-usleep-cxx.o"
candidate_cxx_object="$work_dir/candidate-usleep-cxx.o"

default_definitions=()
strict_definitions=(-D__STRICT_ANSI__)
posix_definitions=(-D_POSIX_C_SOURCE=200809L)
xopen_700_definitions=(-D_XOPEN_SOURCE=700)
xopen_600_definitions=(-D_XOPEN_SOURCE=600 -DCRABC_EXPECT_USLEEP)
bsd_definitions=(-D_BSD_SOURCE -DCRABC_EXPECT_USLEEP)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_USLEEP)

for definitions_name in default_definitions strict_definitions posix_definitions \
    xopen_700_definitions xopen_600_definitions bsd_definitions gnu_definitions; do
    declare -n definitions="$definitions_name"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${definitions[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# -H makes project-header provenance observable rather than merely compiling
# against whichever host unistd.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project GNU usleep header contract drifted"
fi
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ "${gnu_definitions[@]}" \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]usleep$' ||
        fail "C++ probe does not retain C linkage for usleep"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*usleep'; then
        fail "C++ probe retained a mangled usleep reference"
    fi
done

# The selector is exact: GNU/BSD and XOPEN=600 expose usleep, while default,
# strict, POSIX.1-2008, and XOPEN=700 do not. -U_GNU_SOURCE prevents a C++
# toolchain environment from widening the header profile behind this test.
for definitions_name in default_definitions strict_definitions posix_definitions \
    xopen_700_definitions; do
    declare -n definitions="$definitions_name"
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_USLEEP_HIDDEN -fsyntax-only "$c_probe" \
        >"$work_dir/oracle-c-${definitions_name}.out" 2>&1; then
        fail "pinned musl exposes usleep outside its selected C profiles"
    fi
    if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
        "${definitions[@]}" -DCRABC_REQUIRE_USLEEP_HIDDEN \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe" \
        >"$work_dir/project-c-${definitions_name}.out" 2>&1; then
        fail "project unistd.h exposes usleep outside its selected C profiles"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
        -DCRABC_REQUIRE_USLEEP_HIDDEN -fsyntax-only "$cxx_probe" \
        >"$work_dir/oracle-cxx-${definitions_name}.out" 2>&1; then
        fail "pinned musl exposes usleep outside its selected C++ profiles"
    fi
    if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
        -DCRABC_REQUIRE_USLEEP_HIDDEN -I "$ROOT_DIR/include" \
        -fsyntax-only "$cxx_probe" \
        >"$work_dir/project-cxx-${definitions_name}.out" 2>&1; then
        fail "project unistd.h exposes usleep outside its selected C++ profiles"
    fi
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> usleep ABI: PASS\n'
