#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <fcntl.h> ABI slice.
#
# Pinned musl 1.2.6 is the declaration/value/layout oracle. The project
# headers are then placed first; neither pass links or selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 fcntl.h ABI: %s\n' "$*" >&2
    exit 1
}

assert_cxx_posix_fallocate_linkage() {
    local object="$1"
    local profile="$2"
    local undefined

    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]posix_fallocate$' ||
        fail "$profile C++ probe does not retain C linkage for posix_fallocate"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*posix_fallocate'; then
        fail "$profile C++ probe retains a mangled posix_fallocate reference"
    fi
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/fcntl_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/fcntl_header_abi_probe.cpp"
strict_c_probe="$ROOT_DIR/compat/x86_64/fcntl_posix_fallocate_strict_probe.c"
strict_cxx_probe="$ROOT_DIR/compat/x86_64/fcntl_posix_fallocate_strict_probe.cpp"
largefile_c_probe="$ROOT_DIR/compat/x86_64/fcntl_posix_fallocate_largefile64_probe.c"
largefile_cxx_probe="$ROOT_DIR/compat/x86_64/fcntl_posix_fallocate_largefile64_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-fcntl-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
strict_cxx_oracle_object="$work_dir/strict-cxx-oracle.o"
strict_cxx_project_object="$work_dir/strict-cxx-project.o"
largefile_cxx_oracle_object="$work_dir/largefile-cxx-oracle.o"
largefile_cxx_project_object="$work_dir/largefile-cxx-project.o"

"$ORACLE_CC" -std=c11 -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -fsyntax-only "$strict_c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -fno-builtin -c \
    "$strict_cxx_probe" -o "$strict_cxx_oracle_object"
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -fsyntax-only "$largefile_c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -fno-builtin -c \
    "$largefile_cxx_probe" -o "$largefile_cxx_oracle_object"

# `-H` makes candidate provenance observable instead of merely compiling
# against whichever system header happens to be installed.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/fcntl.h" "$header_trace" || {
    fail "C probe did not use the project <fcntl.h>"
}
grep -Fq "$ROOT_DIR/include/features.h" "$header_trace" || {
    fail "C probe did not use the project <features.h>"
}
grep -Fq "$ROOT_DIR/include/bits/fcntl.h" "$header_trace" || {
    fail "C probe did not use the project <bits/fcntl.h>"
}
"$ORACLE_CC" -std=c++17 -x c++ -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -I "$ROOT_DIR/include" -fsyntax-only "$strict_c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -I "$ROOT_DIR/include" \
    -fno-builtin -c "$strict_cxx_probe" -o "$strict_cxx_project_object"
"$ORACLE_CC" -std=c11 -U_GNU_SOURCE -I "$ROOT_DIR/include" -fsyntax-only "$largefile_c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -I "$ROOT_DIR/include" \
    -fno-builtin -c "$largefile_cxx_probe" -o "$largefile_cxx_project_object"

assert_cxx_posix_fallocate_linkage "$strict_cxx_oracle_object" "strict oracle"
assert_cxx_posix_fallocate_linkage "$strict_cxx_project_object" "strict project"
assert_cxx_posix_fallocate_linkage "$largefile_cxx_oracle_object" "large-file oracle"
assert_cxx_posix_fallocate_linkage "$largefile_cxx_project_object" "large-file project"

printf 'x86 pinned-musl C/C++ <fcntl.h> ABI: PASS\n'
