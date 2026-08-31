#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ ttyname_r declaration gate.
#
# Pinned musl 1.2.6 is the unconditional <unistd.h> declaration and C-linkage
# oracle. The project-header pass selects neither terminal naming behavior nor
# a static archive result; its direct archive proof is separate.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 unistd.h ttyname_r ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "requires native x86-64" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/ttyname_r_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ttyname_r_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ttyname-r-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-ttyname-r-cxx.o"
candidate_cxx_object="$work_dir/candidate-ttyname-r-cxx.o"

# Musl declares ttyname_r independently of the ordinary strict/POSIX/XSI/GNU/
# BSD selector profiles. Keep each profile explicit rather than assuming a
# host default feature macro.
for selector in '' -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L \
    -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    "$ORACLE_CC" -std=c11 $selector -fno-builtin -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ $selector -fno-builtin -fsyntax-only \
        "$cxx_probe"
    "$ORACLE_CC" -std=c11 $selector -fno-builtin -I "$ROOT_DIR/include" \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ $selector -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C ttyname_r header contract drifted"
fi
for header in unistd.h sys/types.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -fno-builtin -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ttyname_r$' ||
        fail "C++ probe does not retain C linkage for ttyname_r"
    if printf '%s\n' "$undefined" | grep -Eq '_Z9ttyname_riPcm'; then
        fail "C++ probe retained a mangled ttyname_r reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> ttyname_r ABI: PASS\n'
