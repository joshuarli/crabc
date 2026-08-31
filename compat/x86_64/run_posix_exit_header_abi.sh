#!/usr/bin/env bash
# Native Linux/x86-64 POSIX <unistd.h> _exit ABI slice.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. Both C11 and
# C++ require the unconditional `_exit(int)` declaration; this compile-only
# gate selects no C11 immediate-termination implementation, ordinary exit,
# CRT, or runtime-state claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 unistd.h POSIX _exit ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/posix_exit_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/posix_exit_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-posix-exit-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-posix-exit-cxx.o"
candidate_cxx_object="$work_dir/candidate-posix-exit-cxx.o"

for include_args in "" "-I $ROOT_DIR/include"; do
    # shellcheck disable=SC2086 # candidate branch intentionally expands one include pair.
    "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -fno-builtin $include_args \
        -fsyntax-only "$c_probe"
    # shellcheck disable=SC2086 # candidate branch intentionally expands one include pair.
    "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -fno-builtin $include_args \
        -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C POSIX _exit header contract drifted"
fi
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || {
        fail "C probe did not use the project <$header>"
    }
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]_exit$' || {
        fail "C++ probe does not retain C linkage for _exit"
    }
    if printf '%s\n' "$undefined" | grep -Eq '_Z5_exiti'; then
        fail "C++ probe retained a mangled _exit reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> POSIX _exit ABI: PASS\n'
