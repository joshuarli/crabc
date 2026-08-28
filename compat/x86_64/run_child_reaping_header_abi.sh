#!/usr/bin/env bash
# Native Linux/x86-64 <sys/wait.h> child-reaping ABI slice.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. `wait` and
# `waitpid` are always declared by musl; `waitid`/`siginfo_t` are compared
# under POSIX feature selection. The project header currently keeps waitid
# visible more broadly, an existing deliberate header-surface divergence that
# this artifact does not promote into a general x86 header-completion claim.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/wait.h child reaping ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/child_reaping_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/child_reaping_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-child-reaping-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-child-reaping-cxx.o"
candidate_cxx_object="$work_dir/candidate-child-reaping-cxx.o"

# Musl declares wait/waitpid in strict C and C++; the selected POSIX pass adds
# waitid plus its siginfo_t record contract on both headers.
for selector in strict posix; do
    case "$selector" in
        strict)
            compiler_args=()
            ;;
        posix)
            compiler_args=(-D_POSIX_C_SOURCE=200809L -DCRABC_CHILD_REAPING_POSIX)
            ;;
    esac
    "$ORACLE_CC" -std=c11 "${compiler_args[@]}" -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${compiler_args[@]}" -U_GNU_SOURCE \
        -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "${compiler_args[@]}" -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${compiler_args[@]}" -U_GNU_SOURCE \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_CHILD_REAPING_POSIX -fno-builtin -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C child-reaping header contract drifted"
fi
for header in sys/wait.h sys/types.h signal.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || {
        fail "C probe did not use the project <$header>"
    }
done

# C++ references must retain C names, not merely compatible function types.
for output_args in \
    "oracle:$oracle_cxx_object:" \
    "candidate:$candidate_cxx_object:-I $ROOT_DIR/include"; do
    IFS=: read -r kind object include_args <<<"$output_args"
    # shellcheck disable=SC2086 # the candidate branch intentionally has one include pair.
    "$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
        -DCRABC_CHILD_REAPING_POSIX -U_GNU_SOURCE -fno-builtin $include_args \
        -c "$cxx_probe" -o "$object"
done
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in wait waitpid waitid; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" || {
            fail "C++ probe does not retain C linkage for ${symbol}"
        }
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z(4wait|7waitpid|6waitid)'; then
        fail "C++ probe retained a mangled child-reaping reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/wait.h> child reaping ABI: PASS\n'
