#!/usr/bin/env bash
# Native Linux/x86-64 ctermid C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. The candidate
# pass places project headers first. This compile-only boundary selects neither
# terminal I/O nor static-archive linkage by itself.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 stdio.h ctermid ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/ctermid_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/ctermid_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-ctermid-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
unistd_header_trace="$work_dir/unistd-header-trace"
oracle_cxx_object="$work_dir/oracle-ctermid-cxx.o"
candidate_cxx_object="$work_dir/candidate-ctermid-cxx.o"
oracle_unistd_cxx_object="$work_dir/oracle-unistd-ctermid-cxx.o"
candidate_unistd_cxx_object="$work_dir/candidate-unistd-ctermid-cxx.o"

for selector in -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_CTERMID -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_CTERMID \
        -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_EXPECT_CTERMID -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_EXPECT_CTERMID \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_CTERMID -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C ctermid header contract drifted"
fi
for header in stdio.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_CTERMID -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_CTERMID -fno-builtin -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ctermid$' ||
        fail "C++ probe does not retain C linkage for ctermid"
    if printf '%s\n' "$undefined" | grep -Eq '_Z7ctermidPc'; then
        fail "C++ probe retained a mangled ctermid reference"
    fi
done

# Pinned musl hides ctermid and L_ctermid in strict stdio.h, but its separate
# strict unistd.h declaration remains visible. Check those independently so a
# transitive header inventory cannot mask either feature-test boundary.
for language in c cxx; do
    case "$language" in
        c)
            compiler_args=(-std=c11)
            probe="$c_probe"
            ;;
        cxx)
            compiler_args=(-std=c++17 -x c++)
            probe="$cxx_probe"
            ;;
    esac
    if "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_CTERMID_HIDDEN -fno-builtin -fsyntax-only "$probe" \
        >/dev/null 2>"$work_dir/oracle-${language}-hidden-errors"; then
        fail "pinned musl exposes ctermid in strict stdio.h ${language}"
    fi
    if "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_CTERMID_HIDDEN -fno-builtin -I "$ROOT_DIR/include" \
        -fsyntax-only "$probe" \
        >/dev/null 2>"$work_dir/project-${language}-hidden-errors"; then
        fail "project stdio.h exposes ctermid in strict ${language}"
    fi

    "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_L_CTERMID_HIDDEN -fno-builtin -fsyntax-only "$probe"
    "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE \
        -DCRABC_REQUIRE_L_CTERMID_HIDDEN -fno-builtin -I "$ROOT_DIR/include" \
        -fsyntax-only "$probe"
done

"$ORACLE_CC" -std=c11 -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -fsyntax-only "$cxx_probe"
"$ORACLE_CC" -std=c11 -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
"$ORACLE_CC" -std=c++17 -x c++ -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"

for selector in -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_CTERMID_FROM_UNISTD \
        -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "$selector" -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "$selector" -DCRABC_CTERMID_FROM_UNISTD \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$unistd_header_trace"; then
    sed -n '1,160p' "$unistd_header_trace" >&2
    fail "project strict unistd.h ctermid contract drifted"
fi
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$unistd_header_trace" ||
        fail "strict C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -c "$cxx_probe" -o "$oracle_unistd_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -DCRABC_CTERMID_FROM_UNISTD -fno-builtin \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_unistd_cxx_object"
for object in "$oracle_unistd_cxx_object" "$candidate_unistd_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]ctermid$' ||
        fail "strict C++ unistd.h probe does not retain C linkage for ctermid"
    if printf '%s\n' "$undefined" | grep -Eq '_Z7ctermidPc'; then
        fail "strict C++ unistd.h probe retained a mangled ctermid reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <stdio.h>/<unistd.h> ctermid ABI: PASS\n'
