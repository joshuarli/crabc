#!/usr/bin/env bash
# Native Linux/x86-64 XSI grantpt C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. `grantpt` is
# visible under X/Open, GNU, and BSD profiles but hidden by strict/POSIX
# profiles. This compile-only boundary selects no PTY allocation, grant,
# unlock, naming, session, or terminal policy.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 stdlib.h grantpt ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/grantpt_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/grantpt_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-grantpt-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-grantpt-cxx.o"
candidate_cxx_object="$work_dir/candidate-grantpt-cxx.o"

compile_visible_profile() {
    local selector="$1" variant

    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "$selector" \
            -DCRABC_EXPECT_GRANTPT -fno-builtin -fsyntax-only \
            "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "$selector" \
            -DCRABC_EXPECT_GRANTPT -fno-builtin -fsyntax-only \
            "${include_args[@]}" "$cxx_probe"
    done
}

for selector in -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    compile_visible_profile "$selector"
done

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_EXPECT_GRANTPT -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C grantpt header contract drifted"
fi
for header in stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_EXPECT_GRANTPT -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_XOPEN_SOURCE=700 \
    -DCRABC_EXPECT_GRANTPT -fno-builtin -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]grantpt$' ||
        fail "C++ probe does not retain C linkage for grantpt"
    if printf '%s\n' "$undefined" | grep -Eq '_Z7grantpti'; then
        fail "C++ probe retained a mangled grantpt reference"
    fi
done

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
    for selector in '' -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L; do
        if "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE "$selector" \
            -DCRABC_REQUIRE_GRANTPT_HIDDEN -fno-builtin -fsyntax-only "$probe" \
            >/dev/null 2>"$work_dir/oracle-${language}-hidden-errors"; then
            fail "pinned musl exposes grantpt outside X/Open/GNU/BSD ${language}"
        fi
        if "$ORACLE_CC" "${compiler_args[@]}" -U_GNU_SOURCE "$selector" \
            -DCRABC_REQUIRE_GRANTPT_HIDDEN -fno-builtin -I "$ROOT_DIR/include" \
            -fsyntax-only "$probe" \
            >/dev/null 2>"$work_dir/project-${language}-hidden-errors"; then
            fail "project stdlib.h exposes grantpt outside X/Open/GNU/BSD ${language}"
        fi
    done
done

printf 'x86 pinned-musl/project C/C++ <stdlib.h> grantpt ABI: PASS\n'
