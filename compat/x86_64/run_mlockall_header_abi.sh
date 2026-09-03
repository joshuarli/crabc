#!/usr/bin/env bash
# Native Linux/x86-64 mlockall C/C++ declaration evidence.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. This compile-only
# matrix selects the one-argument mlockall spelling and the shared
# MCL_CURRENT/MCL_FUTURE values; it does not claim mlockall runtime behavior,
# MCL_ONFAULT header availability, whole-process lock policy, or public x86
# support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/mman.h mlockall ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_profile() {
    local language="$1" profile="$2"
    shift 2
    local variant

    for variant in oracle project; do
        local -a include_args=()
        [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
        if [ "$language" = c ]; then
            "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "$@" "${include_args[@]}" \
                -fsyntax-only "$ROOT_DIR/compat/x86_64/mlockall_header_abi_probe.c" ||
                fail "${variant} C ${profile} declaration/profile drifted"
        else
            "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "$@" \
                "${include_args[@]}" -fsyntax-only \
                "$ROOT_DIR/compat/x86_64/mlockall_header_abi_probe.cpp" ||
                fail "${variant} C++ ${profile} declaration/profile drifted"
        fi
    done
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-mlockall-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

for language in c cpp; do
    compile_profile "$language" strict -D__STRICT_ANSI__
    compile_profile "$language" posix -D_POSIX_C_SOURCE=200809L
    compile_profile "$language" xopen700 -D_XOPEN_SOURCE=700
    compile_profile "$language" gnu -D_GNU_SOURCE
    compile_profile "$language" bsd -D_BSD_SOURCE
    compile_profile "$language" default-source -D_DEFAULT_SOURCE
done

if ! "$ORACLE_CC" -std=c11 -D__STRICT_ANSI__ -U_GNU_SOURCE \
    -I "$ROOT_DIR/include" -H -fsyntax-only \
    "$ROOT_DIR/compat/x86_64/mlockall_header_abi_probe.c" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project mlockall header contract drifted"
fi
for header in sys/mman.h features.h bits/alltypes.h bits/mman.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "C probe unexpectedly retained the project <sys/types.h> type-owner shortcut"
fi

for variant in oracle project; do
    include_args=()
    [ "$variant" = project ] && include_args=(-I "$ROOT_DIR/include")
    object="$work_dir/${variant}-mlockall-cxx.o"
    "$ORACLE_CC" -std=c++17 -x c++ -D__STRICT_ANSI__ -U_GNU_SOURCE \
        "${include_args[@]}" -c \
        "$ROOT_DIR/compat/x86_64/mlockall_header_abi_probe.cpp" -o "$object"
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]mlockall$' ||
        fail "C++ probe does not retain C linkage for mlockall (${variant})"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*mlockall'; then
        fail "C++ probe retained mangled mlockall reference (${variant})"
    fi
done

printf 'x86 pinned-musl/project C/C++ <sys/mman.h> mlockall ABI: PASS\n'
