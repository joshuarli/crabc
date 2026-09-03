#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl public type-header ABI check.
#
# Compile the C and C++ project-header-first probes with no link step, then
# compile those same assertions against the pinned musl headers. The profiles
# cover the plain type vocabulary plus GNU/BSD and large-file tails. This
# proves only the explicitly checked source-level declarations and opaque-
# object layouts; it does not select crabc-libc or claim pthread behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 type header ABI: %s\n' "$*" >&2
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

# Prove the compiler/header provenance before using it for declarations.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/types_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/types_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-types-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/gnu-project-header-trace"

compile_profile() {
    local tree="$1"
    local profile="$2"
    local -a feature_args=()
    local -a include_args=()

    case "$profile" in
        strict)
            feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE
                -D__STRICT_ANSI__)
            ;;
        gnu)
            feature_args=(-D_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE)
            ;;
        bsd)
            feature_args=(-U_GNU_SOURCE -D_BSD_SOURCE=1 -U_DEFAULT_SOURCE)
            ;;
        largefile64)
            feature_args=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE
                -D_LARGEFILE64_SOURCE)
            ;;
        *) fail "unknown type-header profile: $profile" ;;
    esac

    case "$tree" in
        reference) ;;
        candidate) include_args=(-I "$ROOT_DIR/include") ;;
        *) fail "unknown type-header tree: $tree" ;;
    esac

    "$ORACLE_CC" -std=c11 "${feature_args[@]}" "${include_args[@]}" \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${feature_args[@]}" \
        "${include_args[@]}" -fsyntax-only "$cxx_probe"
}

for profile in strict gnu bsd largefile64; do
    compile_profile reference "$profile"
    compile_profile candidate "$profile"
done

# The GNU sys/types tail owns the endian/select exposure. Its direct request
# path must not pull the unrelated time umbrella into a plain type include.
if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project GNU type-header contract drifted"
fi
for header in sys/types.h features.h bits/alltypes.h endian.h sys/select.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "GNU type-header trace omitted project <$header>"
done
if grep -Fq "$ROOT_DIR/include/time.h" "$header_trace"; then
    fail "GNU type-header trace reached unexpected project <time.h>"
fi

printf 'x86 pinned-musl C/C++ public type header ABI: PASS (4 profiles)\n'
