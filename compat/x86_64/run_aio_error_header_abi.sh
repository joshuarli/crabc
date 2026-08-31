#!/usr/bin/env bash
# Native Linux/x86-64 compile-only <aio.h> aio_error ABI slice.
#
# Pinned musl 1.2.6 is the declaration/layout and C-linkage oracle. Project
# headers are placed first for the candidate pass; neither pass links or
# selects crabc-libc. This direct accessor remains separate from AIO request,
# wait, cancellation, and completion behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 aio.h aio_error ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/aio_error_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/aio_error_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-aio-error-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-aio-error-cxx.o"
candidate_cxx_object="$work_dir/candidate-aio-error-cxx.o"

for selector in default largefile; do
    selector_args=()
    case "$selector" in
        default) ;;
        largefile) selector_args=(-D_LARGEFILE64_SOURCE) ;;
        *) fail "unknown header selector ${selector}" ;;
    esac
    # Pinned musl's <aio.h> embeds struct sigevent, whose complete public
    # definition is feature-selected. Keep the GNU profile explicit rather
    # than mistaking the strict-profile oracle limitation for ABI behavior.
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE "${selector_args[@]}" -fno-builtin \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE "${selector_args[@]}" -fno-builtin \
        -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 -D_GNU_SOURCE "${selector_args[@]}" -fno-builtin \
        -I "$ROOT_DIR/include" \
        -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE "${selector_args[@]}" -fno-builtin \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# -H makes project-header provenance observable rather than merely compiling
# against whichever ambient aio.h happens to be installed.
if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project C aio_error header contract drifted"
fi
for header in aio.h sys/types.h time.h signal.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

# C++ references must remain an unmangled C symbol, not merely have the right
# function-pointer type.
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fno-builtin \
    -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]aio_error$' ||
        fail "C++ probe does not retain C linkage for aio_error"
    if printf '%s\n' "$undefined" | grep -Eq '_Z.*aio_error'; then
        fail "C++ probe retained a mangled aio_error reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <aio.h> aio_error ABI: PASS\n'
