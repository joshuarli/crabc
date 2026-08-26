#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl oracle toolchain check.
#
# Invoke only from docker/Dockerfile.x86_64's native linux/amd64 image. This
# does not build or select crabc-libc. It proves that the C/POSIX oracle is the
# exact musl 1.2.6 source build beneath /opt rather than Alpine's bootstrap
# runtime, and leaves all generated files in a disposable directory.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_VERSION=1.2.6
readonly MUSL_SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a
readonly MUSL_REV=9fa28ece75d8a2191de7c5bb53bed224c5947417
readonly MUSL_ROOT="/opt/musl-${MUSL_VERSION}"
readonly MUSL_LIBC="${MUSL_ROOT}/lib/libc.so"
readonly MUSL_LOADER="${MUSL_ROOT}/lib/ld-musl-x86_64.so.1"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: pinned x86 musl oracle: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || fail "requires $1"
}

require_native_linux_x86_64
require_tool readelf
require_tool sha256sum
require_tool realpath
[ -x "$ORACLE_CC" ] || fail "missing x86 oracle compiler wrapper"
[ -f "$MUSL_LIBC" ] || fail "missing pinned musl libc"
[ -f "$MUSL_LOADER" ] || fail "missing pinned musl loader"
[ -d "${MUSL_ROOT}/include" ] || fail "missing pinned musl headers"

if ! diff -u <(
    printf '%s\n' \
        'format=crabc-pinned-musl-oracle-v1' \
        "version=${MUSL_VERSION}" \
        "source_sha256=${MUSL_SHA256}" \
        "fallback_revision=${MUSL_REV}" \
        'architecture=x86_64'
) "${MUSL_ROOT}/.crabc-oracle"; then
    fail "source-verification manifest does not match the pinned release"
fi

sha256sum -c "${MUSL_ROOT}/.crabc-musl-gcc-specs.sha256" >/dev/null || {
    fail "musl-gcc specs integrity check failed"
}

grep -Fxq \
    'exec /usr/bin/gcc -specs /opt/musl-1.2.6/lib/musl-gcc.specs "$@"' \
    "$ORACLE_CC" || fail "compiler wrapper does not select the pinned specs"

compiler_target="$(
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH "$ORACLE_CC" -dumpmachine
)"
case "$compiler_target" in
    x86_64*-musl*) ;;
    *) fail "oracle compiler is not an x86_64 musl GCC: ${compiler_target}" ;;
esac

work_dir="$(mktemp -d /tmp/crabc-x86-64-musl-oracle.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="${work_dir}/probe"
canonical_libc="$(realpath "$MUSL_LIBC")"
version_file="$work_dir/libc-version"
file_header="$work_dir/file-header"
program_headers="$work_dir/program-headers"
dynamic_section="$work_dir/dynamic-section"

"$MUSL_LIBC" >"$version_file" 2>&1 || true
grep -Fxq 'musl libc (x86_64)' "$version_file" || {
    fail "pinned libc did not identify itself as musl x86_64"
}
grep -Fxq "Version ${MUSL_VERSION}" "$version_file" || {
    fail "pinned libc did not report musl ${MUSL_VERSION}"
}

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" \
    "-DCRABC_MUSL_ORACLE_LIBC_PATH=\"${canonical_libc}\"" \
    "${ROOT_DIR}/compat/x86_64/musl_oracle_probe.c" \
    -o "$probe"

readelf --file-header --wide "$probe" >"$file_header"
grep -Fq 'Advanced Micro Devices X86-64' "$file_header" || {
    fail "oracle probe is not an x86-64 ELF executable"
}
readelf --program-headers --wide "$probe" >"$program_headers"
interpreter="$(sed -n 's/.*Requesting program interpreter: \(.*\)].*/\1/p' "$program_headers")"
[ "$interpreter" = "$MUSL_LOADER" ] || {
    fail "oracle probe interpreter is ${interpreter:-missing}, not ${MUSL_LOADER}"
}
readelf --dynamic --wide "$probe" >"$dynamic_section"
grep -Fq 'Shared library: [libc.so]' "$dynamic_section" || {
    fail "oracle probe does not need musl libc.so"
}
if grep -Eq 'libc\.so\.6|ld-linux|libgcc_s|\((RPATH|RUNPATH)\)' "$dynamic_section"; then
    fail "oracle probe permits a glibc or search-path runtime dependency"
fi

runtime_output="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$runtime_output" = "pinned musl x86_64 runtime: ${canonical_libc}" ] || {
    fail "oracle probe did not map exactly the pinned musl libc"
}

printf 'x86 pinned musl %s oracle toolchain: PASS (%s)\n' \
    "$MUSL_VERSION" "$compiler_target"
