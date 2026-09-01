#!/usr/bin/env bash
# Native Linux/x86-64 <sys/io.h> and <bits/io.h> header ABI/codegen gate.
#
# This is a compile-and-object-inspection boundary only.  Executing in/out
# instructions requires I/O privilege and belongs to `system.kernel-admin`,
# not to the installed-header contract proved here.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly C_PROBE="$ROOT_DIR/compat/x86_64/sys_io_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/sys_io_header_abi_probe.cpp"
readonly EXPECTED_PROFILE_COUNT=7
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
readonly -a INLINE_NAMES=(inb inw inl outb outw outl insb insw insl outsb outsw outsl)

fail() {
    printf 'ERROR: x86 sys/io header ABI: %s\n' "$*" >&2
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

run_compiler() {
    local compiler="$1"
    shift
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$compiler" "$@"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE=1' ;;
        c11-strict|cxx17-strict) ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE=1' ;;
        *) fail "unknown profile: $1" ;;
    esac
}

compile_profile() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local object="$4"
    local compiler include_root source
    local -a profile_args arguments

    case "$tree" in
        reference)
            compiler="$ORACLE_CC"
            include_root="$MUSL_ROOT/include"
            ;;
        candidate)
            compiler="$CANDIDATE_CC"
            include_root="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$include_root"
        -isystem "$candidate_compiler_builtin_include"
        -U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -U_XOPEN_SOURCE -U_POSIX_C_SOURCE
        -H -O2 -fno-builtin -fno-stack-protector
        "${profile_args[@]}"
    )
    case "$profile" in
        c11-*)
            source="$C_PROBE"
            arguments=(-x c -std=c11 "${arguments[@]}" -c -o "$object" "$source")
            ;;
        cxx17-*)
            source="$CXX_PROBE"
            arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}" -c -o "$object" "$source")
            ;;
        *) fail "unknown profile language: $profile" ;;
    esac
    run_compiler "$compiler" "${arguments[@]}" >/dev/null 2>"$trace"
}

check_trace() {
    local tree="$1"
    local profile="$2"
    local trace="$3"
    local root path

    case "$tree" in
        reference) root="$MUSL_ROOT/include" ;;
        candidate)
            root="$PROJECT_INCLUDE"
            if grep -Fq "$MUSL_ROOT/include/" "$trace"; then
                fail "$profile candidate trace reached pinned musl despite -nostdinc"
            fi
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    while IFS= read -r path; do
        case "$path" in
            "$root"/*|"$candidate_compiler_builtin_include"/*) ;;
            *) fail "$profile $tree trace escaped its declared header roots: $path" ;;
        esac
    done < <(trace_paths "$trace")
    for header in sys/io.h bits/io.h features.h; do
        grep -Fq "$root/$header" "$trace" ||
            fail "$profile $tree trace omitted $root/$header"
    done
}

check_undefined_symbols() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local undefined inline_name

    undefined="$(nm --undefined-only "$object")"
    for symbol in iopl ioperm; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree $profile object does not retain ${symbol} declaration reference"
    done
    for inline_name in "${INLINE_NAMES[@]}"; do
        if printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${inline_name}$"; then
            fail "$tree $profile object made inline ${inline_name} an external reference"
        fi
    done
    if [[ "$profile" == cxx17-* ]] && printf '%s\n' "$undefined" | grep -Eq '_Z.*(iopl|ioperm)'; then
        fail "$tree $profile object retained mangled iopl/ioperm references"
    fi
}

require_instruction() {
    local disassembly="$1"
    local label="$2"
    local pattern="$3"

    grep -Eq "$pattern" "$disassembly" ||
        fail "$label omits required x86 port-I/O instruction pattern $pattern"
}

check_codegen() {
    local tree="$1"
    local profile="$2"
    local object="$3"
    local function="$4"
    local disassembly="$5"

    objdump -d --disassemble="$function" "$object" >"$disassembly"
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]out[[:space:]].*%al,\(%dx\)'
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]out[[:space:]].*%ax,\(%dx\)'
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]out[[:space:]].*%eax,\(%dx\)'
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]in[[:space:]]+\(%dx\),%al'
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]in[[:space:]]+\(%dx\),%ax'
    require_instruction "$disassembly" "$tree $profile" '[[:space:]]in[[:space:]]+\(%dx\),%eax'
    for mnemonic in outsb outsw outsl insb insw insl; do
        require_instruction "$disassembly" "$tree $profile" "rep.*${mnemonic}"
    done
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in env grep mapfile mktemp nm objdump realpath sed uname; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$C_PROBE" ] || fail "missing C sys/io header ABI probe"
[ -f "$CXX_PROBE" ] || fail "missing C++ sys/io header ABI probe"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile roster drifted"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] ||
    fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-sys-io-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

for profile in "${PROFILES[@]}"; do
    for tree in reference candidate; do
        trace="$work_dir/$profile.$tree.trace"
        object="$work_dir/$profile.$tree.o"
        if ! compile_profile "$tree" "$profile" "$trace" "$object"; then
            fail "$profile $tree sys/io declarations or inline code did not compile"
        fi
        check_trace "$tree" "$profile" "$trace"
        check_undefined_symbols "$tree" "$profile" "$object"
        case "$profile" in
            c11-*) function=crabc_x86_sys_io_header_abi_codegen ;;
            cxx17-*) function=crabc_x86_sys_io_header_abi_codegen_cpp ;;
            *) fail "unknown profile language: $profile" ;;
        esac
        check_codegen "$tree" "$profile" "$object" "$function" \
            "$work_dir/$profile.$tree.disassembly"
    done
done

printf 'x86 pinned-musl/project C/C++ sys/io inline header ABI and object-code matrix: PASS (%s profiles; no port-I/O execution)\n' \
    "$EXPECTED_PROFILE_COUNT"
