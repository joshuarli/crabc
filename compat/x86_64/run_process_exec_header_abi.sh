#!/usr/bin/env bash
# Native Linux/x86-64 <unistd.h> process-exec C/C++ declaration evidence.
#
# Pinned musl 1.2.6 owns the header profile oracle. execl, execle, execlp,
# execv, execve, execvp, and fexecve are unconditional declarations; execvpe
# is a GNU/BSD extension. GNU C++ drivers normally predefine _GNU_SOURCE, so
# that ordinary strict-language driver profile intentionally retains execvpe;
# an explicitly scrubbed strict C++ profile proves the extension is otherwise
# hidden. This compile-only gate selects no implementation provider.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly C_PROBE="$ROOT_DIR/compat/x86_64/process_exec_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/process_exec_header_abi_probe.cpp"

fail() {
    printf 'ERROR: x86 process-exec headers: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

run_compiler() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH "$@"
}

select_tree() {
    case "$1" in
        oracle)
            selected_cc="$ORACLE_CC"
            selected_include="$MUSL_ROOT/include"
            ;;
        project)
            selected_cc="$CANDIDATE_CC"
            selected_include="$PROJECT_INCLUDE"
            ;;
        *) fail "unknown header tree $1" ;;
    esac
}

compile_visible() {
    local tree="$1" language="$2" profile="$3"
    shift 3
    select_tree "$tree"
    case "$language" in
        c)
            run_compiler "$selected_cc" -std=c11 -DCRABC_EXPECT_EXECVPE \
                -nostdinc -I "$selected_include" -isystem "$builtin_include" \
                "$@" -fsyntax-only "$C_PROBE"
            ;;
        cxx)
            run_compiler "$selected_cc" -std=c++17 -x c++ \
                -DCRABC_EXPECT_EXECVPE -nostdinc -nostdinc++ \
                -I "$selected_include" -isystem "$builtin_include" \
                "$@" -fsyntax-only "$CXX_PROBE"
            ;;
        *) fail "unknown header language $language" ;;
    esac || fail "$tree $language $profile profile lost process-exec declarations"
}

compile_universal() {
    local tree="$1" language="$2" profile="$3"
    shift 3
    select_tree "$tree"
    case "$language" in
        c)
            run_compiler "$selected_cc" -std=c11 -nostdinc \
                -I "$selected_include" -isystem "$builtin_include" \
                "$@" -fsyntax-only "$C_PROBE"
            ;;
        cxx)
            run_compiler "$selected_cc" -std=c++17 -x c++ -nostdinc \
                -nostdinc++ -I "$selected_include" \
                -isystem "$builtin_include" "$@" -fsyntax-only "$CXX_PROBE"
            ;;
        *) fail "unknown header language $language" ;;
    esac || fail "$tree $language $profile profile lost unconditional process-exec declarations"
}

reject_execvpe() {
    local tree="$1" language="$2" profile="$3" output
    shift 3
    select_tree "$tree"
    output="$work_dir/$tree.$language.$profile.out"
    case "$language" in
        c)
            if run_compiler "$selected_cc" -std=c11 \
                -DCRABC_REQUIRE_EXECVPE_HIDDEN -Werror=implicit-function-declaration \
                -nostdinc -I "$selected_include" -isystem "$builtin_include" \
                "$@" -fsyntax-only "$C_PROBE" >"$output" 2>&1; then
                fail "$tree C $profile profile unexpectedly exposes execvpe"
            fi
            ;;
        cxx)
            if run_compiler "$selected_cc" -std=c++17 -x c++ \
                -DCRABC_REQUIRE_EXECVPE_HIDDEN -nostdinc -nostdinc++ \
                -I "$selected_include" -isystem "$builtin_include" \
                "$@" -fsyntax-only "$CXX_PROBE" >"$output" 2>&1; then
                fail "$tree C++ $profile profile unexpectedly exposes execvpe"
            fi
            ;;
        *) fail "unknown header language $language" ;;
    esac
}

assert_unmangled_references() {
    local object="$1" tree="$2" profile="$3" undefined symbol

    undefined="$(nm --undefined-only "$object")"
    for symbol in execl execle execlp execv execve execvp execvpe fexecve; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "$tree C++ $profile probe does not retain C linkage for $symbol"
        if printf '%s\n' "$undefined" | grep -Eq "_Z.*${symbol}"; then
            fail "$tree C++ $profile probe retained a mangled $symbol reference"
        fi
    done
}

require_native_linux_x86_64
for tool in grep mktemp nm sed uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl headers"
[ -f "$C_PROBE" ] || fail "missing process-exec C header probe"
[ -f "$CXX_PROBE" ] || fail "missing process-exec C++ header probe"

bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-process-exec-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
[ -d "$builtin_include" ] || fail "missing compiler builtin include directory"

# C profiles: POSIX forms stay visible everywhere; execvpe is GNU/BSD only.
for tree in oracle project; do
    compile_visible "$tree" c gnu -U_GNU_SOURCE -D_GNU_SOURCE
    compile_visible "$tree" c bsd -U_GNU_SOURCE -D_BSD_SOURCE
    compile_universal "$tree" c strict -U_GNU_SOURCE -D__STRICT_ANSI__
    compile_universal "$tree" c posix -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    compile_universal "$tree" c xopen700 -U_GNU_SOURCE -D_XOPEN_SOURCE=700
    reject_execvpe "$tree" c strict -U_GNU_SOURCE -D__STRICT_ANSI__
    reject_execvpe "$tree" c posix -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    reject_execvpe "$tree" c xopen700 -U_GNU_SOURCE -D_XOPEN_SOURCE=700
done

# GNU C++ drivers make their ordinary strict-language profile GNU-visible;
# scrub that predefinition in the explicit negative profiles.
for tree in oracle project; do
    compile_visible "$tree" cxx gnu -D_GNU_SOURCE
    compile_visible "$tree" cxx bsd -D_BSD_SOURCE
    compile_visible "$tree" cxx strict-driver-default -D__STRICT_ANSI__
    compile_universal "$tree" cxx strict-scrubbed -U_GNU_SOURCE -D__STRICT_ANSI__
    compile_universal "$tree" cxx posix-scrubbed -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
    reject_execvpe "$tree" cxx strict-scrubbed -U_GNU_SOURCE -D__STRICT_ANSI__
    reject_execvpe "$tree" cxx posix-scrubbed -U_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
done

# Inspect actual C++ relocations rather than merely accepting declarations:
# every selected spelling must retain unmangled C linkage.
for profile in gnu bsd strict-driver-default; do
    case "$profile" in
        gnu) profile_args=(-D_GNU_SOURCE) ;;
        bsd) profile_args=(-D_BSD_SOURCE) ;;
        strict-driver-default) profile_args=(-D__STRICT_ANSI__) ;;
    esac
    for tree in oracle project; do
        select_tree "$tree"
        object="$work_dir/$tree.$profile.process-exec.cxx.o"
        run_compiler "$selected_cc" -std=c++17 -x c++ \
            -DCRABC_EXPECT_EXECVPE -nostdinc -nostdinc++ \
            -I "$selected_include" -isystem "$builtin_include" \
            "${profile_args[@]}" -c "$CXX_PROBE" -o "$object"
        assert_unmangled_references "$object" "$tree" "$profile"
    done
done

header_trace="$work_dir/project-header-trace"
if ! run_compiler "$CANDIDATE_CC" -std=c11 -D_GNU_SOURCE \
    -DCRABC_EXPECT_EXECVPE -nostdinc -I "$PROJECT_INCLUDE" \
    -isystem "$builtin_include" -H -fsyntax-only "$C_PROBE" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project GNU process-exec header contract drifted"
fi
for header in unistd.h features.h bits/alltypes.h; do
    grep -Fq "$PROJECT_INCLUDE/$header" "$header_trace" ||
        fail "C probe did not use project <$header>"
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> process-exec ABI: PASS\n'
