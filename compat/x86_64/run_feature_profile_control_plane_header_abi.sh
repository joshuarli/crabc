#!/usr/bin/env bash
# Native Linux/x86-64 musl feature-profile control-plane regression.
#
# This keeps feature selection separate from C++ linkage: `features.h` owns
# only macro implications; each public header owns its direct declaration
# boundary and C linkage. It is compile-only evidence, not archive, runtime,
# family-promotion, or public-support evidence.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly C_PROBE="$ROOT_DIR/compat/x86_64/feature_profile_control_plane_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/feature_profile_control_plane_probe.cpp"

fail() {
    printf 'ERROR: x86 feature-profile control plane: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v grep >/dev/null 2>&1 || fail "requires grep"
command -v mktemp >/dev/null 2>&1 || fail "requires mktemp"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-feature-profile-control-plane.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

base_profile_arguments() {
    printf '%s\0' \
        -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE -U_POSIX_SOURCE \
        -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -U_ALL_SOURCE \
        -U_LARGEFILE64_SOURCE
}

profile_arguments() {
    case "$1" in
        strict) printf '%s\0' -DCRABC_FEATURE_PROFILE_STRICT ;;
        posix-2008) printf '%s\0' -D_POSIX_C_SOURCE=200809L -DCRABC_FEATURE_PROFILE_POSIX_2008 ;;
        xopen-700) printf '%s\0' -D_XOPEN_SOURCE=700 -DCRABC_FEATURE_PROFILE_XOPEN_700 ;;
        gnu) printf '%s\0' -D_GNU_SOURCE -DCRABC_FEATURE_PROFILE_GNU ;;
        bsd) printf '%s\0' -D_BSD_SOURCE -DCRABC_FEATURE_PROFILE_BSD ;;
        default-source) printf '%s\0' -D_DEFAULT_SOURCE -DCRABC_FEATURE_PROFILE_DEFAULT_SOURCE ;;
        all-source) printf '%s\0' -D_ALL_SOURCE -DCRABC_FEATURE_PROFILE_ALL_SOURCE ;;
        implicit-default) printf '%s\0' -DCRABC_FEATURE_PROFILE_IMPLICIT_DEFAULT ;;
        *) fail "unknown feature profile: $1" ;;
    esac
}

language_arguments() {
    case "$1:$2" in
        c:implicit-default) printf '%s\0' -x c -std=gnu11 ;;
        cxx:implicit-default) printf '%s\0' -x c++ -std=gnu++17 ;;
        c:*) printf '%s\0' -x c -std=c11 ;;
        cxx:*) printf '%s\0' -x c++ -std=c++17 ;;
        *) fail "unknown language/profile: $1:$2" ;;
    esac
}

compile_case() {
    local tree="$1" language="$2" profile="$3" header_case="$4"
    local output_kind="$5" output_path="$6" trace_path="$7"
    local source
    local -a base_args profile_args language_args command

    mapfile -d '' -t base_args < <(base_profile_arguments)
    mapfile -d '' -t profile_args < <(profile_arguments "$profile")
    mapfile -d '' -t language_args < <(language_arguments "$language" "$profile")
    case "$language" in
        c) source="$C_PROBE" ;;
        cxx) source="$CXX_PROBE" ;;
        *) fail "unknown language: $language" ;;
    esac
    command=("$ORACLE_CC" "${language_args[@]}" -fno-builtin
        "${base_args[@]}" "${profile_args[@]}")
    if [ -n "$header_case" ]; then
        command+=("-D$header_case")
    fi
    case "$tree" in
        oracle) ;;
        project) command+=(-I "$ROOT_DIR/include") ;;
        *) fail "unknown header tree: $tree" ;;
    esac
    case "$output_kind" in
        syntax) command+=(-fsyntax-only "$source") ;;
        object) command+=(-c "$source" -o "$output_path") ;;
        *) fail "unknown output kind: $output_kind" ;;
    esac
    if [ -n "$trace_path" ]; then
        command+=(-H)
    fi
    "${command[@]}" >/dev/null 2>"$trace_path"
}

assert_project_provenance() {
    local trace="$1" header="$2"
    grep -Fq "$ROOT_DIR/include/$header" "$trace" ||
        fail "project probe did not use <$header>"
    grep -Fq "$ROOT_DIR/include/features.h" "$trace" ||
        fail "project probe did not use <features.h>"
}

assert_success_case() {
    local profile="$1" header_case="$2" expected_header="$3" linkage_symbols="$4"
    local language tree trace object symbol mangled_symbols
    mangled_symbols="${linkage_symbols// /|}"
    for language in c cxx; do
        for tree in oracle project; do
            trace="$work_dir/${profile}-${header_case:-features}-${tree}-${language}.trace"
            object=/dev/null
            if [ "$language" = cxx ] && [ -n "$linkage_symbols" ]; then
                object="$work_dir/${profile}-${header_case}-${tree}-${language}.o"
                compile_case "$tree" "$language" "$profile" "$header_case" object "$object" "$trace" ||
                    fail "$tree $language $profile/$header_case did not compile"
                for symbol in $linkage_symbols; do
                    nm --undefined-only "$object" | grep -Eq "[[:space:]]${symbol}$" ||
                        fail "$tree C++ $profile/$header_case lacks unmangled $symbol"
                done
                if nm --undefined-only "$object" | grep -Eq "_Z.*(${mangled_symbols})"; then
                    fail "$tree C++ $profile/$header_case retained a mangled C reference"
                fi
            else
                compile_case "$tree" "$language" "$profile" "$header_case" syntax "$object" "$trace" ||
                    fail "$tree $language $profile/$header_case did not compile"
            fi
            if [ "$tree" = project ] && [ -n "$expected_header" ]; then
                assert_project_provenance "$trace" "$expected_header"
            fi
        done
    done
}

assert_hidden_case() {
    local profile="$1" header_case="$2" expected_header="$3"
    local language tree trace
    for language in c cxx; do
        for tree in oracle project; do
            trace="$work_dir/${profile}-${header_case}-${tree}-${language}.trace"
            if compile_case "$tree" "$language" "$profile" "$header_case" syntax /dev/null "$trace"; then
                fail "$tree $language $profile/$header_case unexpectedly exposed a hidden declaration"
            fi
            if [ "$tree" = project ]; then
                assert_project_provenance "$trace" "$expected_header"
            fi
        done
    done
}

# Pin the exact musl feature implication model before checking declarations.
for profile in strict posix-2008 xopen-700 gnu bsd default-source all-source implicit-default; do
    assert_success_case "$profile" '' '' ''
done

assert_success_case bsd CRABC_FEATURE_HEADER_FCNTL_BSD fcntl.h 'lockf'
assert_success_case gnu CRABC_FEATURE_HEADER_MATH_GNU math.h \
    'sincos exp10 exp10f exp10l pow10 pow10f pow10l lgammal_r'
assert_hidden_case bsd CRABC_FEATURE_HEADER_MATH_BSD_HIDDEN math.h
for profile in strict posix-2008 xopen-700 gnu bsd; do
    assert_hidden_case "$profile" CRABC_FEATURE_HEADER_PTHREAD_HIDDEN pthread.h
done

printf 'x86 pinned-musl/project feature-profile control plane C/C++ ABI: PASS\n'
