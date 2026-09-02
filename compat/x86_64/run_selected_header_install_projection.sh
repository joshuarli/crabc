#!/usr/bin/env bash
# Private native Linux/x86-64 selected installed-header projection diagnostic.
#
# This materializes only the pinned 183-path musl public surface plus the
# project-owned private bits/** dependencies.  The shared include/ source tree
# is intentionally not changed: its eight project-only non-bits paths are
# fail-closed exclusions from this one x86 projection.  This proves isolated
# empty-TU C11/C++17 consumer closure, not ABI/layout/provider/runtime/sysroot
# or public-support completion.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly CONTRACT_VALIDATOR="$ROOT_DIR/compat/x86_64/selected_header_install_projection.py"
readonly CONTRACT="$ROOT_DIR/compat/x86_64/selected-header-install-projection.toml"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/public_headers.txt"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/selected_header_install_projection_cxx.cpp"
readonly MUSL_ORACLE_RUNNER="$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"
readonly LINUX_UAPI_RUNNER="$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly CANDIDATE_CC=/usr/bin/gcc
readonly LINUX_UAPI_INCLUDE=/opt/linux-5.10-uapi/include
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/selected-header-install-projection"
readonly REPORT_PATH="$REPORT_DIR/latest.tsv"
readonly EXPECTED_SELECTED_PUBLIC_HEADER_COUNT=183
readonly EXPECTED_EXCLUDED_PROJECT_ONLY_HEADER_COUNT=8
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_PROJECTION_RECORD_COUNT=1281
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)

fail() {
    printf 'ERROR: x86 selected header install projection: %s\n' "$*" >&2
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

validate_relative_path() {
    case "$1" in
        ''|/*|*'..'*|*$'\t'*|*$'\r'*|*$'\n'*)
            fail "unsafe selected-header relative path: $1"
            ;;
    esac
}

validate_regular_header_tree() {
    local root="$1"
    local path

    [ -d "$root" ] || fail "header tree is not a directory: $root"
    [ ! -L "$root" ] || fail "header tree is a symlink: $root"
    while IFS= read -r path; do
        [ ! -L "$path" ] || fail "header tree contains a symlink: $path"
        if [ -d "$path" ] || [ -f "$path" ]; then
            continue
        fi
        fail "header tree contains a non-regular path: $path"
    done < <(find "$root" -mindepth 1 -print | LC_ALL=C sort)
}

list_public_headers() {
    local root="$1"
    local path
    local relative

    [ -d "$root" ] || return 1
    while IFS= read -r path; do
        relative="${path#"$root"/}"
        case "$relative" in
            bits/*) continue ;;
        esac
        printf '%s\n' "$relative"
    done < <(find "$root" -type f -name '*.h' -print | LC_ALL=C sort)
}

write_manifest() {
    local root="$1"
    local manifest="$2"
    local path
    local relative
    local digest

    : > "$manifest"
    while IFS= read -r path; do
        relative="${path#"$root"/}"
        validate_relative_path "$relative"
        digest="$(sha256sum "$path")"
        digest="${digest%%[[:space:]]*}"
        printf '%s\t%s\n' "$relative" "$digest" >> "$manifest"
    done < <(find "$root" -type f -print | LC_ALL=C sort)
}

write_source_selection_manifest() {
    local source_root="$1"
    local selected_paths="$2"
    local manifest="$3"
    local unsorted="$manifest.unsorted"
    local header
    local path
    local digest
    local relative

    : > "$unsorted"
    while IFS= read -r header; do
        validate_relative_path "$header"
        path="$source_root/$header"
        [ -f "$path" ] && [ ! -L "$path" ] || fail "selected source header is absent or unsafe: $header"
        digest="$(sha256sum "$path")"
        digest="${digest%%[[:space:]]*}"
        printf '%s\t%s\n' "$header" "$digest" >> "$unsorted"
    done < "$selected_paths"
    while IFS= read -r path; do
        relative="${path#"$source_root"/}"
        validate_relative_path "$relative"
        digest="$(sha256sum "$path")"
        digest="${digest%%[[:space:]]*}"
        printf '%s\t%s\n' "$relative" "$digest" >> "$unsorted"
    done < <(find "$source_root/bits" -type f -print | LC_ALL=C sort)
    LC_ALL=C sort "$unsorted" > "$manifest"
    rm -f -- "$unsorted"
}

materialize_selected_tree() {
    local source_root="$1"
    local selected_paths="$2"
    local installed_root="$3"
    local header
    local path
    local relative

    validate_regular_header_tree "$source_root"
    [ -d "$source_root/bits" ] || fail "source bits/ tree is absent"
    mkdir -p "$installed_root"
    [ -d "$installed_root" ] && [ ! -L "$installed_root" ] ||
        fail "fresh selected install root is unsafe: $installed_root"
    while IFS= read -r header; do
        validate_relative_path "$header"
        path="$source_root/$header"
        [ -f "$path" ] && [ ! -L "$path" ] || fail "selected source header is absent or unsafe: $header"
        mkdir -p "$(dirname "$installed_root/$header")"
        cp -- "$path" "$installed_root/$header"
    done < "$selected_paths"
    while IFS= read -r path; do
        relative="${path#"$source_root"/}"
        validate_relative_path "$relative"
        mkdir -p "$(dirname "$installed_root/$relative")"
        cp -- "$path" "$installed_root/$relative"
    done < <(find "$source_root/bits" -type f -print | LC_ALL=C sort)
    validate_regular_header_tree "$installed_root"
}

run_compiler() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$CANDIDATE_CC" "$@"
}

profile_language() {
    case "$1" in
        c11-*) printf '%s\n' c ;;
        cxx17-*) printf '%s\n' cxx ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

profile_arguments() {
    case "$1" in
        c11-gnu|cxx17-gnu) printf '%s\n' '-D_GNU_SOURCE' ;;
        c11-strict) ;;
        c11-posix-2008) printf '%s\n' '-D_POSIX_C_SOURCE=200809L' ;;
        c11-xopen-700) printf '%s\n' '-D_XOPEN_SOURCE=700' ;;
        c11-bsd) printf '%s\n' '-D_BSD_SOURCE' ;;
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

write_source() {
    local header="$1"
    local profile="$2"
    local source="$3"

    case "$(profile_language "$profile")" in
        c) printf '#include <%s>\nint main(void) { return 0; }\n' "$header" > "$source" ;;
        cxx) printf '#include <%s>\nint main() { return 0; }\n' "$header" > "$source" ;;
        *) fail "unknown language profile: $profile" ;;
    esac
}

compile_source() {
    local profile="$1"
    local source="$2"
    local stdout_path="$3"
    local diagnostic_path="$4"
    local language
    local -a profile_args
    local -a arguments

    language="$(profile_language "$profile")"
    mapfile -t profile_args < <(profile_arguments "$profile")
    arguments=(
        -nostdinc
        -I "$installed_include"
        -isystem "$candidate_compiler_builtin_include"
        -isystem "$LINUX_UAPI_INCLUDE"
        -H
        -fsyntax-only
        "${profile_args[@]}"
        "$source"
    )
    case "$language" in
        c) arguments=(-x c -std=c11 "${arguments[@]}") ;;
        cxx) arguments=(-x c++ -std=c++17 -nostdinc++ "${arguments[@]}") ;;
        *) fail "unknown language profile: $profile" ;;
    esac
    run_compiler "${arguments[@]}" > "$stdout_path" 2> "$diagnostic_path"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

trace_has_header() {
    grep -Fq "$1/$2" "$3"
}

trace_has_unapproved_path() {
    local trace="$1"
    local path

    while IFS= read -r path; do
        case "$path" in
            "$installed_include"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*) ;;
            *) return 0 ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

first_diagnostic() {
    local diagnostic="$1"
    local line

    line="$(sed -n '/fatal error:/p; /error:/p' "$diagnostic" | sed -n '1p' || true)"
    if [ -z "$line" ]; then
        printf '%s\n' 'no compiler diagnostic'
    else
        printf '%s\n' "$line" | tr '\t\r\n' ' '
    fi
}

prepare_report_path() {
    local path

    for path in "$ROOT_DIR/compat" "$ROOT_DIR/compat/reports" \
        "$ROOT_DIR/compat/reports/x86_64" "$REPORT_DIR"; do
        [ ! -L "$path" ] || fail "report path component is a symlink: $path"
        if [ -e "$path" ] && [ ! -d "$path" ]; then
            fail "report path component is not a directory: $path"
        fi
    done
    mkdir -p "$REPORT_DIR"
    [ -d "$REPORT_DIR" ] && [ ! -L "$REPORT_DIR" ] || fail "report directory is unsafe"
    [ ! -L "$REPORT_PATH" ] || fail "report path is a symlink: $REPORT_PATH"
    if [ -e "$REPORT_PATH" ] && [ ! -f "$REPORT_PATH" ]; then
        fail "report path is not a regular file: $REPORT_PATH"
    fi
}

[ "$#" -eq 0 ] || fail "usage: $0"
require_native_linux_x86_64
for tool in bash chown cp diff find gcc grep mkdir mktemp mv python3 realpath rm sed sha256sum sort stat tr wc; do
    require_tool "$tool"
done
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$CONTRACT_VALIDATOR" ] || fail "missing selected-header projection validator"
[ -f "$CONTRACT" ] || fail "missing selected-header projection contract"
[ -f "$INVENTORY" ] || fail "missing pinned public-header inventory"
[ -f "$CXX_PROBE" ] || fail "missing selected-header C++ probe"
[ -x "$MUSL_ORACLE_RUNNER" ] || fail "missing pinned musl oracle verifier"
[ -x "$LINUX_UAPI_RUNNER" ] || fail "missing Linux 5.10 UAPI verifier"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"

python3 "$CONTRACT_VALIDATOR" --contract "$CONTRACT" --check >/dev/null
bash "$MUSL_ORACLE_RUNNER" >/dev/null
bash "$LINUX_UAPI_RUNNER" >/dev/null

candidate_compiler_builtin_include="$(run_compiler -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases pinned musl"

work_dir="$(mktemp -d /tmp/crabc-x86-64-selected-header-install-projection.XXXXXX)"
report_tmp=''
trap 'rm -rf -- "$work_dir"; [ -z "$report_tmp" ] || rm -f -- "$report_tmp"' EXIT

selected_paths="$work_dir/selected-paths"
excluded_paths="$work_dir/excluded-paths"
pinned_observed="$work_dir/pinned-observed"
installed_observed="$work_dir/installed-observed"
source_manifest="$work_dir/source-selection-manifest.tsv"
installed_manifest="$work_dir/installed-manifest.tsv"
source="$work_dir/header.c"
compiler_stdout="$work_dir/compiler-stdout"
diagnostic="$work_dir/compiler-diagnostic"
cxx_stdout="$work_dir/cxx-stdout"
cxx_diagnostic="$work_dir/cxx-diagnostic"
installed_include="$work_dir/usr/include"
records="$work_dir/records.tsv"

python3 "$CONTRACT_VALIDATOR" --contract "$CONTRACT" --selected-paths > "$selected_paths"
python3 "$CONTRACT_VALIDATOR" --contract "$CONTRACT" --excluded-paths > "$excluded_paths"
selected_count="$(wc -l < "$selected_paths" | tr -d '[:space:]')"
excluded_count="$(wc -l < "$excluded_paths" | tr -d '[:space:]')"
[ "$selected_count" = "$EXPECTED_SELECTED_PUBLIC_HEADER_COUNT" ] ||
    fail "selected public-header count drifted: expected $EXPECTED_SELECTED_PUBLIC_HEADER_COUNT, got $selected_count"
[ "$excluded_count" = "$EXPECTED_EXCLUDED_PROJECT_ONLY_HEADER_COUNT" ] ||
    fail "excluded project-only header count drifted: expected $EXPECTED_EXCLUDED_PROJECT_ONLY_HEADER_COUNT, got $excluded_count"
[ "${#PROFILES[@]}" = "$EXPECTED_PROFILE_COUNT" ] || fail "profile count drifted"

list_public_headers "$MUSL_ROOT/include" > "$pinned_observed"
if ! diff -u "$INVENTORY" "$pinned_observed"; then
    fail "checked-in selected inventory drifted from pinned musl 1.2.6"
fi
materialize_selected_tree "$PROJECT_INCLUDE" "$selected_paths" "$installed_include"
write_source_selection_manifest "$PROJECT_INCLUDE" "$selected_paths" "$source_manifest"
write_manifest "$installed_include" "$installed_manifest"
if ! diff -u "$source_manifest" "$installed_manifest"; then
    fail "selected header projection differs from the source selection"
fi
list_public_headers "$installed_include" > "$installed_observed"
if ! diff -u "$selected_paths" "$installed_observed"; then
    fail "selected install public header roster drifted"
fi
while IFS= read -r header; do
    [ ! -e "$installed_include/$header" ] ||
        fail "excluded project-only header entered the selected install tree: $header"
done < "$excluded_paths"

# The selected C++ witness protects the C++ spellings without relying on the
# shared source-tree closure's project-only <stdatomic.h> inclusion.
if ! compile_source cxx17-gnu "$CXX_PROBE" "$cxx_stdout" "$cxx_diagnostic"; then
    fail "selected C++ projection probe failed: $(first_diagnostic "$cxx_diagnostic")"
fi
if grep -Fq "$PROJECT_INCLUDE/" "$cxx_diagnostic"; then
    fail "candidate include trace reached source include tree"
fi
if grep -Fq "$MUSL_ROOT/include/" "$cxx_diagnostic"; then
    fail "candidate include trace reached pinned musl despite -nostdinc"
fi
if trace_has_unapproved_path "$cxx_diagnostic"; then
    fail "candidate include trace escaped selected install/builtin/Linux-5.10 roots"
fi
for header in aio.h err.h iso646.h regex.h uchar.h; do
    trace_has_header "$installed_include" "$header" "$cxx_diagnostic" ||
        fail "selected C++ projection probe did not preprocess installed $header"
done

: > "$records"
record_count=0
while IFS= read -r profile; do
    while IFS= read -r header; do
        write_source "$header" "$profile" "$source"
        if ! compile_source "$profile" "$source" "$compiler_stdout" "$diagnostic"; then
            fail "selected header $header ($profile) failed: $(first_diagnostic "$diagnostic")"
        fi
        if grep -Fq "$PROJECT_INCLUDE/" "$diagnostic"; then
            fail "candidate include trace reached source include tree"
        fi
        if grep -Fq "$MUSL_ROOT/include/" "$diagnostic"; then
            fail "candidate include trace reached pinned musl despite -nostdinc"
        fi
        if trace_has_unapproved_path "$diagnostic"; then
            fail "candidate include trace escaped selected install/builtin/Linux-5.10 roots"
        fi
        # GCC owns a few language headers itself; every non-builtin selected
        # header still has to resolve inside the temporary selected tree.
        if ! trace_has_header "$installed_include" "$header" "$diagnostic" && \
            ! trace_has_header "$candidate_compiler_builtin_include" "$header" "$diagnostic"; then
            fail "selected header was not observed in permitted roots: $header ($profile)"
        fi
        printf '%s\t%s\tcompile-ok\n' "$header" "$profile" >> "$records"
        record_count=$((record_count + 1))
    done < "$selected_paths"
done < <(printf '%s\n' "${PROFILES[@]}")
[ "$record_count" = "$EXPECTED_PROJECTION_RECORD_COUNT" ] ||
    fail "projection record count drifted: expected $EXPECTED_PROJECTION_RECORD_COUNT, got $record_count"

prepare_report_path
report_tmp="$(mktemp "$REPORT_DIR/.latest.tsv.tmp.XXXXXX")"
source_manifest_sha256="$(sha256sum "$source_manifest" | sed 's/[[:space:]].*$//')"
{
    printf '# schema=crabc.x86_64-selected-header-install-projection/v1\n'
    printf '# target=x86_64-unknown-linux-musl\n'
    printf '# platform=Linux/x86-64 little-endian\n'
    printf '# oracle=pinned musl 1.2.6 selected pathname inventory; linux_uapi=hash-pinned Linux 5.10\n'
    printf '# selected_public_header_count=%s\n' "$selected_count"
    printf '# excluded_project_only_header_count=%s\n' "$excluded_count"
    printf '# profile_count=%s\n' "$EXPECTED_PROFILE_COUNT"
    printf '# projection_record_count=%s\n' "$record_count"
    printf '# source_selection_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf '# materialization=selected public paths plus private project bits/** only; source-only paths are absent\n'
    printf '# candidate_isolation=-nostdinc; C++ also -nostdinc++; roots=selected-install, raw-GCC-builtin, Linux-5.10-UAPI\n'
    printf '# scope=private selected header install projection only; not declaration/layout/provider/linkage/runtime/sysroot/product/family-promotion/public-support evidence\n'
    printf '# result=pass\n'
    printf 'header\tprofile\tstatus\n'
    cat "$records"
} > "$report_tmp"
mv "$report_tmp" "$REPORT_PATH"
report_tmp=''
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"

printf 'x86 selected header install projection: PASS (%s records; %s)\n' \
    "$record_count" "$REPORT_PATH"
