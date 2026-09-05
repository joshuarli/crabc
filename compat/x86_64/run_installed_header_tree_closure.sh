#!/usr/bin/env bash
# Private native Linux/x86-64 installed-header-tree closure diagnostic.
#
# This runner proves only that a fresh regular-file materialization of the
# repository's `include/` tree supplies the existing isolated 1,337-row C11 /
# C++17 header-closure matrix. It deliberately reuses that matrix, raw GCC,
# pinned musl 1.2.6 reference, and hash-pinned Linux 5.10 UAPI policy instead
# of introducing a second, weaker compiler harness. It is header-tree closure
# only: not ABI/layout/linkage/sysroot/promotion/public-support parity.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly CANDIDATE_CLOSURE_RUNNER="$ROOT_DIR/compat/x86_64/run_candidate_header_closure.sh"
readonly MUSL_ORACLE_RUNNER="$ROOT_DIR/compat/x86_64/run_musl_oracle.sh"
readonly MUSL_ORACLE_PROBE="$ROOT_DIR/compat/x86_64/musl_oracle_probe.c"
readonly LINUX_UAPI_RUNNER="$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh"
readonly INVENTORY="$ROOT_DIR/compat/x86_64/public_headers.txt"
readonly CXX_CLOSURE_PROBE="$ROOT_DIR/compat/x86_64/header_cxx_closure.cpp"
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/installed-header-tree-closure"
readonly REPORT_PATH="$REPORT_DIR/latest.tsv"
readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183
readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_RECORD_COUNT=1337
readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)

fail() {
    printf 'ERROR: x86 installed header-tree closure: %s\n' "$*" >&2
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
            fail "unsafe installed-header relative path: $1"
            ;;
    esac
}

validate_regular_header_tree() {
    local root="$1"
    local path

    [ -d "$root" ] || fail "header tree is not a directory: $root"
    [ ! -L "$root" ] || fail "header tree is a symlink: $root"

    while IFS= read -r path; do
        [ ! -L "$path" ] || fail "source header tree contains a symlink: $path"
        if [ -d "$path" ] || [ -f "$path" ]; then
            continue
        fi
        fail "source header tree contains a non-regular path: $path"
    done < <(find "$root" -mindepth 1 -print | LC_ALL=C sort)
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

materialize_header_tree() {
    local source_root="$1"
    local installed_root="$2"
    local path
    local relative

    validate_regular_header_tree "$source_root"
    mkdir -p "$installed_root"
    [ -d "$installed_root" ] && [ ! -L "$installed_root" ] ||
        fail "fresh installed include root is unsafe: $installed_root"

    while IFS= read -r path; do
        relative="${path#"$source_root"/}"
        validate_relative_path "$relative"
        mkdir -p "$installed_root/$relative"
    done < <(find "$source_root" -mindepth 1 -type d -print | LC_ALL=C sort)

    while IFS= read -r path; do
        relative="${path#"$source_root"/}"
        validate_relative_path "$relative"
        mkdir -p "$(dirname "$installed_root/$relative")"
        cp -- "$path" "$installed_root/$relative"
    done < <(find "$source_root" -type f -print | LC_ALL=C sort)

    validate_regular_header_tree "$source_root"
    validate_regular_header_tree "$installed_root"
}

prepare_report_path() {
    local path

    for path in \
        "$ROOT_DIR/compat" \
        "$ROOT_DIR/compat/reports" \
        "$ROOT_DIR/compat/reports/x86_64" \
        "$REPORT_DIR"; do
        [ ! -L "$path" ] || fail "report path component is a symlink: $path"
        if [ -e "$path" ] && [ ! -d "$path" ]; then
            fail "report path component is not a directory: $path"
        fi
    done
    mkdir -p "$REPORT_DIR"
    [ -d "$REPORT_DIR" ] && [ ! -L "$REPORT_DIR" ] ||
        fail "report directory is unsafe after creation: $REPORT_DIR"
    [ ! -L "$REPORT_PATH" ] || fail "report path is a symlink: $REPORT_PATH"
    if [ -e "$REPORT_PATH" ] && [ ! -f "$REPORT_PATH" ]; then
        fail "report path is not a regular file: $REPORT_PATH"
    fi
}

copy_runner_input() {
    local source="$1"
    local destination="$2"

    [ -f "$source" ] && [ ! -L "$source" ] ||
        fail "closure harness input is unsafe: $source"
    cp -- "$source" "$destination"
    [ -f "$destination" ] && [ ! -L "$destination" ] ||
        fail "copied closure harness input is unsafe: $destination"
}

prepare_materialized_runner() {
    local project_root="$1"
    local runner="$project_root/compat/x86_64/run_candidate_header_closure.sh"

    mkdir -p "$project_root/compat/x86_64" "$project_root/usr"
    copy_runner_input "$CANDIDATE_CLOSURE_RUNNER" "$runner"
    copy_runner_input "$MUSL_ORACLE_RUNNER" "$project_root/compat/x86_64/run_musl_oracle.sh"
    copy_runner_input "$MUSL_ORACLE_PROBE" "$project_root/compat/x86_64/musl_oracle_probe.c"
    copy_runner_input "$LINUX_UAPI_RUNNER" "$project_root/compat/x86_64/run_linux_5_10_uapi.sh"
    copy_runner_input "$INVENTORY" "$project_root/compat/x86_64/public_headers.txt"
    copy_runner_input "$CXX_CLOSURE_PROBE" "$project_root/compat/x86_64/header_cxx_closure.cpp"

    # Repoint exactly the existing runner's candidate tree. Every compiler
    # argument, profile, oracle exception, trace check, row count, and report
    # validation remains owned by `run_candidate_header_closure.sh`.
    sed -i \
        's|readonly PROJECT_INCLUDE="$ROOT_DIR/include"|readonly PROJECT_INCLUDE="$ROOT_DIR/usr/include"|' \
        "$runner"
    grep -Fxq 'readonly PROJECT_INCLUDE="$ROOT_DIR/usr/include"' "$runner" ||
        fail "could not redirect existing closure runner to materialized usr/include"
    chmod 755 "$runner" "$project_root/compat/x86_64/run_musl_oracle.sh" \
        "$project_root/compat/x86_64/run_linux_5_10_uapi.sh"
}

[ "$#" -eq 0 ] || fail "usage: $0"

require_native_linux_x86_64
for tool in bash chown cp diff find grep mkdir mktemp mv realpath sed sha256sum sort stat tr wc; do
    require_tool "$tool"
done
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -x "$CANDIDATE_CLOSURE_RUNNER" ] || fail "missing existing candidate header-closure runner"
[ -x "$MUSL_ORACLE_RUNNER" ] || fail "missing pinned musl oracle runner"
[ -x "$LINUX_UAPI_RUNNER" ] || fail "missing Linux 5.10 UAPI verifier"
[ -f "$MUSL_ORACLE_PROBE" ] || fail "missing pinned musl oracle probe"
[ -f "$INVENTORY" ] || fail "missing checked-in public-header inventory"
[ -f "$CXX_CLOSURE_PROBE" ] || fail "missing focused C++ header-closure probe"

readonly temporary_root="${TMPDIR:-}"
case "$temporary_root" in
    "$ROOT_DIR"/.work/*) ;;
    *) fail "TMPDIR must be a physical checkout .work directory" ;;
esac
[ -d "$temporary_root" ] && [ "$(realpath "$temporary_root")" = "$temporary_root" ] ||
    fail "TMPDIR must be a physical checkout .work directory"
work_dir="$(mktemp -d "$temporary_root/crabc-x86-64-installed-header-tree-closure.XXXXXX")"
report_tmp=''
trap 'rm -rf -- "$work_dir"; [ -z "$report_tmp" ] || rm -f -- "$report_tmp"' EXIT

materialized_project="$work_dir/project"
installed_include="$materialized_project/usr/include"
source_manifest="$work_dir/source-manifest.tsv"
installed_manifest="$work_dir/installed-manifest.tsv"
child_stdout="$work_dir/candidate-closure-stdout"
child_stderr="$work_dir/candidate-closure-stderr"
child_report="$materialized_project/compat/reports/x86_64/candidate-header-closure/latest.tsv"

mkdir -p "$materialized_project"
materialize_header_tree "$PROJECT_INCLUDE" "$installed_include"
write_manifest "$PROJECT_INCLUDE" "$source_manifest"
write_manifest "$installed_include" "$installed_manifest"
if ! diff -u "$source_manifest" "$installed_manifest"; then
    fail "installed header manifest differs from source tree"
fi
source_manifest_sha256="$(sha256sum "$source_manifest" | sed 's/[[:space:]].*$//')"

prepare_materialized_runner "$materialized_project"
# The copied oracle derives its checkout boundary from the materialized
# project. Give that project its own physical scratch beneath the outer
# checkout's contained work tree instead of inheriting the parent's TMPDIR.
materialized_temporary="$materialized_project/.work/x86_64/tmp"
mkdir -p "$materialized_temporary"
if ! TMPDIR="$materialized_temporary" "$materialized_project/compat/x86_64/run_candidate_header_closure.sh" \
    >"$child_stdout" 2>"$child_stderr"; then
    cat "$child_stderr" >&2
    fail "existing candidate header-closure matrix failed against materialized usr/include"
fi
[ -f "$child_report" ] && [ ! -L "$child_report" ] ||
    fail "existing closure runner did not produce a regular report"
grep -Fxq "# record_count=$EXPECTED_RECORD_COUNT" "$child_report" ||
    fail "existing closure report lost the 1,337-row contract"
grep -Fxq "# pinned_public_header_count=$EXPECTED_PINNED_PUBLIC_HEADER_COUNT" "$child_report" ||
    fail "existing closure report lost the pinned public-header inventory"
grep -Fxq "# candidate_public_header_count=$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT" "$child_report" ||
    fail "existing closure report lost the materialized candidate public-header inventory"
grep -Fq "# profiles=c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict" \
    "$child_report" || fail "existing closure report lost the seven-profile contract"
grep -Fxq '# status.reference-not-applicable=2' "$child_report" ||
    fail "existing closure report did not preserve exactly two aio strict oracle-N/A rows"
grep -Fxq '# result=pass' "$child_report" ||
    fail "existing closure report is not a passing installed-tree closure"

# The copied runner's candidate root is exactly `usr/include`; its preprocessor
# `-H` trace accepts that tree, raw-GCC builtin headers, and the pinned Linux
# 5.10 UAPI only. Its C++ invocation retains `-nostdinc++`. It rejects the
# original source include tree, pinned musl, and ambient/non-project `bits`
# paths before this wrapper can accept its pass.
if grep -Fq "$PROJECT_INCLUDE/" "$child_report"; then
    fail "candidate include trace reached source include tree"
fi
if grep -Fq '/opt/musl-1.2.6/include/' "$child_report"; then
    fail "candidate include trace reached pinned musl despite -nostdinc"
fi
if grep -Fq 'candidate-include-escape' "$child_report" || \
    grep -Fq 'candidate-private-bits-escape' "$child_report"; then
    fail "candidate include trace escaped installed-tree/builtin/Linux-5.10 roots"
fi

prepare_report_path
report_tmp="$(mktemp "$REPORT_DIR/.latest.tsv.tmp.XXXXXX")"
{
    printf '# schema=crabc.x86_64-installed-header-tree-closure/v1\n'
    printf '# target=x86_64-unknown-linux-musl\n'
    printf '# platform=Linux/x86-64 little-endian\n'
    printf '# source_tree=repository include/ regular files only\n'
    printf '# materialized_root=fresh temporary usr/include\n'
    printf '# manifest=deterministic relative-path plus SHA-256; sha256=%s\n' "$source_manifest_sha256"
    printf '# closure_runner=run_candidate_header_closure.sh redirected only to the materialized usr/include\n'
    printf '# oracle=pinned musl 1.2.6; linux_uapi=hash-pinned Linux 5.10; candidate_compiler=raw GCC with -nostdinc\n'
    printf '# closure_contract=%s records; aio strict oracle-not-applicable rows=%s\n' \
        "$EXPECTED_RECORD_COUNT" "${#ORACLE_NOT_APPLICABLE_ROWS[@]}"
    printf '# scope=header-tree closure only; not ABI/layout/linkage/sysroot/promotion/public-support parity\n'
    printf '# result=pass\n'
    printf '# candidate-closure-report-begin\n'
    cat "$child_report"
} > "$report_tmp"
mv "$report_tmp" "$REPORT_PATH"
report_tmp=''
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"

printf 'x86 installed header-tree closure: PASS (%s records; %s)\n' \
    "$EXPECTED_RECORD_COUNT" "$REPORT_PATH"
