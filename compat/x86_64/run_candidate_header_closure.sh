#!/usr/bin/env bash
# Native Linux/x86-64 isolated C11/C++17 public-header closure diagnostic.
#
# The candidate side intentionally does not use the musl-specs wrapper: each
# compilation invokes the image's raw GCC with only the project include tree,
# that compiler's builtin headers, and the separately hash-pinned Linux 5.10
# UAPI tree. The reference side uses the pinned-musl compiler wrapper. A
# successful record therefore proves
# empty-translation-unit header closure, not declarations, layouts, linkage,
# runtime coverage, installed-header completion, or public x86 support.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly CANDIDATE_CC=/usr/bin/gcc
readonly INVENTORY="$ROOT_DIR/compat/x86_64/public_headers.txt"
readonly CXX_CLOSURE_PROBE="$ROOT_DIR/compat/x86_64/header_cxx_closure.cpp"
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/candidate-header-closure"
readonly REPORT_PATH="$REPORT_DIR/latest.tsv"
readonly PROJECT_INCLUDE="$ROOT_DIR/include"
readonly LINUX_UAPI_ROOT=/opt/linux-5.10-uapi
readonly LINUX_UAPI_INCLUDE="$LINUX_UAPI_ROOT/include"
readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183
readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191
readonly EXPECTED_CANDIDATE_ONLY_HEADER_COUNT=8
# One record is one resolved public header through one intentional language /
# feature-profile consumer. Keep this closed seven-profile matrix distinct
# from declaration, layout, linkage, and runtime evidence.
readonly EXPECTED_PROFILE_COUNT=7
readonly EXPECTED_RECORD_COUNT=1337
readonly -a PROFILES=(c11-gnu cxx17-gnu c11-strict c11-posix-2008 c11-xopen-700 c11-bsd cxx17-strict)
# Pinned musl 1.2.6 itself cannot consume <aio.h> in the macro-free C11/C++17
# profiles: its public record embeds struct sigevent while <signal.h> keeps
# that record incomplete without a POSIX/GNU feature request. The profile
# matrix records those two oracle-not-applicable rows explicitly; it never
# suppresses a candidate header failure or a new oracle failure.
readonly -a ORACLE_NOT_APPLICABLE_ROWS=(aio.h:c11-strict aio.h:cxx17-strict)

fail() {
    printf 'ERROR: x86 candidate header closure: %s\n' "$*" >&2
    exit 1
}

validate_profile_contract() {
    local profile
    declare -A observed_profiles=()

    [ "${#PROFILES[@]}" -eq "$EXPECTED_PROFILE_COUNT" ] ||
        fail "profile count drifted: expected $EXPECTED_PROFILE_COUNT, got ${#PROFILES[@]}"
    for profile in "${PROFILES[@]}"; do
        if [[ -v "observed_profiles[$profile]" ]]; then
            fail "profile list contains duplicate $profile"
        fi
        observed_profiles["$profile"]=1
    done
}

validate_oracle_not_applicable_contract() {
    local row
    local profile
    declare -A declared_rows=()

    for row in "${ORACLE_NOT_APPLICABLE_ROWS[@]}"; do
        case "$row" in
            *.h:*) profile="${row#*:}" ;;
            *) fail "invalid oracle-not-applicable row: $row" ;;
        esac
        if [[ -v "declared_rows[$row]" ]]; then
            fail "oracle-not-applicable row is duplicated: $row"
        fi
        declared_rows["$row"]=1
        if ! [[ " ${PROFILES[*]} " == *" $profile "* ]]; then
            fail "oracle-not-applicable row uses unknown profile: $row"
        fi
    done
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

validate_header_name() {
    case "$1" in
        ''|/*|*'..'*|*$'\t'*|*$'\r'*|*$'\n'*)
            fail "unsafe public-header inventory entry: $1"
            ;;
    esac
}

run_compiler() {
    local compiler="$1"
    shift

    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u GCC_SPECS -u COMPILER_PATH \
        "$compiler" "$@"
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
        # GCC otherwise predefines _GNU_SOURCE for C++ invocations; remove
        # it so this profile exercises the declared macro-free C++17 form.
        cxx17-strict) printf '%s\n' '-U_GNU_SOURCE' ;;
        *) fail "unknown language profile: $1" ;;
    esac
}

oracle_not_applicable() {
    local header="$1"
    local profile="$2"
    local diagnostic="$3"
    local row

    for row in "${ORACLE_NOT_APPLICABLE_ROWS[@]}"; do
        if [ "$row" = "$header:$profile" ]; then
            # This is a pinned-musl source behavior, not a generic reference
            # failure waiver: aio.h embeds aio_sigevent, whose type stays
            # incomplete in signal.h without a POSIX/GNU feature request.
            grep -Fq 'aio_sigevent' "$diagnostic" &&
                grep -Fq 'incomplete type' "$diagnostic"
            return
        fi
    done
    return 1
}

write_source() {
    local header="$1"
    local profile="$2"
    local source="$3"
    local language

    language="$(profile_language "$profile")"

    case "$language" in
        c)
            printf '#include <%s>\nint main(void) { return 0; }\n' "$header" > "$source"
            ;;
        cxx)
            printf '#include <%s>\nint main() { return 0; }\n' "$header" > "$source"
            ;;
        *) fail "unknown language profile: $language" ;;
    esac
}

compile_header() {
    local tree="$1"
    local profile="$2"
    local source="$3"
    local stdout_path="$4"
    local diagnostic_path="$5"
    local include_root
    local compiler
    local language
    local -a profile_args
    local -a arguments

    language="$(profile_language "$profile")"
    mapfile -t profile_args < <(profile_arguments "$profile")

    case "$tree" in
        candidate)
            include_root="$PROJECT_INCLUDE"
            compiler="$CANDIDATE_CC"
            ;;
        reference)
            include_root="$MUSL_ROOT/include"
            compiler="$ORACLE_CC"
            ;;
        *) fail "unknown header tree: $tree" ;;
    esac

    arguments=(
        -nostdinc
        -I "$include_root"
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
        *) fail "unknown language profile: $language" ;;
    esac

    run_compiler "$compiler" "${arguments[@]}" > "$stdout_path" 2> "$diagnostic_path"
}

trace_has_header() {
    local trace="$1"
    local root="$2"
    local header="$3"

    grep -Fq "$root/$header" "$trace"
}

trace_paths() {
    sed -n -E 's/^[. ]+ (\/[^[:space:]]+).*$/\1/p' "$1"
}

trace_has_unapproved_candidate_path() {
    local trace="$1"
    local path

    while IFS= read -r path; do
        case "$path" in
            "$PROJECT_INCLUDE"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*)
                ;;
            *) return 0 ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

trace_has_unapproved_reference_path() {
    local trace="$1"
    local path

    while IFS= read -r path; do
        case "$path" in
            "$MUSL_ROOT/include"/*|"$candidate_compiler_builtin_include"/*|"$LINUX_UAPI_INCLUDE"/*)
                ;;
            *) return 0 ;;
        esac
    done < <(trace_paths "$trace")
    return 1
}

candidate_bits_state() {
    local trace="$1"
    local path
    local observed=false

    while IFS= read -r path; do
        case "$path" in
            */bits/*)
                observed=true
                case "$path" in
                    "$PROJECT_INCLUDE"/bits/*) ;;
                    *) printf '%s\n' nonproject; return ;;
                esac
                ;;
        esac
    done < <(trace_paths "$trace")
    if [ "$observed" = true ]; then
        printf '%s\n' project-only
    else
        printf '%s\n' none
    fi
}

uapi_state() {
    local trace="$1"

    if grep -Fq "$LINUX_UAPI_INCLUDE/" "$trace"; then
        printf '%s\n' linux-5.10-used
    else
        printf '%s\n' not-used
    fi
}

reference_header_root() {
    local trace="$1"
    local header="$2"

    # GCC owns a small standard-header subset (for example float.h and
    # stddef.h) even when its caller is the pinned-musl oracle wrapper. That
    # is an explicitly declared raw-GCC builtin input, not an ambient escape.
    # The report retains which permitted root supplied the top-level path.
    if trace_has_header "$trace" "$MUSL_ROOT/include" "$header"; then
        printf '%s\n' pinned-musl
    elif trace_has_header "$trace" "$candidate_compiler_builtin_include" "$header"; then
        printf '%s\n' raw-gcc-builtin
    else
        printf '%s\n' not-observed
    fi
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

    # The native image runs as root over a developer-owned bind mount. Refuse
    # unsafe report components before creating, replacing, or chowning the
    # diagnostic output.
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

[ "$#" -eq 0 ] || fail "usage: $0"

require_native_linux_x86_64
for tool in chown comm diff find grep mkdir mktemp mv realpath sed sort stat tr wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -x "$CANDIDATE_CC" ] || fail "missing raw native candidate compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$PROJECT_INCLUDE" ] || fail "missing project include tree"
[ -f "$INVENTORY" ] || fail "missing checked-in public-header inventory"
[ -f "$CXX_CLOSURE_PROBE" ] || fail "missing focused C++ header-closure probe"
validate_profile_contract
validate_oracle_not_applicable_contract

# Verify both inputs before compiling. The UAPI verifier establishes a fixed
# Linux 5.10 input. Candidate commands then use raw GCC plus -nostdinc, so
# they cannot inherit the musl wrapper's unconditional pinned-musl include.
# Candidate trace rejection remains a defense-in-depth check.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
bash "$ROOT_DIR/compat/x86_64/run_linux_5_10_uapi.sh" >/dev/null

candidate_compiler_builtin_include="$(run_compiler "$CANDIDATE_CC" -print-file-name=include)"
case "$candidate_compiler_builtin_include" in
    /*) ;;
    *) fail "raw candidate compiler did not report an absolute builtin include directory" ;;
esac
candidate_compiler_builtin_include="$(realpath "$candidate_compiler_builtin_include")"
[ -d "$candidate_compiler_builtin_include" ] || fail "missing raw candidate compiler builtin include directory"
[ "$candidate_compiler_builtin_include" != "$MUSL_ROOT/include" ] ||
    fail "compiler builtin include directory aliases the pinned musl tree"

work_dir="$(mktemp -d /tmp/crabc-x86-64-candidate-header-closure.XXXXXX)"
report_tmp=''
trap 'rm -rf -- "$work_dir"; [ -z "$report_tmp" ] || rm -f -- "$report_tmp"' EXIT

pinned_observed="$work_dir/pinned-public-headers"
candidate_observed="$work_dir/candidate-public-headers"
candidate_only="$work_dir/candidate-only"
records="$work_dir/records.tsv"
source="$work_dir/header.c"
compiler_stdout="$work_dir/compiler-stdout"
reference_diagnostic="$work_dir/reference-diagnostic"
candidate_diagnostic="$work_dir/candidate-diagnostic"
cxx_closure_stdout="$work_dir/cxx-closure-stdout"
cxx_closure_diagnostic="$work_dir/cxx-closure-diagnostic"

list_public_headers "$MUSL_ROOT/include" > "$pinned_observed"
list_public_headers "$PROJECT_INCLUDE" > "$candidate_observed"
if ! diff -u "$INVENTORY" "$pinned_observed"; then
    fail "checked-in inventory drifted from pinned musl 1.2.6 public headers"
fi
comm -13 "$pinned_observed" "$candidate_observed" > "$candidate_only"
pinned_public_header_count="$(wc -l < "$pinned_observed" | tr -d '[:space:]')"
candidate_public_header_count="$(wc -l < "$candidate_observed" | tr -d '[:space:]')"
candidate_only_header_count="$(wc -l < "$candidate_only" | tr -d '[:space:]')"
[ "$pinned_public_header_count" = "$EXPECTED_PINNED_PUBLIC_HEADER_COUNT" ] ||
    fail "pinned public-header count drifted: expected $EXPECTED_PINNED_PUBLIC_HEADER_COUNT, got $pinned_public_header_count"
[ "$candidate_public_header_count" = "$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT" ] ||
    fail "candidate public-header count drifted: expected $EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT, got $candidate_public_header_count"
[ "$candidate_only_header_count" = "$EXPECTED_CANDIDATE_ONLY_HEADER_COUNT" ] ||
    fail "candidate-only public-header count drifted: expected $EXPECTED_CANDIDATE_ONLY_HEADER_COUNT, got $candidate_only_header_count"

prepare_report_path
report_tmp="$(mktemp "$REPORT_DIR/.latest.tsv.tmp.XXXXXX")"
: > "$records"

# The per-header rows below establish empty-TU closure across the complete
# inventory. Keep this focused compile alongside them because it also names
# the C++ spellings that previously regressed: alternative tokens, C++ builtin
# character types, and the affected C declaration pointer types.
if ! compile_header candidate cxx17-gnu "$CXX_CLOSURE_PROBE" "$cxx_closure_stdout" \
    "$cxx_closure_diagnostic"; then
    fail "focused C++ header-closure probe failed: $(first_diagnostic "$cxx_closure_diagnostic")"
fi
if grep -Fq "$MUSL_ROOT/include/" "$cxx_closure_diagnostic"; then
    fail "focused C++ header-closure probe reached pinned musl despite -nostdinc"
fi
if trace_has_unapproved_candidate_path "$cxx_closure_diagnostic"; then
    fail "focused C++ header-closure probe escaped project/builtin/Linux-5.10 roots"
fi
if [ "$(candidate_bits_state "$cxx_closure_diagnostic")" = nonproject ]; then
    fail "focused C++ header-closure probe reached a non-project bits header"
fi
for header in aio.h err.h iso646.h regex.h stdatomic.h uchar.h; do
    trace_has_header "$cxx_closure_diagnostic" "$PROJECT_INCLUDE" "$header" ||
        fail "focused C++ header-closure probe did not preprocess project $header"
done

declare -A status_counts=()
declare -A observed_oracle_not_applicable_rows=()
record_count=0
incomplete_count=0

record_result() {
    local header="$1"
    local profile="$2"
    local language="$3"
    local scope="$4"
    local status="$5"
    local reference="$6"
    local reference_root="$7"
    local candidate="$8"
    local candidate_root="$9"
    local candidate_bits="${10}"
    local uapi="${11}"
    local detail="${12}"

    detail="$(printf '%s' "$detail" | tr '\t\r\n' ' ' )"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$header" "$profile" "$language" "$scope" "$status" "$reference" "$reference_root" \
        "$candidate" "$candidate_root" "$candidate_bits" "$uapi" "$detail" >> "$records"
    status_counts["$status"]=$(( ${status_counts["$status"]:-0} + 1 ))
    if [ "$status" = reference-not-applicable ]; then
        local row="$header:$profile"
        observed_oracle_not_applicable_rows["$row"]=$(( ${observed_oracle_not_applicable_rows["$row"]:-0} + 1 ))
    fi
    record_count=$((record_count + 1))
    case "$status" in
        closure-ok|candidate-only-closure-ok|reference-not-applicable) ;;
        *) incomplete_count=$((incomplete_count + 1)) ;;
    esac
}

compile_pinned_header() {
    local header="$1"
    local profile="$2"
    local language
    local reference_status
    local reference_root
    local candidate_status
    local candidate_root
    local candidate_bits
    local uapi
    local status
    local detail

    language="$(profile_language "$profile")"
    validate_header_name "$header"
    if [ ! -f "$PROJECT_INCLUDE/$header" ]; then
        record_result "$header" "$profile" "$language" pinned candidate-missing \
            not-run not-observed missing missing none not-observed \
            'project public header is absent'
        return
    fi

    write_source "$header" "$profile" "$source"
    if compile_header reference "$profile" "$source" "$compiler_stdout" \
        "$reference_diagnostic"; then
        reference_status=compile-ok
    else
        reference_status=failed
    fi
    if compile_header candidate "$profile" "$source" "$compiler_stdout" \
        "$candidate_diagnostic"; then
        candidate_status=compile-ok
    else
        candidate_status=failed
    fi

    reference_root="$(reference_header_root "$reference_diagnostic" "$header")"

    if trace_has_header "$candidate_diagnostic" "$PROJECT_INCLUDE" "$header"; then
        candidate_root=project
    else
        candidate_root=not-observed
    fi
    candidate_bits="$(candidate_bits_state "$candidate_diagnostic")"
    uapi="$(uapi_state "$candidate_diagnostic")"

    if trace_has_unapproved_reference_path "$reference_diagnostic"; then
        status=reference-include-escape
        detail='reference include trace escaped the pinned musl/builtin/Linux-5.10 roots'
    elif [ "$reference_status" != compile-ok ] && ! oracle_not_applicable "$header" "$profile" "$reference_diagnostic"; then
        status=reference-compile-failed
        detail="$(first_diagnostic "$reference_diagnostic")"
    elif [ "$reference_root" = not-observed ]; then
        status=reference-root-not-observed
        detail='reference translation unit did not preprocess the pinned-musl or raw-GCC builtin top-level header'
    elif grep -Fq "$MUSL_ROOT/include/" "$candidate_diagnostic"; then
        status=candidate-musl-fallback
        detail='candidate include trace reached pinned musl despite -nostdinc'
    elif trace_has_unapproved_candidate_path "$candidate_diagnostic"; then
        status=candidate-include-escape
        detail='candidate include trace escaped project/builtin/Linux-5.10 roots'
    elif [ "$candidate_root" != project ]; then
        status=candidate-root-not-observed
        detail='candidate translation unit did not preprocess the project public header'
    elif [ "$candidate_bits" = nonproject ]; then
        status=candidate-private-bits-escape
        detail='candidate include trace reached a non-project bits header'
    elif [ "$candidate_status" != compile-ok ]; then
        case "$language" in
            c) status=candidate-c-compile-failed ;;
            cxx) status=candidate-cxx-compile-failed ;;
        esac
        detail="$(first_diagnostic "$candidate_diagnostic")"
    elif [ "$reference_status" != compile-ok ]; then
        status=reference-not-applicable
        detail='pinned musl aio.h embeds incomplete struct sigevent without a POSIX/GNU feature request; candidate closure remains separately recorded'
    else
        status=closure-ok
        detail='isolated project-header closure'
    fi
    record_result "$header" "$profile" "$language" pinned "$status" "$reference_status" \
        "$reference_root" "$candidate_status" "$candidate_root" "$candidate_bits" \
        "$uapi" "$detail"
}

compile_candidate_only_header() {
    local header="$1"
    local profile="$2"
    local language
    local candidate_status
    local candidate_root
    local candidate_bits
    local uapi
    local status
    local detail

    language="$(profile_language "$profile")"
    validate_header_name "$header"
    write_source "$header" "$profile" "$source"
    if compile_header candidate "$profile" "$source" "$compiler_stdout" \
        "$candidate_diagnostic"; then
        candidate_status=compile-ok
    else
        candidate_status=failed
    fi
    if trace_has_header "$candidate_diagnostic" "$PROJECT_INCLUDE" "$header"; then
        candidate_root=project
    else
        candidate_root=not-observed
    fi
    candidate_bits="$(candidate_bits_state "$candidate_diagnostic")"
    uapi="$(uapi_state "$candidate_diagnostic")"

    if grep -Fq "$MUSL_ROOT/include/" "$candidate_diagnostic"; then
        status=candidate-only-musl-fallback
        detail='candidate-only include trace reached pinned musl despite -nostdinc'
    elif trace_has_unapproved_candidate_path "$candidate_diagnostic"; then
        status=candidate-only-include-escape
        detail='candidate-only include trace escaped project/builtin/Linux-5.10 roots'
    elif [ "$candidate_root" != project ]; then
        status=candidate-only-root-not-observed
        detail='candidate-only translation unit did not preprocess the project public header'
    elif [ "$candidate_bits" = nonproject ]; then
        status=candidate-only-private-bits-escape
        detail='candidate-only include trace reached a non-project bits header'
    elif [ "$candidate_status" != compile-ok ]; then
        case "$language" in
            c) status=candidate-only-c-compile-failed ;;
            cxx) status=candidate-only-cxx-compile-failed ;;
        esac
        detail="$(first_diagnostic "$candidate_diagnostic")"
    else
        status=candidate-only-closure-ok
        detail='isolated project-only header closure'
    fi
    record_result "$header" "$profile" "$language" candidate-only "$status" \
        not-in-pinned-inventory not-applicable "$candidate_status" "$candidate_root" \
        "$candidate_bits" "$uapi" "$detail"
}

for profile in "${PROFILES[@]}"; do
    while IFS= read -r header; do
        compile_pinned_header "$header" "$profile"
    done < "$pinned_observed"
done

for profile in "${PROFILES[@]}"; do
    while IFS= read -r header; do
        compile_candidate_only_header "$header" "$profile"
    done < "$candidate_only"
done

for row in "${ORACLE_NOT_APPLICABLE_ROWS[@]}"; do
    [ "${observed_oracle_not_applicable_rows["$row"]:-0}" -eq 1 ] ||
        fail "oracle-not-applicable row drifted: expected exactly one $row record"
done
[ "${#observed_oracle_not_applicable_rows[@]}" -eq "${#ORACLE_NOT_APPLICABLE_ROWS[@]}" ] ||
    fail "oracle-not-applicable row drifted: observed an undeclared row"

[ "$record_count" = "$EXPECTED_RECORD_COUNT" ] ||
    fail "header-closure record count drifted: expected $EXPECTED_RECORD_COUNT, got $record_count"

result=pass
[ "$incomplete_count" -eq 0 ] || result=incomplete
{
    printf '# schema=crabc.x86_64-candidate-header-closure/v3\n'
    printf '# target=x86_64-unknown-linux-musl\n'
    printf '# platform=Linux/x86-64 little-endian\n'
    printf '# oracle=Pinned musl 1.2.6\n'
    printf '# linux_uapi=hash-pinned Linux 5.10 exported headers at %s\n' "$LINUX_UAPI_INCLUDE"
    printf '# profiles=%s\n' "${PROFILES[*]}"
    printf '# candidate_compiler=/usr/bin/gcc without musl specs; candidate_include_inputs=project include, raw-GCC builtin include, Linux 5.10 UAPI only\n'
    printf '# reference_compiler=crabc-x86_64-musl-gcc; reference_include_inputs=pinned musl include, raw-GCC builtin include, Linux 5.10 UAPI\n'
    printf '# candidate_isolation=-nostdinc for all profiles; C++ also uses -nostdinc++; trace rejects any musl or non-project bits escape\n'
    printf '# scope=empty-TU include closure only; not declaration/layout/linkage/runtime/installed-header/public-support parity\n'
    printf '# pinned_public_header_count=%s\n' "$pinned_public_header_count"
    printf '# candidate_public_header_count=%s\n' "$candidate_public_header_count"
    printf '# candidate_only_header_count=%s\n' "$candidate_only_header_count"
    printf '# record_count=%s\n' "$record_count"
    printf '# incomplete_record_count=%s\n' "$incomplete_count"
    printf '# result=%s\n' "$result"
    for status in "${!status_counts[@]}"; do
        printf '# status.%s=%s\n' "$status" "${status_counts["$status"]}"
    done | LC_ALL=C sort
    printf 'header\tprofile\tlanguage\tscope\tstatus\treference\treference_root\tcandidate\tcandidate_root\tcandidate_bits\tuapi\tdetail\n'
    cat "$records"
} > "$report_tmp"

mv "$report_tmp" "$REPORT_PATH"
report_tmp=''
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"

if [ "$result" = pass ]; then
    printf 'x86 isolated C/C++ candidate header closure: PASS (%s records; %s)\n' \
        "$record_count" "$REPORT_PATH"
    exit 0
fi

printf 'x86 isolated C/C++ candidate header closure: INCOMPLETE (%s unresolved records; %s)\n' \
    "$incomplete_count" "$REPORT_PATH" >&2
exit 1
