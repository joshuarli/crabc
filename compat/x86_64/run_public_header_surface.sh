#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl public-header C consumability inventory.
#
# The checked-in list is derived from the pinned musl 1.2.6 installed public
# tree (not a selected hand-maintained subset). Each listed header is compiled
# once with the pinned tree and once with the project tree first. This proves
# only C11+GNU header consumability: it deliberately does not compare
# declarations, constants, layouts, archives, runtime behavior, or public x86
# support. This legacy runner intentionally does not add the image's declared
# Linux 5.10 UAPI root to either compiler input, so its three UAPI-dependent
# reference headers remain explicit report records.
set -euo pipefail
export LC_ALL=C

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly MUSL_ROOT=/opt/musl-1.2.6
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
readonly INVENTORY="$ROOT_DIR/compat/x86_64/public_headers.txt"
readonly REPORT_DIR="$ROOT_DIR/compat/reports/x86_64/public-header-surface"
readonly REPORT_PATH="$REPORT_DIR/latest.tsv"
readonly EXPECTED_PINNED_PUBLIC_HEADER_COUNT=183
readonly EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT=191
readonly EXPECTED_COMPILE_OK_COUNT=180
readonly EXPECTED_REFERENCE_UAPI_UNAVAILABLE_COUNT=3
readonly EXPECTED_CANDIDATE_ONLY_COUNT=8

fail() {
    printf 'ERROR: x86 public-header surface: %s\n' "$*" >&2
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

uapi_dependency_for() {
    case "$1" in
        sys/kd.h) printf '%s\n' linux/kd.h ;;
        sys/soundcard.h) printf '%s\n' linux/soundcard.h ;;
        sys/vt.h) printf '%s\n' linux/vt.h ;;
        *) return 1 ;;
    esac
}

compile_reference() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH \
        "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fsyntax-only "$1"
}

compile_candidate() {
    env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
        -u GCC_EXEC_PREFIX -u COMPILER_PATH \
        "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" \
        -fsyntax-only "$1"
}

show_diagnostic() {
    local label="$1"
    local path="$2"

    printf '%s:\n' "$label" >&2
    sed -n '1,80p' "$path" >&2
}

prepare_report_path() {
    local path

    # This runner executes as container root over a developer-owned bind
    # mount. Refuse a pre-existing symlink or non-directory anywhere in its
    # dedicated ignored-report path before creating, writing, or chowning it.
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
    [ -d "$REPORT_DIR" ] && [ ! -L "$REPORT_DIR" ] \
        || fail "report directory is unsafe after creation: $REPORT_DIR"
    [ ! -L "$REPORT_PATH" ] || fail "report path is a symlink: $REPORT_PATH"
    if [ -e "$REPORT_PATH" ] && [ ! -f "$REPORT_PATH" ]; then
        fail "report path is not a regular file: $REPORT_PATH"
    fi
}

require_native_linux_x86_64
for tool in chown comm diff find grep mkdir mktemp mv sed sort stat tr wc; do
    require_tool "$tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
[ -d "$MUSL_ROOT/include" ] || fail "missing pinned musl include tree"
[ -d "$ROOT_DIR/include" ] || fail "missing project include tree"
[ -f "$INVENTORY" ] || fail "missing checked-in public-header inventory"

# The inventory relies on the exact source-built oracle, not Alpine headers.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-public-headers.XXXXXX)"
report_tmp=''
trap 'rm -rf -- "$work_dir"; [ -z "$report_tmp" ] || rm -f -- "$report_tmp"' EXIT

pinned_observed="$work_dir/pinned-public-headers"
candidate_observed="$work_dir/candidate-public-headers"
missing_candidate="$work_dir/missing-candidate"
candidate_only="$work_dir/candidate-only"
source="$work_dir/header.c"
reference_diagnostic="$work_dir/reference-diagnostic"
candidate_diagnostic="$work_dir/candidate-diagnostic"

list_public_headers "$MUSL_ROOT/include" > "$pinned_observed"
list_public_headers "$ROOT_DIR/include" > "$candidate_observed"

if ! diff -u "$INVENTORY" "$pinned_observed"; then
    fail "checked-in inventory drifted from pinned musl 1.2.6 public headers"
fi

comm -23 "$pinned_observed" "$candidate_observed" > "$missing_candidate"
if [ -s "$missing_candidate" ]; then
    sed 's/^/missing project public header: /' "$missing_candidate" >&2
    fail "project public-header tree is missing pinned musl entries"
fi
comm -13 "$pinned_observed" "$candidate_observed" > "$candidate_only"

prepare_report_path
report_tmp="$(mktemp "$REPORT_DIR/.latest.tsv.tmp.XXXXXX")"

pinned_count="$(wc -l < "$pinned_observed" | tr -d '[:space:]')"
candidate_count="$(wc -l < "$candidate_observed" | tr -d '[:space:]')"
candidate_only_count="$(wc -l < "$candidate_only" | tr -d '[:space:]')"
compile_ok_count=0
reference_uapi_unavailable_count=0

{
    printf '# schema=crabc.x86_64-public-header-surface/v1\n'
    printf '# target=x86_64-unknown-linux-musl\n'
    printf '# platform=Linux/x86-64 little-endian\n'
    printf '# oracle=Pinned musl 1.2.6\n'
    printf '# mode=C11 with _GNU_SOURCE; project headers first\n'
    printf '# scope=header consumability only; not declaration/layout/linkage/runtime/public-support parity\n'
    printf '# pinned_public_header_count=%s\n' "$pinned_count"
    printf '# candidate_public_header_count=%s\n' "$candidate_count"
    printf '# candidate_only_header_count=%s\n' "$candidate_only_count"
    printf 'header\tstatus\treference\tcandidate\n'
} > "$report_tmp"

while IFS= read -r header; do
    printf '#include <%s>\nint main(void) { return 0; }\n' "$header" > "$source"

    if compile_reference "$source" > "$reference_diagnostic" 2>&1; then
        reference_status=compile-ok
    else
        reference_status=failed
    fi
    if compile_candidate "$source" > "$candidate_diagnostic" 2>&1; then
        candidate_status=compile-ok
    else
        candidate_status=failed
    fi

    if [ "$reference_status" = compile-ok ] && [ "$candidate_status" = compile-ok ]; then
        printf '%s\tcompile-ok\tcompile-ok\tcompile-ok\n' "$header" >> "$report_tmp"
        compile_ok_count=$((compile_ok_count + 1))
        continue
    fi

    uapi_dependency=''
    if uapi_dependency="$(uapi_dependency_for "$header")" \
        && [ "$reference_status" = failed ] \
        && grep -Fq "${uapi_dependency}: No such file or directory" "$reference_diagnostic"; then
        if [ "$candidate_status" = failed ] \
            && grep -Fq "${uapi_dependency}: No such file or directory" "$candidate_diagnostic"; then
            printf '%s\treference-uapi-unavailable\tmissing-%s\tmissing-%s\n' \
                "$header" "$uapi_dependency" "$uapi_dependency" >> "$report_tmp"
            reference_uapi_unavailable_count=$((reference_uapi_unavailable_count + 1))
            continue
        fi
    fi

    printf 'ERROR: incompatible public-header consumability for %s\n' "$header" >&2
    show_diagnostic 'pinned musl diagnostic' "$reference_diagnostic"
    show_diagnostic 'project-header diagnostic' "$candidate_diagnostic"
    exit 1
done < "$pinned_observed"

while IFS= read -r header; do
    printf '%s\tcandidate-only\tnot-in-pinned-inventory\tpresent\n' "$header" >> "$report_tmp"
done < "$candidate_only"

[ "$pinned_count" = "$EXPECTED_PINNED_PUBLIC_HEADER_COUNT" ] \
    || fail "pinned public-header count changed: expected $EXPECTED_PINNED_PUBLIC_HEADER_COUNT, got $pinned_count"
[ "$candidate_count" = "$EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT" ] \
    || fail "candidate public-header count changed: expected $EXPECTED_CANDIDATE_PUBLIC_HEADER_COUNT, got $candidate_count"
[ "$compile_ok_count" = "$EXPECTED_COMPILE_OK_COUNT" ] \
    || fail "jointly consumable header count changed: expected $EXPECTED_COMPILE_OK_COUNT, got $compile_ok_count"
[ "$reference_uapi_unavailable_count" = "$EXPECTED_REFERENCE_UAPI_UNAVAILABLE_COUNT" ] \
    || fail "reference-UAPI-unavailable header count changed: expected $EXPECTED_REFERENCE_UAPI_UNAVAILABLE_COUNT, got $reference_uapi_unavailable_count"
[ "$candidate_only_count" = "$EXPECTED_CANDIDATE_ONLY_COUNT" ] \
    || fail "candidate-only header count changed: expected $EXPECTED_CANDIDATE_ONLY_COUNT, got $candidate_only_count"

mv "$report_tmp" "$REPORT_PATH"
report_tmp=''
# Docker runs this native evidence lane as root, while the bind-mounted
# checkout belongs to the invoking developer. Keep this generated report
# inspectable and replaceable by that developer without changing source-tree
# ownership or relying on a host-side post-processing step.
chown "$(stat -c '%u:%g' "$ROOT_DIR")" "$REPORT_DIR" "$REPORT_PATH"
printf 'x86 pinned-musl/public-header C consumability: PASS (%s pinned; %s compile-ok; %s reference-UAPI-unavailable; %s candidate-only; %s)\n' \
    "$pinned_count" "$compile_ok_count" "$reference_uapi_unavailable_count" \
    "$candidate_only_count" "$REPORT_PATH"
