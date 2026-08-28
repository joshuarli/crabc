#!/usr/bin/env bash
# Native Linux/x86-64 stdlib callback-algorithms ABI slice.
#
# Pinned musl 1.2.6 supplies declaration and C-linkage evidence. `bsearch`
# and `qsort` are unconditional; GNU/BSD select the GNU-signature qsort_r
# declaration, while strict/POSIX/XOPEN selectors keep it—and musl's private
# __qsort_r helper—out of installed headers.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 stdlib callback algorithms ABI: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/callback_algorithms_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/callback_algorithms_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-callback-algorithms-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-callback-algorithms-cxx.o"
candidate_cxx_object="$work_dir/candidate-callback-algorithms-cxx.o"

compile_selected_declarations() {
    local -a definitions=("$@")
    local variant
    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "${definitions[@]}" \
            -fsyntax-only "${include_args[@]}" "$cxx_probe"
    done
}

# The first pass proves that bsearch/qsort do not depend on any extension
# selector. The next two prove musl's GNU-signature qsort_r declaration under
# both of the source-supported public selectors.
compile_selected_declarations -D__STRICT_ANSI__
compile_selected_declarations -D_GNU_SOURCE -DCRABC_EXPECT_QSORT_R
compile_selected_declarations -D_BSD_SOURCE -DCRABC_EXPECT_QSORT_R

if ! "$ORACLE_CC" -std=c11 -D_GNU_SOURCE -DCRABC_EXPECT_QSORT_R \
    -I "$ROOT_DIR/include" \
    -H -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project callback-algorithms C header contract drifted"
fi
for header in stdlib.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" \
        || fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_GNU_SOURCE \
    -DCRABC_EXPECT_QSORT_R \
    -c "$cxx_probe" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D_GNU_SOURCE \
    -DCRABC_EXPECT_QSORT_R \
    -I "$ROOT_DIR/include" -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    for symbol in bsearch qsort qsort_r; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" \
            || fail "C++ probe does not retain C linkage for ${symbol}"
    done
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*(bsearch|qsort)'; then
        fail "C++ probe retained a mangled callback-algorithms reference"
    fi
done

assert_hidden_declaration() {
    local selector_name="$1" forbidden_macro="$2"
    shift 2
    local -a selector=("$@")
    local language variant
    for language in c cxx; do
        for variant in oracle project; do
            local -a include_args=()
            if [ "$variant" = project ]; then
                include_args=(-I "$ROOT_DIR/include")
            fi
            if [ "$language" = c ]; then
                if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "${selector[@]}" \
                    "-D${forbidden_macro}" -fsyntax-only "${include_args[@]}" \
                    "$c_probe" >/dev/null 2>"$work_dir/${selector_name}-${variant}-c-errors"; then
                    fail "${forbidden_macro} is visible under ${selector_name} C selection (${variant})"
                fi
            elif "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE \
                "${selector[@]}" "-D${forbidden_macro}" -fsyntax-only \
                "${include_args[@]}" "$cxx_probe" \
                >/dev/null 2>"$work_dir/${selector_name}-${variant}-cxx-errors"; then
                fail "${forbidden_macro} is visible under ${selector_name} C++ selection (${variant})"
            fi
        done
    done
}

for selector_name in strict posix xopen; do
    case "$selector_name" in
        strict) selector=(-D__STRICT_ANSI__) ;;
        posix) selector=(-D_POSIX_C_SOURCE=200809L) ;;
        xopen) selector=(-D_XOPEN_SOURCE=700) ;;
    esac
    assert_hidden_declaration "$selector_name" CRABC_REQUIRE_QSORT_R "${selector[@]}"
done
assert_hidden_declaration gnu CRABC_REQUIRE_INTERNAL_QSORT_R -D_GNU_SOURCE
assert_hidden_declaration bsd CRABC_REQUIRE_INTERNAL_QSORT_R -D_BSD_SOURCE

printf 'x86 pinned-musl/project C/C++ stdlib callback algorithms ABI: PASS\n'
