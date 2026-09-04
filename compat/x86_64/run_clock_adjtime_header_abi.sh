#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ <sys/timex.h> clock_adjtime ABI gate.
#
# Pinned musl 1.2.6 is the declaration, x86 record-layout, and linkage oracle.
# The Linux spelling is visible in strict, POSIX, X/Open, and GNU C11/C++17
# profiles. This is header-only evidence, not clock adjustment, authority,
# time-discipline, timer, or general time support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 sys/timex.h clock_adjtime ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

compile_profile() {
    local profile="$1" definition="$2" language variant compiler include_args object undefined

    for language in c cxx; do
        for variant in oracle project; do
            compiler="$ORACLE_CC"
            include_args=()
            if [ "$variant" = project ]; then
                include_args=(-I "$ROOT_DIR/include")
            fi
            if [ "$language" = c ]; then
                "$compiler" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                    "$definition" -Werror=implicit-function-declaration \
                    "${include_args[@]}" -fsyntax-only "$c_probe"
            else
                object="$work_dir/${variant}-${profile}-clock-adjtime-cxx.o"
                "$compiler" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
                    -U_XOPEN_SOURCE -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE \
                    "$definition" "${include_args[@]}" -c "$cxx_probe" -o "$object"
                undefined="$(nm --undefined-only "$object")"
                printf '%s\n' "$undefined" | grep -Eq '[[:space:]]clock_adjtime$' ||
                    fail "C++ probe does not retain C linkage for clock_adjtime (${variant}, ${profile})"
                if printf '%s\n' "$undefined" | grep -Eq '_Z.*clock_adjtime'; then
                    fail "C++ probe retained a mangled clock_adjtime reference (${variant}, ${profile})"
                fi
            fi
        done
    done
}

require_native_linux_x86_64
for tool in grep mktemp nm uname; do
    command -v "$tool" >/dev/null 2>&1 || fail "requires $tool"
done
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/clock_adjtime_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/clock_adjtime_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-clock-adjtime-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

compile_profile strict -D__STRICT_ANSI__
compile_profile posix -D_POSIX_C_SOURCE=200809L
compile_profile xopen -D_XOPEN_SOURCE=700
compile_profile gnu -D_GNU_SOURCE

header_trace="$work_dir/project-strict-header-trace"
if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE -U_XOPEN_SOURCE \
    -U_POSIX_C_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__ \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project strict C clock_adjtime header contract drifted"
fi
for header in sys/timex.h sys/time.h sys/select.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "strict C probe did not use the project <$header>"
done
if grep -Fq "$ROOT_DIR/include/sys/types.h" "$header_trace"; then
    fail "strict C probe leaked <sys/types.h> through <sys/timex.h>"
fi

printf 'x86 pinned-musl/project C/C++ <sys/timex.h> clock_adjtime ABI: PASS\n'
