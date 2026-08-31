#!/usr/bin/env bash
# Native Linux/x86-64 wchar.h wcswcs C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. `wcswcs` is
# unconditional in wchar.h, so strict, POSIX, X/Open, GNU, and BSD profiles
# retain its same C and C++ function-pointer ABI. Project headers are placed
# first only for the candidate pass; this gate does not link crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 wchar.h wcswcs ABI: %s\n' "$*" >&2
    exit 1
}

require_native_linux_x86_64() {
    [ "$(uname -s)" = Linux ] || fail "requires native Linux"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "refuses emulation on $(uname -m)" ;;
    esac
}

require_native_linux_x86_64
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
command -v nm >/dev/null 2>&1 || fail "requires nm"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/wcswcs_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/wcswcs_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-wcswcs-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-wcswcs-cxx.o"
candidate_cxx_object="$work_dir/candidate-wcswcs-cxx.o"

compile_profile() {
    local selector="$1" variant

    for variant in oracle project; do
        local -a include_args=()
        if [ "$variant" = project ]; then
            include_args=(-I "$ROOT_DIR/include")
        fi
        "$ORACLE_CC" -std=c11 -U_GNU_SOURCE "$selector" -fno-builtin \
            -fsyntax-only "${include_args[@]}" "$c_probe"
        "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE "$selector" \
            -fno-builtin -fsyntax-only "${include_args[@]}" "$cxx_probe"
    done
}

for selector in -D__STRICT_ANSI__ -D_POSIX_C_SOURCE=200809L \
    -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    compile_profile "$selector"
done

if ! "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -D__STRICT_ANSI__ -fno-builtin \
    -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C wcswcs header contract drifted"
fi
for header in wchar.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D__STRICT_ANSI__ \
    -fno-builtin -c "$cxx_probe" -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -D__STRICT_ANSI__ \
    -fno-builtin -I "$ROOT_DIR/include" -c "$cxx_probe" \
    -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]wcswcs$' ||
        fail "C++ probe does not retain C linkage for wcswcs"
    if printf '%s\n' "$undefined" | grep -Eq '_Z[0-9].*wcswcs'; then
        fail "C++ probe retained a mangled wcswcs reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <wchar.h> wcswcs ABI: PASS\n'
