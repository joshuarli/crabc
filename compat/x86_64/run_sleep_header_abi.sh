#!/usr/bin/env bash
# Native Linux/x86-64 all-profile sleep C/C++ declaration gate.
#
# Pinned musl 1.2.6 is the declaration and C-linkage oracle. Project headers
# are placed first for the candidate pass; neither pass links or selects
# crabc-libc. POSIX `sleep(unsigned)` is visible in every tested profile.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 unistd.h sleep ABI: %s\n' "$*" >&2
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

c_probe="$ROOT_DIR/compat/x86_64/sleep_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/sleep_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-sleep-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"
oracle_cxx_object="$work_dir/oracle-sleep-cxx.o"
candidate_cxx_object="$work_dir/candidate-sleep-cxx.o"

for selector in default -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200809L \
    -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -D_BSD_SOURCE; do
    if [ "$selector" = default ]; then
        selector_args=()
    else
        selector_args=("$selector")
    fi
    "$ORACLE_CC" -std=c11 "${selector_args[@]}" -DCRABC_EXPECT_SLEEP \
        -fno-builtin -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${selector_args[@]}" \
        -DCRABC_EXPECT_SLEEP -fno-builtin -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c11 "${selector_args[@]}" -DCRABC_EXPECT_SLEEP \
        -fno-builtin -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c++17 -x c++ "${selector_args[@]}" \
        -DCRABC_EXPECT_SLEEP -fno-builtin -I "$ROOT_DIR/include" \
        -fsyntax-only "$cxx_probe"
done

if ! "$ORACLE_CC" -std=c11 -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_SLEEP -fno-builtin -I "$ROOT_DIR/include" -H \
    -fsyntax-only "$c_probe" >/dev/null 2>"$header_trace"; then
    sed -n '1,160p' "$header_trace" >&2
    fail "project C sleep header contract drifted"
fi
for header in unistd.h features.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "C probe did not use the project <$header>"
done

"$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_SLEEP -fno-builtin -c "$cxx_probe" \
    -o "$oracle_cxx_object"
"$ORACLE_CC" -std=c++17 -x c++ -D_POSIX_C_SOURCE=200809L \
    -DCRABC_EXPECT_SLEEP -fno-builtin -I "$ROOT_DIR/include" \
    -c "$cxx_probe" -o "$candidate_cxx_object"
for object in "$oracle_cxx_object" "$candidate_cxx_object"; do
    undefined="$(nm --undefined-only "$object")"
    printf '%s\n' "$undefined" | grep -Eq '[[:space:]]sleep$' ||
        fail "C++ probe does not retain C linkage for sleep"
    if printf '%s\n' "$undefined" | grep -Eq '_Z5sleepj'; then
        fail "C++ probe retained a mangled sleep reference"
    fi
done

printf 'x86 pinned-musl/project C/C++ <unistd.h> sleep ABI: PASS\n'
