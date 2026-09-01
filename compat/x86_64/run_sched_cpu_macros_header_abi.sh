#!/usr/bin/env bash
# Native Linux/x86-64 GNU <sched.h> CPU-set construction macro gate.
#
# Pinned musl 1.2.6 is the header oracle. This is syntax/type/visibility
# evidence only: its calloc/free/memcmp/memset references neither link nor run,
# and it selects no allocator, byte-string, affinity, or scheduler behavior.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 GNU sched CPU-set macros: %s\n' "$*" >&2
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
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

c_probe="$ROOT_DIR/compat/x86_64/sched_cpu_macros_header_abi_probe.c"
cxx_probe="$ROOT_DIR/compat/x86_64/sched_cpu_macros_header_abi_probe.cpp"
work_dir="$(mktemp -d /tmp/crabc-x86-64-sched-cpu-macros.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

strict_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__ -DCRABC_REQUIRE_CPU_MACROS_HIDDEN)
posix_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -DCRABC_REQUIRE_CPU_MACROS_HIDDEN)
xopen_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -DCRABC_REQUIRE_CPU_MACROS_HIDDEN)
bsd_definitions=(-U_GNU_SOURCE -D_BSD_SOURCE=1 -DCRABC_REQUIRE_CPU_MACROS_HIDDEN)
gnu_definitions=(-D_GNU_SOURCE -DCRABC_EXPECT_CPU_MACROS)
cxx_strict_definitions=(-DCRABC_EXPECT_CPU_MACROS)
cxx_forced_hidden_definitions=(-U_GNU_SOURCE -U_BSD_SOURCE -U_DEFAULT_SOURCE -D__STRICT_ANSI__ -DCRABC_REQUIRE_CPU_MACROS_HIDDEN)

for definitions_name in strict_definitions posix_definitions xopen_definitions bsd_definitions gnu_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    "$ORACLE_CC" -std=c11 -fno-builtin -Werror=implicit-function-declaration \
        "${definitions[@]}" -fsyntax-only "$c_probe"
    "$ORACLE_CC" -std=c11 -fno-builtin -Werror=implicit-function-declaration \
        "${definitions[@]}" -I "$ROOT_DIR/include" -fsyntax-only "$c_probe"
done

for definitions_name in gnu_definitions cxx_strict_definitions cxx_forced_hidden_definitions; do
    declare -n definitions_ref="$definitions_name"
    definitions=("${definitions_ref[@]}")
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${definitions[@]}" \
        -fsyntax-only "$cxx_probe"
    "$ORACLE_CC" -std=c++17 -x c++ -fno-builtin "${definitions[@]}" \
        -I "$ROOT_DIR/include" -fsyntax-only "$cxx_probe"
done

# -H makes the project-header root observable, rather than accepting a host
# sched.h that happens to define a similar CPU-set macro family.
if ! "$ORACLE_CC" -std=c11 -fno-builtin -Werror=implicit-function-declaration \
    "${gnu_definitions[@]}" -I "$ROOT_DIR/include" -H -fsyntax-only "$c_probe" \
    >/dev/null 2>"$header_trace"; then
    cat "$header_trace" >&2
    fail "project GNU C CPU-set macro contract drifted"
fi
for header in sched.h sys/types.h time.h features.h bits/alltypes.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "GNU C probe did not use the project <$header>"
done

printf 'x86 pinned-musl/project GNU C/C++ <sched.h> CPU-set macros: PASS\n'
