#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl signal-header ABI check.
#
# Compile the fixed GNU and POSIX declaration/layout assertions against musl
# 1.2.6, then repeat them with the project include directory first. This is a
# source-only public-header slice: it neither links code nor selects crabc-libc.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 signal header ABI: %s\n' "$*" >&2
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

# Prove the compiler/header provenance before using it as the declaration
# oracle for the target-specific signal-frame records.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

gnu_probe="$ROOT_DIR/compat/x86_64/signal_header_abi_probe.c"
posix_probe="$ROOT_DIR/compat/x86_64/signal_header_posix_abi_probe.c"
work_dir="$(mktemp -d /tmp/crabc-x86-64-signal-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

# First prove the fixed facts against the pinned C/POSIX oracle itself.
"$ORACLE_CC" -std=c11 -fsyntax-only "$gnu_probe"
"$ORACLE_CC" -std=c11 -fsyntax-only "$posix_probe"

# Then prove that both project-header-first contexts resolve <signal.h> from
# this tree. There is intentionally no object file or link step.
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -H -fsyntax-only "$gnu_probe" \
    >/dev/null 2>"$header_trace"
grep -Fq "$ROOT_DIR/include/signal.h" "$header_trace" || {
    fail "GNU probe did not use the project signal header"
}
for header in features.h bits/alltypes.h bits/signal.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" || {
        fail "GNU probe did not use the project <$header>"
    }
done
"$ORACLE_CC" -std=c11 -I "$ROOT_DIR/include" -fsyntax-only "$posix_probe"

# Pinned musl exposes sigisemptyset, sigandset, and sigorset only in its GNU
# block. Keep the same strict-POSIX C negative witnesses for the project
# header; the paired binary artifact owns its separate C++ declaration proof.
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -DCRABC_REQUIRE_SIGISEMPTYSET_HIDDEN -fsyntax-only "$posix_probe" \
    >"$work_dir/oracle-sigisemptyset-hidden.out" 2>&1; then
    fail "pinned musl exposes sigisemptyset outside _GNU_SOURCE"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -I "$ROOT_DIR/include" -DCRABC_REQUIRE_SIGISEMPTYSET_HIDDEN \
    -fsyntax-only "$posix_probe" >"$work_dir/project-sigisemptyset-hidden.out" \
    2>&1; then
    fail "project signal.h exposes sigisemptyset outside _GNU_SOURCE"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -DCRABC_REQUIRE_GNU_SIGNAL_SET_BINARY_HIDDEN -fsyntax-only "$posix_probe" \
    >"$work_dir/oracle-sigset-binary-hidden.out" 2>&1; then
    fail "pinned musl exposes sigandset/sigorset outside _GNU_SOURCE"
fi
if "$ORACLE_CC" -std=c11 -Werror=implicit-function-declaration \
    -I "$ROOT_DIR/include" -DCRABC_REQUIRE_GNU_SIGNAL_SET_BINARY_HIDDEN \
    -fsyntax-only "$posix_probe" >"$work_dir/project-sigset-binary-hidden.out" \
    2>&1; then
    fail "project signal.h exposes sigandset/sigorset outside _GNU_SOURCE"
fi

printf 'x86 pinned-musl GNU/POSIX signal header ABI: PASS\n'
