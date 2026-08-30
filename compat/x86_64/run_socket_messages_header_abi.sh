#!/usr/bin/env bash
# Native Linux/x86-64 C/C++ socket-message/options header ABI slice.
#
# Pinned musl 1.2.6 supplies the selected declaration, feature-visibility,
# record-layout, and C-linkage oracle. The project pass is compile-only except
# for the C ancillary-macro probe; it does not select a C runtime.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 socket-message/options header ABI: %s\n' "$*" >&2
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

readonly C_PROBE="$ROOT_DIR/compat/x86_64/socket_messages_header_abi_probe.c"
readonly CXX_PROBE="$ROOT_DIR/compat/x86_64/socket_messages_header_abi_probe.cpp"
readonly VISIBILITY_PROBE="$ROOT_DIR/compat/x86_64/socket_messages_header_visibility_probe.c"
work_dir="$(mktemp -d /tmp/crabc-x86-64-socket-messages-header.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
header_trace="$work_dir/header-trace"

compile_profile() {
    local name="$1"
    shift
    local -a flags=("$@")
    local musl_c="$work_dir/musl-${name}-c"
    local project_c="$work_dir/project-${name}-c"

    "$ORACLE_CC" -std=c11 "${flags[@]}" "$C_PROBE" -o "$musl_c"
    "$musl_c"
    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -fsyntax-only "$CXX_PROBE"

    "$ORACLE_CC" -std=c11 "${flags[@]}" -I "$ROOT_DIR/include" \
        -H "$C_PROBE" -o "$project_c" >/dev/null 2>"$header_trace"
    "$project_c"
    "$ORACLE_CC" -std=c++17 -x c++ "${flags[@]}" -I "$ROOT_DIR/include" \
        -fsyntax-only "$CXX_PROBE"
}

# POSIX suppresses musl's default BSD extension namespace; GNU additionally
# exposes mmsghdr/sendmmsg/recvmmsg. CMSG_ALIGN remains available in every
# profile, while the BSD pass keeps its non-GNU profile behavior covered.
compile_profile posix -U_GNU_SOURCE -U_BSD_SOURCE -D_POSIX_C_SOURCE=200809L
compile_profile gnu -U_BSD_SOURCE -D_GNU_SOURCE

for header in sys/socket.h sys/uio.h sys/ioctl.h sys/syscall.h bits/syscall.h \
    bits/alltypes.h time.h; do
    grep -Fq "$ROOT_DIR/include/$header" "$header_trace" ||
        fail "project GNU C probe did not use <$header>"
done
compile_profile bsd -U_GNU_SOURCE -D_BSD_SOURCE

# GNU-only message batches must not leak into the POSIX profile.
if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
    -D_POSIX_C_SOURCE=200809L -fsyntax-only \
    "$VISIBILITY_PROBE" >/dev/null 2>&1; then
    fail "pinned musl exposed GNU mmsghdr APIs in the POSIX profile"
fi
if "$ORACLE_CC" -std=c11 -U_GNU_SOURCE -U_BSD_SOURCE \
    -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" \
    -fsyntax-only "$VISIBILITY_PROBE" >/dev/null 2>&1; then
    fail "project headers exposed GNU mmsghdr APIs in the POSIX profile"
fi
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -fsyntax-only "$VISIBILITY_PROBE"
"$ORACLE_CC" -std=c11 -D_GNU_SOURCE -I "$ROOT_DIR/include" -fsyntax-only \
    "$VISIBILITY_PROBE"
if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
    -D_POSIX_C_SOURCE=200809L -fsyntax-only \
    "$VISIBILITY_PROBE" >/dev/null 2>&1; then
    fail "pinned musl exposed GNU mmsghdr APIs in the POSIX C++ profile"
fi
if "$ORACLE_CC" -std=c++17 -x c++ -U_GNU_SOURCE -U_BSD_SOURCE \
    -D_POSIX_C_SOURCE=200809L -I "$ROOT_DIR/include" -fsyntax-only \
    "$VISIBILITY_PROBE" >/dev/null 2>&1; then
    fail "project headers exposed GNU mmsghdr APIs in the POSIX C++ profile"
fi
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -fsyntax-only \
    "$VISIBILITY_PROBE"
"$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -I "$ROOT_DIR/include" \
    -fsyntax-only "$VISIBILITY_PROBE"

# References emitted by the C++ GNU probe must use unmangled C symbol names.
for mode in musl project; do
    object="$work_dir/${mode}-gnu-cpp.o"
    if [ "$mode" = musl ]; then
        "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -c "$CXX_PROBE" -o "$object"
    else
        "$ORACLE_CC" -std=c++17 -x c++ -D_GNU_SOURCE -I "$ROOT_DIR/include" \
            -c "$CXX_PROBE" -o "$object"
    fi
    undefined="$(nm -u "$object")"
    for symbol in setsockopt getsockopt sendmsg recvmsg sendmmsg recvmmsg sockatmark; do
        printf '%s\n' "$undefined" | grep -Eq "[[:space:]]${symbol}$" ||
            fail "${mode} C++ GNU probe lacks unmangled ${symbol} reference"
    done
done

printf 'x86 pinned-musl C/C++ socket-message/options header ABI: PASS\n'
