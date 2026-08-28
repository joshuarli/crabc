#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw socket and address transport reference.
set -euo pipefail
readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc
fail() { printf 'ERROR: x86 socket transport reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null
work_dir="$(mktemp -d /tmp/crabc-x86-64-socket.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-socket-transport-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_socket_transport_reference_probe.c" -o "$probe"
expected='syscalls=ioctl:16,socket:41,socketpair:53,bind:49,listen:50,connect:42,accept:43,accept4:288,getsockname:51,getpeername:52,shutdown:48,setsockopt:54,sendto:44,recvfrom:45,sendmsg:46,recvmsg:47,recvmmsg:299,sendmmsg:307 abi=iovec16:msghdr56:mmsghdr64:sockaddr_in16:sockaddr_in6-28:storage128 libc-raw=socketpair:udp:ipv6:tcp:options:msg:mmsg errors=EINVAL:invalid-type,ENOPROTOOPT-or-EOPNOTSUPP:invalid-level,EBADF:closed-fd c-api-selection=excluded'
actual="$(cd "$work_dir" && env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || { printf 'ERROR: output mismatch\nexpected: %s\nactual: %s\n' "$expected" "$actual" >&2; exit 1; }
printf 'x86 pinned-musl/raw socket and address transport ABI/behavior reference: PASS\n'
