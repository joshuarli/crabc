#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw interface-device reference.
#
# It proves the fixed `ifreq` ioctl and rtnetlink record contracts used by the
# Rust facade. The probe uses only loopback/self-consistency assertions: it
# does not turn host-specific interface order or counts into a contract.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 interface-device reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"

# Establish compiler/header/runtime provenance before using musl as the oracle.
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-interface-device.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-interface-device-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH -u LD_PRELOAD \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_interface_device_reference_probe.c" \
    -o "$probe"

expected='syscalls=ioctl:16,socket:41,sendto:44,recvmsg:47 abi=ifreq40:iovec16:msghdr56:netlink16:ifinfomsg16:ifaddrmsg8:rtattr4 ioctl=loopback-index-name:invalid-index-ENODEV rtnetlink=link-dump:ipv4-loopback:ipv6-loopback:truncation-checked raw=matches-musl c-api-selection=excluded'
actual="$(cd "$work_dir" && env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH \
    -u LIBRARY_PATH -u GCC_EXEC_PREFIX -u COMPILER_PATH -u LD_LIBRARY_PATH \
    -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 interface-device reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw interface-device ABI/behavior reference: PASS\n'
