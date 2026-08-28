#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw inotify ABI and behavior reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 inotify reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-inotify.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-inotify-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_inotify_reference_probe.c" -o "$probe"

expected='syscalls=inotify_init1:294,inotify_add_watch:254,inotify_rm_watch:255 layout=size16:align4:wd0:mask4:cookie8:len12:name16 flags=nonblock:0x800:cloexec:0x80000 musl=nonblock:cloexec:create-byte-name:remove-ignored raw=matches-musl errors=invalid-flags:EINVAL:missing-path:ENOENT:overlong-path:ENAMETOOLONG:bad-fd:EBADF:bad-watch:EINVAL c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 inotify reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}
printf 'x86 pinned-musl/raw inotify reference: PASS\n'
