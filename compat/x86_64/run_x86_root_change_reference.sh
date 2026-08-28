#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw process-root-change reference.
#
# The C APIs are oracle-only for a private typed Rust boundary. Each successful
# root change occurs in a disposable child; this launcher selects no C ABI,
# errno/TLS contract, confinement framework, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 root-change reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-root-change.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-root-change-reference"

env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_root_change_reference_probe.c" \
    -o "$probe"

set +e
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
status=$?
set -e

success='chroot=161 raw+musl=success root=absolute-inside cwd=preserved-relative errors=ENOENT,ENOTDIR child-contained'
unavailable='chroot=161 raw+musl=EPERM privilege=unavailable child-contained'
if [ "$status" -eq 0 ] && [ "$actual" = "$success" ]; then
    printf 'x86 pinned-musl/raw process-root-change reference: PASS\n'
    exit 0
fi
if [ "$status" -eq 77 ] && [ "$actual" = "$unavailable" ]; then
    printf 'ERROR: x86 root-change reference requires CAP_SYS_CHROOT; evidence not established\n' >&2
    exit 77
fi

printf 'ERROR: x86 root-change reference failed (status %s)\nexpected success: %s\nactual: %s\n' \
    "$status" "$success" "$actual" >&2
exit 1
