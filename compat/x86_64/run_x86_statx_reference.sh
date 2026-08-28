#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw statx ABI and metadata reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 statx reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-statx.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-statx-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_statx_reference_probe.c" -o "$probe"

available='statx=332 layout=size256:align8:offsets-through-dio156 at=fdcwd:-100:nofollow:0x100:no-automount:0x800:empty-path:0x1000:force-sync:0x2000:dont-sync:0x4000 mask=basic:0x7ff:btime:0x800:mnt-id:0x1000:dioalign:0x2000:reserved:0x80000000 musl=path:absolute:follow:nofollow:empty-path raw=matches-musl errors=empty-without-flag:ENOENT:missing:ENOENT:sync-conflict:EINVAL:reserved-mask:EINVAL c-api-selection=excluded'
raw_enosys='statx=332 layout=size256:align8:offsets-through-dio156 at=fdcwd:-100:nofollow:0x100:no-automount:0x800:empty-path:0x1000:force-sync:0x2000:dont-sync:0x4000 mask=basic:0x7ff:btime:0x800:mnt-id:0x1000:dioalign:0x2000:reserved:0x80000000 musl=path:absolute:follow:nofollow:empty-path raw=ENOSYS-musl-fallback errors=empty-without-flag:ENOENT:missing:ENOENT:sync-conflict:EINVAL direct-mask-errors=unavailable c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
case "$actual" in
    "$available"|"$raw_enosys") ;;
    *)
        printf 'ERROR: x86 statx reference output mismatch\navailable: %s\nraw-ENOSYS: %s\nactual: %s\n' \
            "$available" "$raw_enosys" "$actual" >&2
        exit 1
        ;;
esac

printf 'x86 pinned-musl/raw statx ABI and metadata reference: PASS\n'
