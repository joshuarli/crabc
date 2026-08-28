#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw extended-attribute reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 xattr reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-xattr.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-xattr-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_xattr_reference_probe.c" -o "$probe"

supported='syscalls=set:188,lset:189,fset:190,get:191,lget:192,fget:193,list:194,llist:195,flist:196,remove:197,lremove:198,fremove:199 flags=create:1,replace:2 raw=matches-musl forms=path:nofollow:fd value=binary:size-query:prefix list=nul-separated:size-query errors=EEXIST:ENODATA:EINVAL:ERANGE cleanup=deterministic c-api-selection=excluded'
unavailable='syscalls=set:188,lset:189,fset:190,get:191,lget:192,fget:193,list:194,llist:195,flist:196,remove:197,lremove:198,fremove:199 xattr=unavailable:EOPNOTSUPP-or-ENOSYS raw=matches-musl cleanup=deterministic c-api-selection=excluded'
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe")"
case "$actual" in
    "$supported"|"$unavailable") ;;
    *)
        printf 'ERROR: x86 xattr reference output mismatch\nsupported: %s\nunavailable: %s\nactual: %s\n' \
            "$supported" "$unavailable" "$actual" >&2
        exit 1
        ;;
esac
printf 'x86 pinned-musl/raw xattr reference: PASS\n'
