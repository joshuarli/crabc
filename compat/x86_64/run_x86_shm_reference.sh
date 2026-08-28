#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw POSIX shared-memory reference.
#
# This private oracle compares the existing Rust facade's direct `/dev/shm`
# name mapping with musl 1.2.6's C/POSIX wrapper. It deliberately records
# musl's additional O_NOFOLLOW|O_NONBLOCK policy; it does not select a C IPC
# ABI, shared-memory mappings, SysV IPC, errno/TLS, or public x86 support.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 POSIX shared-memory reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-shm.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-shm-reference"
env -u CPATH -u C_INCLUDE_PATH -u CPLUS_INCLUDE_PATH -u LIBRARY_PATH \
    -u GCC_EXEC_PREFIX -u COMPILER_PATH \
    "$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_shm_reference_probe.c" -o "$probe"

expected='syscalls=fcntl:72,openat:257,unlinkat:263 namespace=dev-shm-tmpfs:name-max255 names=leading-slash-normalized:invalid-EINVAL:overlong-ENAMETOOLONG lifecycle=raw-create:musl-open:musl-unlink-after-open:musl-recreate:raw-unlink-after-open descriptors=mode0600:size0:cloexec flags=raw-cloexec-only:user-nonblock-direct:musl-cloexec-nonblock nofollow=raw-follows-symlink:raw-caller-nofollow-ELOOP:musl-ELOOP c-api-selection=excluded'

set +e
actual="$(env -u LD_LIBRARY_PATH -u LD_PRELOAD "$probe" 2>"$work_dir/probe.stderr")"
probe_status=$?
set -e
if [ "$probe_status" -ne 0 ]; then
    if [ -s "$work_dir/probe.stderr" ]; then
        sed 's/^/probe: /' "$work_dir/probe.stderr" >&2
    fi
    if [ "$probe_status" -eq 77 ]; then
        fail "/dev/shm must be a writable native tmpfs for POSIX shared-memory evidence (no fallback or skip)"
    fi
    fail "shared-memory probe failed with status $probe_status"
fi
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 POSIX shared-memory reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl/raw POSIX shared-memory reference: PASS\n'
