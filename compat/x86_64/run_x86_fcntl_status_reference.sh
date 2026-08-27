#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw fcntl status-flags reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() {
    printf 'ERROR: x86 fcntl status reference: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in
    x86_64|amd64) ;;
    *) fail "refuses emulation on $(uname -m)" ;;
esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-fcntl-status.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-fcntl-status-reference"

"$ORACLE_CC" -std=c11 \
    "$ROOT_DIR/compat/x86_64/x86_fcntl_status_reference_probe.c" \
    -o "$probe"
expected='syscall=72 commands=F_GETFL-3/F_SETFL-4 access=immutable-O_RDWR creation=excluded status=shared-open-description fd-cloexec=per-descriptor mutation=append+nonblock restoration=exact invalid=EBADF'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 fcntl status reference output mismatch\nexpected: %s\nactual: %s\n' \
        "$expected" "$actual" >&2
    exit 1
}

printf 'x86 pinned-musl fcntl status-flags reference: PASS\n'
