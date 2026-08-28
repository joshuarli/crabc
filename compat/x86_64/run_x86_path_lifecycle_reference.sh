#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl pathname lifecycle and metadata reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 path lifecycle reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-path-lifecycle.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-path-lifecycle-reference"
"$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_path_lifecycle_reference_probe.c" -o "$probe"
expected='stat=144/offsets=proved openat=257 newfstatat=262 truncate=76 mkdirat=258 mknodat=259 unlinkat=263 chmod=fchmod91/fchmodat268 chown=fchown93/fchownat260 lifecycle=regular/symlink/fifo/dirs errors=ENOENT'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 path lifecycle reference output mismatch\nexpected: %s\nactual: %s\n' "$expected" "$actual" >&2
    exit 1
}
printf 'x86 pinned-musl/raw pathname lifecycle and metadata reference: PASS\n'
