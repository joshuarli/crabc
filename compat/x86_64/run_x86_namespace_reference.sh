#!/usr/bin/env bash
# Native Linux/x86-64 pinned-musl/raw namespace-links reference.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ORACLE_CC=/usr/local/bin/crabc-x86_64-musl-gcc

fail() { printf 'ERROR: x86 namespace reference: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "refuses emulation on $(uname -m)" ;; esac
[ -x "$ORACLE_CC" ] || fail "missing pinned musl oracle compiler"
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-64-namespace.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
probe="$work_dir/x86-namespace-reference"
"$ORACLE_CC" -std=c11 "$ROOT_DIR/compat/x86_64/x86_namespace_reference_probe.c" -o "$probe"
expected='symlinkat=266 readlinkat=267 linkat=265 renameat2=316 flags=NOREPLACE:1,EXCHANGE:2,WHITEOUT:4,EMPTY_PATH:4096,NOFOLLOW:256,FOLLOW:1024 raw=matches-musl descriptor-relative=proved hardlink=inode-equal symlink=exact-short-no-nul replacement=proved errors=EEXIST,EINVAL,ENOENT cleanup=deterministic'
actual="$($probe)"
[ "$actual" = "$expected" ] || {
    printf 'ERROR: x86 namespace reference output mismatch\nexpected: %s\nactual: %s\n' "$expected" "$actual" >&2
    exit 1
}
printf 'x86 pinned-musl/raw namespace-links reference: PASS\n'
