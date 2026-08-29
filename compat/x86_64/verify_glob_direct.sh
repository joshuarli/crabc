#!/usr/bin/env bash
# Native Linux/x86-64 direct crabc-rs glob archive proof.
#
# The allocation-enabled probe supplies its own fixed Rust allocator. This
# check intentionally permits Rust allocation internals while rejecting any
# public C glob, directory-stream, errno-TLS, or allocator boundary.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ARCHIVE="${1:-$ROOT_DIR/target/x86_64-unknown-linux-musl/release/examples/libglob_direct_probe.a}"

fail() {
    printf 'ERROR: x86 direct glob archive proof: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "requires native Linux"
case "$(uname -m)" in x86_64|amd64) ;; *) fail "requires native x86-64" ;; esac
command -v readelf >/dev/null 2>&1 || fail "requires readelf"
command -v nm >/dev/null 2>&1 || fail "requires nm"
[ -f "$ARCHIVE" ] || fail "archive does not exist: $ARCHIVE"

header="$(readelf --file-header "$ARCHIVE")"
printf '%s\n' "$header" | grep -F 'Advanced Micro Devices X86-64' >/dev/null \
    || fail "archive is not an x86-64 ELF member"

defined="$(nm --defined-only "$ARCHIVE")"
printf '%s\n' "$defined" | grep -E '[[:space:]]crabc_rs_glob_direct_probe$' >/dev/null \
    || fail "archive does not define the glob probe entry point"

undefined="$(nm --undefined-only "$ARCHIVE")"
for symbol in \
    glob globfree fnmatch \
    opendir readdir readdir64 closedir scandir \
    __errno_location \
    malloc calloc realloc reallocarray free aligned_alloc posix_memalign memalign valloc pvalloc malloc_usable_size
do
    if printf '%s\n' "$undefined" | grep -E "[[:space:]]${symbol}(@[^[:space:]]*)?$" >/dev/null; then
        fail "archive references forbidden public C ABI/allocation symbol: $symbol"
    fi
done

printf 'native x86 direct glob proof: PASS (%s)\n' "$ARCHIVE"
