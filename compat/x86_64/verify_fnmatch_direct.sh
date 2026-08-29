#!/usr/bin/env bash
# Native Linux/x86-64 direct crabc-rs fnmatch archive proof.
#
# The x86 evidence image intentionally carries binutils but not Python. Keep
# this narrow archive check in its native lane while the shared Python verifier
# continues to prove the corresponding AArch64 archive contract.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ARCHIVE="${1:-$ROOT_DIR/target/x86_64-unknown-linux-musl/release/examples/libfnmatch_direct_probe.a}"

fail() {
    printf 'ERROR: x86 direct fnmatch archive proof: %s\n' "$*" >&2
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
printf '%s\n' "$defined" | grep -E '[[:space:]]crabc_rs_fnmatch_direct_probe$' >/dev/null \
    || fail "archive does not define the fnmatch probe entry point"

undefined="$(nm --undefined-only "$ARCHIVE")"
for symbol in fnmatch __errno_location malloc calloc realloc free; do
    if printf '%s\n' "$undefined" | grep -E "[[:space:]]${symbol}(@[^[:space:]]*)?$" >/dev/null; then
        fail "archive references forbidden public C ABI/allocation symbol: $symbol"
    fi
done

printf 'native x86 direct fnmatch proof: PASS (%s)\n' "$ARCHIVE"
