#!/usr/bin/env bash
# Native state evidence for the private x86 RuntimeV1 initial TLS registry.
#
# This compiles only the typed loader-owned registry under the pinned native
# image. It proves initial one-based IDs and generation one seal cleanly, and
# that a runtime TLS/DTV-growth request is rejected without mutating that
# sealed state. It does not map a runtime DSO, grow a DTV, allocate a thread,
# or promote the x86 dynamic product.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REGISTRY_SOURCE="$ROOT_DIR/ldso/src/x86_64_initial_tls_registry.rs"

fail() {
    printf 'ERROR: x86 RuntimeV1 initial TLS registry: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail 'requires native Linux'
case "$(uname -m)" in x86_64|amd64) ;; *) fail 'requires native x86-64' ;; esac
command -v rustc >/dev/null 2>&1 || fail 'requires rustc'
[ -f "$REGISTRY_SOURCE" ] || fail 'registry source is missing'
bash "$ROOT_DIR/compat/x86_64/run_musl_oracle.sh" >/dev/null

work_dir="$(mktemp -d /tmp/crabc-x86-runtime-v1-registry.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

rustc --edition=2021 --test "$REGISTRY_SOURCE" -o "$work_dir/registry-tests"
env -i PATH=/usr/bin:/bin "$work_dir/registry-tests"

printf '%s\n' 'x86 RuntimeV1 initial TLS registry: PASS (sealed generation-one, runtime growth rejected)'
