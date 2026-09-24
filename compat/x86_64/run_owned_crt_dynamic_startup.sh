#!/usr/bin/env bash
# Installed dynamic CRT entry, lifecycle, finalization, helper-archive and
# link-interface leaf for one product. The implementation and its
# musl-differential roster live in crt/x86_64_owned_dynamic_startup.py.
# Without an argument it first builds one clean installed dynamic product
# below this run's evidence directory.
set -euo pipefail
ulimit -c 0
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ "$#" -le 1 ] || { printf 'usage: %s [INSTALLED_DYNAMIC_SYSROOT]\n' "$0" >&2; exit 2; }
product="${1:-}"
if [ -z "$product" ]; then
    work="$(mktemp -d "$TMPDIR/owned-crt-dynamic-product.XXXXXX")"
    # Supplied-product replays resolve this path from the host.
    chmod a+rx "$work"
    python3 -B "$ROOT/scripts/build_x86_64_owned_dynamic_sysroot.py" --output "$work/dynamic-sysroot" \
        >"$work/dynamic-build.json"
    printf 'owned dynamic CRT startup product: %s\n' "$work/dynamic-sysroot"
    product="$work/dynamic-sysroot"
fi
exec python3 -B "$ROOT/crt/x86_64_owned_dynamic_startup.py" "$product"
