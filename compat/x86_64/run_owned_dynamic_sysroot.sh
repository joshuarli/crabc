#!/usr/bin/env bash
# Validate the planned x86 owned-dynamic product contract without pretending
# that the dynamic installer, general loader, or dynamic smoke suite exists.
#
# `--check-contract` validates the schema, non-materialized state, and
# plan-only driver seed; it is still not product evidence. The no-argument
# product-gate spelling remains intentionally red until a future installer
# materializes the dynamic runtime and replaces this seed with the complete
# native smoke suite described by dynamic-product.toml.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly VALIDATOR="$ROOT_DIR/compat/x86_64/dynamic_product_contract.py"

fail() {
    printf 'ERROR: x86 owned dynamic product seed: %s\n' "$*" >&2
    exit 2
}

[ -f "$VALIDATOR" ] || fail "missing dynamic-product contract validator"

case "$#" in
    0)
        python3 "$VALIDATOR" --check
        printf '%s\n' \
            'x86 owned dynamic product: INCOMPLETE; contract validation is not dynamic product evidence.' >&2
        exit 1
        ;;
    1)
        [ "$1" = "--check-contract" ] || fail "usage: $0 [--check-contract]"
        python3 "$VALIDATOR" --check
        printf '%s\n' \
            'x86 owned dynamic product contract: checked-in planned plan-only seed; not product evidence.'
        ;;
    *)
        fail "usage: $0 [--check-contract]"
        ;;
esac
