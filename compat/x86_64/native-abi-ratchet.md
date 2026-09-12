# Native x86 public-dynamic ABI ratchet

`compat/x86_64/native_abi_ratchet.py` applies a reviewed monotonic regression
floor to the public defined dynamic-symbol inventory collected by
`native_abi_inventory.py`.  It is one future input to
`compat.abi-differential`; it does not establish C ABI compatibility, complete
that family, promote a product, or make native x86 publicly supported.

The checked policy is
[`../ratchet/x86_64-dynamic.json`](../ratchet/x86_64-dynamic.json).  It is a
tracked reviewed baseline, never an output of this command.  Its origin is the
parent-replayed inventory report from collector revision
`4b1e653698c3a95945df6ecab71536a85ccb6b5d`:

- report SHA-256
  `aece2d1129f97e99ae2c3822f5f4adb7a00df168ecb372790286b2dfbf2a33ab`;
- parent validation SHA-256
  `8f163679d27c3e715e58a9f0fe92c6feb66165f533087a98bd1ea63cae3924df`;
- pinned musl 1.2.6 shared object and pin identity; and
- the separate materialized-unqualified candidate build identity at
  `640c093918692cbec384ed9ae8fb4f5ef425d19c`.

The baseline has 1,650 musl identities and 2,053 candidate identities.  Its
initial observation retains 72 missing identities, 475 unexpected identities,
99 binding differences, two visibility differences, and no type,
selected-version, or OBJECT/TLS-data-size differences.  Those are visible
measurements, not approved exceptions or a classification of the candidate
exports.

## Policy

A symbol identity is the exact `(name, version, version_default)` triple.
The ratchet compares `type`, `binding`, and `visibility`.  For a musl
`OBJECT` or `TLS` identity it also compares data size.  Function code size,
value, and section index remain raw inventory measurements and are not ratchet
fields.  The inventory retains unsupported raw observations; a public dynamic
row whose type, binding, or visibility is outside this ratchet's explicit
surface fails closed instead of disappearing from policy input.

For every baseline-present musl identity, the fresh candidate may retain the
historical candidate value or move to the pinned musl value.  A
baseline-correct field must remain correct, and any third value fails.  A
baseline-present musl identity cannot disappear.  A baseline-missing musl
identity may appear only with all selected metadata correct.  Existing
unexpected candidate identities have no musl ABI metadata in this policy and
may disappear, but no new unexpected identity may appear.  Version/defaultness
changes are additions/removals of distinct identities.

The current musl pin, shared-library identity, and complete public symbol
surface must exactly match the reviewed oracle floor.  A current candidate can
have a different materialized build identity; the result records it separately
from the historical baseline build.  A current inventory must first pass the
public inventory reader and must have been collected by the same clean source
revision/content as the ratchet invocation.

## Commands

Collect a fresh inventory first.  With `INPUTS` naming the prepared matching
products, run the host-only ratchet reader/checker through the dispatcher:

```sh
./scripts/dev-x86_64.sh native-abi-ratchet check \
  --inventory-report .work/x86_64/native-abi-ratchet/inventory/report.json \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json" \
  --output .work/x86_64/native-abi-ratchet/check

./scripts/dev-x86_64.sh native-abi-ratchet validate-report \
  .work/x86_64/native-abi-ratchet/check/ratchet.json \
  --inventory-report .work/x86_64/native-abi-ratchet/inventory/report.json \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json"

./scripts/dev-x86_64.sh native-abi-ratchet-test
```

`check` always retains a complete `ratchet.json` after a successfully replayed
inventory, including failures and improvements.  It exits nonzero if a
monotonic rule fails.  `validate-report` runs no ELF tools or compiler: it
replays the supplied inventory with its existing public reader, reconstructs
the policy result from the fixed baseline, and rejects any changed retained
field, baseline digest, source identity, or product/oracle input.
