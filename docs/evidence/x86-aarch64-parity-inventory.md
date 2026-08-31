# Derived x86-64/AArch64 parity inventory

`compat/x86_64/aarch64_parity_inventory.json` is a checked snapshot generated
from the AArch64 semantic-capability ledger, its pinned musl ABI/header oracle,
and x86's promotion ledger plus header/export ratchets. It is deliberately not
a feature checklist and does not count symbols as parity.

The inventory classifies each AArch64 capability according to its owning x86
promotion family:

- `implemented-foundation` means only that its family is an x86 native
  foundation, not that the whole public contract is complete.
- `selected-private` means an explicitly recorded private x86 vertical owns
  that capability inside a still-planned family.
- `missing` means the family still owes the capability to the promotion
  program. It is not an unsupported-platform claim.
- `unsupported_contracts` lists only x86 ledger surfaces explicitly excluded
  from the promotion program; it is not inferred from absent symbols.

The derivation validates its own selected-record boundary before it reports a
state: every `verified_slice` must name non-duplicate capabilities owned by
that same family, no capability may be selected by two slices, verified record
IDs are unique across slices and artifacts, and an artifact cannot carry a
capability claim. These checks keep a malformed ledger from turning an
unrelated capability into `selected-private` when the inventory runs on its
own; they do not make that state a completion or promotion decision.

The report also checks the 183 pinned public header paths against the AArch64
musl header oracle and records the selected x86 static-export ratchet only as
boundary evidence. Neither measure establishes C ABI or runtime parity.

Run `python3 compat/x86_64/aarch64_parity_inventory.py`. It recomputes the
report and rejects drift from the checked snapshot. `--write` is a deliberate
review/update operation for changes to the underlying contract. The validator
always retains `promotion_ready=false` and `public_support=false`; promotion
remains governed by every gate in `x86-64.md` and `compat/x86_64/parity.toml`.
