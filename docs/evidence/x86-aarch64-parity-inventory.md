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
  that capability inside a family that has not reached its own foundation state.
- `missing` means the family still owes the capability to the promotion
  program. It is not an unsupported-platform claim.
- `unsupported_contracts` lists only x86 ledger surfaces explicitly excluded
  from the promotion program; it is not inferred from absent symbols.

The derivation validates its own selected-record boundary before it reports a
state: every `verified_slice` must name non-duplicate capabilities owned by
that same family, no capability may be selected by two slices, verified record
IDs are unique across slices and artifacts, and an artifact cannot carry a
capability claim. Every selected slice or artifact must also carry nonempty
native evidence whose records are all `verified` and have a command and scope.
Its command must be the canonical two-word invocation of a checked-in x86 or
CRT dispatcher, and its final dispatch arm must invoke a `run_*` verifier.
That excludes build-only commands such as `image`, stale subcommands, and
arbitrary shell text. A selected artifact cannot repeat the same canonical
command: repetition is not independent native corroboration. These checks keep
a malformed ledger from turning an unrelated or unproven capability into
`selected-private` when the inventory runs on its own; they do not make that
state a completion or promotion decision.

The report also checks the 183 pinned public header paths against the AArch64
musl header oracle and records the selected x86 static-export ratchet only as
boundary evidence. Neither measure establishes C ABI or runtime parity.

`compat/x86_64/aarch64_frozen_baseline.json` is the immutable settlement
record. It binds the full frozen source commit, capability and family counts,
and SHA-256 digests of the AArch64 capability ledger, ABI manifest, and public
header oracle. Run `python3 compat/x86_64/aarch64_parity_inventory.py`; normal
validation first rejects drift from that record, then rejects drift from the
checked x86-derived inventory. It intentionally has no `--write` or snapshot
refresh path: rebaselining requires explicit user direction and a separately
recorded old-to-new baseline transition. `promotion_ready` and
`public_support` are derived from current x86 contracts, not hard-coded false;
promotion remains governed by every gate in `x86-64.md` and
`compat/x86_64/parity.toml`.
