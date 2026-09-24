# Native x86 public-dynamic ABI ratchet

`compat/x86_64/native_abi_ratchet.py` applies a reviewed monotonic regression
floor to the public defined dynamic-symbol inventory collected by
`native_abi_inventory.py`.  It is one future input to
`compat.abi-differential`; it does not establish C ABI compatibility, complete
that family, promote a product, or make native x86 publicly supported.

The checked policy has two tracked inputs:

- [`../ratchet/x86_64-dynamic.json`](../ratchet/x86_64-dynamic.json) is the
  frozen historical floor. It is never an output of this command.
- [`native-abi-ratchet-additions.json`](native-abi-ratchet-additions.json) is
  a separate exact reviewed-extension policy. It does not revise the floor or
  turn an observed historical extra into a musl identity.

The frozen floor's origin is the parent-replayed inventory report from collector revision
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
may disappear, but no new unexpected identity may appear unless it is an exact
entry in the additions policy. Version/defaultness changes are additions or
removals of distinct identities.

The additions policy has a closed schema. Every entry has one exact identity,
the complete expected ABI metadata, and a closed selection attribution. An
addition cannot reuse any musl-oracle or historical-candidate symbol name, and
the policy cannot repeat or version-shift a selected name. It contains no
wildcards. A selected entry must be present with every ratcheted field equal;
`missing_additions` and `mismatched_additions` remain violations. The raw
`current` comparison remains against pinned musl, so a reviewed extension is
still listed under `current.unexpected`.

The first reviewed extension is the unversioned `tgkill`, with `FUNC GLOBAL
DEFAULT` metadata and `data_size: null`. Its selection attribution records the
frozen crabc GNU/BSD C provider
`3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/src/c_abi.rs::tgkill` and
declaration `3e100d45c5a0798c2d3862d5e2eef584c610ccf9:include/signal.h`,
together with the paired
[`native-thread-signal-abi.md`](native-thread-signal-abi.md) component
contract. That component preserves the caller-selected Linux `SYS_tgkill=234`
`(tgid, tid, sig)` operation and errno translation. It is an explicit native
x86 extension, not a claim that musl exports `tgkill` or that the Rust
`process.thread-kill` facade contract is the same C ABI. It does not complete a
family, promote a product, or change public-support status.

The second is the unversioned private `__crabc_runtime_v1` getter, also `FUNC
GLOBAL DEFAULT` with `data_size: null`. Frozen crabc exports it from
`3e100d45c5a0798c2d3862d5e2eef584c610ccf9:libc/src/c_abi.rs::__crabc_runtime_v1`
over the `RuntimeV1` table in `crabc-core/src/runtime.rs`, and the crabc-rs
`dl`, `runtime_thread`, and `cfile` facades import it. The x86 owned dynamic
libc supplies it from `libc/src/c_abi/x86_64/runtime_facade_v1.rs`; the
"Rust RuntimeV1 facades" section of [`README.md`](README.md) names its
`runtime-private-facades` component evidence. It is a private crabc protocol,
not a C interface, and the selection policy keeps its consumer parity open.

The current musl pin, shared-library identity, and complete public symbol
surface must exactly match the reviewed oracle floor.  A current candidate can
have a different materialized build identity; the result records it separately
from the historical baseline build.  A current inventory must first pass the
public inventory reader and must have been collected by the same clean source
revision/content as the ratchet invocation.

The receipt schema is
`crabc.x86_64-native-abi-dynamic-ratchet-check/v2`. Its `additions_policy`
record includes the fixed tracked path, physical file identity, and parsed
policy content. `validate-report` reconstructs all three from the fixed
baseline and fixed additions file; it rejects an altered policy hash, policy
content, or report field. Neither command accepts a policy selector. The
pre-provider products are not a passing result for this new required extension;
this policy change records no product evidence.

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
the policy result from the fixed baseline and additions policy, and rejects any
changed retained field, policy or baseline digest/content, source identity, or
product/oracle input.
