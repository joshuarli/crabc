# Native x86 ABI inventory

`compat/x86_64/native_abi_inventory.py` records a source-bound observation of
the fixed musl 1.2.6 x86-64 ABI and one selected owned static/dynamic product
pair. It is an input to the still-planned `compat.abi-differential` family.
The report is measurement only: it neither defines a symbol ratchet nor
establishes compatibility, family completion, promotion, or public support.

The collector consumes a prepared-unqualified static product and its static
preparation receipt, plus a materialized-unqualified dynamic product. The
dynamic state is always the manifest-bound
`share/crabc/dynamic-product-state.json` inside that product; there is no
separate state-file or dynamic-qualification input. Its payload and contract
identities cross-bind to the static preparation source identity. A historical
product stays an observation of the revision named by its own receipt, never a
claim about the collector's current revision.

The native collector runs only through the pinned dispatcher. Its three inputs
must be physical paths below the canonical checkout's `.work/` directory and
the output must be a fresh directory below this checkout's `.work/x86_64/`.
For example, with `INPUTS` set to a prepared pair beneath that canonical
`.work/` tree:

```sh
./scripts/dev-x86_64.sh native-abi-inventory collect \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json" \
  --output .work/x86_64/native-abi-inventory/one

./scripts/dev-x86_64.sh native-abi-inventory validate-report \
  .work/x86_64/native-abi-inventory/one/report.json \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json"

./scripts/dev-x86_64.sh native-abi-inventory-test
```

Collection seals the clean collector revision and imported source bytes before
and after inspection. It snapshots the fixed `/opt/musl-1.2.6` installation,
including the complete physical header tree, pinned manifests, tool identities,
and raw `C`-locale `readelf`, `nm`, and `ar` output. It checks each command
against the selected artifact and replays those bytes on the host without
calling native tools.

The report keeps complete dynamic-symbol table indexes, public name/type/
binding/visibility/version/defaultness records, and size/value/section
measurements. Archive rows retain member occurrences, duplicate names, raw
`nm` classes, named no-global-definition observations, and unsupported member
observations. Shared alias groups retain
their type/section/address domain; archive aliases remain unclassified when a
member/section observation cannot prove one. Program headers, dynamic tags,
and relocations retain unknown rows rather than silently shrinking a claimed
complete shape. Function size/value changes are measurements; `OBJECT` and
`TLS` size changes are explicit data-layout triage. None of those differences
is an automatic compatibility decision.

The existing native header-closure owner remains
`compat/x86_64/headers_layouts_aggregate.py` and its report identity. This
inventory routes that identity; simple header hashes are not declaration
evidence. The corresponding collector, replay reader, and focused tests are
`compat/x86_64/native_abi_inventory.py`,
`compat/x86_64/tests/test_native_abi_inventory.py`, and
`compat/x86_64/tests/test_native_abi_inventory_dispatcher.py`.
