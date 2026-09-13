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

Complete symbol and archive facts are available through opt-in parsing APIs in
`native_abi_inventory.py`. They are prerequisites for a future versioned
collector and selection contract; the v1 collector, command roster, public
projection, static `nm` projection, report reader and ratchet remain unchanged.

- `parse_dynamic_symbol_rows(raw)` requires exactly one complete `.dynsym`
  table and retains every row, including the unnamed zero row, local and hidden
  definitions, undefined imports, unknown kinds/bindings and extra `st_other`
  bits. `parse_elf_symbol_tables(raw)` does the same for every table in
  `readelf --wide --symbols` output. Both preserve table/row order, raw rows and
  displayed names, version/defaultness and the displayed version index. Repeated
  names are facts, not deduplicated identities. `parse_dynamic_symbols(raw)` is
  still the existing public v1 projection.
- `parse_elf_sections(raw)` requires complete native ELF64
  `readelf --wide --section-headers` output. It retains section indexes and names,
  types (including unknown types), addresses, offsets, sizes, entry sizes, flags,
  links, info and alignment, together with raw rows and the flag legend.
- `parse_archive_elf_facts(headers_raw, sections_raw, symbols_raw, members,
  expected_archive=...)` joins three separate `readelf -hW`, `-SW`, `-sW`
  outputs with the exact `ar t` roster. Every stream must name the same archive
  and match the complete member order. The result records zero-based
  `member_index` and zero-based `member_occurrence`; duplicate member names are
  never dictionary keys. Each member must be native ELF64 little-endian x86-64
  relocatable ELF. Every symbol table binds to its section index in section
  order, with its exact ELF64 entry size, row count and string-table link.
  Numeric symbol section indexes must exist. A member without a symbol table
  requires independent complete section evidence; a missing or unsupported
  member cannot become an empty successful observation.

Completeness of these text streams is tied to the pinned GNU readelf's C-locale
x86-64 display. The header requires all 19 ordered field occurrences, including
the two distinct `Version` positions and the complete section metadata tail.
The mandatory section count must agree with the section rows. The section
display requires the complete four-line flag legend, ending with the pinned
processor-specific entry. Both observed endings, with and without `R (retain)`,
are admitted and preserved; a comma-continued prefix is incomplete. A tool update
that changes either display requires an explicit parser change and retained
native evidence. These display boundaries leave unknown symbol/section kinds,
flags and reserved section-index spellings intact. They establish textual
completeness and the documented joins, not full ELF validity.

The archive API performs no extraction or tool invocation. Its caller must bind
all four actual commands, pinned tool identities, unchanged archive bytes,
stdout/stderr and successful exit statuses. Nonempty diagnostics cannot be
silently passed off as a complete observation. GNU readelf archive traversal
order supplies the occurrence domain; name-based extraction would overwrite
duplicate members and cannot substitute for this evidence. The APIs accept
retained raw bytes as text and fail on malformed, missing, repeated or reordered
rows. They do not provide a fallback to `nm` or a smaller public symbol view.

For a static definition, compare the archive identity, member ordinal, symbol
table section index, definition section index and value before considering an
alias. Same names or zero `nm` values across members or sections prove nothing.
Section `alignment` is `sh_addralign`; it is not a promise that every contained
symbol has that alignment. Symbol `common_alignment` records the hexadecimal
`st_value` alignment for `COM` rows. `size` and `value` preserve readelf spelling;
`size_bytes` also provides the numeric decimal/explicit-hex size. No function
size comparison, alias group, binding or visibility observation selects public
ABI policy by itself. Readelf's displayed names are not a claim of lossless ELF
string bytes; an exact byte-name contract requires separately bound ELF facts.

The complete-projection regressions are
`NativeAbiCompleteSymbolFactsTests` in the existing inventory test module, so
`./scripts/dev-x86_64.sh native-abi-inventory-test` includes them. They cover
private/import/data/TLS/COMMON rows, unusual GNU display fields, duplicate
members and sections, and malformed or incomplete joins. Native fixture
inspection builds only small ELF/archive test inputs; it does not rebuild or
qualify runtime products, select exports, or change any promotion flag.

The separate [ELF fact supplement](native-abi-elf-facts.md) now binds these
complete projections to the finite libc/loader/CRT/builtins placement roster.
It requires a fresh same-current-collector v1 inventory and preserves this v1
report and its measurement/ratchet meaning.
