# Native ABI ELF fact supplement

`native_abi_elf_facts.py` records complete symbol, section and header observations
for the finite native provider-placement artifacts. It supplements the existing
[native ABI inventory](native-abi-inventory.md); it neither selects public ABI
names nor defines aliases, export visibility policy, family completion, a ratchet
or promotion. Source declarations and behavioral expectations remain separate
selection and capability evidence.

The supplement requires a freshly validated v1 inventory produced by the same
clean current collector revision and source content. The supplied static product,
dynamic product and static preparation receipt must be the ones bound by that
inventory. Product build provenance remains distinct: an older unchanged
prepared/materialized product pair can be inspected by a newer clean collector.
An old collector's report cannot be relabeled or resealed as current evidence.

Use two successive inspections at one clean source revision, with `INPUTS`
pointing to the unchanged prepared/materialized products under the canonical
checkout's `.work/`. Both output directories must be fresh, with existing parent
directories below this checkout's `.work/x86_64/`:

```sh
./scripts/dev-x86_64.sh native-abi-inventory collect \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json" \
  --output .work/x86_64/abi-facts/base

./scripts/dev-x86_64.sh native-abi-elf-facts collect \
  --base-inventory .work/x86_64/abi-facts/base/report.json \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json" \
  --output .work/x86_64/abi-facts/complete

./scripts/dev-x86_64.sh native-abi-elf-facts validate-report \
  .work/x86_64/abi-facts/complete/report.json \
  --base-inventory .work/x86_64/abi-facts/base/report.json \
  --static-product "$INPUTS/static/products/primary" \
  --dynamic-product "$INPUTS/dynamic" \
  --static-preparation "$INPUTS/static/preparation.json"
```

Collection uses the pinned native amd64 image with no network and read-only
product, preparation and base-inventory mounts. Replay runs on the host, invokes
the public v1 reader, rehashes retained tool/source/raw bytes and supplied inputs,
and reconstructs the facts without running an ELF tool. The original v1 report
bundle must remain available alongside its products and preparation receipt.
Neither operation builds or qualifies a runtime product.

The explicit `ARTIFACTS` roster has 17 placements. Its candidate membership must
agree with both the imported static/dynamic product contracts and the relevant
manifest payloads. Equal bytes never merge two placements.

Placement classification is closed. `NON_ELF_REQUIRED` explicitly names each
driver/helper required by the product contracts, and `NON_ELF_METADATA` names
each other installed metadata payload. Those sets, the exact ELF placements,
and the current source `include/` regular-file roster must account for every
manifest payload exactly once. Header names classify placements; the validated
v1 product receipts bind their actual bytes and build provenance. An older
product with a different installed header roster therefore needs an explicit
contract update before collection. The existing loader compatibility symlink
remains an independently validated v1 alias rather than a regular payload.

No filename extension admits or excludes a payload. A new versioned DSO,
arbitrary ELF filename, driver, metadata file or header placement rejects until
classified. An ELF addition also needs an explicit observation and correlation
decision; adding it to a product manifest does not extend the v1 public view.

| Owner | Artifact placements | Count |
| --- | --- | ---: |
| Pinned musl reference | `lib/libc.a`, `lib/libc.so` | 2 |
| Candidate static product | `usr/lib/libc.a`; `crt1.o`, `Scrt1.o`, `rcrt1.o`, `crti.o`, `crtn.o` and `libcrabc-builtins.a` under `usr/lib/` | 7 |
| Candidate dynamic product | `usr/lib/libc.so`, `lib/ld-crabc-x86_64.so.1`; `crt1.o`, `Scrt1.o`, `crti.o`, `crtn.o`, `crabc-dynamic-attach.o` and `libcrabc-builtins.a` under `usr/lib/` | 8 |

The four archives each receive `ar t` and `readelf -hW`, `-SW`, `-sW`. The other
13 ELF artifacts each receive those three readelf commands: exactly 55 commands.
The loader's compatibility symlink is already bound by v1 and is not a second
ELF definition. The dynamic attach object is a manifest-owned runtime input;
its observation is not a public-header or ABI selection decision.

`collect_facts(...)` and `validate_report(...)` own the separate
`crabc.x86_64-native-abi-elf-facts/v1` schema. The top-level closed fields are:

| Field | Binding |
| --- | --- |
| `schema`, `target`, `image`, `status` | Exact schema/target, the v1 pinned image, measurement-only status with family/promotion/public-support flags false |
| `collector_execution_source`, `collector_sources` | Current clean Git revision/content seal and exact retained execution-source roster, distinct from product build source |
| `base_inventory` | Retained original v1 report bytes, its same-current collector identity and unchanged candidate build provenance |
| `artifacts` | Exact placement roster, ELF/archive kind, expected ELF type, physical byte identity and manifest/reference ownership |
| `tools` | Exact `ar`/`readelf` byte snapshots, equal to the tools bound by v1 |
| `commands` | Exact 55-command roster, argv, execution root, C locale, collector source, input artifact before/after, tool identity, exit status, stdout and stderr |
| `facts` | Complete projections reconstructed from every raw observation |

Report values distinguish JSON booleans from numbers. Extra/missing keys or
placements, duplicate JSON keys, stale collectors, substituted build/manifest
ownership, different argv/tool/input bytes, nonzero exits, diagnostics and
truncated or inconsistent projections reject. Failed tool observations retain
raw bytes and `commands.json` for inspection but do not produce an accepted
report. Hashes bind retained observations; they are not a signature of an
untrusted collector.

The underlying v1 reader also requires literal `false` for its three fixed
measurement-status flags. Rebinding a base report with numeric `0` cannot turn
Python equality into an accepted Boolean contract. This corrects the reader's
type check without changing the v1 schema or its source/product revision rules.

`native_abi_inventory.parse_elf_facts` joins the hardened complete header,
section and symbol-table APIs for standalone `REL` or `DYN` ELF. Its archive
counterpart preserves exact member order, repeated member names and occurrence
indexes. The section roster independently accounts for every `SYMTAB`/`DYNSYM`
table, its entry count/size, string-table link and each numeric definition
section. A legitimate symbol-free CRT object requires independent complete
section evidence. Shared objects retain all symbol tables and their unnamed,
local, hidden and undefined rows, versions/defaultness, unknown kinds and raw
metadata; their `.dynsym` public projection must also reproduce v1's public view.

The pinned readelf header/legend completeness boundaries remain as documented in
`native-abi-inventory.md`. These facts do not prove all ELF validity, lossless
raw ELF string bytes, source signatures, semantic aliasing or application ABI
selection. No selected symbol is inferred from a prefix, `nm` class or address.
Object/TLS sizes, section alignment and COMMON alignment remain observations for
later explicit contract checks.

Focused reader/parser and dispatcher tests live in
`tests/test_native_abi_elf_facts.py` and
`tests/test_native_abi_elf_facts_dispatcher.py`. They exercise malformed receipt
rosters, exact JSON types, source/build separation, private/import preservation,
complete shared table joins, truncation, duplicate member domains and the host
replay boundary. The existing v1 and ratchet test modules remain independent.
