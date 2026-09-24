# Native x86 resolver-family admission contract

`libc.resolver` remains planned in [`parity.toml`](parity.toml). This contract
defines its fixed admission map; it does not reclassify the family, alter the
shared ledger, or turn a successful component into x86 support.

The coordinator is [`owned_resolver_family.py`](owned_resolver_family.py) and
its machine-readable roster is [`resolver-family.toml`](resolver-family.toml).
They derive the exact frozen source set from
`compat/crabc-rs/coverage.toml` only after its digest matches
`aarch64_frozen_baseline.json`. The selected resolver set is exactly:

| Frozen capability | Required behavior proofs |
| --- | --- |
| `network.resolver-transport` | Controlled A/AAAA/CNAME UDP/TCP transport and response validation; cancellation, wait-state, retry, and descriptor-retirement behavior; one common source/product cohort. |
| `network.resolver` | Controlled configuration/search/failover behavior; classic and modern lookup behavior; public resolver state/alias boundaries; cancellation/retirement; one common source/product cohort. |
| `network.netdb` | Classic host/service and modern lookup lifetime behavior; fixed musl protocol-table behavior; one common source/product cohort. |

`network.ip-codec` and the legacy IPv4 rows are intentionally absent. They are
separate frozen capabilities with their own numeric-codec artifacts; placing
their symbols in this coordinator would make it a symbol-count claim rather
than a resolver behavior contract.

## Required component boundaries

The family requires six C-runtime modes whenever a behavior crosses the
installed runtime: static ET_EXEC, static PIE, dynamic PIE by kernel and direct
interpreter entry, and dynamic non-PIE by kernel and direct interpreter entry.
The names in the two readers differ slightly, but the roster binds their exact
six-mode contracts.

| Component | Existing proof boundary | Family treatment |
| --- | --- | --- |
| `resolver-network-physical` | [`resolver_network_component_receipt.py`](resolver_network_component_receipt.py) replays the retained raw local-DNS receipt for both installed and extracted product arms. It checks A/AAAA/CNAME, malformed and wrong-ID replies, search, retry/failover, and UDP truncation/TCP fallback across all twelve arm/mode executions. | Required reader. |
| `classic-netdb` | [`owned_classic_netdb_component_receipt.py`](owned_classic_netdb_component_receipt.py) replays its full six-mode host/service, legacy/modern lookup, record-order, error, allocation, thread, and fork receipt. | Required reader. |
| `resolver-alias-private-bodies` | [`owned_resolver_alias_contract_reader.py`](owned_resolver_alias_contract_reader.py) replays one source-bound static/dynamic cohort for `res_mkquery`, `res_send`, `res_search`, their private bodies, and protected controls. | Required ABI corroboration. It does not replace an entry-mode behavior matrix. |
| `resolver-cancellation` | [`owned_resolver_cancellation_receipt.py`](owned_resolver_cancellation_receipt.py) replays one explicitly named source-bound static/dynamic receipt. It validates all 847 raw oracle/candidate observations, isolation, the application object, product trees, driver/ELF audits, and provider symbols. | Required reader. It proves one supplied product pair; it cannot substitute for the shared primary/reproduction/extracted cohort. |
| `protocol-database-product` | [`owned_protocol_database_receipt.py`](owned_protocol_database_receipt.py) reconstructs the pinned-musl `proto.c` oracle, one project-header object, provider symbols, isolated roots, and raw observations for installed, reproduction, and extracted products across all eighteen C-runtime executions. | Required reader. It proves the fixed C table, never a `/etc/protocols` parser. |
| `resolver-family-cohort` | [`owned_resolver_family_cohort.py`](owned_resolver_family_cohort.py) validates the canonical static-preparation and dynamic-qualification receipts, then joins their primary/reproduction/extracted roots to every other reader's declared product roots and manifest identities. | Required reader. It accepts no source or product compatibility exception. |

The cohort reader is intentionally narrower than a product builder or a
generic receipt framework. The static-preparation and dynamic-qualification
owners remain responsible for validating the products. The resolver adapter
requires their current source identities to agree, recovers exactly the three
static/dynamic pairs, and rejects a reader whose declared roots combine members
from different pairs. It records the canonical roots and their manifests in the
assessment, but does not make the family promoting.

Each behavior reader must still reconstruct its own retained evidence before
the cohort reader runs. The network reader binds primary plus extracted; the
protocol-table reader binds primary, reproduction, and extracted; classic
netdb, alias/private-body, and cancellation readers bind their one declared
static/dynamic pair. Equal source hashes, byte-identical payloads, or an old
report are never substitutes for those exact physical root and manifest joins.

The alias/private-body receipt also names a loader-debug product report. For a
common cohort, collect that report through
[`run_loader_debug_abi.sh`](run_loader_debug_abi.sh) with the same primary
static and installed dynamic roots supplied together. A loader-debug report
that built private product roots cannot stand in for this input: the alias
reader checks the selected dynamic manifest, state, libc, and loader paths and
identities against the declared pair.

## Fixed protocol-table receipt

`owned_protocol_database.py` consumes three independently prepared product
pairs. It compiles the existing state-machine probe once, verifies the pinned
musl 1.2.6 `proto.lo` oracle, and records all raw outputs. Every execution
root contains a deliberately irrelevant `/etc/protocols` fixture: the selected
C ABI must continue to use its fixed 36-record musl table. The Rust-facing
snapshot API is not linked or credited here.

The three products must match in every regular payload byte and mode, every
alias, and every directory access mode. Dynamic archive extraction creates
parent directories locally, so the comparison normalizes only an inherited
directory setgid bit. Each root's unnormalized physical tree is still sealed
before and after collection.

Run this native producer inside the pinned x86 evidence environment, with the
three pairs taken from one current product preparation:

```sh
python3 -B compat/x86_64/owned_protocol_database.py \
  --work .work/x86_64/protocol-database/current \
  --installed-static-sysroot "$installed_static" --installed-dynamic-sysroot "$installed_dynamic" \
  --reproduction-static-sysroot "$reproduction_static" --reproduction-dynamic-sysroot "$reproduction_dynamic" \
  --extracted-static-sysroot "$extracted_static" --extracted-dynamic-sysroot "$extracted_dynamic"
python3 -B compat/x86_64/owned_protocol_database_receipt.py \
  --report .work/x86_64/protocol-database/current/owned-protocol-database-products.json
```

The second command is read-only. It replays the pinned object and provider
ELF observations, validates the three source/product seals, validates every
isolated root, and compares the retained raw oracle/candidate observations.

## Family execution and ledger admission

One dispatcher command runs the complete family against one current cohort:

```sh
./scripts/dev-x86_64.sh owned-resolver-family \
  --static-preparation .work/x86_64/STATIC/preparation.json \
  --dynamic-qualification .work/x86_64/tmp/materialized-dynamic.XXXXXX/qualification.json \
  --output .work/x86_64/resolver-family/NEW_DIR
```

The static preparation comes from `owned-posix-static-products` and the
dynamic qualification from `materialized-dynamic-sysroot`, both on the same
clean committed source. `owned_resolver_family.py plan` first replays both
owners through the cohort reader, then writes a fixed `plan.json` and
`request.json` into the dispatcher-created output (see `execution_layout`).
The dispatcher runs each component under its established isolation—the
network, classic-netdb, cancellation, and protocol-table collectors with
chroot authority and `--network none`; loader-debug and alias collectors bound
to the actual image identity; native ABI inventory and ELF facts through their
own commands—and writes nothing else. Single-pair components use the primary
pair, the network receipt uses primary plus extracted, and the protocol table
uses all three. The public network report is
`compat/reports/resolver-network/x86_64/family-NEW_DIR.json`. The run ends with
`write-assessment` and `validate`, so a successful command leaves a complete
read-only `assessment.json`.

`libc.resolver` becomes `foundation-verified` only through
`require_resolver_family_admission` in `validate_parity_ledger.py`: every
native evidence row must be verified, and the family command row names the
`assessment.json` as its `receipt`. The host ledger cannot replay component
behavior outside the pinned `/workspace` container, so `admission_facts` checks
the retained completion boundary, current contract and request bytes, current
source, and both cohort receipts. The ledger then requires the admitted
`libc.posix-runtime` matrix to have used exactly those static-preparation and
dynamic-qualification receipts. Resolver leaf ratchets keep their private
non-promoting view after admission.

## Assessing explicit evidence

The dispatcher command above writes its request automatically. The
coordinator itself never searches report directories. For a manual replay,
create a request below
`.work` that names every available reader input. An alias receipt additionally
names the exact static/dynamic products and its product, preparation, ELF-fact,
and inventory inputs because its public reader authenticates that cohort.

```json
{
  "schema": "crabc.x86_64-owned-resolver-family-request/v1",
  "components": {
    "resolver-network-physical": { "report": ".work/x86_64/resolver-network/current/report.json" },
    "classic-netdb": { "report": ".work/x86_64/classic-netdb/current/classic-netdb-products.json" },
    "resolver-alias-private-bodies": {
      "report": ".work/x86_64/resolver-alias/current/report.json",
      "static_product": ".work/x86_64/posix-static/current/products/primary",
      "dynamic_product": ".work/x86_64/dynamic/current/installed",
      "product_report": ".work/x86_64/loader-debug/current/report.json",
      "static_preparation": ".work/x86_64/posix-static/current/preparation.json",
      "elf_facts": ".work/x86_64/native-abi-elf-facts/current/report.json",
      "base_inventory": ".work/x86_64/native-abi-inventory/current/report.json"
    },
    "resolver-cancellation": {
      "work": ".work/x86_64/owned-resolver-cancellation/current",
      "static_product": ".work/x86_64/posix-static/current/products/primary",
      "dynamic_product": ".work/x86_64/dynamic/current/installed"
    },
    "protocol-database-product": {
      "report": ".work/x86_64/protocol-database/current/owned-protocol-database-products.json"
    },
    "resolver-family-cohort": {
      "static_preparation": ".work/x86_64/posix-static/current/preparation.json",
      "dynamic_qualification": ".work/x86_64/dynamic/current/qualification.json"
    }
  }
}
```

Run a complete request in the same pinned `/workspace` mount used by the
resolver-network reader:

```sh
python3 -B compat/x86_64/owned_resolver_family.py assess \
  --request .work/x86_64/resolver-family/request.json
```

`assess` is read-only and reports each missing or rejected component. It does
not run a native workload. `write-assessment` may retain that explicit result
under `.work`; `validate` reconstructs it and exits nonzero until every gap is
closed. Neither command can make `family_complete`, `promotion_ready`, or
`public_support` true without all named physical evidence.

```sh
python3 -B compat/x86_64/owned_resolver_family.py write-assessment \
  --request .work/x86_64/resolver-family/request.json \
  --output .work/x86_64/resolver-family/assessment.json
python3 -B compat/x86_64/owned_resolver_family.py validate \
  --assessment .work/x86_64/resolver-family/assessment.json
```

The final command fails until every required reader is named and the cohort
reader can bind their declared roots to one current source-bound product set.
The protocol component's three-pair receipt cannot by itself infer that
unrelated resolver observations used those same roots.
