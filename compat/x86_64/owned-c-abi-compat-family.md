# Native x86 c-abi-compat family admission

`libc.c-abi-compat` remains planned in [`parity.toml`](parity.toml). Its one
family evidence command runs every component of
[`c-abi-compat-family.toml`](c-abi-compat-family.toml) against the primary
static/dynamic pair of one current product cohort and retains a
non-promoting assessment:

```sh
./scripts/dev-x86_64.sh owned-c-abi-compat-family \
  --static-preparation .work/x86_64/STATIC/preparation.json \
  --dynamic-qualification .work/x86_64/tmp/materialized-dynamic.XXXXXX/qualification.json \
  --output .work/x86_64/c-abi-compat-family/NEW_DIR
```

[`owned_c_abi_compat_family.py`](owned_c_abi_compat_family.py) runs each
component's existing installed-product runner, retains its raw streams,
status and single evidence root even when it fails, and writes
`assessment.json`. The assessment replays every component reader, binds every
product root the retained evidence names to the cohort
([`owned_c_abi_compat_family_cohort.py`](owned_c_abi_compat_family_cohort.py)),
accounts the family's libc-test units, and names each failed component as a
gap. `python3 -B compat/x86_64/owned_c_abi_compat_family.py validate
--assessment PATH` reconstructs it in the pinned image.

The roster joins the ledger: the family's capabilities come from its
`parity.toml` row, and every `owned-*` command a `[[family.verified_slice]]`
cites must be a component crediting that slice's capabilities. Source-only
`libc-*` and `*-header-abi` leaves cannot satisfy this family.

The ledger admits the family only through `admission_facts` on a complete
assessment whose cohort receipts the admitted `libc.posix-runtime` matrix also
used (`require_c_abi_compat_family_admission` in
`validate_parity_ledger.py`).

## Allocator capabilities

`memory.allocator-basic` and `memory.allocator-observability` are proved by
`owned-native-allocator-policy`, `owned-allocator-override` and
`owned-native-allocator-dso` on the actual allocator backend selected by the
cohort. The selected `accepted-c` runtime can qualify these public capabilities
before the Rust allocator is promoted. Without supplied products, the runners
keep their native-shadow development builds. Static and dynamic products must
name the same supported backend. Evidence-only C products cannot qualify.

All three policy programs remain required: the basic runtime probe,
observability fixture and public malloc-family size-class probe run unchanged
against pinned musl in all six candidate modes. The policy reader requires
all 22 retained cases and their source, compile, link and product evidence.
Application whole-family and malloc/free/realloc interposition, executable,
initial-DSO and plugin ownership transfers, binding controls, errno and
`dlclose` behavior remain required on the same cohort products.

Allocator identity follows installed manifests and provenance. Accepted-C
provenance must identify the pinned C dependency in both products and cannot
claim Rust-native source evidence. Rust products additionally require their
`crabc-mimalloc/UPSTREAM.md` source identity. These public libc capability
proofs do not qualify Rust-private allocator policy or promote the allocator.
The independent allocator promotion gate owns those proofs.
