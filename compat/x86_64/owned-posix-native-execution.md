# Native POSIX aggregate execution

`owned_posix_native_execution.py` consumes a fully validated three-product POSIX
family `execution.json`, installed-product `crypt-profile.json` and
`atomic-addressable-profile.json` receipts, a complete wordexp product report,
and a separately captured wordexp expected-native-inputs file. It selects their
shared installed dynamic product and executes five fresh component commands in
fixed order: differential, os-test, signal-process, pthread-stress, and
libc-test. It neither builds products nor substitutes the static workload
matrix for these native runs.

The v2 `native-execution.json` request has exactly five prerequisite fields besides
its schema and source mount: `family_execution`, `crypt_profile`,
`atomic_addressable_profile`, `wordexp_profile`, and
`wordexp_expected_native_inputs`. All must be physical checkout-relative files;
the coordinator rejects a missing, extra, or renamed request field before it
creates output.

The wordexp report is replayed through the full
`owned_wordexp_evidence.validate_report` contract using the supplied expected
inputs, rather than a report-derived expectation. The coordinator binds both
files and their parent trees before and after execution. The replay must bind
the selected dynamic product and its manifest, and it must retain all four
dynamic `source-policy` cells. The finite native accounting of the original
raw `functional/wordexp` failure is described in
[`owned-posix-native-dispositions.md`](owned-posix-native-dispositions.md).

The pthread stress command uses `native-v1`, ten iterations and a ten-second
case timeout. Its delegated `READ_FILE` and `ASYNC_LOOP` observations are bound
to all three source-identical I/O cancellation replay objects, all eighteen
static/dynamic cells and their pinned-musl raw transcripts. The installed
product's four dynamic entries are explicit. The child stress receipt retains
its null replacement field; the aggregate owns the composite proof.

Execution requires the pinned native Linux/x86-64 environment and fresh output
under `.work/`, disjoint from all input products and receipt trees. Every step
retains its exact invocation, environment, streams, status, private scratch,
source-derived native observations, immutable fixture-node snapshot and a
predecessor receipt identity. Source, product payload and oracle checks bracket
each command. Failure retains `incomplete.json`, completed receipts, and raw
partial artifacts; it stops the sequence and cannot issue a success receipt.

`validate` is a host-readable reconstruction. It checks the complete prerequisite
matrix and all native source-aware collectors without rerunning commands,
consulting the live target oracle, or starting Docker. It rejects changed
invocations, objects, modes, symbolic/special nodes, missing or extra steps,
changed source/product seals and reordered predecessors.

The dispatcher translates physical host or container receipt/output paths and
starts the pinned native container with private mount authority and no network:

```sh
./scripts/dev-x86_64.sh owned-posix-native \
  --family-execution .work/x86_64/posix-matrix/execution.json \
  --crypt-profile .work/x86_64/crypt/crypt-profile.json \
  --atomic-addressable-profile .work/x86_64/atomic/atomic-addressable-profile.json \
  --wordexp-profile .work/x86_64/wordexp/owned-wordexp-products.json \
  --wordexp-expected-native-inputs .work/x86_64/wordexp-inputs/expected-native-inputs.json \
  --output .work/x86_64/posix-native
```

The component source caches must already contain the pinned upstream inputs;
in particular OS-test reads its verified
`.work/x86_64/source-oracles/os-test-5e9456d510612f83b6ec8b1a0c06d6b1303a2512`
checkout. Missing source inputs fail execution; the coordinator never replaces
them with ambient system programs. The direct interface inside that environment
and the read-only host validation command are:

```sh
python3 -B compat/x86_64/owned_posix_native_execution.py run \
  --family-execution .work/x86_64/posix-matrix/execution.json \
  --crypt-profile .work/x86_64/crypt/crypt-profile.json \
  --atomic-addressable-profile .work/x86_64/atomic/atomic-addressable-profile.json \
  --wordexp-profile .work/x86_64/wordexp/owned-wordexp-products.json \
  --wordexp-expected-native-inputs .work/x86_64/wordexp-inputs/expected-native-inputs.json \
  --output .work/x86_64/posix-native
python3 -B compat/x86_64/owned_posix_native_execution.py validate \
  .work/x86_64/posix-native/native-execution.json
```

A validated `native-execution.json` sets only `native_aggregate_complete`.
`campaign_complete`, `family_completion`, and `public_support` remain false.
The focused coordinator regressions use explicit prerequisite/native judge
seams and five actual subprocesses; they do not claim real runtime qualification.

## Family-admission receipt

After a clean native aggregate exists, `admit` is the one host-readable
consumer that can turn the already validated matrix plus native aggregate into
family evidence. It reruns neither producer nor target program. Instead it
physically reconstructs `native-execution.json`, follows and reconstructs its
exact `execution.json`, requires their current source seals to agree, and
checks the catalog's complete nine-capability/149-spelling roster. Every
spelling must retain its exact six static and twelve dynamic matrix receipt
cells; the zero-spelling composition workload and all named closure workloads
remain independently required. The five native components and the eighteen
I/O replacement cells must also remain complete.

```sh
python3 -B compat/x86_64/owned_posix_native_execution.py admit \
  --native-execution .work/x86_64/posix-native/native-execution.json \
  --output .work/x86_64/posix-family-admission
python3 -B compat/x86_64/owned_posix_native_execution.py validate-admission \
  .work/x86_64/posix-family-admission/family-admission.json
```

The resulting `family-admission.json` sets `family_completion=true` and keeps
`campaign_complete`, `promotion_ready`, and `public_support` false. It is not
a ledger transition. A receipt made from a planned source revision is useful
preflight evidence only: changing any tracked ledger row afterward changes the
source seal, so it cannot be attached to a later transition.

The only transition bootstrap is a clean, unpublished candidate revision. Its
POSIX row names the intended physical `.work` receipt and the eventual
`foundation-verified` native-evidence state, but it is not accepted or reported
as foundation while that receipt is absent. On that exact clean revision, run
the family matrix, the native aggregate, and `admit` at the named path; then
run `validate-admission` and the parity-ledger validator in the same checkout.
Only those successful reconstructions make the candidate an admissible ledger
state. If any tracked source changes, restart from a fresh clean candidate—do
not carry a prior receipt forward or exclude ledger/source files from its
identity. Existing private leaf artifacts remain non-promoting evidence until
that condition is met.

The producer path has no circular ledger gate: `owned-posix-static-products`
builds the static preparation, `materialized-dynamic-sysroot` produces the
unqualified dynamic receipt, and `owned-posix-family` consumes only those two
receipts before `owned-posix-native` consumes the matrix. These entrypoints
require their own clean/source/product identities and retain non-promoting
flags; none validates the parity ledger or branches on the POSIX family
status. The parity-ledger validator runs only after the admission receipt is
present.

### Admission sequence

Run every step from the one clean candidate checkout, in its own `.work`.
Seed `.work/x86_64/source-oracles` with the pinned OS-test and libc-test
checkouts first: the native container has no network. `$DYN` is the
`materialized-dynamic.*` directory printed by step 2 and `$STATIC` is the
primary static product; the four companions must name that same `installed`
dynamic product.

```sh
./scripts/dev-x86_64.sh owned-posix-static-products .work/x86_64/posix-static      # 1
./scripts/dev-x86_64.sh materialized-dynamic-sysroot                               # 2
STATIC=.work/x86_64/posix-static/products/primary
./scripts/dev-x86_64.sh owned-posix-family \
  --static-preparation .work/x86_64/posix-static/preparation.json \
  --dynamic-qualification "$DYN/qualification.json" --output .work/x86_64/posix-family
./scripts/dev-x86_64.sh owned-crypt-runtime --static-sysroot "$STATIC" "$DYN/installed"
./scripts/dev-x86_64.sh owned-atomic-addressable-profile "$DYN/installed"
./scripts/dev-x86_64.sh owned-wordexp --static-sysroot "$STATIC" "$DYN/installed"
./scripts/dev-x86_64.sh owned-wordexp-expected-inputs --static-sysroot "$STATIC" "$DYN/installed"
./scripts/dev-x86_64.sh owned-posix-native --family-execution .work/x86_64/posix-family/execution.json \
  --crypt-profile CRYPT/crypt-profile.json \
  --atomic-addressable-profile ATOMIC/evidence/atomic-addressable-profile.json \
  --wordexp-profile WORDEXP/owned-wordexp-products.json \
  --wordexp-expected-native-inputs EXPECTED/expected-native-inputs.json \
  --output .work/x86_64/posix-native
python3 -B compat/x86_64/owned_posix_native_execution.py admit \
  --native-execution .work/x86_64/posix-native/native-execution.json \
  --output .work/x86_64/posix-family-admission
python3 -B compat/x86_64/owned_posix_native_execution.py validate-admission \
  .work/x86_64/posix-family-admission/family-admission.json
python3 -B compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh campaign-status
```

Steps 1 and 2 are independent, as are the matrix and the four companions.
`owned-wordexp-expected-inputs` only captures the independent native
tool/oracle seal in the same pinned image; it runs no wordexp cell.

The finite credential-alias, address-taken atomic, crypt, strptime, and wordexp
differences retain upstream reports, counts and raw failures. The separately
bounded corrected-math entries retain their candidate-pass/pinned-musl-oracle-
defect accounting. Only the strict native collector may admit those named
records; all other outcomes still require raw success. See
[`owned-posix-native-dispositions.md`](owned-posix-native-dispositions.md) for
the exact source roster and mandatory same-product companions. The crypt,
atomic, wordexp report, expected-input seal, and every retained companion
artifact are rehashed between steps.
