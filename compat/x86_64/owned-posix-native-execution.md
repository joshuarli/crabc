# Native POSIX aggregate execution

`owned_posix_native_execution.py` consumes a fully validated three-product POSIX
family `execution.json` and an installed-product `crypt-profile.json`, selects its installed dynamic product, and executes
five fresh component commands in fixed order: differential, os-test,
signal-process, pthread-stress, and libc-test. It neither builds products nor
substitutes the static workload matrix for these native runs.

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
  --output .work/x86_64/posix-native
python3 -B compat/x86_64/owned_posix_native_execution.py validate \
  .work/x86_64/posix-native/native-execution.json
```

A validated `native-execution.json` sets only `native_aggregate_complete`.
`campaign_complete`, `family_completion`, and `public_support` remain false.
The focused coordinator regressions use explicit prerequisite/native judge
seams and five actual subprocesses; they do not claim real runtime qualification.

The finite credential-alias and crypt differences retain upstream reports, counts
and raw exit 1. Only the strict native profile collector may qualify these two
components; all other outcomes still require raw success. See
[`owned-posix-native-dispositions.md`](owned-posix-native-dispositions.md) for
the exact source roster and mandatory same-product companions. The crypt
receipt and every retained companion artifact are rehashed between steps.
