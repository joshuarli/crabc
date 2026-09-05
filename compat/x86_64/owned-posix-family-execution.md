# POSIX workload matrix execution

The POSIX family requires runtime observations from three independent static
products and three dynamic products. `owned_posix_family_execution.py` consumes
the static preparation receipt and complete dynamic qualification receipt,
then runs the finite workload roster against those products. It does not build
replacement products, publish a product, or close `libc.posix-runtime`.

Run from clean committed source through the pinned native dispatcher:

```bash
./scripts/dev-x86_64.sh owned-posix-family \
  --static-preparation .work/x86_64/static-products/preparation.json \
  --dynamic-qualification .work/x86_64/dynamic-products/qualification.json \
  --output .work/x86_64/posix-family-run
```

Both input receipts must validate against current source and retained products.
The output must be a fresh physical directory under checkout `.work`. The
dispatcher translates the host receipt/output paths through its actual mounts.
The execution container permits the existing contained chroot, procfs-mount,
and credential-namespace workloads. It does not invoke AArch64 commands.

The coordinator pairs `primary` static with `installed` dynamic,
`reproduction` static with `second` dynamic, and the two `extracted` products.
For each pair it runs all eighteen workloads in
`owned_posix_family_workloads.WORKLOADS`: sixteen use supplied static and dynamic
products, the strong `fork` workload uses its dynamic product, and `static-fork`
uses its static product. A normal paired replay covers static ET_EXEC and static
PIE plus dynamic PIE/non-PIE through kernel and direct interpreter entry.

The installed drivers own workload translation. Each leaf retains its exact
object roles and links those bytes to pinned musl and its candidate products.
The coordinator allows translation to repeat for an independently built or
extracted product, but requires byte-identical objects for every role across
all three replays. The static fork pair and the dynamic fork DSO transaction
remain separate contracts. The additional crabc-private fork layout object is
required candidate evidence; musl does not implement crabc's private FS layout.

`owned_posix_family_observations.collect` reads the finite raw-file layouts and
rejects missing statuses, streams, scenarios or entry modes. Ordinary results
are compared byte-for-byte. The selected credential alias profile and
`fexecve` seccomp result retain their exact documented differences. Timer
reclamation checks and the bounded musl timer startup-race investigation remain
explicit supplemental observations. Fork's worker-survivor protocol retains
the full PID-bearing stream and validates its semantic tail; different process
IDs are not represented as byte-identical raw stdout.

Every command has a private `runs/PRODUCT/WORKLOAD/tmp` directory. Its runner
must declare exactly one retained evidence root directly below that directory.
The coordinator seals command arguments, fixed environment, raw outer status
and streams, source/object identities, and every retained leaf artifact.
Snapshots preserve file bytes, permissions, ownership, link counts, symlink
targets and special fixture-node kinds without opening FIFOs or following
symlinks. Link receipts, compiler/header audits and inspected ELF files stay
in the source-bound leaf snapshot; specialized leaf judges keep their own
one-object, multiple-process or DSO contracts.

After runtime permission checks, retention adds regular-file read bits and
directory read/traverse bits. It preserves write and execute bits and never
follows symlink targets. A failed step retains its invocation, actual exit
status, both streams and any artifacts already produced. Prior successful
step receipts remain available; a failure does not produce `execution.json`.

The final `execution.json` has schema
`crabc.x86_64-owned-posix-family-execution/v1` and status
`workload-matrix-verified`. It binds current clean revision/content, both
validated input receipts and the observed musl identity, all workload receipts,
and each of the 149 frozen spellings to all six static and twelve dynamic
cells. The explicit `fork → static-fork` static binding prevents a dynamic-only
result or the composition workload from standing in for static fork evidence.

Validate without executing workloads again:

```bash
python3 -B compat/x86_64/owned_posix_family_execution.py validate \
  .work/x86_64/posix-family-run/execution.json
```

Validation recomputes the receipt from its source seals, current products,
retained files, raw observations and immutable object sets. It rejects changed
source, missing product/workload cells, receipt or fixture mutation and JSON
scalar-type substitutions. Checkout-relative identities and the retained
source mount support host validation of container-produced evidence.

A complete workload matrix is one input to the native successors of the frozen
differential, OS-test, signal/process, pthread-stress and libc-test aggregate.
`native_aggregate_complete`, `family_completion` and `public_support` remain
false in this receipt. Those obligations and the frozen family scope remain in
`owned-posix-runtime.md`; a workload matrix cannot substitute for them.
