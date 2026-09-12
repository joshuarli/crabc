# Installed pthread/TLS behavior component

`owned-pthread-family` is a finite, non-promoting installed-product component
for `libc.pthread-tls`. It consumes one already validated
`owned-posix-family` `execution.json`; that immutable input seals the three
static products, three dynamic products, their exact source and pinned-musl
identities, and the prerequisite retained workload results. It never builds a
sysroot or treats a private archive/header leaf as installed behavior.

Run it after preparing matching products from clean committed source:

```bash
./scripts/dev-x86_64.sh owned-pthread-family \
  --family-execution .work/x86_64/posix-family-run/execution.json \
  --output .work/x86_64/pthread-family-run \
  --jobs 3
```

The output must be a fresh physical child of `.work`. `--jobs` bounds only the
three independent supplied-product replays; it is `1`, `2`, or `3`. Each replay
uses its supplied static and dynamic products and does not rebuild either.

[`pthread-family.toml`](pthread-family.toml) is the exact required
behavior-by-mode roster. Its six static cells are primary, reproduction, and
extracted `static-et-exec` and `static-pie`; its twelve dynamic cells are
installed, second, and extracted `dynamic-pie`/`dynamic-non-pie` through both
kernel and direct-loader entry. The coordinator rejects a missing row or mode,
rather than treating a runner’s lack of coverage as an exemption.

| Required behavior | Required cells | Retained owner |
| --- | --- | --- |
| C11 lifecycle/TLS/synchronization composition | all 18 | one supplied-product composition replay per product pair |
| static and dynamic atfork/fork | six static; twelve dynamic | POSIX matrix `static-fork` and `fork` rows |
| ordered atfork callbacks and pthread exit/TLS | twelve dynamic each | dynamic qualification `atfork-registry` and `pthread-exit` cases |
| pthread signal delivery | all 18 | POSIX matrix `pthread-signal` row |
| timer-thread notification, callback cleanup, TLS/DTV reuse | all 18 | POSIX matrix `posix-timers` row |
| join/cancellation, condition, mutex, spin, getattr, scheduling, CPU clock | twelve dynamic each | named dynamic-qualification case receipts |

The one new composition starts from an installed-header C11 object, compiled
once for each product pair and required to have identical bytes across the
three pairs. Pinned musl separately links the same object. The object checks
C11 create/join results; per-worker initialized and zero TLS; contended
`call_once` publication; two-pass TSD destructor rearming before join returns;
three reusable barrier phases with one serial return each; overlapping rwlock
readers, writer exclusion, and post-writer publication; and a contended
spinlock state handoff. Its synchronization uses barriers and mutex/condition
handshakes, never scheduling delays.

The receipt schema is `crabc.x86_64-owned-pthread-family/v1`. It keeps the
POSIX execution input, roster identity, each selected prerequisite receipt,
and each composition leaf’s source/object/product/oracle identities, link
evidence, command argv/status/stdout/stderr, and runtime raw streams. A receipt
sets `component_complete=true` only when every required cell is present and
valid. It always sets `family_completion=false`, `promotion_ready=false`, and
`public_support=false`; dependency ordering and family admission remain
separate gates.

The coordinator retains the POSIX matrix request’s native source mount. This
lets a host-side replay require the original `/workspace` command and
environment spelling instead of substituting host checkout paths. Every
composition link is then rechecked through the retained-receipt reader in
`owned_posix_product_evidence` with the retained `workload.o`, executable,
link receipt, and selected static or dynamic product. It rehashes the current
payload, link inputs, sidecars, trace, and ELF while comparing each receipt’s
native `ld.lld` identity to a before/after compiler-tool roster; it does not
pretend that the host has the native container linker. The musl compiler,
libc runtime, and oracle-pin hashes must match the validated POSIX matrix
oracle.

Each coordinator phase creates a private `_ValidatedPthreadInputs` context.
At its boundary, `_validated_phase_inputs` asks the POSIX matrix owner to
perform one complete validation, then
`owned_posix_family_execution._validated_input_products` recovers only the
sealed request, physical product paths, source identity, and product-manifest
anchors needed by the pthread mappings. It does not make a second public
producer-validation path. Before the complete matrix validation begins, the
context snapshots the declared POSIX matrix, static-preparation, and
dynamic-qualification evidence subtrees. It also follows every hash-sealed
dynamic case record's `artifacts` map and snapshots each declared artifact
directory, including an exact retained leaf outside the dynamic work directory.
It records that case roster and its hashes without adding a broad `.work` cache
parent.
The static-preparation collector retains its products, archives, and steps
under its preparation root; POSIX matrix leaves are constrained below their
own `runs/*/*/tmp` step roots. Those roots already cover their complete retained
input closure.

The context records source and roster identities separately from the oracle.
Offline collection and standalone validation use
`owned_dynamic_qualification.validate_oracle` to check retained oracle bytes,
pins, manifests, and specs before admission, after matrix validation, and at
phase end; they never probe image-only live oracle paths. Only `execute` marks
its explicit native runtime phase and uses `require_live_oracle` before and
after its composition subprocesses. The context requires the same roots and
identities after matrix validation, then checks them again before the phase
accepts or writes its result. A changed retained artifact, product, source,
request, or oracle therefore cannot use facts admitted before the change.
Contexts do not cross phase boundaries: composition execution, its following
receipt collection, and standalone receipt validation each admit a fresh
upstream matrix. The mutable pthread output must be disjoint from those input
evidence roots.

The same host reconstruction compares the whole `dynamic-root` copied product
to its selected installed product, including every payload file and alias. It
also requires `consumer-pie` and `consumer-non-pie` to be exact copies of their
respective sealed executables before accepting either kernel or direct-loader
runtime stream.
