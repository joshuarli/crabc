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


## ELF alias and internal-binding contract

`run_owned_pthread_alias_contract.sh STATIC_SYSROOT DYNAMIC_SYSROOT` checks the
ELF binding boundary for the selected pthread, C11, and TSS bodies. It uses
pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` as the source and artifact oracle.
The relevant source files are `src/thread/pthread_cond_timedwait.c`,
`pthread_create.c`, `pthread_detach.c`, `pthread_join.c`,
`pthread_key_create.c`, `pthread_key_delete.c`, `pthread_getspecific.c`,
`pthread_mutex_{lock,timedlock,trylock,unlock}.c`, `pthread_once.c`, and
`pthread_{setcancelstate,testcancel}.c`.

| Source provider form | Public weak aliases |
| --- | --- |
| hidden global `__pthread_cond_timedwait` | `pthread_cond_timedwait` |
| hidden global `__pthread_create`, `__pthread_exit`, `__pthread_join` | `pthread_create`, `pthread_exit`, `pthread_join` |
| source-local `__pthread_detach` | `pthread_detach`, `thrd_detach` |
| source-local `__pthread_getspecific` | `pthread_getspecific`, `tss_get` |
| hidden global `__pthread_key_create`, `__pthread_key_delete` | `pthread_key_create`, `pthread_key_delete` |
| hidden global `__pthread_mutex_lock`, `__pthread_mutex_timedlock`, `__pthread_mutex_trylock`, `__pthread_mutex_unlock` | matching public mutex name |
| hidden global `__pthread_once`, `__pthread_setcancelstate`, `__pthread_testcancel` | matching public name |

The default static archive preserves the hidden global bodies already selected
there. `pthread_cond_timedwait` and `pthread_mutex_timedlock` are the
`x86-owned-static-runtime` additions. The two source-local bodies are retained
through typed local references because the assembler `.set` alias alone is not
a compiler reachability edge. `mq_notify` retains musl's public
`pthread_detach` relocation instead of naming the source-local body, so a
static application strong override may receive that source call. The alias
work does not change its worker, cancellation, synchronization, or lifetime
logic.

The runner compiles one C11 application object once. It links that object with
pinned musl static `ET_EXEC`, pinned musl shared PIE/non-PIE, owned static
`ET_EXEC`, static PIE, and owned shared PIE/non-PIE products. Static candidates
compare to static musl; each shared candidate kernel/direct-loader execution
compares to the matching pinned-musl shared mode. `readelf` retains and checks
`ET_EXEC` for static/non-PIE and PIE `ET_DYN` for static-PIE/shared-PIE before
checking one definition per public name, `FUNC WEAK DEFAULT` public aliases,
exact member/value/type/section identity with their provider, archive
hidden/global or source-local binding, and the shared dynamic export boundary.
It also checks musl's `mq_notify` archive member and the candidate's
`notify_start` relocation section: each names public `pthread_detach` and
neither names the source-local provider. The candidate product builder may
merge callers and aliases into one object, so this checks the caller relocation
rather than an unresolved-symbol-table row.

Its strong application `pthread_setcancelstate` override must handle the
application's direct call while `pthread_join` keeps its internal
`__pthread_setcancelstate` route, as `src/thread/pthread_join.c` requires. A
worker result and `pthread_join` provide the completion edge; each command has
a finite 45-second cap.

Run this focused proof in the pinned native image with fresh matching products:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" \
  ./compat/x86_64/run_owned_pthread_alias_contract.sh \
  .work/x86_64/pthread-alias-contract/static-product \
  .work/x86_64/pthread-alias-contract/dynamic-product
```

### Replayable owning receipt

The plain invocation above remains the immediate behavior and ELF judge.  A
selection consumer needs a stricter retained record, so the same runner also
accepts a fresh `--receipt-dir` together with the authenticated current product
anchor and the earlier pre-receipt input ledger:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" \
  ./compat/x86_64/run_owned_pthread_alias_contract.sh \
  --receipt-dir "$PWD/.work/x86_64/pthread-alias-receipt/clean-receipt" \
  --product-report "$PWD/.work/x86_64/pthread-alias-receipt/products-b41/loader-debug-report.json" \
  --historical-inputs "$PWD/.work/x86_64/pthread-alias-receipt/products-b41/historical-input-identities.json" \
  --historical-source-commit d8d6dc9a8fcfabb088ebd4de7e7504d526ff7d46 \
  "$PWD/.work/x86_64/pthread-alias-receipt/products-b41/static-product" \
  "$PWD/.work/x86_64/pthread-alias-receipt/products-b41/dynamic-product"

python3 -B compat/x86_64/owned_pthread_alias_contract_reader.py \
  --validate-report "$PWD/.work/x86_64/pthread-alias-receipt/clean-receipt/report.json"
```

`owned_pthread_alias_contract_reader.py` writes and replays the closed
`crabc.x86_64-owned-pthread-alias-contract/v1` component record.  It copies
the collector, probe, compact source-contract roster from the selected product
commit, musl inputs, selected product manifests and payloads, and the supplied
loader-debug product anchor.  The collector’s clean checkout identity and the
selected product source commit/digest are separate fields: the receipt code
may be newer than the b41 products it inspects.  The static and dynamic
manifests independently seal the drivers, `libc.a`, `libc.so`, and dynamic
loader.  The prior `d8d6dc9a` input ledger is retained only as historical
provenance and is explicitly forbidden from serving as a selected product.

The record contains every command argv/status/stdout/stderr, one compiled
probe object, each linked ELF and `readelf` header, musl linker maps, the
sealed static-driver JSON/map/trace sidecars, the dynamic-driver link receipts,
all raw symbol/relocation streams, and the four materialized chroot-root
trees.  Replay rehashes those retained files, reconstructs the static and
dynamic product/driver bindings, checks exact command/object/map paths,
recomputes the same-definition aliases and `mq_notify` public-detach source
policy, and verifies the runtime transcripts and executable modes.  It runs no
compiler, linker, or ELF tool.

The receipt covers only the 17 aliases in the table above, their listed source
providers, the `mq_notify` public `pthread_detach` relocation, and the one
strong-override/internal-`pthread_join` behavior.  It does not turn historical
products into current evidence, establish unlisted pthread symbols, complete a
pthread family, qualify a product, or promote native public support.

This is an ELF and internal-binding proof for the listed bodies. It does not
complete the pthread family, qualify the runtime, promote x86-64 support, or
change the public-support boundary.
