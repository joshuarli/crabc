# Native x86 loader structural-owner receipt

`loader-structural-owner-receipt.toml` defines a finite component for eight
current structural identities. Without its admitted receipt, each carries the
selector reason `current source-bound owning component and consumer semantics receipt`.
The separate `native_loader_structural_owner_adapter` and
`attach_loader_structural_owner` in `native_abi_selection.py` discharge only
that reason after validating the component. They add no symbol placement or
family qualification.

The design anchor is clean
`7dcafabe18a8ccea5bd73c6af49ae51be718c249`. Its selector report contains
2,531 identities, 30,667 raw occurrences, 1,365 unnamed raw occurrences, and
339 blockers after the declaration-companion removal. The anchor is only for
source and record-shape inspection. A later receipt must use products newly
collected from its own committed clean source; it cannot relabel this cohort as
current evidence.

## Exact boundary and raw facts

| Group | Identities | Current disposition | Replacement boundary |
| --- | --- | --- | --- |
| `loader-entry-stages` | `__dls2b`, `__dls3`, `_dlstart` | structural replacement | Selected x86 initial graph, TLS, relocation, registry publication, and entry transfer. |
| `loader-registration-operations` | `__ldso_register_dlopen`, `__ldso_register_dlsym`, `__ldso_register_dlclose`, `__ldso_register_dlerror` | structural replacement | Selected x86 direct runtime operations and per-thread `dlerror` state. |
| `loader-always-atomic-guard` | `__ldso_register_mark_multithreaded` | structural replacement | An always-atomic loader graph lock from the first transaction, plus a separately proved worker-TLS-token-before-clone relation. |

None has an expected placement. The component must not invent a
candidate archive, shared-library, loader `dynsym`, private provider, or
current-occurrence rule for these structural dispositions.

At the anchor, `__dls2b`, `__dls3`, and `_dlstart` each have one
`reference-shared` `FUNC GLOBAL DEFAULT` definition in `.dynsym` and one in
`.symtab`: six reference rows total. The five registration spellings have
`frozen-project-dynamic` and native-structural-contract origins, with no
invented reference occurrence. The receipt retains all supplied raw rows,
including unnamed rows. It filters only non-null names in this exact eight-name
set before logical identity construction. The report and selector join
compare complete and unnamed counts before and after the join; no unowned row
is discarded.

## Selected x86 source and legacy context

The selected x86 route is distinct from legacy source context. The reader must
validate both relationships, without treating a final successful application as
proof of startup order.

| Requirement | Selected source proof | Ordinary public observation | Explicit limit |
| --- | --- | --- | --- |
| `__dls2b`, `__dls3`, `_dlstart` | `ldso/src/x86_64_general_initial_graph.rs::run` chooses kernel `parse_mapped` or `x86_64_direct_entry.rs::prepare`, then enters `run_with_initial_tls`. That function discovers and selects canonical libc, plans TLS, relocates/protects and seals RELRO, prepares the registry and reservations, materializes then commits TLS, and publishes the registry. | Constructor and main reach the selected interpreter in all four candidate entry cells and complete normal public dlfcn work. | Internal stages are never called. The exact order comes from isolated selected source proof, not a passing application. |
| Four dlfcn registration spellings | `static_c_abi.rs` selects `general_dlfcn.rs`; its closed imports map through `x86_64_runtime_registry.rs::runtime_function`. The selected initial graph publishes the prepared registry before constructor or application entry can use that leaf. | A known plugin completes `dlopen`, `dlsym`, failed lookup, one non-null then one null `dlerror`, and `dlclose`. | Generic setters in `libc/src/c_abi.rs` are frozen source context. A passing `dlopen` does not prove their installation or make them the selected x86 route. |
| `__ldso_register_mark_multithreaded` | `x86_64_runtime_lock.rs` owns one `AtomicI32` graph lock. Every `RuntimeGuard` acquisition uses its atomic CAS and every drop releases it. Separately, `dynamic_tls.rs::allocate_thread` requests the loader token; `x86_64_initial_worker_tls.rs::allocate` acquires `RuntimeGuard` before materializing/registering it; `pthread_create_join.rs::create_selected_worker_with_attributes` obtains it before clone. | After normal public dlfcn work, a probe creates and joins its first application worker; the worker performs a defined public lookup. | There is no selected enabled-state or one-time lock transition. Worker success does not prove scheduling order; source proves the guard/token-before-clone relation. |

The reviewed `pthread_creator` body also retains the native-shadow attach and
allocator-descriptor control fields plus the parent post-clone handoff under
exactly `native-mimalloc-shadow`. `static_c_abi.rs` rejects combining that
feature with the selected C-backend `x86-owned-dynamic-runtime` route unless
the separate `x86-owned-dynamic-native-shadow` owner is selected. The selected
C-backend route does not compile these native-shadow fields, so this extension
does not change its control-record layout. It keeps the same token-before-clone
relation. Worker entry and exit lifecycle algorithms remain allocator evidence
and are not added to this structural-owner receipt.

`__dls2b` and `__dls3` remain legacy helper context in
`libc/src/loader_startup_exports.rs`. `_dlstart` has its own legacy context:
`libc/src/c_abi.rs` contains the old libc-side route, while
`libc/src/dynamic_loader_introspection_exports.rs` documents its trampoline to
`__ldso_dlstart`. `libc/src/lib.rs` selects `static_c_abi` for x86, so neither
is the selected x86 entry owner. The TOML records these contexts separately so
the two helper names cannot appear to stand for all three historical stages.

The existing `loader_runtime_registry_evidence.py` remains a nested receipt for
its different nine-name private protocol; its `crt_structural_leaves=false`
limit prevents it from discharging this component. The loader-debug component
supplies selected entry/debugger product context only.

## Component collection and retained replay

`run_loader_structural_owner_contract.sh` compiles the two ordinary C
consumers and their one public plugin once, then links each unchanged
consumer/plugin object pair through pinned musl 1.2.6 and the supplied
candidate in the four dynamic entry cells. The startup consumer performs its
normal public dlfcn transaction in a constructor and again in `main`. The
registration consumer completes that transaction before its first application
worker, whose public lookup is joined before the fixed transcript. Neither
probe names a frozen stage spelling or a private registration callback.

`loader_structural_owner_contract_reader.py` retains every source/product/tool
input, command stream, executable, and before/after root. It validates the
selected source functions independently: the graph order, crate-qualified
ldso/libc feature routes, owned-CRT constructor tail, always-atomic lock,
worker token before clone, and closed public dlfcn registry route. It replays
the same current clean source, static preparation, complete facts, loader-debug
receipt, and loader-runtime-registry receipt before and after normal execution.
Host replay reconstructs the retained bytes without a compiler, linker, or
target execution tool. This is component evidence only; it cannot attach a
selector companion or close a runtime family.

The source checks isolate brace-balanced selected bodies, remove comments only
for their reviewed fingerprints, retain every string and character literal,
and reject duplicated or false-branch transitions. The fingerprint is a
reviewed source-algorithm baseline, separate from the retained current source
hash: a changed cfg feature or resolver target cannot become accepted merely
by retaining its own new bytes.

Native collection records checkout and supplied-product paths under the fixed
`/workspace` mount. It separately retains the pinned image invocations for
the musl compiler/runtime, `timeout`, and `chroot`; retained host replay uses
those copied identities and canonical recorded paths, never an ambient host
`/opt` or `/usr/local` tool. The existing pinned-image manifest
`owned-resolver-alias-image-inputs.json` is a source-contract input for this
finite invocation set: it resolves `/usr/bin/timeout` and `/usr/sbin/chroot`
to their one physical `/bin/coreutils` target while preserving their canonical
argv spellings.

## Exact startup and constructor tail

The selected cfg is crate-qualified in the TOML. `ldso`'s
`x86_64-owned-dynamic-runtime` feature selects
`x86_64-general-initial-lifecycle` and
`x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter`; its
build route emits `crabc_general_initial_graph`,
`crabc_general_initial_lifecycle`,
`crabc_general_initial_tls_materialization_v1`,
`crabc_general_loader_libc_tls_runtime_v1`, and
`crabc_dynamic_main_thread_runtime_v1` for
`x86_64_general_initial_graph.rs::run_with_initial_tls`. Separately, libc's
`x86-owned-dynamic-runtime` feature selects
`static_c_abi.rs::fixed_graph_dlfcn` from `general_dlfcn.rs`. The two feature
names are source-specific routes and cannot substitute for one another.

`run_with_initial_tls` must retain this order: discovery; canonical-libc
selection; TLS planning; debugger/relocation; protection and RELRO; initializer
preflight and registry preparation; lifecycle/publication reservations; TLS
materialization; RuntimeV1 commit; registry publication; conventional-startup
publication when applicable. The reader rejects materialization moved before
relocation or RELRO, and after registry publication.

For all four candidate cells, the tail is fixed to the owned CRT handoff, never
an unconstrained `dispatch or jump` choice. Under the selected lifecycle plus
dynamic-main-thread cfg, the graph retains the dependency plan;
`x86_64_general_initial_lifecycle.rs::owned_dependency_constructors` exposes
it through `OwnedCrtHandoffV1`. After libc state and executable preinit,
`crt/src/x86_64_dynamic_startup.rs::__crabc_x86_64_dynamic_executable_init`
runs the retained dependency constructors, then `_init` and the executable init
array. Kernel cells use `run`'s mapped-main branch; direct cells use its
`x86_64_direct_entry::prepare` branch. The report records that named branch and
owned-CRT tail per candidate cell.

## Cohort, source and replay relation

The component has one permitted epoch: one clean current canonical source
identity `{revision, tree, source_sha256}`. `collector`, `selected_source`, and
each retained source-contract/collector Git blob equal that identity and its
recorded mode. Static preparation must expose the same revision/content hash;
the dynamic state must expose its source hash; loader-debug must expose the
same source commit/hash; and loader-runtime-registry must expose the same
revision/content hash. Public base-inventory and full-facts replay validates the
same static preparation and dynamic root. A future multi-epoch contract would
need a separately named and authenticated relation; this design has no waiver.

The report schema is
`crabc.x86_64-loader-structural-owner-receipt/v1`. Alongside current source,
products, preparation, facts, source algorithms, commands, roots and coverage,
it records `source_cohort`, `selected_runtime`, and
`normal_consumer_matrix`. The matrix records exact cells, pairings, shared
object identities, and candidate entry/tail references. Collection admits the
whole cohort before compiling, repeats the admission after commands, and host
replay repeats it from retained bytes without ambient compiler, linker, target
loader, or ELF tool. It also rechecks report bytes unchanged.

The product input projection is complete, not counts: the six static roles
`crt1.o`, `rcrt1.o`, `crti.o`, `crtn.o`, `libc.a`, and
`libcrabc-builtins.a` are each `0644`; the seven dynamic roles `crt1.o`,
`Scrt1.o`, `crti.o`, `crtn.o`, `libcrabc-builtins.a`, and
`crabc-dynamic-attach.o` are `0644`, while `libc.so` is `0755`. The reader
compares this exact role/path/mode map to
`owned_posix_product_evidence.link_input_mode_projection()` and validates raw
current modes before trusting retained copies or manifests.

## Ordinary normal-consumer matrix

Each of the two new installed-header C probes has exactly eight retained
executions: four pinned-musl-1.2.6 comparator cells and four candidate cells:
`dynamic-pie-kernel`, `dynamic-pie-direct`, `dynamic-non-pie-kernel`, and
`dynamic-non-pie-direct`. Each candidate cell has exactly one same-mode pinned
comparator. The consumer and plugin object bytes are identical within every
pair; a missing, substituted, duplicate, unpaired, or extra cell rejects.

`loader_structural_owner_startup_probe.c` requires a constructor dlfcn
transaction before main and a second exact main transaction.
`loader_structural_owner_registration_probe.c` requires its public dlfcn
transaction before first application `pthread_create`, then a worker lookup and
join. They use only installed public headers: `dlfcn.h`, `pthread.h` where the
worker probe needs it, and `stdio.h`/`stdlib.h` for their fixed transcript and
failure path. No source fixture names an internal stage, callback registration
spelling, or private registry function. Pinned musl compares this public
surface; it is never an oracle for calling historical internal stages.

## Tests and qualification boundary

Focused reader/contract tests begin with missing, duplicate, reordered and
extra identities; missing/changed raw counts; null/unknown rows; stale or
cross-epoch source/products/nested reports; a changed link-input role/path/mode;
a changed cfg, entry branch, canonical-libc selection, reservation/materialize/
publish ordering, or owned-CRT tail; and missing/substituted/unpaired matrix
cells. Source fixtures retain expected public references before link. Every
candidate dynamic mode and its paired pinned comparator remains required.

Bounded native evidence is accepted at clean revision
`60f18674e7ea831bbf17a14d3c0f1d7c508e8298`, retained in
`.work/worktrees/loader_structural_owner_contract`. Its
`.work/x86_64/loader-structural-owner/clean-60f18674/report.json` is
`component-verified` (SHA-256
`f0ab5260f278509d4315dd5bacee38bfbafd7a0df92a8b5d60a583f690f075f4`),
with 37 successful commands and all 16 paired consumer executions. The
separately recorded replay recovery preserves the original failed attempt.

The selector audit at that revision passed; its closure replay returned the
expected incomplete status. The retained
`.work/x86_64/native-abi-selection/clean-60f18674/report.json` (SHA-256
`3db65b7b49b9d9829d2d3c68f7951b8e551337fe47a49601764ce3dc7232447b`)
has 331 blockers. Compared with the design anchor, only the eight named
requirements were removed. All 2,531 identities, 30,667 occurrences, and
1,365 unnamed occurrences remain; no placement was added.

The component receipt itself retains `selector_admission=false` and
`runtime_qualification=false`: the separate selector proves its bounded attachment.
Neither result closes a family or campaign, promotes the runtime, or changes
public support. The evidence contains no AArch64 execution, ELF or binary
mutation control, or dynamic-ELF authority review.
The stopped private pthread dynamic-ELF authority review with final-only
mutation controls remains stopped and is not reframed here.
