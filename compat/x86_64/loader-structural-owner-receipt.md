# Native x86 loader structural-owner receipt design

`loader-structural-owner-receipt.toml` defines a finite design for eight current
structural identities. Every one currently has exactly the selector reason
`current source-bound owning component and consumer semantics receipt`. This is
not a selector adapter, family receipt, export rule, or request to reproduce a
historical symbol in an installed product.

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

None has an expected placement. The future component must not invent a
candidate archive, shared-library, loader `dynsym`, private provider, or
current-occurrence rule for these structural dispositions.

At the anchor, `__dls2b`, `__dls3`, and `_dlstart` each have one
`reference-shared` `FUNC GLOBAL DEFAULT` definition in `.dynsym` and one in
`.symtab`: six reference rows total. The five registration spellings have
`frozen-project-dynamic` and native-structural-contract origins, with no
invented reference occurrence. The receipt retains all supplied raw rows,
including unnamed rows. It filters only non-null names in this exact eight-name
set before logical identity construction. The report and eventual selector join
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

## Exact startup and constructor tail

The selected cfg set is fixed in the TOML:
`x86-owned-dynamic-runtime`, `crabc_general_initial_graph`,
`crabc_general_initial_lifecycle`,
`crabc_general_initial_tls_materialization_v1`,
`crabc_general_loader_libc_tls_runtime_v1`, and
`crabc_dynamic_main_thread_runtime_v1`.

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
join. Both use only installed `dlfcn.h` and `pthread.h`; no source fixture
names an internal stage, callback registration spelling, or private registry
function. Pinned musl compares this public surface; it is never an oracle for
calling historical internal stages.

## Tests and limits before collection

Focused reader/contract tests begin with missing, duplicate, reordered and
extra identities; missing/changed raw counts; null/unknown rows; stale or
cross-epoch source/products/nested reports; a changed link-input role/path/mode;
a changed cfg, entry branch, canonical-libc selection, reservation/materialize/
publish ordering, or owned-CRT tail; and missing/substituted/unpaired matrix
cells. Source fixtures retain expected public references before link. Every
candidate dynamic mode and its paired pinned comparator remains required.

This design neither implements nor selects a receipt. It contains no native
collection, selector admission, family/campaign/promotion/public-support claim,
AArch64 execution, ELF or binary mutation control, or dynamic-ELF authority
review. The stopped private pthread dynamic-ELF authority review with
final-only mutation controls remains stopped and is not reframed here.
