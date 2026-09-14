# Native x86 loader structural-owner receipt design

`loader-structural-owner-receipt.toml` is the finite design for eight current
structural identities that each retain exactly one selector reason: `current
source-bound owning component and consumer semantics receipt`. It is not a
selector adapter, a family receipt, or a request to export any new symbol.

The design anchor is the clean `7dcafabe18a8ccea5bd73c6af49ae51be718c249`
cohort. Its selector report has 2,531 identities, 30,667 raw occurrences, and
1,365 unnamed raw occurrences; it has 339 blockers after the declaration
companion removal. The anchor is inspection evidence only. A later component
must collect fresh products from its own committed source and cannot relabel
this cohort as current evidence.

The TOML records the inspected 7dc selection, full-facts, inventory, static
preparation, dynamic manifest, and current registry-report identities. They
are development anchors for source and record-shape tests only. A future
collector records the same categories for its own clean revision and rejects a
receipt whose current source, products, manifests, or nested report differs.

## Exact boundary

The receipt covers these eight names and nothing selected by prefix:

| Group | Identities | Current selector disposition | What is being established |
| --- | --- | --- | --- |
| `loader-entry-stages` | `__dls2b`, `__dls3`, `_dlstart` | structural replacement | The selected interpreter's real initial load, relocation, TLS, debugger publication, and entry-transfer path replaces musl's named internal stages. |
| `loader-registration-operations` | `__ldso_register_dlopen`, `__ldso_register_dlsym`, `__ldso_register_dlclose`, `__ldso_register_dlerror` | structural replacement | The selected x86 direct runtime dlfcn operations and their per-thread diagnostics replace the old mutable registration protocol. |
| `loader-always-atomic-guard` | `__ldso_register_mark_multithreaded` | structural replacement | The selected loader lock and worker/TLS path supply the one-way before-first-worker synchronization boundary. |

None has an `expected_placement`. The component must not turn a structural
replacement into a `libc.a`, `libc.so`, or loader `dynsym` provider rule.

At the 7dc anchor, the frozen startup names have exactly six raw source
observations: each is `FUNC GLOBAL DEFAULT` once in `reference-shared`
`.dynsym` and once in `.symtab`. The five registration names have only
`frozen-project-dynamic` and native-structural-contract origins; they have no
invented reference row. These facts preserve the frozen identity origins, but
they do not prove current behavior.

The reader must retain every raw fact row, including all unnamed rows. It first
filters only rows whose `name` is a string in the exact eight-name set, then
constructs logical identities. A `null` row name never becomes an identity.
The report records the full and unnamed counts and the finite startup-reference
projection, and the later adapter compares those counts to its pre-join
accounting. Candidate rows are retained as raw observations, not silently
promoted to proof because this contract has no placement rule.

## Current source mapping

The current sources split the legacy spellings from the selected x86 behavior.
That distinction is a requirement, not an inconsistency to hide.

| Requirement | Source algorithm proof | Normal consumer observation | It does not prove |
| --- | --- | --- | --- |
| `__dls2b`, `__dls3`, `_dlstart` | The selected x86 `x86_64_general_initial_graph.rs::run_with_initial_tls` discovers the graph, plans TLS, relocates/protects and seals it, prepares and publishes the registry, then dispatches the preflighted constructor plan or jumps to entry. `x86_64_initial_graph.rs` and `x86_64_direct_entry.rs` close kernel/direct entry. `loader_startup_exports.rs` documents compatibility forwarding helpers, but is not the selected x86 entry owner. | A constructor and main in a normal dynamic C application reach the selected interpreter by PIE/non-PIE kernel and direct entry, then complete public dlfcn work. | No test calls `__dls2b`, `__dls3`, or `_dlstart`; success only shows that the selected entry route ran. The exact internal order comes from the isolated selected x86 graph source proof. |
| Four `__ldso_register_*` dlfcn names | The generic callback setters in `libc/src/c_abi.rs` are frozen-origin context. Separately, x86 `static_c_abi.rs` selects `general_dlfcn.rs` under `x86-owned-dynamic-runtime`; that leaf imports the closed runtime-operation table in `x86_64_runtime_registry.rs`. The selected x86 initial graph prepares and publishes that registry before a dependency constructor or application entry can use the public leaf. | A public installed-header C probe performs `dlopen`, `dlsym`, failed lookup plus one non-null/one-null `dlerror`, and `dlclose` against a known plugin. | A passing `dlopen` alone does not prove the source publication order or turn legacy callback slots into the selected x86 route. The source proof establishes the order; the runtime probe establishes the replacement's public behavior. |
| `__ldso_register_mark_multithreaded` | `dynamic_tls.rs::allocate_thread` asks the loader for a worker TLS token; `x86_64_initial_worker_tls.rs::allocate` takes `RuntimeGuard` before materializing and registering that token; `pthread_create_join.rs::create_selected_worker_with_attributes` obtains it before its clone seam. `__ldso_mark_multithreaded` and the generic registration slot remain legacy source context, not the selected x86 pthread call chain. | After its dlfcn sequence, the same C probe performs its first application `pthread_create`; the worker performs a defined public dlfcn lookup and joins. | A joined worker cannot establish global first-clone ordering. The exact token-before-clone and guard relation comes from this selected source path; the probe only observes its public consequence. |

The existing `loader_runtime_registry_evidence.py` is useful only as a nested
current receipt for its different nine-name private runtime-operation protocol.
Its contract explicitly leaves `crt_structural_leaves=false`; it cannot be
relabelled as proof of these eight names. The existing loader-debug component
likewise supplies retained selected-entry/debugger product context but is
component evidence, not this receipt.

## Planned receipt and replay schema

The future report schema is
`crabc.x86_64-loader-structural-owner-receipt/v1`. Its top-level fields are
listed exactly in the TOML: current `selected_source` and `collector`, finite
input identities, selected products and static preparation, base inventory,
complete facts, source algorithm projection, normal-consumer executions,
commands/runtime/artifacts, coverage, and false limits.

`coverage` names the exact eight identities, three groups, exact source
functions, dynamic execution cells, and a fact-filter record with complete and
unnamed counts. The report is valid only with `component-verified` and all
family/promotion/public/qualification flags false.

Collection first admits the clean current source, static preparation, dynamic
product, base inventory, full facts, and nested loader-debug and runtime-registry
reports. It obtains the six static and seven dynamic link-input modes from
`owned_posix_product_evidence.link_input_mode_projection()`, then retains all
source/probe/runner/tool/product/link/root bytes and modes before compiling. It then runs the prescribed normal C probes, captures
commands and roots, re-admits every input and source condition, and seals the
report. Public host replay reconstructs the source and supplied-product joins
from retained bytes and must not invoke an ambient compiler, linker, target
loader, or ELF tool. It performs the same final recheck and verifies report
bytes unchanged.

Static preparation is an authenticated cohort input even though this component
has no static interpreter-entry execution cell. A static execution must not be
presented as evidence for `_dlstart` or dynamic dlfcn registration.

## Probe design

Two new source-compiled C consumers use installed `dlfcn.h` and `pthread.h`
only. They never declare or call an internal stage/registration spelling.
Their common object bytes are linked first to the pinned musl 1.2.6 lane and
then to each candidate dynamic cell.

`loader_structural_owner_startup_probe.c` has a constructor that completes a
known-plugin dlfcn transaction before `main`; `main` repeats it and emits an
exact transcript. `loader_structural_owner_registration_probe.c` performs the
same complete dlfcn transaction, then creates and joins its first application
worker; the worker performs a defined lookup. Both run dynamic PIE and dynamic
non-PIE by ordinary kernel entry and direct interpreter entry. The pinned lane
is a behavioral comparator for the public dlfcn surface, never an oracle for
calling musl's internal stage names.

The component source guard isolates the selected x86 `run_with_initial_tls`
function body and verifies the fixed ordering of discovery, initial-TLS planning,
relocation, protection/RELRO, initializer preflight, registry preparation,
publication, and dispatch or jump. It separately verifies the selected x86
`general_dlfcn` module choice, its exact closed runtime imports, the matching
registry map, and the selected before-clone worker-TLS lock relation. It rejects
reordered, missing, duplicate, or widened transitions; it does not use an
arbitrary whole-file substring search.

## Tests before collection

The implementation starts with focused contract/reader tests that reject a
missing, duplicate, reordered, or extra identity; stale source/product/nested
receipt; changed source-algorithm order; altered command/root/object; and a
changed full/unnamed fact count. A fixture with unnamed and unrelated named
rows confirms name filtering happens before strict identity construction and
that unrelated rows survive the proposed join.

Normal source fixtures must retain the expected public references before link,
use the same object bytes in their compared lanes, and preserve all four
candidate dynamic cells. No dummy stage callable, static fallback, ELF/binary
mutation, dynamic-ELF authority review, AArch64 execution, family admission,
or selector discharge is part of this component.

## Limits

The stopped action is the separate private pthread dynamic-ELF authority review
with final-only mutation controls. It remains stopped. This contract is limited
to source/product/normal-runtime/retained-replay evidence and must stop rather
than widen into that route. It does not claim arbitrary DSO search, mapping,
relocation authority, a full loader family, campaign completion, qualification,
promotion, or public x86 support.
