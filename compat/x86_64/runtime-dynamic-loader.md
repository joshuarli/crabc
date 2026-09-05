# General runtime-loader ownership work

The materialized initial dynamic product is the execution substrate, not a
substitute for runtime loading. `run_general_dynamic_dlopen.sh` reuses the
ordinary nested plugin consumer, whose plugin and transitive dependency are
absent from the initial graph. Its original status-10 failure is now replaced
by an executed installed/extracted runtime-load differential, not a private
selected-graph callback seam. The complete dynamic campaign remains open.

The compatibility source is musl 1.2.6, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT:
`ldso/dynlink.c::{dlopen,load_library,load_deps,extend_bfs_deps,do_relocs,
queue_ctors,do_init_fini,install_new_tls,__libc_exit_fini}` and
`src/ldso/dlclose.c`. `dynlink.c::{find_sym2,do_dlsym,dladdr,dl_iterate_phdr}`
and `src/ldso/dlinfo.c` provide lookup and introspection behavior. Runtime maps remain resident after close; reopen retains
identity and process finalization owns destructors. Failed admission rolls back
only new maps. Physical close-time unmapping is not the musl parity target.

## Relocation and coherent TLS generations

`x86_64_general_relocation.rs` now takes borrowed slice-sized scope views and
uses the same lookup, preflight and apply algorithms for initial and runtime
transactions. Ordinary runtime relocation writes only the new suffix: retained
maps supply symbols, while only explicitly queued deferred GOT/PLT words may
be filled by a later successful admission. The initial private handoff
remains initial-only. Runtime GD relocations use monotonic module IDs with no
initial-array ceiling; TPOFF still requires an initial module with retained
Variant-II placement. Forty-object and new-GD-versus-IE regressions check the
direct algorithm boundary, including all-or-nothing failure before writes.

`x86_64_runtime_tls_view.rs` implements one prepared current-view generation.
FS+8 and FS+16 remain the immutable initial DTV and size table described by
the unchanged 72-byte RuntimeV1 record. The reserved aligned FS+24 word holds
an atomic pointer to a descriptor containing both current tables. Readers
acquire that pointer once; a new DTV cannot be paired with an old size table.
Existing module addresses are copied unchanged, preserving live mutations;
new module storage is copied from relocated templates with the ELF alignment
phase and zeroed TBSS. Prepared-but-abandoned generations unmap only their own
storage and cannot change a live thread's view.

The existing aligned FS+32 slot is reserved for libc's opaque
`SelectedWorkerCancellation *` cancellation-state pointer, not a ThreadControl
pointer. It is zero in fresh main/worker allocations, is never copied
from another thread, and survives descriptor growth unchanged. libc owns
release publication before callbacks/handler unmask, signal-safe acquire
lookup and clear/reclamation lifetime. ldso never dereferences it or calls
the pthread owner while locked. FS+40 remains the compiler's process guard;
neither reservation expands RuntimeV1 or the existing TCB allocation extent.

This descriptor layout and retained-generation storage are crabc ownership
machinery, not musl's private `struct pthread` or signal-barrier implementation.
Published old views remain mapped for in-flight readers and for TLS images
referenced by later views. Their release is attached to the existing opaque
worker-token boundary, after kernel clear-child-TID and reader withdrawal.
A failed unmap retains the current unreleased head for retry. The main thread's
views remain process-owned. An actual mmap test proves multiple generations,
over-aligned template/TBSS, unchanged addresses/live values, abandoned
preparation, old-view readers, bounds and unchanged initial attachment.
Concurrent acquire readers remain valid during repeated generation
publication; malformed/gapped/duplicate/overflowing module populations leave
the live view unchanged. The installed initial-product gate still passes
through the updated resolver/release path. `PreparedAllThreads` now owns every
unpublished per-thread view under the mutation guard: partial failure drops
only new views and leaves every live descriptor untouched. Successful admission
publishes all views before making new object scope observable.

## One executing runtime registry

`x86_64_runtime_registry.rs` owns runtime object nodes and their dependencies in stable loader-owned
mappings, independent of the initial fixed stack-array capacity. The initial
canonical map owner remains immutable and is borrowed, never remapped or made
rollback eligible. Admission and scope changes serialize with worker TLS
allocation/release under one loader mutation boundary; no pthread list lock or
libc allocation is acquired there. The selected pthread owner calls allocate
before list publication and release only after list withdrawal, with that list
lock released in both cases.

All current-thread descriptors are prepared before any new module scope is
published. Scope publication follows descriptor publication for the retained
main and every registered worker, including allocations not yet cloned. Worker
creation copies the latest complete module population under the same lock.
No lock spans application constructors/destructors. Per-object execution
ownership handles recursive loading, concurrent initialization and process
shutdown while preserving source-shaped dependency and finalization order.

Initial registry nodes borrow canonical map identities and immutable metadata.
Their callback addresses and initial queue are prepared before ARCH_SET_FS;
publication follows the existing initial graph/RuntimeV1 commit without a
fallible step. The registry becomes the sole executing callback owner for the
installed feature; the old initial execution state serves only cfg-disjoint
private roots. Runtime nodes own newly mapped objects until relocation,
callback preflight, protection, RELRO and all-thread TLS preparation succeed.
Failed transactions drop only these new nodes/maps in reverse order. Retained
objects are not made rollback eligible; previously resolved words are never
relocated again.

The mutation boundary is a raw private futex lock, independent of libc malloc
and the pthread list. Constructor claims identify the executing kernel TID;
same-thread recursion skips its own claim, other threads wait outside the lock.
Finalizer ownership is registered before constructor invocation, but eligibility
requires completed initialization. An exiting constructor never dispatches
its own partially initialized object's destructor; completed dependencies
still finalize, matching musl's separate `ctor_visitor`/`constructed` states. Process shutdown closes
new admissions; process finalization is once-only and distinct from retained
`dlclose`, which validates identity without unloading or calling destructors.

`general_dlfcn.rs` is the cfg-selected installed C bridge. It owns real TLS
diagnostics and C sentinel adaptation, not object state. Its private function
imports resolve directly to the interpreter; the 72-byte RuntimeV1 and
32-byte OwnedCrtHandoff do not expand. An x86 tail trampoline preserves the
original C return address for `RTLD_NEXT`. Names, program headers and link-map
records borrow retained objects; `dl_iterate_phdr` drops the lock around user
callbacks and reads the successor afterward, admitting nested loading.

## Executed evidence and remaining conditions

`run_general_dynamic_dlopen.sh` first reuses the unchanged portable nested
plugin fixtures. Its ordinary TLS consumer then loads 41 runtime-new DSOs
while four workers remain alive, checks newly created worker templates,
GD/dlsym TLS, over-alignment, TBSS, retained live values/addresses, local/global
scope, promotion, repeated close/reopen/NOLOAD/NODELETE, introspection,
recursive self-open and concurrent once-only construction. Full stdout,
including reverse-order process destructors, matches pinned musl. A separate
scope consumer proves `RTLD_NEXT` from a local caller and ordered global
promotion. Five pre-callback failure cases preserve object count, existing
scope and TLS and permit a later successful load; new initial-exec TLS and
undefined-symbol failures are musl differentials, while malformed ELF cases
are owned fail-closed tests. The materialized product gate repeats these
consumers through both freshly installed and extracted sealed drivers.

`run_general_dynamic_constructor_exit.sh` separately compares the same exiting
constructor as a runtime-new DSO and an initial dependency. Both retain the
completed earlier dependency's destructor but skip the incomplete object's
destructor. The source-root tests keep the harness libc's own ELF TLS resolver;
the owned resolver is exported only in production. Raw mincore-after-unmap
probes run in isolated no-libc child mappings so unrelated parallel test mmap
reuse cannot manufacture a failure. This harness isolation is not dynamic
fork support; the full source suite remains parallel.

Runtime counts and scratch allocation are resource-sized. Existing initial
ELF/path/per-object admission bounds remain; this is not a claim to remove
every initial parser limit. Search currently uses
the admitted absolute RUNPATH and `/usr/lib`, or a direct pathname. Complete
caller/ancestor/environment search semantics remain unqualified. Initial
physical enumeration still follows canonical discovery order, while symbol
scope is breadth-first; broader initial-graph introspection/order parity needs
its own differential before qualification.

## Deferred GOT/PLT admission and RELRO safety correction

`x86_64_deferred_relocations.rs` implements pinned musl's
`prepare_lazy/do_relocs/redo_lazy_relocs`: `RTLD_LAZY` may retain unresolved
strong GOT/PLT relocations, but not malformed symbols, absolute data/TLS
relocations, or objects requesting BIND_NOW. Undefined weak references bind
zero immediately. This is retry-on-later-dlopen behavior, not a first-call
PLT resolver. Calling a still-unresolved function is not made safe.

The registry retains validated pending coordinates in raw loader-owned
storage. New relocation preflight includes deferred destinations in the same
metadata/overlap proof. Retries use prospective final global scope: LOCAL
provider admission leaves a pending word unchanged, while later NOLOAD/GLOBAL
promotion can resolve it. Failed graph/TLS/relocation preparation cannot alter
retained pending words, visibility or TLS descriptors. All registered TLS
views publish before atomic aligned GOT-pointer stores; no callbacks occur
under the loader lock.

There is one explicitly isolated pinned-source safety correction. Musl seals
RELRO in `reloc_all`, then `redo_lazy_relocs` writes deferred GLOB_DAT through
that read-only page when a provider arrives. The ordinary GOT fixture faults
with SIGSEGV in pinned musl 1.2.6. Crabc preallocates a page/write journal,
temporarily makes only affected RELRO pages RW as the final fallible admission
step, publishes the committed graph/TLS and resolved pointers, and restores
every page read-only before callbacks or return. Abandonment or a later
mprotect failure restores earlier pages without writing any pointer. An
impossible restoration failure terminates rather than exposing a writable
runtime outside the transaction. This correction is not reported as musl
parity. Source tests prove actual protection faults after abandonment, late
permission failure and successful commit, with raw no-libc child isolation.

The installed driver defaults to NOW. `--binding lazy` selects genuine lazy
ELF; unresolved imports additionally require shared-object-only repeated
`--runtime-import NAME` declarations. Exact strong undefined object symbols
are checked against owned definitions before linking, and output dynamic
imports are checked again. No incidental undefined symbol, foreign provider
or private fixture graph is admitted; the receipt records binding and imports.

`run_general_dynamic_lazy.sh` runs installed/extracted PIE and non-PIE
consumers. It checks NOW rejection, deferred PLT/GOT admission, a later failed
absolute relocation leaving old GOT bytes/object count/visibility unchanged,
LOCAL versus GLOBAL promotion, preexisting-worker GD TLS, retained close, and
read-only GOT protection after completion. PLT output is a musl differential;
the GOT/RELRO fault versus success is the isolated safety correction above.
The prior retained loader rejects the same lazy consumer with status 2 before
callbacks. The complete dynamic campaign, search policy, dynamic fork and
main/last-thread process-exit qualification remain open.

Dynamic fork repair and
main/last-thread pthread_exit remain explicitly unqualified and cfg-excluded
from the separate static lifecycle work. No new RuntimeV1 fields, public
support promotion or AArch64 qualification follows from these prerequisites.
