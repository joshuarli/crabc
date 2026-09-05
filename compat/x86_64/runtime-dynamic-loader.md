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
transactions. Runtime relocation writes only the new suffix: already retained
maps supply symbols but are never relocated again. The initial private handoff
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
objects are neither relocated again nor made rollback eligible.

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
every initial parser limit. `RTLD_NOW` is implemented. `RTLD_LAZY` currently
admits only objects whose ELF requests BIND_NOW (including sealed-driver DSOs),
and explicitly rejects genuinely deferred objects. Musl's
`prepare_lazy/redo_lazy_relocs` remains the source target for a subsequent
deferred GOT/PLT owner; the flag is not silently ignored. Search currently uses
the admitted absolute RUNPATH and `/usr/lib`, or a direct pathname. Complete
caller/ancestor/environment search semantics remain unqualified. Initial
physical enumeration still follows canonical discovery order, while symbol
scope is breadth-first; broader initial-graph introspection/order parity needs
its own differential before qualification.

Dynamic fork repair and
main/last-thread pthread_exit remain explicitly unqualified and cfg-excluded
from the separate static lifecycle work. No new RuntimeV1 fields, public
support promotion or AArch64 qualification follows from these prerequisites.
