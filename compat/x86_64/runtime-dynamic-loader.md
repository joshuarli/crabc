# General runtime-loader ownership work

The materialized initial dynamic product is the execution substrate, not a
substitute for runtime loading. `run_general_dynamic_dlopen.sh` reuses the
ordinary nested plugin consumer, whose plugin and transitive dependency are
absent from the initial graph. Until the runtime registry is connected, that
consumer fails with status 10; this is not passing campaign evidence.

The compatibility source is musl 1.2.6, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT:
`ldso/dynlink.c::{dlopen,load_library,load_deps,extend_bfs_deps,do_relocs,
queue_ctors,do_init_fini,install_new_tls,__libc_exit_fini}` and
`src/ldso/dlclose.c`. Runtime maps remain resident after close; reopen retains
identity and process finalization owns destructors. Failed admission rolls back
only new maps. Physical close-time unmapping is not the musl parity target.

## Implemented prerequisites

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
through the updated resolver/release path. These are prerequisite tests, not
an executed all-thread dlopen growth claim.

## Publication contract still being connected

Runtime object nodes and their dependencies must be stable loader-owned
mappings, independent of the initial fixed stack-array capacity. The initial
canonical map owner remains immutable and is borrowed, never remapped or made
rollback eligible. Admission and scope changes serialize with worker TLS
allocation/release under one loader mutation boundary; no pthread list lock or
libc allocation is acquired there. The selected pthread owner calls allocate
before list publication and release only after list withdrawal, with that list
lock released in both cases.

All current-thread descriptors must be prepared before any new module scope is
published. Scope publication follows descriptor publication for the retained
main and every registered worker, including allocations not yet cloned. Worker
creation must copy the latest complete module population under the same lock.
No lock may span application constructors/destructors. Per-object execution
ownership must handle recursive loading, concurrent initialization and process
shutdown while preserving source-shaped dependency and finalization order.

These remaining registry/callback/all-thread publication steps are required
before claiming runtime `dlopen` or DTV growth. Dynamic fork repair and
main/last-thread pthread_exit remain explicitly unqualified and cfg-excluded
from the separate static lifecycle work. No new RuntimeV1 fields, public
support promotion or AArch64 qualification follows from these prerequisites.
