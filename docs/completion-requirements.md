# Completion requirements

What the native x86-64 runtime and the Rust allocator port must do before
either is called complete. [plan.md](../plan.md) sequences the work and
[scope.md](scope.md) bounds the product; this file is the standard an item is
judged against.

## Runtime

Feature implementation and current-source qualification are distinct claims.
A C ABI pass does not prove the Rust-native path, or the reverse.

| Area | Requirement |
| --- | --- |
| Headers and layouts | Complete installed header paths, the selected strict, POSIX, XOpen, GNU, BSD and large-file profiles, declarations of every kind, C and selected C++ linkage, LP64 and x87 layouts, transitive includes, and installed-tree isolation. No missing selected declaration or unclassified callable owner. |
| POSIX runtime | Coherent filesystem, directory and traversal, descriptor, environment, process-control, signal and kernel-administration behavior, including aliases, errno and TLS, shared state, selected cancellation, errors, and ownership, through the owned C entries and the Rust-native paths. |
| pthread, C11 and TLS | Lifecycle, attributes, join and detach, synchronization, once, TSD, cleanup, cancellation, signals, timers, atfork and fork, and exit. Main, loader, worker, static TLS, dynamic TLS, DTV and `__tls_get_addr` use one ownership model. |
| Text, math, locale, stdio | Selected iconv, wide and multibyte, regex, word expansion, calendar, and complete stream behavior. One stream engine owns locking, buffering, orientation, every stream kind, positioning, errors, and exit flushing. Preserve restricted locales, x87, MXCSR and fenv, the long-double ABI, rounding, signed zero, NaNs, and exceptions. |
| Resolver | Conventional files and bounded netdb behavior end to end: A, AAAA and CNAME, search, UDP and TCP fallback, timeout, retry and failover, reply validation, errors, cancellation, and result lifetime, proven through owned C products on controlled networks. |
| C compatibility | Selected crypt through approved primitives, allocation, legacy compatibility, process globals, and final provider closure: names, aliases, bindings, visibility, sizes, and static and shared ownership, by ordinary archive extraction or an explicit structural boundary, never a hidden unresolved provider. |
| Loader | General admitted dependency graphs: self-relocation and entry, search, RPATH and RUNPATH, mapping, protection and RELRO, supported RELA and RELR relocations, symbol scope, RuntimeV1, initial and runtime TLS, DTV growth, constructors and finalizers, and selected `dl*` introspection, including concurrency, reentrancy, fork, retained handles, malformed input, and failed-load rollback. |
| CRT, builtins, sysroot | Compatibility products retain owned static, static-PIE, dynamic PIE and dynamic non-PIE entry. Hardened products require dynamic PIE or static PIE and reject non-PIE selection. Both require libc handoff, lifecycle arrays, finalization, compiler helpers, and a deterministic link interface. The sysroot owns headers, CRT objects, `libc.a`, shared libc, the interpreter, builtins, allocator selection and link specifications; a pinned host compiler is permitted, ambient target inputs are not. |
| Runtime hardening | The native x86-64 [hardened profile](../COMPATIBILITY-PROFILE.md#runtime-hardening-profiles) is enforced across kernel/direct loader entry, initial dependencies/preloads, runtime `dlopen`, and applicable owned static-PIE startup. PIE admission, non-executable stacks, page-level W^X, bounded relocation writes, effective RELRO, eager binding, search restrictions and secure startup have positive, negative and failure-path evidence. Product selection cannot silently downgrade. |
| Consumers | Rust std, dependency-bearing std, build-std, LTO, and the Lua source build through the real `_Unwind_*` ABI, ordinary archive extraction, and shared symbol resolution. Dummy unwind symbols, hidden providers, or C recovery are not implementations. |
| Rust facade | Every other frozen family and exact semantic mapping, with direct native API, error, ownership, and dependency ownership. |

### Hardening evidence

Hardening is part of native correctness and public-promotion acceptance, not
post-promotion tuning or a prerequisite that waits on the Rust allocator.
Use the existing loader, CRT, sysroot and pthread matrices and qualification
chain, with product identities distinguishing compatibility and hardened runs.
Historical receipts cannot prove a newly selected contract.

- Execute admitted PIE/DSO/static-PIE controls, and verify policy rejections
  before constructor sentinels or application entry. Keep non-PIE and lazy
  binding compatibility controls; do not relabel their failures as security.
- Prove actual protections with isolated child-process write/execute faults
  and mapping observations, including static-PIE and post-`dlopen` RELRO.
  ELF tags and compiler/linker flags alone do not establish protection.
- Exercise malformed/duplicate/overflowing headers and relocation ranges,
  conflicting page permissions, missing required metadata, and unresolved
  imports. A policy rejection and a malformed-input safety defect are distinct.
- Inject mapping/protection/relocation/publication failures and verify that
  rejected loads preserve the old graph, handles, TLS state and page
  permissions, release newly owned resources, and run no rejected constructors.
  Inability to restore safe protections is a fatal path, never partial success.
- Verify guard, TLS, secure-state and protection ordering before callbacks
  for each entry path and new threads, plus environment/command-line attempts
  to weaken the selected profile. Require Linux 5.10-compatible core behavior.

## Native allocator

`crabc-mimalloc` is a `#![no_std]` engine with no production `alloc`, C or C++
implementation, bindgen, native build script, dependency on crabc-libc, or
hidden C fallback. Libc owns errno and C ABI policy and depends on the engine,
never the reverse. Port complete source transitions, not test-shaped routes.
Inapplicability needs a source-backed reason, not unavailable hardware.

1. **Persistent source owners.** Each allocating thread keeps its TLD and
   Theap across operations; the initial thread keeps source-required static
   storage. Local small, direct-cache and generic queue operations stay
   owner-local, and independent owners progress independently.
2. **Pointer-centered dispatch.** `free`, usable-size and realloc derive the
   page from the pointer and PageMap, recover the canonical aligned block,
   and choose local, live-remote or abandoned behavior from page and process
   state, not caller identity or a client registry. Realloc follows
   `mi_theap_realloc_zero_ex` and preserves the old allocation on failure.
3. **Page-local remote publication.** Translate the pinned remote-free atomic
   protocol without borrowing the owner's TLD or engine. PageMap and metadata
   stay valid through every legal live client and unfinished publication.
   Ordinary lookup takes no structural PageMap mutation lease.
4. **One owner-exit traversal.** `_mi_theap_collect_abandon` performs deferred
   free, retired-page collection, queue traversal, per-page collection,
   release or abandonment, cache repair, and Heap, Theap and TLD detachment
   through one generic coordinator, not caller-selected geometry routes.
5. **Callbacks without invalid borrows.** Deferred, VM, output and
   initialization callbacks run outside owner, engine, TLD and Theap reference
   projections, and attachment identity is revalidated before exclusive
   collection resumes.
6. **Abandonment outlives threads, not TLS.** Surviving pages belong to source
   page and process abandonment structures. Any surviving thread can free,
   reallocate or reclaim as source permits. A failed reclaim preserves
   ownership and retains exactly one identifiable terminal owner.
7. **No production scaffolding.** No per-allocation side ledger, live-TLS-owner
   or post-exit registry, historical-thread scan, per-call park and resume,
   global ordinary-operation scheduler, or fixture-geometry route. A
   constant-size page-local lifetime aid needs a documented source invariant
   and model evidence.

Also required:

- **Bootstrap.** Initialization is idempotent, race-safe, reentrant and
  allocation-free until primitives are ready, from raw startup auxv,
  page-size, `AT_RANDOM` and environment facts, with no public libc call.
- **Memory.** Target-probed page and address geometry; complete raw Linux
  reservation, commit, purge, protection, remap, entropy, advice and NUMA
  behavior, with fault injection at that primitive boundary.
- **Fork.** Allocation-free hooks that preserve the parent, repair inherited
  locks, vanished-thread ownership and child TLS, and permit all standard
  allocation in the child. A bridge that disables child allocation is not
  completion.
- **Integration.** Libc owns malloc-family policy (interposition, errno,
  zero-size, alignment, overflow, `realloc(p, 0)`, usable size). A Rust
  pointer never crosses into the C backend as recovery. Worker attachment
  establishes its owner before user code; cleanup and TSD destructors precede
  owner teardown, which precedes TLS unmapping. Logical process-done runs
  from libc's own `.fini_array`. The dynamic RuntimeV1 handshake transfers
  runtime and TLS coordinates, not allocator pointers
  ([design/x86-dynamic-native-allocator.md](design/x86-dynamic-native-allocator.md)).
- **Safety.** `#![deny(unsafe_op_in_unsafe_fn)]`, strict provenance, short
  validated raw projections, no long-lived reference that contradicts remote
  access. A legal free cannot return unavailable, and allocation cannot
  report OOM because a scheduler token is busy.
- **Memory metrics.** For total-memory rows dominated by mandatory live
  payload or kernel charge granularity, require no regression; keep the raw
  reference and candidate measurements.

Source feature groups, each of which must be implemented and verified for
Linux/x86-64: source foundations, memory substrate, local engine, allocation
API, concurrency and lifecycle, owned Heap, Theap, arena and subprocess APIs,
configuration and options, and runtime composition. The applicable
inventories are the milestone manifests under `compat/allocator/`.
