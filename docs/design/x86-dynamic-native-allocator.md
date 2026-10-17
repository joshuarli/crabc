# Native allocator ownership in the x86 dynamic shadow

The dynamic producer keeps `accepted-c` as its default. Explicit
`--allocator-backend native-shadow` selects `x86-owned-dynamic-native-shadow`;
`libc/src/c_abi/x86_64/static_c_abi.rs` rejects `native-mimalloc-shadow` on a
dynamic runtime without it, and `libc/build.rs` rejects `native-mimalloc-shadow`
together with `x86-allocator-runtime`. The builders' `--allocator-backend` also
lists `native` (the production-shaped Rust product: the same libc features, but
it refuses any test-audit feature) and `pinned-c-evidence` (an evidence-only
build with the exact pinned v3.5.0 C source as the reference for
`allocator-perf-integrated`). The dynamic builder's native ELF audit currently
keys on `native-shadow` only. This is a development product, not allocator
promotion or public x86 support.

The loader owns mappings, ELF metadata and TLS coordinates. Its
`GeneralLoaderLibcTlsRuntimeV1` handshake has no allocator pointer or allocator
ownership transfer. `ldso/src/x86_64_initial_graph.rs` and
`ldso/src/x86_64_general_initial_tls_state.rs` allocate their storage through
raw Linux mapping syscalls. After the validated initial TLS handshake and
installation of environment/auxv/security state,
`libc/src/c_abi/x86_64/owned_dynamic_runtime.rs`'s `prepare` calls
`native_mimalloc_lifecycle::initialize_selected_process` before preinit and DSO
constructors; the static product calls the same function from `static_startup.rs`.
It publishes the startup facts, initializes the process, and pins the initial
thread's source owner (`prepare_native_initial_thread_owner`). That pinning
reserves no arena: the first allocation activates the owner and reserves one
only if its page claim needs it. Failure terminates startup; it never
substitutes the C allocator.
`pthread_create_join` retains its selected native attach/finish handshake: a
child attaches before its start routine runs, the parent returns `EAGAIN` when
the attach is rejected, and a fatal mismatch terminates instead. A successful
no-allocation worker attachment must already retain its owner in compiler TLS,
before an allocation activates the page engine.

First-class Heap attachments use `subproc_main_heaps.rs`, reached through
`source_heap_api::heap_theap` and Heap allocation entries. Each attachment
publishes a source-owned Theap in the calling thread's regular TLS slot,
TLD list and Heap list. `finish_current_thread_native_after_user_destructors`
calls `native_thread_done` before finishing the fixed main-Heap owner.
That path releases the regular TLS array, clears the fast slot, traverses
the auxiliary Theaps with `MI_ABANDON`, then resets roots and detaches the
Theaps. `ProductionOwnerExitCallbacks` links an OS page to its own Heap's
`os_abandoned_pages` before unown. A later `native_free_nonlocal` claims the
singleton, removes that exact node, clears its clipped PageMap span and
metadata, then releases the mapping.

The `allocator-dynamic-os-aligned-singleton` differential compares this
production path with pinned v3.5.0 C for one 7-byte, 128 KiB-aligned client.
Its 21 observations cover the sole `BIN_HUGE` member, empty `BIN_FULL`,
worker teardown, joined consumer free, OS-list removal and PageMap clearance.
`native_dynamic_os_singleton_owner_exit` separately compiles the allocator
without test or audit features and uses `mincore` to check that the returned
client's page is unmapped.
The old `dynamic_theap.rs` attachment remains an isolated test model.
These checks establish this one production lifecycle slice. General lifecycle
and promotion claims remain partial.

The finalizer remains an entry in **libc's own `.fini_array`**. The accepted C
oracle is `libmimalloc-sys` 0.1.49's bundled v3.3.2
`c_src/mimalloc/v3/src/prim/prim.c`: its compiler destructor calls
`_mi_auto_process_done`. The owned producer suppresses only that transport with
`MI_PRIM_HAS_PROCESS_ATTACH=1`; `libc/src/c_abi/x86_64/allocator_mimalloc_lifecycle.rs`
replaces it in the same image. The native v3.5.0 source pin and port mapping
are in [`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md); the
shared allocator design is in [`allocator.md`](allocator.md). This comparison
establishes lifecycle transport, not equivalence between the two allocator
versions.

`libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_lifecycle.rs`'s `exit` runs user atexit handlers,
executable fini, loader dependency fini, then stdio flush. Thus a DSO depending
on libc finalizes before libc; an independent DSO can finalize after libc.
Moving native process-done after all DSO or stdio callbacks would change the
source ordering. Instead `libc/src/c_abi/x86_64/native_mimalloc_lifecycle.rs`
preserves the same-image finalizer and, by default, the source's
default-release backing retention, so subsequent DSO and buffered-stream
callbacks can still allocate. Only a nonzero `destroy_on_exit` option selects
physical destruction (see "Process destruction" in [`allocator.md`](allocator.md)),
and it is not the default.

The existing C feature entrypoints retain their dependency contracts.
`x86-owned-static-native-shadow` repeats the fixed backend-neutral leaves
from the accepted-C aggregate and selects the Rust allocator;
`x86-owned-dynamic-native-shadow` enables the static native feature and
selects dynamic linkage through `libc/build.rs`. A regression requires the
C/native nonallocator leaf lists to remain equivalent. `libc/build.rs` emits
fixed Linux/x86-64 capability cfgs and rejects native/C overlap; it never
manufactures Cargo feature flags. The AArch64 dependency table is unchanged.
The two native `feature_archive` rows name exact `provider_profile` alternatives
for the corresponding C static/dynamic callable contracts. This shares symbol
ownership accounting only: native rows remain planned, own no duplicate names,
and cannot inherit C receipts or qualification. Their source capability lists
and installed public callable sets must match the referenced profiles.

Both owned builders keep accepted C as the default. For a native backend they
attest Cargo's target normal/build
dependency graph, require the native allocator and forbid `libmimalloc-sys` in
that graph, then reject any C allocator archive in the fresh build. Every raw
libc archive member still passes the existing strict Rust/compiler-helper
classification. The native selected archive is Rust-only; native provenance
has no C compiler, header, or excluded-backend record. The pinned C oracle
remains isolated in the allocator test harness, and accepted-C products still
compile and byte-attest their own backend. Native code resides in the Rust
fat-LTO object. The C-specific hidden-symbol
list is applied only to C products. The existing musl dynamic list and private
errno/compiler-helper policies remain in both products. Native ELF inspection
rejects C `mi_`/`_mi_` symbols and loader allocator definitions/imports, and
requires the private local native fini entry. Its symbol record is included
in the sealed product metadata.

## Focused development comparison

Build two fresh products with `scripts/build_x86_64_owned_dynamic_sysroot.py`,
`--allocator-backend accepted-c` or `native-shadow`, and the explicit
`--allocator-lifecycle-test-audit` flag. The latter adds only a phase scalar;
it never selects an allocator or exposes ownership pointers. Run
`compat/x86_64/run_dynamic_native_allocator.py --native-product PATH --work
FRESH_PATH [--c-product PATH]` in the pinned native environment with
`SYS_CHROOT` (the runner executes each consumer under `chroot`), using
checkout-local product and work paths. The C product is optional: native phase
ordering is proved directly, and the C product adds the comparison.
`--check` takes no other arguments and rereads the retained native lifecycle
receipt.

The runner compiles identical C objects once. It compares dependency and
independent DSO fini order, constructor/atexit/fini/stdio allocations, errno,
no-allocation and allocating worker exits, remote frees, and final-worker
ordinary exit. It covers PIE/non-PIE and kernel/direct-loader entry. Final-worker
runs release the worker only after Linux reports the initial task dead.
Receipts are explicitly nonqualifying. The existing supplied-product
`run_owned_c_allocation_interposition.sh` and
`run_owned_stdio_allocator_interposition.sh` also check the native product's
public/private allocation binding behavior. Focused Python selection tests
reject unknown archive members, unknown backends and forbidden allocator
symbol edges. Installed execution evidence is required before admitting this
opt-in; source and selection checks alone do not prove dynamic ownership.
