# Native allocator ownership in the x86 dynamic shadow

The dynamic producer keeps `accepted-c` as its default. Explicit
`--allocator-backend native-shadow` selects
`x86-owned-dynamic-native-shadow`; merely combining the generic native and
owned-dynamic features remains a compile error. This is a development product,
not allocator promotion or public x86 support.

The loader owns mappings, ELF metadata and TLS coordinates. Its
`GeneralLoaderLibcTlsRuntimeV1` handshake has no allocator pointer or allocator
ownership transfer. `x86_64_initial_graph.rs` and
`x86_64_general_initial_tls_state.rs` allocate their storage through raw Linux
mapping syscalls. After the validated initial TLS handshake and installation
of environment/auxv/security state, `owned_dynamic_runtime::prepare` initializes
libc's native process owner and dormant initial arena before constructors.
Failure terminates startup; it never substitutes the C allocator.
`pthread_create_join` retains its selected native attach/finish handshake. A
successful no-allocation worker attachment must already retain its owner in
compiler TLS, before the page engine is activated by an allocation.

The finalizer remains an entry in **libc's own `.fini_array`**. The accepted C
oracle is `libmimalloc-sys` 0.1.49's bundled v3.3.2
`c_src/mimalloc/v3/src/prim/prim.c`: its compiler destructor calls
`_mi_auto_process_done`. The owned producer suppresses only that transport with
`MI_PRIM_HAS_PROCESS_ATTACH=1`; `allocator_mimalloc_lifecycle.rs` replaces it in
the same image. The native v3.5.0 source pin and port mapping remain in
`crabc-mimalloc/UPSTREAM.md`. This comparison establishes lifecycle transport,
not equivalence between the two allocator versions.

`dynamic_main_thread_runtime_v1_lifecycle::exit` runs user atexit handlers,
executable fini, loader dependency fini, then stdio flush. Thus a DSO depending
on libc finalizes before libc; an independent DSO can finalize after libc.
Moving native process-done after all DSO or stdio callbacks would change the
source ordering. Instead `native_mimalloc_lifecycle.rs` preserves the same-image
finalizer and source default-release backing retention, allowing subsequent
DSO and buffered-stream callbacks to allocate. This does not select the
separate destroy-on-exit path or retire arenas with live owners.

The existing C feature entrypoints retain their dependency contracts.
`x86-owned-static-native-shadow` repeats the fixed backend-neutral leaves
from the accepted-C aggregate and selects the Rust allocator;
`x86-owned-dynamic-native-shadow` adds dynamic linkage. A regression requires
the C/native nonallocator leaf lists to remain equivalent. `libc/build.rs`
emits fixed Linux/x86-64 capability cfgs and rejects native/C overlap. It
never manufactures Cargo feature flags. The AArch64 dependency table is unchanged.

Both owned builders accept explicit `--allocator-backend native-shadow` while
keeping accepted C as the default. They attest Cargo's target normal/build
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
`compat/x86_64/run_dynamic_native_allocator.py --c-product PATH
--native-product PATH --work FRESH_PATH` in the pinned native environment with
`SYS_CHROOT`, using checkout-local product and work paths.

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
