# Owned general dynamic startup and process exit

This private native x86 integration composes the existing general initial
graph, retained TLS generation, Rust-produced `Scrt1.o`, and real libc startup
and exit owners. It is not an installed shared-runtime product or a support
promotion. The frozen AArch64 223/26 baseline is unchanged.

`run_general_dynamic_lifecycle.sh` selects the existing loader features
`x86_64-general-initial-lifecycle` and
`x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter`.
`crt/build_x86_64.py --general-dynamic-lifecycle` selects the matching entry.
`dynamic_main_thread_runtime_v1_source_root.rs` uses
`crabc_general_dynamic_lifecycle` to compose the actual startup owner with
the existing errno, environment, auxv, security, termination, and shared
`process_exit.rs` registration owners. There is no fixture-success callback
in this libc composition. The legacy source-root mode remains unchanged.

Run `./scripts/dev-x86_64.sh general-dynamic-lifecycle` from the checkout.
The dispatcher supplies the pinned native environment and contained scratch.

## Durable handoff and ordering

The 72-byte RuntimeV1 descriptor is unchanged. Its validated main-resident
consumer attaches to the loader's already installed FS/TCB/DTV, never issuing
a second `ARCH_SET_FS`. The existing 32-byte `OwnedCrtHandoffV1` layout
provides the dependency constructor callback and authenticates the loader's
conventional `rdx` process-finalizer address. Only the admitted main weak
import resolves this private record; callbacks are not public ELF exports.
The explicit CRT mode rejects a null or mismatching register before callbacks.
Default Scrt1 preserves its pinned-musl null-finalizer entry bytes.

The startup/ordinary-exit sequence is:

1. Loader maps, relocates, validates, and retains the arbitrary admitted
   dependency graph and initial TLS generation, with initialization deferred.
2. CRT authenticates both handoffs. Libc validates initial vectors and copies
   the kernel `AT_RANDOM` guard to the reserved FS+40 word, masking its second
   byte as musl does. Libc publishes environment, auxv, and secure-execution
   state before any application callback.
3. CRT runs executable preinit, general dependency initialization, then
   executable initialization. Libc invokes `main`.
4. Return from `main` and explicit `exit` drain ordinary handlers LIFO, then
   executable fini and loader process fini. Loader finalization uses its
   existing once-claimed reverse initialization order. `_Exit` skips all of
   these callbacks.

`process_exit.rs` is a behavior-neutral extraction of the existing bounded
32-entry registration implementation. Static startup still owns its existing
exit/start and optional stdio sequence. This is process finalization, not
`dlclose`: mappings and the initial TLS owner survive until kernel exit.
Runtime loading, unmapping, worker DTV growth, concurrent registration,
recursive process exit, constructor-triggered loading/exit, and DSO-filtered
C++ finalization are not admitted by this integration.

## Evidence and exact oracle difference

The native runner compiles a normal PIC PIE and a diamond of TLS-bearing,
stack-protected dependencies using the same general graph owner as any
admitted topology. Both sibling orders run ordinary return (19), explicit
exit (23), and immediate exit (29). Preinit, dependency callbacks, executable
callbacks, and handlers verify environment, auxv/security, compiler guard,
errno, and initial TLS. Guard checks require the exact masked `AT_RANDOM`
copy, not merely a nonzero slot. Negative entry shims erase or replace `rdx`,
or erase `AT_RANDOM`, and
must exit 127 without any callback marker. A native ptrace launch requires
exactly one attempted and successful FS installation.

Pinned musl 1.2.6 `ldso/dynlink.c::do_init_fini` dispatches `DT_INIT` and
`DT_INIT_ARRAY`, but not `DT_PREINIT_ARRAY`. Therefore the runner checks the
owned `P` preinit prefix independently and compares every remaining byte and
exit status with musl. It does not report complete preinit equivalence.
Oracle ELF checks require pinned musl PT_INTERP, `NEEDED libc.so`, and an
undefined `__libc_start_main`; candidate artifacts must not shadow the
oracle's implicit `-lc` or supply its startup implementation.

For left-before-right, owned ordinary exit is `PSLRIMbaFrls`; musl is
`SLRIMbaFrls`. Reversed siblings produce `PSRLIMbaFlrs` and `SRLIMbaFlrs`.
Immediate exit stops after `M`. `P` is executable preinit, uppercase S/L/R
are dependency init, I/M executable init/main, b/a handlers, F executable
fini, and lowercase r/l/s dependency fini.

Remaining product conditions include installed shared-libc composition and
sealed compiler-driver closure, general executable COPY/initial-exec TLS
relocations, buffered dynamic stdio, allocator/pthread integration, runtime
load/unload and TLS growth, and the broader campaign acceptance criteria.
PIC addressing here deliberately avoids unsupported executable COPY
relocations; it is not evidence that ordinary default-PIE relocation closure
is complete. Standalone dependency lifecycle and legacy dynamic-main-thread
fixtures remain regression gates, not replacement product claims.
