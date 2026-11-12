# Native x86-64 initial lifecycle

The installed `x86_64-owned-dynamic-runtime` feature includes initial-graph
lifecycle, TLS and RuntimeV1 together. This describes product ownership;
public support and full correctness acceptance remain separate claims.

## Ownership and ordering

`ldso/src/x86_64_general_initial_lifecycle.rs::GeneralInitialLifecycle`
preflights an immutable callback plan against the canonical initial graph.
The installed plan visits dependencies in graph-derived postorder and then
the main image. It includes each object's `DT_INIT`, `DT_INIT_ARRAY`,
`DT_FINI_ARRAY` and `DT_FINI`; callback storage is sized from validated counts,
not the old private fixture's fixed object/array limits.

Array metadata must be paired, nonempty, aligned and contained in readable
file-backed loads. Legacy callbacks must lie in executable loads. Relocation
and RELRO sealing precede whole-graph callback validation; every callback
must be a nonzero executable address in its owning object. Addresses are
copied before any application constructor runs, so later ELF-array changes
do not rewrite the retained plan.

The installed registry adopts that plan before publishing initial TLS and
owns execution alongside later runtime-loaded objects. Initialization runs
legacy init followed by the init array forwards. It releases registry and
callback locks around constructors and keeps no registry reference across
application code. Process finalization follows the reverse construction list,
running each initialized object's fini array backwards, then legacy fini.
The callback guard remains held during finalizers and is released while
waiting for a constructor; shutdown and callback claims prevent redispatch.
Initial mappings and TLS remain resident through process exit. Runtime loading
and close behavior belong to the [runtime loader](runtime-dynamic-loader.md).

## Owned CRT handoff

The loader passes `process_finalizer` in the x86-64 `rdx` entry register.
The owned CRT authenticates it against the private post-relocation handoff,
attaches loader-owned initial TLS, and enters libc startup before dispatching
the loader's initial constructor queue. The installed owned dynamic mode
skips the executable's `DT_PREINIT_ARRAY`, matching its pinned musl oracle.
Its executable-finalization callback is empty: main-image finalizers belong
to the loader's reverse construction list. libc retains normal exit handlers.
The handoff adds no public lifecycle API or exported `process_finalizer`.

Legacy private source roots retain a separate atomic execution plan. Its
early/repeated-finalization tests do not define installed registry shutdown
semantics. The installed feature uses the plan for preflight and gives actual
callback ownership to `x86_64_runtime_registry`.

## Native evidence

Run `bash compat/x86_64/run_owned_ldso_lifecycle_cases.sh DYNAMIC_SYSROOT`
inside the pinned native x86 image, with an existing installed dynamic sysroot
and `TMPDIR` below the checkout's `.work/` directory. The runner uses `chroot`
and leaves evidence in a unique `general-loader-lifecycle-product.*` directory.
It is also a case in the installed dynamic-product qualification runner.

The fixture links the product's actual CRT, attachment object, libc and
builtins. Both sibling encounter orders of a diamond graph must match the
pinned musl trace, with the shared dependency initialized once. Null or
non-executable finalizers and malformed fini-array metadata must fail before
constructors. ELF checks require an ET_DYN interpreter without external
`NEEDED` entries, its own `PT_INTERP`, or an exported process finalizer.
This case proves the selected startup/exit behavior; other loader and TLS
cases retain their own contracts.
