# General initial dependency lifecycle

`x86_64-general-initial-lifecycle` is an additive private Cargo feature over
the arbitrary admitted initial graph. It is an integration prerequisite for
`ldso.dynamic-runtime`, not family closure or a supported dynamic product.
The frozen AArch64 223-capability/26-family baseline is unchanged.

`ldso/src/x86_64_general_initial_lifecycle.rs::GeneralInitialLifecycle`
retains one callback record per dependency, indexed back to the canonical
`GeneralInitialLoaderState` object store. The main image never enters this
plan. The same ownership applies with or without the initial TLS feature;
TLS coordinates and graph publication precede dependency initialization.

The parser admits dependency `DT_INIT`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY`,
and `DT_FINI`. Existing bounds remain 32 graph objects and 16 callbacks per
array, plus one legacy callback per direction. Array metadata must be paired,
nonempty, aligned, bounded, and contained in readable file-backed loads. Legacy callbacks
must be in executable loads. After relocation and RELRO sealing, the entire
graph's callback targets are checked for nonzero executable addresses in
their owning objects, and copied before any constructor runs. Discovery
cycles retain the existing preflight rejection; this work does not admit
cyclic constructor graphs.

Initialization visits dependencies once in graph-derived postorder, running
legacy init then the init array in forward order. Finalization visits that
completed order backwards, running each fini array backwards then legacy
fini. `GeneralInitialLoaderState` retains immutable plans alongside the
immutable graph and object/map metadata; only atomic execution claims change.
The states are queued, initializing, initialized, finalizing, and finalized.
No loader lock or mutable graph borrow spans foreign callback execution.
Finalization's claim is made before calling foreign code, so a callback that
recursively calls the finalizer does not redispatch itself. Concurrent or
repeated finalizer callers lose the claim and return; they do not wait for
the active finalizer. Calling before initialization completes does nothing
and does not consume the later finalization claim.

The loader passes `process_finalizer` as the conventional x86-64 `rtld_fini`
address in `rdx` at application entry. It adds no exported lifecycle symbol.
The CRT/libc remains responsible for executable arrays, exit handlers, and
invoking that address after executable finalization. The current witness
uses a freestanding entry stub to retain and call the address; the oracle
uses normal pinned-musl startup and process return. It therefore proves the
dependency lifecycle and register handoff, not owned CRT/libc integration.

Process finalization does not unmap initial objects or free initial TLS.
Runtime mapping/unload and reference counts, `dlclose`, worker DTV growth,
fork interaction, constructor-triggered loading, exit from constructors or
destructors, and full reentrant exit semantics remain separate work. The
once-only recursive callback test is not a claim about recursive `exit()`.
Initializers still run before entry to the application CRT; moving dispatch
behind libc startup and executable preinit requires the owned startup seam.

## Native evidence

Run `bash compat/x86_64/run_general_loader_lifecycle.sh` inside the pinned
`docker/Dockerfile.x86_64` environment. Set `TMPDIR` below the checkout's
`.work/` tree, and bind that directory to container `/tmp` for the existing
oracle launcher's legacy temporary path. The runner leaves evidence in a
unique `general-loader-lifecycle.*` directory beneath `TMPDIR`.

`CRABC_GENERAL_LOADER_LIFECYCLE_ROOT=crabc-target` selects Cargo's
`x86_64-unknown-linux-musl` artifact; the default builds the same source root
directly. `CRABC_GENERAL_LOADER_LIFECYCLE_TLS=1` adds the existing general
initial TLS feature and verifies TLS reads in constructors, application
code, and finalizers. No external libc is linked into the candidate.

The native regression first failed with the old parser's `graph` rejection.
The candidate and musl 1.2.6 then produce equal traces for both sibling
encounter orders of a diamond graph. The shared dependency runs once. The
candidate recursively calls its finalizer from destructor callbacks and
calls it again after completion. Malformed null/non-executable fini entries
fail with `ctorplan` and no constructor output; a non-executable legacy fini
fails during mapping with `graph`.
Fini-array metadata with an unpaired tag, zero or excessive size, unaligned
storage, storage outside mapped loads, or non-readable storage also fails
before any constructor.
ELF checks retain an ET_DYN interpreter
without external dependencies, interpreter TLS, or an exported finalizer.

Native Rust tests prove concurrent finalization has one callback owner,
recursive/repeated execution cannot redispatch, preflight copies callback
addresses independently of later source-array contents, and lifecycle
ownership survives canonical graph publication. The existing graph identity,
publication, and rollback tests run in the same source root. Established
general graph and initial-TLS runners remain regression gates with the
lifecycle feature disabled.
