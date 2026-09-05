# Materialized dynamic sysroot component

`scripts/build_x86_64_owned_dynamic_sysroot.py` produces a real native x86-64
shared runtime. `run_materialized_dynamic_sysroot.sh` builds and executes
ordinary C consumers through the installed `bin/crabc-cc-dynamic`, repeats
through an extracted package, and compares two fresh builds byte for byte.
It also executes retained runtime graphs and all-thread DTV growth. This is
component evidence, not completion of `dynamic-product.toml`.
Run it from the host with `./scripts/dev-x86_64.sh materialized-dynamic-sysroot`.

## One owner per runtime state

`x86-owned-dynamic-runtime` shares the existing owned x86 C ABI leaf roster,
including the accepted pinned C mimalloc backend, errno, environment, pthread
and FILE registries. `owned_dynamic_runtime.rs` selects the actual dynamic
startup/exit composition; `dynamic_tls.rs` selects loader-owned TLS through
the opaque allocation token described in [initial-worker-tls.md](initial-worker-tls.md).
Neither linkage path clones those implementations. The static feature remains
cfg-disjoint and its existing installed gate remains applicable unchanged.

The executable contains owned `Scrt1.o` and `crabc-dynamic-attach.o`. The latter
contains only the established loader/libc attachment owner. The 72-byte
RuntimeV1 and 32-byte OwnedCrtHandoff are unchanged. The loader supplies the
conventional x86 `rdx` finalizer, installs initial FS once, and retains the
canonical graph. Shared libc publishes process/TLS identity before callbacks;
executable preinit precedes dependency constructors. Ordinary exit dispatches
exit registrations, executable finalizers, dependency finalizers, and shared
stdio flushing. `_Exit` bypasses callbacks and flushing.

Initial TLS is copied from relocated templates for every worker, including
over-aligned modules, TBSS, errno and the accepted allocator's IE TLS. Live
main-thread mutations are never the worker template. CLONE_SETTLS installs a
worker's TP; release requires clear-child-TID and reader withdrawal. Runtime
module admission and coherent DTV generations use the same loader allocation
registry, as described in [runtime-dynamic-loader.md](runtime-dynamic-loader.md).

## Installed artifacts and purity

The producer installs headers, `usr/lib/{Scrt1.o,crti.o,crtn.o,libc.so,
crabc-dynamic-attach.o,libcrabc-builtins.a}`, the canonical
`lib/ld-crabc-x86_64.so.1`, and its single relative `ld-musl-x86_64.so.1` alias.
It does not install the current static-only `crt1.o` under a dynamic promise.
The driver admits PIE and shared-object output; non-PIE dynamic entry remains
unqualified. Applications name each DSO explicitly; SONAME, transitive NEEDED,
imports and `/usr/lib` search ownership are checked before linkage.

The final libc link consumes only classified Rust C ABI objects, the byte-
matched pinned allocator object and owned compiler helpers. Cargo's stock
compiler/runtime archive members are excluded. Allocator header dependency
traces, source pin, flags, object hashes and exact tool identities are retained.
PIC generated math remains source-oracle machinery, not an ambient runtime.
The actual shared libc and loader must have no NEEDED, PT_INTERP, TEXTREL or
absolute 32-bit dynamic relocations, and must have RELRO and an NX stack.
Every application link records hashed inputs, exact command and checked LLD
input trace; undeclared target inputs fail. The driver disables Python bytecode
publication itself, so importing its shared checks cannot dirty the install.
An output-derived receipt is exclusively reserved before compilation or
linkage. Existing sidecars, symlinks and hardlinks are never overwritten;
failed tools release only their own reservation, and receipt publication checks
the still-owned inode. Producer payloads remain private under the dedicated
`.build/installed` directory until the complete manifest passes validation and
Linux no-replacement atomic rename publishes the requested install. A failing
build or a competing publisher cannot expose or replace a partial install.

The manifest covers the exact regular-file roster and the one permitted
relative alias. `owned_dynamic_package.py` creates deterministic archives and
validates names, sizes, types, hashes and roster before extraction publication.
Traversal, absolute names, duplicate entries, unexpected links and replacement
of an existing output are rejected. Package extraction never follows archive
links. All build, extraction and private-chroot state stays under `.work`.

## Evidence and limits

The native gate checks the installed and extracted real PIE plus GD-TLS DSO:
allocation/reallocation, ordinary environment COPY interposition, independent
main/worker errno, 24 create/join/release cycles, over-aligned TLS and TBSS,
buffered file I/O and ordinary-exit flushing. Its stdout equals pinned musl
1.2.6. The main errno sentinel is installed after constructors: the accepted C
allocator probes `/proc/sys/vm/overcommit_memory` and sysfs during initialization
(`libmimalloc-sys` 0.1.49, `mimalloc/v2/src/prim/unix/prim.c`), which can leave
ENOENT inside the intentionally empty chroot. Each worker's initial errno is
still required to be zero, independent of the main's live errno.

The first actual libc exposed 648 RELA entries, exceeding the legacy 512-write
scratch buffer. General relocation preflight now owns checked ELF-sized raw
mmap scratch, with no libc allocation or arbitrary new limit. Regression tests
cover 1025 RELA writes, 600 RELR entries, size overflow and a late overlapping
destination rejected before any graph write. Legacy private roots retain their
bounded admission. Allocation failure aborts the uncommitted initial graph.

The gate also runs an ordinary ELF memory-interposition consumer through both
installed and extracted drivers. The application exports `memcpy`/`memset`,
then calls `posix_spawnp` with a missing PATH component before an owned child
executable. No application memory callback may run in the shared-address-space
child or during lock-held spawn stack setup; neither child nor parent uses an
ambient target executable.

The component gate also runs 42 loader tests and 15 driver/package
boundary tests. Two cold producer manifests and deterministic package bytes
must match; the extracted driver must compile and execute the same consumer.
These checks do not promote public support or the frozen AArch64 baseline.

`run_general_dynamic_dlopen.sh INSTALLED_SYSROOT` is the independent
ordinary regression, reusing the portable nested plugin fixtures without an
initial dependency. Its nested plugin, 41-module worker TLS/lifecycle, scope
and rollback consumers now run through installed and extracted products with
pinned musl differentials. Remaining product work includes dynamic non-PIE
startup, deferred lazy relocation, complete runtime search policy and broader
introspection/order qualification, dynamic fork repair and main-thread pthread_exit
composition, followed by the complete installed dynamic campaign. Musl's
retained dlclose mappings, not physical unloading, are the parity target.
