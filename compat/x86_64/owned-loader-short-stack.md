# Owned loader short-stack regression

`./scripts/dev-x86_64.sh owned-loader-short-stack` proves the selected native
x86 general-initial-TLS startup path works with the 100 KiB process stack used
by the pinned libc-test launcher. It is focused private loader evidence. It
does not complete the dynamic product contract or change the frozen AArch64
baseline.

## Trigger and oracle

The pinned Laputa libc-test revision
`68edb8bd73dab8147ee54c8bec638f4d2b3cff37` calls
`t_setrlim(RLIMIT_STACK, 100*1024)` in
`src/common/runtest.c::start` after `fork` and immediately before `execv`.
`src/common/setrlim.c::t_setrlim` reads the existing limit and sets both
`rlim_cur` and `rlim_max` to the requested value. The regression launcher
repeats that exact child-side ordering and both-limit update.

`owned_loader_short_stack_launcher.c` is built with the pinned musl compiler
and starts outside the target root, so its own loader cannot borrow the
candidate. It forks, chroots only the child into a disposable root, preserves
the ordinary inherited environment, sets the limit, and `execv`s the target.
`owned_loader_short_stack.c` only writes one fixed line, keeping application
stack use out of the observation. The runner builds the same source through
the installed owned dynamic driver and the pinned musl driver. The oracle root
contains only its musl executable and `ld-musl-x86_64.so.1`; the candidate root
contains only the freshly materialized owned product and executable. Both must
produce the same line and exit successfully.

Before this change, the candidate died with SIGSEGV at 96, 100, 104, and
112 KiB, while the musl oracle passed at 100 KiB. The candidate first passed at
120 KiB. That isolated the failure to early interpreter startup rather than
the application or libc-test workload.

## Loader ownership change

`x86_64_general_initial_graph::run_with_initial_tls` previously formed its
complete `GeneralInitialTlsState` as a Rust local. Its bounded graph owner
contains the complete `[Object; MAX_OBJECTS]` transaction and, after inlining,
the selected release build needed more than the 100 KiB kernel stack mapping.

`GeneralInitialTlsTransaction` now owns an anonymous raw `mmap` sized for that
state. It is created before graph discovery, with the existing loader syscall
boundary and no libc allocation, allocator, or TLS service. Its fallible map
allocation returns `tlsstorage` before any graph mutation; it never falls back
to a larger stack allocation. `GeneralInitialTlsState::initialize_at` and
`GeneralInitialLoaderState::initialize_at` write each field into explicitly
owned uninitialized storage, including the kernel-main map provenance and
every object slot.

The transaction dereferences that one mapping for the existing discovery,
relocation, protection, RELRO, reservation, and rollback sequence. On every
pre-publication error, `rollback_initial_tls_state` still releases admitted
object mappings in its established order, then the transaction drop unmaps its
private storage. After the sole successful `ARCH_SET_FS`, the existing
non-fallible commit publishes the TLS attachment and common loader owner in
their existing order; the wrapper then unmaps only the now-moved transaction
storage. RuntimeV1 retains its descriptor-ready ordering after the common
owner is published.

The non-TLS general root remains a distinct stack-local regression root. This
evidence covers the general-initial-TLS materialization route used by the
installed dynamic product.

## Recheck

Run the focused command above in the pinned native x86 environment. It retains
its generated roots, binaries, stdout, and build products below
`.work/x86_64/tmp/owned-loader-short-stack.*`; those paths are measurements for
the exact checkout revision, not durable status claims. The loader/TLS source
tests remain a separate check of the existing transaction and RuntimeV1
invariants.
