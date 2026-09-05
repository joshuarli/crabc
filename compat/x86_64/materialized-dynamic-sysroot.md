# Materialized dynamic sysroot component

`scripts/build_x86_64_owned_dynamic_sysroot.py` produces a real native x86-64
shared runtime. `run_materialized_dynamic_sysroot.sh` builds and executes
ordinary C consumers through the installed `bin/crabc-cc-dynamic`, compares
two fresh builds byte for byte, and executes the complete consumer matrix
through each clean build and an extracted package.
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

The executable contains owned `Scrt1.o` (PIE) or dynamic `crt1.o` (ET_EXEC),
and `crabc-dynamic-attach.o`. Both entries compile the same authenticated
dynamic startup source under linkage-specific relocation models. The default
CRT builder still produces the original static `crt1.o`; only its explicit
`--owned-dynamic-sysroot` mode selects dynamic `crt1.o`. The attachment object
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

The producer installs headers, `usr/lib/{crt1.o,Scrt1.o,crti.o,crtn.o,libc.so,
crabc-dynamic-attach.o,libcrabc-builtins.a}`, the canonical
`lib/ld-crabc-x86_64.so.1`, and its single relative `ld-musl-x86_64.so.1` alias.
The driver admits `--dynamic-pie`, `--dynamic-non-pie` and shared-object
output; the executable modes select their actual owned dynamic entry. The
non-PIE mode emits ET_EXEC with the same canonical interpreter, initial TLS
and lifecycle handoff, without a static-TLS bootstrap. Applications name each DSO explicitly; SONAME, transitive NEEDED,
imports and search ownership are checked before linkage. `/usr/lib` is the
default emitted application RUNPATH; `--application-runpath PATHS` declares and receipts an application
path without adding ambient link inputs. Nondefault DSO paths require a
matching output receipt.

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

The component gate also runs 46 loader tests, 18 driver/package and two CRT-mode
boundary tests. Two cold producer manifests and deterministic package bytes
must match; the extracted driver must compile and execute the same consumer.
These checks do not promote public support or the frozen AArch64 baseline.

`run_general_dynamic_dlopen.sh INSTALLED_SYSROOT` is the independent
ordinary regression, reusing the portable nested plugin fixtures without an
initial dependency. Its nested plugin, 41-module worker TLS/lifecycle, scope
and rollback consumers now run through installed and extracted products with
pinned musl differentials for both PIE and non-PIE entry. Initial/runtime-loaded constructors that call exit
must skip their own incomplete destructor, while completed objects finalize;
`run_general_dynamic_constructor_exit.sh` checks both installed product arms.
`run_general_dynamic_pthread_exit.sh INSTALLED_SYSROOT` runs an ordinary
TLS-bearing DSO and executable in both PIE and non-PIE modes. The main-only
case and eight simultaneous surviving workers prove cleanup-before-TSD and
ordinary atexit -> executable fini -> DSO fini ordering. Its external parent
waits for the initial kernel task's zombie state before releasing workers
through stdin, so worker TLS use occurs after actual main-task retirement.
Main/worker cancellation uses the same exit path. Successful ordinary-exit
cases unlock explicit FILE ownership in cleanup; separate `_Exit` probes
check that orphaned FILEs remain unavailable to another thread, matching
musl's permanent owner sentinel without asserting recoverable locks.

`pthread_create_join::exit_selected_final_runtime_task` keeps static and
dynamic logical task accounting together. The dynamic arm calls
`owned_dynamic_runtime::exit`, whose existing startup owner retains atexit,
executable/loader finalization, and stdio flushing. The loader's initial TLS
mapping stays process-lifetime storage when the initial task exits early.
The focused host command is `./scripts/dev-x86_64.sh owned-dynamic-pthread-exit`;
the aggregate runs the consumer against installed and extracted products.

`./scripts/dev-x86_64.sh owned-pthread-getattr` also runs the ordinary live
stack/guard/detach and filtered-main stack-probe differential through installed
PIE and non-PIE entry; the aggregate repeats these checks with installed and
extracted sysroots. Both startup paths publish the auxiliary vector used by
`pthread_attr::pthread_getattr_np`; workers retain their actual application
stack metadata independently of loader TLS storage. The initial executable's
pure-TBSS TLS fixture ensures caller-stack checks do not depend on a guessed
musl TLS/control size. Both dynamic entries now include fork adoption through
the complete loader/libc transaction below.

`./scripts/dev-x86_64.sh owned-dynamic-fork` qualifies the loader/libc fork
transaction through ordinary initial/runtime DSOs. The aggregate repeats
`run_general_dynamic_fork.sh` for installed and extracted PIE/non-PIE products.
Its pinned-musl cases cover initial and worker callers with a live sibling,
reverse-prepare/forward-parent-or-child hooks that call loader APIs, inherited
TLS/TSD/cleanup, postfork module growth and fresh workers, ordinary and kernel
robust owner death, raw `EAGAIN` unwind, nested constructor fork, and rejected
closures containing a constructor held by a vanished task. An external parent
observes the adopted main task's actual kernel retirement before releasing a
surviving child worker to grow TLS and create another worker. This avoids a
`/proc` dependency inside the installed product's private chroot.

Constructor callbacks release loader callback ownership, so recursive
constructor fork can copy and translate the surviving visitor. Finalizers
retain that ownership through process exit: the held-finalizer fixture proves
another task's fork cannot pass it. A sole task can fork from its own finalizer
without acquiring its already-held callback lock, matching musl's `need_locks`
condition. An abandoned constructor remains incomplete: reopening its closure
fails with an inconsistent-state diagnostic, and the dedicated fixture uses
`_Exit` because normal finalization cannot wait for a vanished constructor to
return. No copied constructor is rerun or marked completed as a fallback.

The transaction and source mapping are documented in
[runtime-dynamic-loader.md](runtime-dynamic-loader.md). Allocator-wide fork
repair and arbitrary application locks remain separate obligations; these
probes qualify the selected loader and libc owners, not the whole campaign.

The shared initial/runtime search matrix proves 37 musl decisions through
installed/extracted PIE and non-PIE consumers, including conventional system
path configuration, preload TLS/lifecycle, main ORIGIN with contained proc,
and real setuid AT_SECURE execution. Direct interpreter entry now admits
owned PIE/non-PIE executables through the same transaction, with musl command
options, listing, explicit mapping ownership and reconstructed argv/auxv.
Its 46-case-per-arm installed/extracted differential is described in
[direct-interpreter.md](direct-interpreter.md); the shared search policy and
limits remain in [runtime-dynamic-loader.md](runtime-dynamic-loader.md).
Remaining product work includes broader introspection/order
qualification, followed
by the complete installed dynamic campaign. Musl's
retained dlclose mappings, not physical unloading, are the parity target.

### Contained process search evidence

The native dispatcher gives only `materialized-dynamic-sysroot` the additional
mount authority needed for the main-executable ORIGIN and secure-execution
search matrix: `SYS_ADMIN`, `SYS_CHROOT`, and an unconfined container AppArmor
profile. It retains Docker's separate mount and PID namespaces. The fixture
owns a read-only proc mount beneath a disposable `.work/x86_64` child root,
unmounts it on completion or failure, and retires temporary setuid permissions.
Other chroot consumers use the existing narrower container helper.
`tests/test_dynamic_loader_dispatch.py` observes actual Docker arguments for
the dynamic product, wordexp, and CRT dispatches to guard that boundary.

`run_general_dynamic_pthread_signal.sh` reuses the ordinary pthread/C11 signal
consumer under installed and extracted PIE/non-PIE entries. Its read-only proc
mount observes completed kernel tasks before checking still-valid joinable
handles, and is unmounted by the runner's exit trap. The integrated dynamic
gate passed with search policy, pure-TBSS, live pthread attributes, signal
transactions and existing cancellation/lifecycle consumers; retained log:
`.work/x86_64/pthread-signals-getattr-search-integrated.log`, product:
`.work/x86_64/tmp/materialized-dynamic.irVBKA`. This is component evidence,
not final same-revision platform qualification.

Installed and extracted products also run `run_owned_pthread_join_cancel.sh`.
The selected installed or extracted product compiles one fixture object, which
links through each PIE/non-PIE consumer and runs through both its PT_INTERP and
direct `/lib/ld-crabc-x86_64.so.1` entries. A supplied product resolves before
evidence creation and must be a physical directory below the checkout `.work`
tree. The runner compares `pthread_join`, `pthread_tryjoin_np`, and
`pthread_timedjoin_np` with
musl: busy/timeout/invalid-deadline paths preserve the result and target,
completed `pthread_tryjoin_np` delegates to the cancellation point, and pending
entry/blocked/disabled or masked callers retain the source cleanup and state
behavior. The owned wait
uses the shared clear-child-TID futex while the musl oracle uses its private
detach-state futex; the shared object receives that expected observation from
the runner. Musl times its private detach-state wait before its untimed
`__tl_sync`; the selected lifecycle times the shared clear-child-TID until it
reaches zero before its existing result/reclamation transaction. This does not
claim byte identity between those private state records. The public GNU names
are weak same-address aliases of hidden strong `__pthread_tryjoin_np` and
`__pthread_timedjoin_np` bodies; the runner checks the alias graph in the
dynamic `libc.so` provider. The oracle is pinned musl 1.2.6.

Initial dependency cycles use musl 1.2.6 `ldso/dynlink.c:queue_ctors`
(mark before descending, skip visited edges, append on completion), matching
the frozen AArch64 constructor traversal. `InitialGraphState` retains inode
identity and existing capacities; its owned-runtime constructor plan visits
each DSO exactly once. Legacy private proof roots retain cycle rejection.
`run_general_dynamic_cycle.sh` builds a real A/B `DT_NEEDED` cycle with the
installed driver and compares both dependency orders, PIE/non-PIE, and kernel
/direct interpreter entry against pinned musl. It verifies constructor and
reverse finalizer ordering, initial and worker TLS, and repeated `dlopen`
without reinitialization. Both installed and extracted products run this gate.

The three-product execution regression rejects the earlier artifact whose
second clean build had only a manifest/archive comparison and no consumer
outcome. `check_basic_product` now requires matching musl output, spawn
interposition and non-PIE startup for each product; `check_runtime_suites`
runs the same leaf roster for all three. The integrated gate passed at the
`550bb254` runtime plus this harness change; log
`.work/x86_64/three-dynamic-products-integrated.log`, retained product
`.work/x86_64/tmp/materialized-dynamic.uyzJLv`. This measurement predates the dedicated
dynamic cancellation composition and current publication receipts.

Installed and extracted products run `run_owned_pthread_cond_cancel.sh` for
main and worker pending/blocked condition cancellation, cleanup with the mutex
reacquired, condition reuse, disabled/MASKED states, and consumed-signal
suppression. Blocked checks read the exact futex syscall through an inherited
read-only `/proc` descriptor; private chroots require no additional proc mount.
The same fixture runs unchanged against pinned musl 1.2.6.

`run_owned_dynamic_io_cancellation.sh INSTALLED_SYSROOT` runs the shared
`owned_io_cancellation_fixtures.sh` roster through the actual installed
`libc.so`, loader-owned initial TCB, and dynamic worker TLS/clone lifecycle.
Each ordinary fixture is linked by the sealed dynamic driver as PIE and
non-PIE and run through both kernel PT_INTERP startup and direct interpreter
entry. The exact stdout must equal pinned musl. This covers scalar, vector,
and positioned I/O, readiness and signal waits, sockets, sleep and child waits,
open and blocking record locks, memory sync, unnamed semaphores, entropy,
System V messages, FILE lock cleanup, main/worker cancellation, and fork
inheritance. The common roster shares test selection, header requirements,
and scratch arguments; static and dynamic evidence remain separate runs.

The runner verifies each persistent application object and link input against
its receipt, the product manifest and output hashes, ELF mode, canonical
interpreter, and sole `DT_NEEDED` dependency on owned `libc.so`. Both runtime
artifacts remain free of external runtime dependencies and text relocations.
Only copied owned artifacts and test scratch inhabit its private execution
root. `run_pthread_wait_witness.py` supplies a read-only `/proc` directory
descriptor through `CRABC_TEST_PROC_FD`; `owned_cancellation_proc_witness.h`
uses it for the existing exact blocked-syscall observations. No proc mount,
new mount authority, host shell, or ambient loader is needed. Without a
supplied descriptor, ordinary static runs retain their existing proc path.
The optional no-argument runner invocation first builds a fresh dynamic product.

`run_owned_system_cancellation.sh INSTALLED_SYSROOT` separately qualifies
`system` and `pclose` child-wait cancellation in PIE/non-PIE and direct
interpreter modes. A same-runtime protocol target occupies `/bin/sh` inside
each private root; no ambient shell or runtime is copied into the candidate.
Both consumer and child are sealed-driver outputs with owned interpreter and
libc dependency checks. The pinned-musl reference uses static copies of those
same fixture sources in its own root. Normal cancellation tests and injected
tester failure/timeout verify source wait semantics and supervisor child
ownership. This is process/wait evidence, not a shell implementation claim.

`run_owned_pthread_cond_timed.sh SYSROOT` qualifies supplied installed/extracted
products for:
clocked expiration and validation, C11 timed status, robust mutex relock error
precedence, main/worker timed/shared cancellation, private-barrier handoff onto
a shared mutex, and shared conditions across distinct child mapping addresses.
The condition and mutex algorithms are local owned-runtime code, and both PIE
and non-PIE consumers use the same pinned-musl fixtures. This adds component
coverage while the pthread-family and final platform gates remain open.
