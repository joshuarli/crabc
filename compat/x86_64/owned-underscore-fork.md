# Owned `_Fork`

`_Fork` creates a child without user `pthread_atfork` handlers. The child
retains the caller's compiler TLS, pthread identity and robust-list storage,
while Linux TID and libc main-task bookkeeping describe the sole surviving
task. This is a minimal async-signal-safe transition: it does not repair
inherited allocator, loader, pthread-key or application locks. The child of a
multithreaded parent uses permitted async-signal-safe operations through exec
or immediate `_Exit`; this evidence does not admit arbitrary runtime reuse.

The source oracle is musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT `COPYRIGHT`.
`src/process/_Fork.c` (SHA-256
`3821faa03c1718620f1f4804133aa7473065c2f34f9cb49708b7930787e0e9e5`)
maps `_Fork` to `pthread_atfork.rs::fork_without_handlers` and
`__post_Fork` to `pthread_create_join.rs::adopt_process_child_caller` plus
the abort-lock/AIO-hook completion in its caller. Existing `src/linux/clone.c`
translation uses the same captured-caller substrate. Source `fork.c` remains
the outer user-handler/key/owned-lock/loader coordinator.

The owned thread representation differs from musl's inline `struct pthread`:
`ProcessChildCaller` captures the executing worker control through the already
published `%fs:32` cancellation pointer, independently of registry mutation.
The child's inherited control remains mapped. Atomic caller TSD values are
copied before changing libc main identity; the key metadata lock stays copied
until normal `fork` completes its outer key owner. Static and dynamic compiler
TLS images and the FS base are unchanged. Vanished worker records become
unreachable without freeing or traversing their inherited links.

The inner transaction blocks every signal, captures its caller, acquires the
abort/process lock, forks, repairs child identity, releases abort ownership,
invokes the child AIO hook and restores its exact signal mask. Normal fork
prepares the inert AIO seam after its pthread-key owner and before owned locks;
parent/error completion releases it after owned locks and before keys. The
child seam runs only inside the inner transaction. The weak AIO hook stays
inert; no AIO engine or close coordination is admitted by this change.

`run_owned_underscore_fork.sh` compiles one installed-header object, executes
pinned musl, then executes owned static/static-PIE and dynamic PIE/non-PIE
through both kernel and direct-loader entry. Product receipts, installed header
dependencies, symbols and raw stdout/stderr/status remain retained beneath
`.work/x86_64/`. The probe covers main and worker calls, callback absence,
compiler TLS and pthread identity, captured robust-list head retention with
cleared offset/pending state, exec/immediate exit, signal masks, and repeated
seccomp-denied `fork=57` failures with `EAGAIN`. Signal-handler calls interrupt a worker that
continually creates and reaps workers, and also run on the initial task: this is bounded concurrency stress,
not proof of a deterministic interruption at a particular locked instruction.
The child inspects captured robust storage directly rather than invoking a
non-async-signal-safe mutex operation.

Before implementation the common installed object linked against pinned musl
but failed the owned static link with `undefined symbol: _Fork` at its ordinary
and error-case call sites. The existing clone/process-trio, ordinary atfork and
worker TLS evidence must accompany the new matrix after shared-owner changes.
AArch64 and the frozen private archive retain their existing paths.

The `underscore-fork` case is required for all three dynamic products. Its
independent six-mode runner also supplies static/static-PIE replay; the
aggregate consumes the supplied dynamic product without rebuilding it. The
owned feature accounts for `_Fork` as one additive callable, while the frozen
default static export contract remains unchanged.
