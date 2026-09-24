# Installed POSIX process control

The installed native Linux/x86-64 products compose selected C process
providers from distinct source leaves. This evidence binds **all 44 names** of
the frozen `process.control` roster to one installed-header workload object;
it does not reinterpret that object as a general process runtime. The
implementation follows pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` under the musl MIT license
recorded in `COPYRIGHT`.

| Pinned musl source | Installed entries exercised here |
| --- | --- |
| `src/process/{fork,vfork}.c`, `src/linux/clone.c`, `src/legacy/daemon.c` | `fork`, `vfork`, `clone`, `daemon` |
| `src/process/{execve,execv,execvp,execl,execle,execlp,fexecve}.c` | `execve`, `execv`, `execvp`, `execvpe`, `execl`, `execle`, `execlp`, `fexecve` |
| `src/unistd/nice.c` | `nice` |
| `src/unistd/{setpgid,setpgrp,setsid}.c` | `setpgid`, `setpgrp`, `setsid` |
| `src/process/{wait,waitpid,waitid}.c` | `wait`, `waitpid`, `waitid` |
| `src/linux/{wait3,wait4}.c` | `wait3`, `wait4` |
| `src/process/{posix_spawn,posix_spawnp}.c` and `posix_spawn_file_actions_{init,destroy,addopen,addclose,adddup2,addchdir,addfchdir}.c` | `posix_spawn`, `posix_spawnp`, and the seven `posix_spawn_file_actions_*` entries |
| `src/process/posix_spawnattr_{init,destroy,getflags,setflags,getpgroup,setpgroup,getsigmask,setsigmask,getsigdefault,setsigdefault}.c` and `posix_spawnattr_sched.c` | the 14 `posix_spawnattr_*` init/destroy/get/set entries |

The source providers remain separately named in
`libc/src/c_abi/x86_64/owned_process_trio.rs`, `pthread_atfork.rs` (`fork`),
`owned_spawn.rs`, `process_exec.rs`, `process_exec_env.rs`,
`process_exec_path.rs`, the three variadic exec leaves,
`process_context.rs`, `child_reaping.rs`, `wait_extensions.rs`,
`process_resources.rs`, and the `posix_spawn*` leaves. That preserves the
existing extraction and ownership boundaries while the owned static/dynamic
product composes them.

## Workload and lifecycle boundary

Run `./scripts/dev-x86_64.sh owned-process-control [DYNAMIC_SYSROOT]`. The
runner compiles exactly one C object with the supplied installed dynamic
driver, links that same object to pinned musl, owned static, static-PIE,
dynamic PIE, and dynamic non-PIE products, and runs both kernel and direct
interpreter entry for the dynamic forms. It checks archive and shared-provider
symbols. Static receipts bind the one object, selected CRT, owned archive and
builtins hashes, manifest-recognized static payload, link trace/map, and final
consumer. Dynamic consumer receipts bind the object, manifest, owned runtime
inputs, interpreter, and `libc.so` dependency to the supplied product.
Every oracle and candidate execution retains its raw stdout, stderr, and
timeout/chroot exit status in sibling `.stdout`, `.stderr`, and `.status`
files. Nonzero status still fails the runner after capture. Successful
candidate statuses are compared to the oracle alongside the stream checks;
the explicit `fexecve` stdout difference below remains separately checked.

For family replay inside the pinned native environment, the leaf also accepts
`bash compat/x86_64/run_owned_process_control.sh [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`.
The dispatcher retains its existing zero-argument or dynamic-only interface.
With no arguments the leaf builds both products and runs the full matrix.
A lone dynamic product preserves the dynamic-only replay. A supplied static
product runs both static modes; when no dynamic product is supplied, the leaf
builds a default dynamic product for the installed-driver compilation and
dynamic runs. Supplying both products reuses both without invoking a producer.
Supplied static products undergo the existing package owner's complete
installed-tree validation before evidence creation, and every static link
retains the same receipt/ELF and deliberate tampering checks described above.
Empty, option-valued, or duplicate product arguments fail with usage status 2
before output directories or builds are created. All supplied products must
remain under the checkout's `.work` tree.

The workload performs each image replacement in a raw fixture child. It checks
PATH and explicit-environment forwarding, variadic argv construction, and a
successful descriptor execution. Its `nice` and group/session transitions also
run in disposable children. Pipe-controlled children make `WNOHANG`, exit
status, `WNOWAIT`, the one later reap, `ECHILD`, and `wait3`/`wait4` resource
reports observable without relying on scheduling. The raw `fork`, pipe, wait,
and exit calls are fixture plumbing only; they do not select a public fork,
pipe, supervision, or lifecycle API.

The public creation entries are exercised directly. `fork` reports the
child's own pid and parent through a pipe. As in musl, `fork` also succeeds in
a process image copied by a raw `SYS_fork` from the initial thread or from a
worker: that sole task keeps the copied TLS but has a new TID. Such an image
was never prepared, so under the native allocator it takes the unprepared raw
copy rather than the prepared-fork child contract. `clone` rejects a null stack and
`CLONE_THREAD`, preserves `errno` on success, and runs its callback to an exit
status. `vfork` execs the consumer. `daemon(1, 1)` runs in a raw-fork image under a
subreaper supervisor that observes a new non-leader process in the new session and reaps
all three processes; its `/dev/null` and root-directory arguments stay in
`owned-process-trio`. Both spawn entries run the consumer through
`addopen`, `adddup2`, `addclose`, and `addchdir_np` (`posix_spawn`) or
`addfchdir_np` (`posix_spawnp`, found through `PATH`), and the child verifies
each resulting descriptor and working directory. A missing image returns
`ENOENT` without a pid, and invalid descriptors return `EBADF` from each
file-action constructor. `errno` after a spawn is unspecified; musl's shared-VM
child writes it, so the workload does not compare it.

`wait`, `waitpid`, and `waitid` retain the owned runtime's musl
cancellation-point route and their dedicated cancellation evidence in
`owned_sleep_wait_cancellation_probe.c`. `wait3` and `wait4` come from musl's
direct Linux paths, so this workload deliberately treats neither as a
cancellation point.

The `fexecve` seccomp child denies only `execveat(2)` with `ENOSYS`. Musl then
falls back through `/proc/self/fd/<fd>` and maps a final `ENOENT` to `EBADF`
(`9`). The installed crabc provider deliberately exposes `fexecve`'s direct
`execveat(2)` `ENOSYS` (`38`) and does not add a procfs fallback. The
runner compares those two stated results explicitly; it does not call the
difference generic musl parity.

## Relationship to other process evidence

`owned-process-trio` keeps the deeper clone flag, pidfd, robust-list, atfork
and seccomp rollback matrix for `clone`, `vfork`, and `daemon`, and
`owned-dynamic-spawn` keeps spawn attributes, signal state, worker spawn, and
failure rollback. This workload does not repeat those matrices; it makes every
roster name observable from the one object in every linkage mode.

`process-control` is a required dynamic-product qualification case, so the
same workload replays on each clean product and the extracted product.
It remains private native-x86 product evidence. It does not complete
`process.control`, `libc.posix-runtime`, a sysroot, a general process or
supervision API, platform promotion, or public x86 support.
