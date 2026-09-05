# Installed residual POSIX process control

The installed native Linux/x86-64 products already compose selected C process
providers from distinct source leaves. This evidence binds the **31 residual**
names below to one installed-header workload object; it does not reinterpret
that object as a general process runtime. The implementation follows pinned
musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417` under
the musl MIT license recorded in `COPYRIGHT`.

| Pinned musl source | Installed entries exercised here |
| --- | --- |
| `src/process/{execve,execv,execvp,execl,execle,execlp,fexecve}.c` | `execve`, `execv`, `execvp`, `execvpe`, `execl`, `execle`, `execlp`, `fexecve` |
| `src/unistd/nice.c` | `nice` |
| `src/unistd/{setpgid,setpgrp,setsid}.c` | `setpgid`, `setpgrp`, `setsid` |
| `src/process/{wait,waitpid,waitid}.c` | `wait`, `waitpid`, `waitid` |
| `src/linux/{wait3,wait4}.c` | `wait3`, `wait4` |
| `src/process/posix_spawnattr_{init,destroy,getflags,setflags,getpgroup,setpgroup,getsigmask,setsigmask,getsigdefault,setsigdefault}.c` and `posix_spawnattr_sched.c` | the 14 `posix_spawnattr_*` init/destroy/get/set entries |

The source providers remain separately named in
`libc/src/c_abi/x86_64/process_exec.rs`, `process_exec_env.rs`,
`process_exec_path.rs`, the three variadic exec leaves,
`process_context.rs`, `child_reaping.rs`, `wait_extensions.rs`,
`process_resources.rs`, and the `posix_spawnattr_*` leaves. That preserves the
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

The workload performs each image replacement in a raw fixture child. It checks
PATH and explicit-environment forwarding, variadic argv construction, and a
successful descriptor execution. Its `nice` and group/session transitions also
run in disposable children. Pipe-controlled children make `WNOHANG`, exit
status, `WNOWAIT`, the one later reap, `ECHILD`, and `wait3`/`wait4` resource
reports observable without relying on scheduling. The raw `fork`, pipe, wait,
and exit calls are fixture plumbing only; they do not select a public fork,
pipe, supervision, or lifecycle API.

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

## Composite accounting

This runner executes the residual 31 names only. The documented
**44-name composite** also depends on the existing independent evidence for
`clone`, `vfork`, and `daemon` in `owned-process-trio`; `fork` in the dynamic
fork case; and `posix_spawn`, `posix_spawnp`, and the seven POSIX spawn
file-action entries (`posix_spawn_file_actions_{init,destroy,addchdir_np,
addclose,adddup2,addfchdir_np,addopen}`) in `owned-dynamic-spawn`.
It does not execute the other 13 names, and those existing matrices do not
become part of this object merely because their union is useful accounting.

`process-control` is a required dynamic-product qualification case, so the
same residual workload replays on each clean product and the extracted product.
It remains private native-x86 product evidence. It does not complete
`process.control`, `libc.posix-runtime`, a sysroot, a general process or
supervision API, platform promotion, or public x86 support.
