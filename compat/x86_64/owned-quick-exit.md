# Owned C11 quick termination

The installed native x86-64 products provide C11 `at_quick_exit` and
`quick_exit` through `libc/src/c_abi/x86_64/owned_quick_exit.rs`. The frozen
private archive and the paused AArch64 allocation-backed
`libc/src/quick_exit_exports.rs` remain separate.

This module translates musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under the musl MIT license in
`COPYRIGHT`. `src/exit/at_quick_exit.c::{at_quick_exit,__funcs_on_quick_exit}`
maps to the fixed registry and drain, while
`src/exit/quick_exit.c::quick_exit` maps to its final `_Exit` dispatch. The
source archive is pinned by `compat/upstreams.toml`; the development copy is
kept under `.work/x86_64/source-oracles/`.

The registry retains musl's 32 function-pointer slots and count. Its private
one-word guard uses the source `__lock`/`__unlock` sign-bit congestion state,
ten bounded spins, and private futex wait/wake instead of a spin-only lock.
A full table returns `-1` without changing `errno`. Drain removes the newest
callback before releasing the guard around it, so callbacks run in LIFO order
and may register a replacement that runs in the same transition. Its empty
return retains the guard for the terminal `_Exit`. `quick_exit` does not flush
stdio or run ordinary `atexit` callbacks or DSO destructors.
Callers provide a non-null executable callback that remains valid until a
possible quick-exit dispatch; concurrent quick-exit callers retain musl's
quiescent-user contract.

`pthread_atfork.rs::fork` takes the quick-exit guard after pthread key
metadata and before stdio-family state, following musl
`src/process/fork.c`'s `__at_quick_exit_lockptr` position. Parent and raw-error
completion release it; the child clears its copied guard before callbacks can
resume. The callback table itself is inherited, so each process can register
additional callbacks independently after fork.

Run `./scripts/dev-x86_64.sh owned-quick-exit`. The runner uses the same C11
object with pinned musl, installed static/static-PIE, and dynamic PIE/non-PIE
through kernel and direct-loader entry. It checks strong archive and shared
ELF provider binding; LIFO order; the 32-slot limit and unchanged `errno`;
reentrant refill; no ordinary-exit, destructor, or buffered-stdio action;
worker process termination; controlled concurrent registration; a 32-worker
barrier that contends every available slot; and forked table inheritance with
copied-lock repair. It retains its artifact directory under
`.work/x86_64/tmp/` and is a required dynamic qualification case. This is
component evidence and does not complete a runtime family or public native-x86
support.
