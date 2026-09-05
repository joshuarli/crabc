# Owned pthread spin locks

Installed x86 static and dynamic products include `pthread_spin_lock`,
`pthread_spin_trylock`, and `pthread_spin_unlock` alongside their existing
initialization and destruction entries. Private and shared locks use the same
four-byte caller-owned word. Successful acquisition observes the previous
owner's release; a busy trylock returns `EBUSY` without changing errno.

`libc/src/c_abi/x86_64/pthread_spin_operations.rs` already translates musl
1.2.6 `src/thread/pthread_spin_lock.c`, `pthread_spin_trylock.c`, and
`pthread_spin_unlock.c`, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT, pinned in
`compat/upstreams.toml`). The installed change selects that existing port;
it changes no algorithm. The frozen private default archive remains unchanged
and its explicit `x86-pthread-spin-operations` feature remains available.

Run `./scripts/dev-x86_64.sh owned-pthread-spin`. One object compiled against
installed headers runs under pinned musl, owned static/static-PIE, and dynamic
PIE/non-PIE with kernel and direct-interpreter entry. Four workers and the
main task publish a counter and its complement through a private lock; a
parent and fork child repeat the publication through shared anonymous memory.
The child first observes `EBUSY` while its parent holds the lock. The workload
also checks trylock/release, errno preservation, and quiescent destruction.
Before owned selection, musl passed and the owned link failed on the three
missing operations. Contention tests establish behavior, not fairness or
performance qualification.

`run_owned_pthread_spin.sh` accepts an existing dynamic product for the
`pthread-spin` case in `owned_dynamic_qualification.py`. Both clean products
and extraction must independently execute it during aggregate qualification.
This component does not complete the pthread family or promote x86 support.
