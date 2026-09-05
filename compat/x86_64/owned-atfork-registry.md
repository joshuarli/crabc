# Owned atfork callback registry

Owned Linux/x86-64 static and dynamic products allocate one process-lifetime
record for each successful `pthread_atfork` registration. There is no fixed
callback count. If the existing owned allocator cannot supply a record,
registration returns positive `ENOMEM` before acquiring the registry lock or
changing the list. The frozen private archive still uses its no-allocation
32-record table and reports `ENOMEM` when that table is full.

`libc/src/c_abi/x86_64/pthread_atfork.rs` translates
`src/thread/pthread_atfork.c` from musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT; archive digest in
`compat/upstreams.toml`). `AtforkNode` retains the source record's three
optional callbacks followed by previous/next links. Registration allocates
before locking and prepends the completed record. `__fork_handler` traverses
newest to oldest for prepare callbacks, leaving the head cursor at the oldest
record. Parent or child completion follows the previous links forward through
registration order and restores the newest head before unlocking. A failed
fork executes the parent callbacks and also restores that orientation.

The owned internal allocation entry in
`libc/src/c_abi/x86_64/static_c_abi.rs::allocator::allocate_internal` uses the
same backend, alignment and failure translation as the existing C malloc
wrapper. It preserves musl's private `__libc_malloc` choice without calling an
application replacement for public malloc. This adds no allocator algorithm,
backend, dependency, C allocation API, or AArch64 change. Records are never
freed because the source API has no callback deregistration operation. Each
callback must remain executable whenever a later fork can reach it.

The selected runtime retains its existing paired registry lock even when the
list is empty. Musl's unlocked empty-list fast path is omitted so a concurrent
first registration cannot cross an unprotected fork snapshot. All node links
and the traversal cursor are accessed under the lock; allocation remains
outside it. User callbacks must return normally and must not reenter this
registry while its lock is held. The outer fork transaction and the private
archive's callback table are otherwise unchanged by this registry slice.

Run `./scripts/dev-x86_64.sh owned-atfork-registry` for the installed-product
differential. `owned_atfork_registry_probe.c` first completes an empty-registry
fork, then registers 67 distinct callback triples, then verifies exact reverse prepare and forward parent/child
order. It also observes a null triple, registration and another fork in the
first child, parent and worker registrations after a completed fork, callback
records surviving worker exit, repeated forks, and parent completion following
contained syscall failures. Subsequent registrations bring the count to 70.
The first regression passed on pinned musl and failed the owned static
product at registration 33 with `ENOMEM`.

`run_owned_atfork_registry.sh` runs the probe through the pinned musl oracle
and installed static/static-PIE products, plus dynamic PIE/non-PIE with kernel
and direct interpreter entry. The dynamic qualification catalog runs the
same leaf on each supplied product. Driver receipts retain ordinary owned
linkage evidence. The focused private `libc-pthread-atfork` gate independently
checks that the older 32-record path remains intact. The runtime fixture does
not force exhaustion of the allocator or change the outer fork subsystem's
existing limits.
