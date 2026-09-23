# Owned C allocator interposition

`./scripts/dev-x86_64.sh owned-c-allocation-interposition` qualifies five
narrow dynamic C-allocation boundaries against pinned musl 1.2.6 commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. It is focused x86 evidence; it
does not close stdio, passwd, allocator, or dynamic-runtime qualification.

`run_owned_c_allocation_interposition.sh [DYNAMIC_SYSROOT]` accepts the
qualification owner's supplied product. Without an argument it builds a fresh
product. The dynamic product catalog requires a separate passing receipt for
each independent build and the extracted package.

The one consumer object in `owned_c_allocation_interposition_probe.c` defines
aligned executable `malloc`, `realloc`, and `free` providers. It records each
allocation and overwrites released storage with byte 42. The `asprintf` case
requires the returned bytes to originate with that provider, verifies their
contents, then frees them through the executable. The passwd case uses the
installed local `/etc/passwd` record for a successful `getpwnam_r` lookup and
a missing lookup. Together they require the temporary public `getline`
allocation to be released after both the successful reentrant-copy path and
the EOF path.

The `lio` case checks musl `src/aio/lio_listio.c`'s public list-state
allocation independently of `src/aio/aio.c`'s private descriptor map and queue
allocations. Rejecting the executable's next `malloc` must return
`-1/EAGAIN` before modifying the submitted control block. A successful
`LIO_WAIT` then writes one byte, retires the list state through the executable's
`free`, and closes the descriptor. Exactly one public allocation is made on
that successful path, and its released bytes remain unchanged. The request
notification runs after private queue retirement; the observer waits for that
callback before checking for late allocator misuse. Extra public
queue allocations or private frees of public state fail the observer.

The `host` case calls `gethostbyname` twice with a numeric IPv4 address. The
nonreentrant cache must allocate both records through the executable's
`malloc`, release the first through its `free`, and leave the second live.
The observer also checks the released bytes. The numeric address avoids a DNS
or hosts-file dependency in this allocator ownership case.

The `timezone` case installs a POSIX `TZ` rule longer than the 32-byte static
cache, then rejects every executable `malloc` while `tzset` grows `OLD_TZ`.
Pinned musl's `src/time/__tz.c` maps that allocation to `__libc_malloc` because
it occurs under the timezone lock. The case requires no public allocation
attempt and checks the parsed standard and daylight names. The selected native
shadow previously called the executable allocator and failed this case; the
private `allocator::allocate_internal` seam now owns the cache.

`owned_printf.rs::vasprintf` already has an ordinary external `malloc`
boundary: the product records its `R_X86_64_GLOB_DAT` lookup and the consumer
passes through executable interposition in every run. No printf implementation
change follows from this audit.

`owned_passwd.rs` receives its line from the public `getline` provider. That
provider can allocate through the executable's C allocator, so passwd's two
matching release edges must use that same public provider. The direct Rust
`free` spelling was lowered to private `mi_free` in the candidate product.
`__crabc_x86_passwd_cabi_free` is a hidden x86 opaque tail that branches to
`free@plt`; `next_record` and `lookup_reentrant` use it for their line cleanup.
The retained product symbol, relocation, and disassembly artifacts prove the
public `malloc` lookup and passwd `free@plt` tail.
The AIO `__crabc_x86_aio_cabi_malloc` and `__crabc_x86_aio_cabi_free` tails
likewise retain ordinary public PLT lookups for list state; the product audit
and executed `lio` observer both check that boundary.
`owned_classic_netdb.rs` uses the same public lookup for its nonreentrant host
cache through `__crabc_x86_host_cache_cabi_malloc` and
`__crabc_x86_host_cache_cabi_free`. The selected native shadow previously
reached its private `native_free` with the executable's cache pointer and
terminated with status 134 on the second lookup. The product audit checks both
hidden tails and their `malloc@plt`/`free@plt` jumps.

The runner compiles the consumer once through a fresh installed crabc dynamic
sysroot, then links that exact object with pinned musl and the installed PIE
and non-PIE drivers. It verifies that each executable exports all three
interposers, installs a one-record passwd file in disposable chroots, and runs
all five cases through kernel and direct-interpreter entry. It compares
status, stdout, and stderr for twenty musl/candidate pairs. A passing receipt
therefore requires all forty executions to succeed with the same
observable results.
Every target must independently exit zero before comparison; a failure or
timeout stops the runner after retaining its raw status and streams. Matching
oracle and candidate failures cannot qualify this boundary.

The timezone case covers cache growth under executable allocator replacement;
it does not qualify the complete timezone or allocator lifecycle.
