# Dynamic FILE allocator interposition

`./scripts/dev-x86_64.sh owned-stdio-allocator-interposition` keeps a dynamic
`FILE` on the same public C malloc-family provider for its whole lifetime. It
is focused private x86 evidence; it does not close stdio, allocator, or dynamic
runtime qualification.

Pinned musl 1.2.6 commit `9fa28ece75d8a2191de7c5bb53bed224c5947417` is the
behavior oracle. The pinned libc-test `src/regression/flockfile-list.c`
sequence creates two temporary streams, locks the second then first, releases
and closes the second, then releases the first. The consumer in
`owned_stdio_allocator_interposition_probe.c` retains that order and defines
`malloc`, `realloc`, and `free` in the executable. `free` fills released
storage with byte 42; the consumer rejects an unfreed FILE allocation and any
write through stale lock-list storage after the second stream is closed.

`owned_static_stdio.rs` owns
`__crabc_x86_stdio_cabi_{malloc,realloc,free}`. The hidden x86 tails branch to
the public `malloc`, `realloc`, and `free` PLT entries, rather than permitting
LLVM to fold a Rust extern spelling into the crate's selected mimalloc wrapper.
`fdopen`, `getdelim`, and `fclose` use those exact boundaries.
`owned_stdio_backends.rs` uses the same three boundaries for FILE records and
growing byte/wide memory-stream storage. Thus allocation, reallocation, and
release continue to select an executable interposer as one provider pair.

The runner compiles one consumer object through a fresh installed crabc dynamic
product, links that same object with pinned musl and the product's PIE and
non-PIE drivers, and verifies the executable exports all three interposers. It
runs each dynamic executable through kernel and direct-interpreter entry in a
disposable chroot, retaining and comparing status, stdout, and stderr. The
pre-fix candidate reached mimalloc's private `mi_free` while closing an
executable-allocated FILE and received SIGSEGV; the passing receipt requires
all eight runs to exit successfully.

This receipt is limited to the owned FILE allocation clients. Other x86
direct malloc-family clients remain separately owned and need their own
interposition audit before their allocation lifetimes can claim this property:
`owned_printf.rs::vasprintf`, `owned_timezone.rs`, `owned_passwd.rs`, and
`owned_classic_netdb.rs`.
