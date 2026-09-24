# Static application replacement of libc functions

Pinned musl 1.2.6 builds `libc.a` from one object per source file. A static
program may therefore define a libc function itself: the linker takes the
program's definition, extracts no member for it, and libc callers that name
the public symbol reach the program's definition. The installed crabc static
archive must give the same link result and behavior.

`./scripts/dev-x86_64.sh owned-static-replacement [STATIC_SYSROOT]` runs
`compat/x86_64/run_owned_static_replacement.sh`. Without an argument it builds
a fresh static product. Each role of
`compat/x86_64/owned_static_replacement_probe.c` is compiled once with the
project headers and linked unchanged by static musl and by the installed
`crabc-cc` in `-static` and `-static-pie` mode. Musl's link must succeed and
its run must pass; the candidate must link and reproduce musl's status,
stdout and stderr byte for byte.

## Allocator roles

The allocator roles define a bump arena whose `free` terminates the program
on a pointer it did not allocate. `MALLOC_TRIO` replaces `malloc`, `free` and
`realloc`, musl's minimum replaceable set; `MALLOC_FULL` also replaces
`calloc`, `reallocarray`, the aligned entries and `malloc_usable_size`. The
probe reports, for each libc client, who owns the result and whether the call
crossed the public allocation and release spellings. Musl routes these through
the public symbols: `calloc` (with only the trio replaced) and `reallocarray`;
`strdup`, `strndup`, `wcsdup`, `asprintf`, `realpath`, `getcwd(NULL, 0)`,
`getline`/`getdelim` growth, `fopen`/`fclose`, `open_memstream`, `scandir`,
`getaddrinfo`/`freeaddrinfo`, and `setenv`/`unsetenv`.

In the owned static archive, `libc/src/allocator_mimalloc.rs` binds the whole
allocation family weak, as the native-shadow entries are
(`libc/src/c_abi/x86_64/allocator_native_mimalloc.rs`). Its entries share one
member where musl uses nine, so a strong binding collided with the program's
definitions whenever any libc member named the wrapper. Weak binding also
keeps every libc call an ordinary preemptible reference: ThinLTO had inlined
the strong `free` into libc callers as a direct backend release, so
`unsetenv` never reached a replaced `free`. With `malloc` replaced, `calloc`
allocates through the public `malloc` and zeroes, and `aligned_alloc`
refuses (see `compat/allocator/known-differences.md`); the roles therefore
exercise libc's own aligned entries only when the program replaces them.

Two clients reached private storage instead: `getaddrinfo` mapped one page
per result node, and `getcwd` rejected a null buffer. In the owned runtimes
`libc/src/c_abi/x86_64/numeric_netdb.rs` allocates each node with the public
`calloc` and releases it with the public `free`, and
`libc/src/c_abi/x86_64/pathname_lifecycle.rs` returns a public `strdup` copy
for a null buffer, as musl does.

Replacing the whole family leaves the program with no initialized TLS (the
bundled allocator's `.tdata` is not linked). LLD then places the `.tbss`-only
`PT_TLS` outside every `PT_LOAD`; the static TLS bootstrap
(`libc/src/c_abi/x86_64/static_tls.rs`) now requires `PT_LOAD` coverage only
for a template with initialized bytes.

Musl itself does not support every subset. With only the trio replaced, its
`calloc` inspects the result with mallocng's `__malloc_allzerop` whenever
mallocng is linked, and a program pointer then crashes it; the trio role
therefore links no aligned entry, which would pull mallocng in.

This is focused private x86 evidence. It does not claim replacement of every
libc function, dynamic interposition (see
[owned-c-allocation-interposition.md](owned-c-allocation-interposition.md)),
or public x86 support.
