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

## Link sweep

`compat/x86_64/owned_static_replacement_sweep.py` measures the whole public
surface. For every function that both archives define, it assembles a program
that defines the function and names every other public symbol both archives
define, except those in the function's own musl member, and links it with
musl and with the candidate in both static modes. Musl links it unless its
own objects need that member. The report (`sweep/report.json`) lists every
result and each musl-replaceable function the candidate still rejects. Each
function in the runner's `replaceable_functions` roster must link with musl
and with the candidate.

The installed archive emits one member per Rust module. Leaf files that
group several C entries place each musl object's entries in
`static_archive_member!` (`libc/src/c_abi/x86_64/static_archive_member.rs`),
which becomes a child module only in the installed static build; libc.so and
the per-leaf fixture archives, whose runners pin one object per leaf, keep
the items inline. The roster covers the malloc family, the string, memory and
environment entries, `strerror`/`perror`, `atoi`/`atol`/`atoll`, and `qsort`.

## String role

`STRINGS` defines counting `strlen` and `getenv`. Musl reaches them from
`strdup`, `strcasestr`, `fputs`, `setenv`, `getenv` callers `tzset` and
`setlocale`, and not from `strndup` or `%s` formatting, which use `strnlen`.
The candidate keeps those public edges: `strlen`, `strnlen`, `strncasecmp`
and `getenv` are never inlined into libc callers, `strdup`/`strndup` measure
with the public `strlen`/`strnlen`, owned `strcasestr` follows musl's
`strlen`/`strncasecmp` source (which also makes `strcasestr("", "")` return
null, as musl's does), and owned `%s` formatting measures with `strnlen`.
Musl's `setlocale` also measures each category name with `strlen` while
serializing an `LC_ALL` result; the fixed-profile implementation returns
prebuilt names, so the role compares only its environment edge.

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

In the installed static archive, each entry of `libc/src/allocator_mimalloc.rs`
is its own member with musl's binding (weak `malloc`, strong others), as
musl's nine objects are. The entries had shared one member, so the program's
definitions collided with it whenever any libc member named the wrapper.
The strong entries are also never inlined into libc callers: ThinLTO had
inlined `free` into them as a direct backend release, so `unsetenv` never
reached a replaced `free`. With `malloc` replaced, `calloc`
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
libc function (the sweep report measures the remainder), dynamic interposition (see
[owned-c-allocation-interposition.md](owned-c-allocation-interposition.md)),
or public x86 support.
