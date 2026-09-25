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
function in `compat/x86_64/owned-static-replacement-roster.txt` must link with musl
and with the candidate.

The installed archive emits one member per Rust module. Leaf files that
group several C entries place each musl object's entries in
`static_archive_member!` (`libc/src/c_abi/x86_64/static_archive_member.rs`),
which becomes a child module only in the installed static build; libc.so and
the per-leaf fixture archives, whose runners pin one object per leaf, keep
the items inline. The roster groups its functions by family.

The generated musl math translations (`libc/src/c_abi/x86_64/*_musl_x86_64.S`)
concatenate one compiled musl source file per marker. `libc/build.rs`
partitions each at those markers, and `musl_object_assembly!` assembles one
module per musl object in the installed static build, so each math function
has the member musl gives it; a symbol the generator made local but another
object references becomes a hidden global of its defining object. Other
builds assemble the checked translation unchanged. The generators also give
each translation private copies of the public functions its sources call
(`..._elementary_NAME`, `..._provider_NAME`); the partition calls the public
symbol instead, as musl's objects do. The `MATH` role defines counting
`hypot` and `log1p` and requires musl's result: `cabs` reaches `hypot` and
`acosh` reaches `log1p`.

Two groups stay candidate-divergent: `getopt_long`/`getopt_long_only` and
the `if_*`/`getifaddrs`/`freeifaddrs` interface entries. Their x86 sources
are shared with the paused AArch64 target, whose behavior and evidence this
campaign preserves, so their members are not split here.

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

## Formatted I/O roles

`PRINTF` defines counting `vfprintf` and `vasprintf` (with a minimal
formatter: musl formats every printf-family call, `vsnprintf` included,
through the public `vfprintf`). `VSNPRINTF` defines a counting `vsnprintf`
over a memory stream, and `SCANF` a counting one-directive `vfscanf`. Musl's
`printf`, `vprintf` and `fprintf` reach `vfprintf`; `snprintf`, `sprintf`
(through `vsprintf`) and `vasprintf` reach `vsnprintf`; `asprintf` reaches
`vasprintf`; `scanf`, `vscanf` and `fscanf` reach `vfscanf`.
`libc/src/c_abi/x86_64/stdio_format_scan.rs` and `owned_printf.rs` keep each
entry in its own member, with its `__isoc99_` alias beside it, and route
through those never-inlined `v` forms. Musl's `vsscanf` also scans through
the public `vfscanf` over a string FILE; the candidate's `vsscanf` scans the
string directly, so the `SCANF` role does not call `sscanf`.

## Leaf-family roles

`WIDE` defines counting `wcwidth`, `wcslen`, `mbsrtowcs` and `wcsrtombs`;
musl's `wcswidth`, `wcsdup`, `mbstowcs` and `wcstombs` reach them. `SYSTEM`
defines counting `nanosleep`, `open`, `unlink`, `rmdir`, `sendto` and
`recvfrom` that perform the plain system call; musl's `sleep`, `usleep`,
`creat`, `send` and `recv` reach them, while its `remove` issues the
`unlink` system call directly. `creat` (`descriptor_entry.rs`) calls the
never-inlined `open`, and `send`/`recv` (`socket_transport.rs`) call the
public `sendto`/`recvfrom`, as musl's sources do.

`FILES` defines counting `open`, `mknod` and `fcntl`: musl's `opendir`,
`mkfifo` and `lockf` reach them, and in the owned runtimes the candidate's
now call those public entries (never-inlined `mknod`). `NETWORK` defines
counting `gethostbyname2` and `getservbyname_r`, reached by `gethostbyname`
and `getservbyname`. `ACCOUNTS` defines counting `getgrouplist` and
`setgroups`, reached by `initgroups`. `THREADS` defines counting
`pthread_mutex_lock`/`unlock` and requires that `mtx_lock`/`mtx_unlock` do
not reach them: musl's C11 mutexes call its hidden `__pthread_mutex_*`
bodies.

`PROCESS` defines counting `atexit`, `pthread_atfork`, `getlogin`,
`sem_timedwait`, `strtod` and `longjmp`. Musl's `exit.c` and `fork.c` carry
weak dummy `__funcs_on_exit` and `__fork_handler`, so neither registry is
linked or run; `static_startup.rs` and `pthread_atfork.rs` give `exit` and
`fork` the same weak dummies in the installed archive, `exit` its own member,
and the atexit lock that fork holds its own member. Musl's `getlogin_r`,
`sem_wait`, `atof` and `siglongjmp` reach the replacements; `wcstod` does
not. The float-parse translations take one member per musl object (the
entry file through `musl_object_assembly!`). `EXIT` defines `exit`, which
`__libc_start_main` reaches when `main` returns. `PUSHBACK` defines an
`ungetc` that pushes nothing back: musl's scanner steps its own buffer
position back, and so does the owned scanner (`unread_scanned_byte`), so
`fscanf` still sees every delimiter. `MAPPING` defines a counting `mmap`
and requires that no allocation from process start reaches it: musl's
allocator maps through its internal `__mmap`, and the builders compile the C
mimalloc backend with the same `mmap`/`madvise`/`mremap`/`mprotect`
redirection (`MIMALLOC_INTERNAL_VM_C_FLAGS`). Musl frees individual mappings
through the public `munmap`, and so does the backend.

## Standard I/O roles

`libc/src/c_abi/x86_64/owned_static_stdio.rs` and its stream children
(`owned_stdio_backends.rs`, `owned_wide_stdio.rs`, `owned_stdio_extensions.rs`,
`owned_stdio_process.rs`, `owned_signal_reporting.rs`) keep each musl
`src/stdio` object's entries, with their `_unlocked`, `_IO_` and hidden-target
aliases, in its own member; the FILE records, registry, locks and buffering
helpers stay in the parent. Each entry reaches the others as musl's source
does, and the public callees are never inlined:

- `fputs` measures with the public `strlen` and writes with the public
  `fwrite`; `puts` calls `fputs`; `putw` and `getw` use `fwrite` and `fread`.
- `fclose`, `freopen` and `_flushlbf` call `fflush`; a `freopen` whose new
  open fails closes the stream with `fclose`; `pclose` calls `fclose` and
  `popen` opens its end with `fdopen`.
- `getline` calls `getdelim`, and `fgetln` calls `ungetc` and `getline`;
  `setbuf`, `setbuffer` and `setlinebuf` call `setvbuf`; `flockfile` calls
  `ftrylockfile`; `getwc` and `getwchar` call `fgetwc`, and `putwc` and
  `putwchar` call `fputwc`; `psiginfo` calls `psignal`, which formats with
  `fprintf`.
- `getc`, `getchar`, `putc` and `putchar` transfer bytes themselves, as
  musl's inlined `do_getc`/`do_putc` do, and `getchar_unlocked` and
  `putchar_unlocked` expand stdio_impl.h's macros; none calls `fgetc`,
  `fputc`, `getc_unlocked` or `putc_unlocked`. `__stdio_exit` writes pending
  output itself rather than through `fflush`.

The roles define counting replacements and report whether each client
reached them: `STDIO_BLOCK` (`fwrite`, `fread`), `FPUTS`, `FFLUSH` (a no-op
whose buffered final output only `__stdio_exit` can write), `GETDELIM`,
`SETVBUF`, `WIDE_STREAM` (`fgetwc`, `fputwc`), `FCLOSE`, and `BYTE` (`fgetc`,
`fputc`, `getc_unlocked`, `putc_unlocked`, which musl's other byte entries
do not reach). `PRINTF` also covers `psignal` and `psiginfo`.

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
