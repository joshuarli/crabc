# Private x86-64 owned static sysroot artifact

`./scripts/dev-x86_64.sh owned-static-sysroot` proves one bounded installed
Linux/x86-64 static TLS, allocator, and POSIX consumers in ordinary `ET_EXEC`
and static-PIE `ET_DYN` modes, then repeats them from one extracted package. It is a
verified prerequisite inside the still-planned `sysroot.static-tls` family and
the still-planned `sysroot.owned-artifact` family, not either family’s
completion and not public
x86-64 support.

## Installed contract

`scripts/build_x86_64_owned_sysroot.py` uses the pinned
`nightly-2026-07-24` Rust toolchain in a sealed build environment and installs
only regular files:

```text
usr/include/
bin/crabc-cc
usr/lib/{crt1.o,Scrt1.o,rcrt1.o,crti.o,crtn.o}
usr/lib/libc.a
usr/lib/libcrabc-builtins.a
share/crabc/{manifest,headers,crt,libc-static,libcrabc-builtins,build}*.json
```

The CRT objects come from `crt/build_x86_64.py`. Cargo’s intermediate
`libc.a` is not installed directly: the builder classifies every member,
extracts crabc `c.*.rcgu.o` objects plus the accepted C allocator object, and excludes stock Rust core,
compiler-builtins, and native compiler-rt members before deterministic
re-archiving. `builtins/build_x86_64.py` supplies the separate one-member
Rust-only helper archive. The manifest hash-binds the complete installed
regular-file payload; both the installed driver and private package helper
reject an unlisted regular file, symlink, non-regular entry, missing payload,
or hash mismatch before compilation, packaging, or extraction. It records the
excluded inputs and unselected scope. Final publication is atomic, and two
clean builds in distinct roots must have identical regular-file bytes.

The `x86-owned-static-runtime` composition includes the Cargo-locked
`libmimalloc-sys` 0.1.49 backend, not the incomplete native Rust port. The
builder verifies its single object against the dependency producer archive,
binds the crate checksum and compiler identity, and records source/header
hashes from the actual C compilation. `-nostdinc` permits only project headers
and that pinned backend's own sources. Owned `syscall`, `prctl`, `realpath`,
and `abort` providers remove the earlier musl support-object tail. This is
an accepted C dependency, not full target-runtime Rust purity.

`bin/crabc-cc` is an installed, sealed static-driver seed. Its deterministic
`--print-link-plan -static` contract selects `crt1.o` and `ET_EXEC`; its
`--print-link-plan -static-pie` contract selects `rcrt1.o` and `ET_DYN`. Both
plans name only the installed headers, `crti.o`, `crtn.o`, `libc.a`, and
`libcrabc-builtins.a` around explicitly admitted application objects. It
rejects ambient header/CRT/library search, linker injection, libgcc,
compiler-rt, loader, and dynamic-mode flags before translating or linking.
Receipt-bearing links accept only caller-owned object inputs, reserve their
JSON/map/trace sidecars before linking, and reject output aliases of those
sidecars or any installed-tree path. The source translator remains a
fixed-image development-environment tool; it is not a target runtime input.

The private package helper creates a normalized `tar.xz` only from that
manifest-bound regular-file payload. It rejects archive/extraction paths through existing
symlinks, bounds untrusted extraction to 4096 members, 128 MiB per regular
member, and 512 MiB aggregate regular payload, and validates an archive into a
private staging directory before Linux `renameat2(RENAME_NOREPLACE)` atomically
publishes extraction. An invalid archive or competing destination therefore
leaves no partial or replaced output tree.

## Consumer and rejection evidence

`compat/x86_64/run_owned_static_sysroot.sh` first runs the pinned musl 1.2.6
behavior reference. It separately records `-nostdinc -isystem
<installed>/usr/include` dependencies for all five source files, where
only each named source and that installed header tree are admitted. A forged
host-header record must fail. The installed driver then compiles, links, and
executes those objects in each static mode through the same installed-tree
boundary.

The driver's link receipt, map, and trace establish the exact allowlist:
installed `crt1.o` or `rcrt1.o`, `crti.o`, `crtn.o`, `libc.a`,
`libcrabc-builtins.a`, and the three caller-owned consumer objects.
`compat/x86_64/owned_static_sysroot_builtins.c` forces an
undefined `__udivti3`; omitting the installed helper archive must fail at that
symbol, while the successful linker trace must attribute its member to the
owned archive. Forged trace entries for an ambient CRT, pinned-musl libc,
libgcc/compiler runtime, and loader must each fail.

Both executed images preserve the existing `PIMBCAF` preinit/init/main,
selected pthread, LIFO ordinary-exit, and fini observation over initialized,
TBSS, and 4096-byte-aligned Variant-II static TLS. Their ELF images have GNU
RELRO, one non-executable stack segment, exactly one `PT_TLS`, no interpreter
or dynamic dependency, no unresolved symbol, and no dynamic TLS relocation.
The static PIE additionally retains only relative dynamic relocations and no
unrelaxed initial-TLS access. Mutating `PT_TLS.p_filesz` must still fail closed
with status 127. Two normalized packages are byte-identical, and a safely
extracted copy must reproduce the same per-mode output, receipt, map, and
trace evidence.

The static TLS owner explicitly reserves the x86 compiler guard at `%fs:40`,
initializes it from `AT_RANDOM` before preinit, and copies it into each worker.
The consumer checks the pinned musl guard transformation and executes real
compiler-protected code in the initial thread and worker. A child corrupts
only its own guard and must fault through the owned failure handler; core
dumps are disabled for this negative test.

The existing `libc_allocator_basic_runtime_v1_probe.c` also runs through both
installed modes and the extracted package: allocation/reallocation/alignment
and failure behavior, worker teardown, allocation across a joined-worker fork,
and allocation during ordinary exit. It additionally exercises the support
providers' variadic ABI, pathname/symlink, and SIGABRT behavior. The same
sealed link-receipt and reproducibility checks apply. This does not qualify
fork while other threads are allocating or concurrent signal-disposition
mutation; those remain runtime integration obligations.

`owned_static_posix_probe.c` adds environment ownership/mutation, a real
fork/`execve` environment round trip, and pipe/vector-I/O/readiness/descriptor
lifecycle through that same installed archive. It uses ordinary C interfaces,
not fixture-local startup or syscall substitutes. Its musl reference, both
static modes, and extracted copies share the same source. PATH search,
spawn/vfork, concurrent environment mutation, and cancellation are not proved
by this consumer.

`owned_static_stdio_probe.c` exercises the owned descriptor-stream engine in
`owned_static_stdio.rs`: simultaneous dynamic streams, buffered and terminal
output, positioning/pushback, errors, append/cloexec, recursive stream locking
across threads, unlocked byte/block I/O, and bounded formatting/scanning. Both installed
modes and extracted copies must match pinned musl and flush an unclosed
dynamic stream at ordinary exit. The final image must select the strong
`__stdio_exit` hook. Scratch files are private to each consumer run.
Reopen preserves the FILE/buffer identity and tests descriptor replacement and
failure retirement; allocated line input covers growth, embedded NULs, EOF,
and errors. Complete formatting/scanning, wide and memory/cookie streams,
`popen`, cancellation, and fork-lock recovery remain unqualified.

`owned_static_printf_probe.c` additionally covers positional integer/string/
count/pointer/errno/hex-float formatting and FILE, descriptor, allocated, and
caller-buffer destinations. Its 71-record binary matrix must match pinned
musl in both modes and extracted copies; defined invalid-format checks remain
candidate-specific. Each formatting job also links a separately receipted
`owned_static_printf_float_probe.c` binary: 1,920 records compare decimal and
hex binary64/binary80 output, errno, floating exceptions, and all four rounding
modes with pinned musl. It covers spilled/positional arguments and FILE,
descriptor, allocated, and caller-buffer destinations with private scratch.
Wide formatting and complete scanning remain separate completion work.

`x86-owned-static-runtime` is a planned archive profile, routed through this
runner but selected by `scripts/build_x86_64_owned_sysroot.py`. Its direct
header-callable additions are the owned `abort`/`syscall`/`prctl`/`realpath`
support, descriptor-stream lifecycle and lock entries, allocated-line input,
the eight unlocked byte/block entries, and `asprintf`/`dprintf` plus their
`va_list` forms. It replaces the selected default stream and byte-buffer
formatting implementations where `owned_static_stdio.rs` and `owned_printf.rs`
select a different owner; the feature's allocator, environment, exec,
permanent-format, and resolver dependencies retain their own feature-provider
rows. The installed consumer evidence is not a complete callable-provider
archive audit, so this profile remains planned and does not promote a family,
the default export roster, or public x86 support.

The aggregate also selects the existing C-owned resolver runtime. The
`libc_resolver_runtime_probe.c` fixture runs through its sealed installed
ET_EXEC and static-PIE drivers, including per-thread `h_errno`, hosts/search,
CNAME answers, and missing-name behavior. Each fixture reserves a distinct
loopback DNS address and uses a private chroot configuration; the concurrent
isolation check also occupies the former shared endpoint and verifies early
failure reaps the server. This proves no external DNS behavior or full resolver
family closure. Both modes and extracted copies now run in the same bounded
24-job consumer matrix. Cold producer reproducibility remains a separate
mandatory check; serial-versus-parallel timing is opt-in, not extra default work.

## Deliberately unselected

This tree has a deliberately narrow planned static driver and one private
dual-mode package/extracted-smoke seed, but no shared libc, dynamic loader,
compatibility loader alias, dynamic link mode, complete libc archive closure,
complete compiler-helper profile, or complete static-and-dynamic distribution
artifact. The driver has not yet proven the full static product's coverage
suite, including complete allocator lifecycle, pthread, stdio, filesystem, socket, and
resolver obligations. Those remain requirements of the planned families in
`compat/x86_64/parity.toml`. The artifact does not change x86 promotion or
public-support state.
