# Native syscall alias and interposition contract

`run_owned_syscall_alias_contract.sh STATIC_SYSROOT DYNAMIC_SYSROOT` checks the
native x86-64 linkage shape of fourteen musl 1.2.6 syscall-facing C entries.
It is a focused ELF and call-ownership regression, not a new capability,
product qualification, family-completion result, or public x86 support claim.

The source oracle is musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
`src/time/clock_gettime.c`, `clock_nanosleep.c`, `src/unistd/dup3.c`,
`lseek.c`, `src/stat/fstat.c`, `fstatat.c`, `statvfs.c`,
`src/mman/{madvise,mmap,mprotect,munmap}.c`, `src/linux/sysinfo.c`, and
`src/signal/sigaction.c`. The implementation is kept beside the owning native
leaves: `clock_gettime.rs`, `clock_nanosleep.rs`, `descriptor_io.rs`,
`stat_compat.rs`, `filesystem_capacity.rs`, `memory_mapping.rs`,
`system_observation.rs`, and `signal_control.rs`.

Every ordinary spelling below is a `FUNC WEAK DEFAULT` same-definition alias.
The archive body is `FUNC GLOBAL HIDDEN` unless noted; the shared link
localizes it and omits it from `.dynsym`. Pinned musl records `LOCAL DEFAULT`
there, while the Rust link may retain `LOCAL HIDDEN`; the local binding,
dynamic-symbol absence, and identical defining section/value are the stable
boundary. `__statfs` and `__fstatfs` are source-local even in `libc.a`, so
their archive rows are `FUNC LOCAL DEFAULT` and they are not static export
ledger additions.

| Public weak alias | Internal body |
| --- | --- |
| `clock_gettime` | `__clock_gettime` |
| `clock_nanosleep` | `__clock_nanosleep` |
| `dup3` | `__dup3` |
| `fstat` | `__fstat` |
| `fstatat` | `__fstatat` |
| `fstatfs` | `__fstatfs` (local) |
| `lseek` | `__lseek` |
| `madvise` | `__madvise` |
| `mmap` | `__mmap` |
| `mprotect` | `__mprotect` |
| `munmap` | `__munmap` |
| `statfs` | `__statfs` (local) |
| `sysinfo` | `__lsysinfo` |
| `sigaction` | `__sigaction` |

`sigaction.c` also supplies `__libc_sigaction`: it is hidden/global in the
archive and local/non-dynamic in the shared result, with no public alias. Its
outer `__sigaction` body retains validation and selected SIGABRT serialization;
the raw body retains action conversion and the syscall.

The runner first preserves a pinned-musl static and shared reference. It then
links the same C calls through owned static ET_EXEC/static-PIE and owned shared
PIE/non-PIE products, using both kernel and direct-interpreter entry. The
normal probe reaches all fourteen public names. Its strong-override sibling
defines viable Linux implementations for all fourteen public names, so startup
and the selected C allocator can safely use an ordinary spelling before
`main`; counters prove that direct application calls reach those definitions.
It distinguishes source and final-link ownership: legacy `__fxstat`,
`__fxstatat`, `ftime`, `getloadavg`, `sigignore`, and selected `siginterrupt`
calls name public aliases in source and bind to an application override from
the archive, while the shared link's direct local resolution reaches the
defining libc body. Pinned static caller relocations name `fstat`, `fstatat`,
and `clock_gettime`; pinned shared disassembly directly branches to the local
same-address bodies. `statvfs` and `fstatvfs` retain their local statfs bodies;
`sem_timedwait` reaches `__clock_gettime`; `signal` reaches `__sigaction`; and
selected tree search continues through hidden mapping bodies. The reader
rejects a forwarding body that merely shares an archive member and zero
`st_value` with an alias by also requiring the defining section and type.

Run it only in the pinned native image with supplied products below the
checkout's `.work` tree:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" \
  ./compat/x86_64/run_owned_syscall_alias_contract.sh \
  .work/x86_64/syscall-alias-contract/static-product \
  .work/x86_64/syscall-alias-contract/dynamic-product
```

The static C-ABI export ledger remains root-owned. When its next integration
refresh is authorized, this component proposes exactly these new global-hidden
rows: `__clock_gettime`, `__clock_nanosleep`, `__dup3`, `__fstat`,
`__fstatat`, `__lseek`, `__madvise`, `__mmap`, `__mprotect`, `__munmap`,
`__lsysinfo`, `__sigaction`, and `__libc_sigaction`. It proposes no rows for
the two local statfs bodies.
