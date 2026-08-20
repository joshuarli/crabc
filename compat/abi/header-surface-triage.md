# Pinned AArch64 public-header closure

The ABI probe derives its compile-coverage inventory from
`/opt/musl-1.2.6/include` (excluding musl's private `bits/` tree), then
compiles an empty translation unit containing each pinned header and its
candidate counterpart. The 74 pinned-only names found before this closure
pass are triaged below. A `compile_ok` record proves only that the compiler can
consume both headers; it is not a claim of declaration, constant, macro, or
layout parity, and it does not claim that a declaration-only header supplies a
missing libc implementation.

## Added now: public declaration and constant surface (39)

These headers now carry the pinned musl 1.2.6 AArch64 declaration and
constant surface (including necessary private `bits/` type definitions) rather
than an empty compatibility shim. They either have no libc entry point or
forward to an already-public candidate interface. The focused
`header_surface` and `aarch64_network_headers` fixtures compare their highest
risk constants, ioctl encodings, types, and layouts with pinned musl; that is
stronger evidence than the compile-only inventory, but still not a claim that
every declared kernel or protocol operation has runtime coverage.

`alloca.h`, `ar.h`, `byteswap.h`, `elf.h`, `endian.h`, `features.h`,
`lastlog.h`, `memory.h`, `net/ethernet.h`, `net/if_arp.h`,
`netinet/icmp6.h`, `netinet/igmp.h`, `netinet/in_systm.h`, `netinet/ip.h`,
`netinet/ip6.h`, `netinet/ip_icmp.h`, `netinet/udp.h`, `paths.h`,
`stdalign.h`, `stdarg.h`, `stdc-predef.h`, `stddef.h`, `stdnoreturn.h`,
`sys/dir.h`, `sys/errno.h`, `sys/fcntl.h`, `sys/mtio.h`, `sys/param.h`,
`sys/poll.h`, `sys/signal.h`, `sys/stropts.h`, `sys/syscall.h`,
`sys/syslog.h`, `sys/sysmacros.h`, `sys/termios.h`, `sys/ttydefaults.h`,
`sysexits.h`, `values.h`, `wait.h`.

## ABI declarations backed by existing crabc exports (18)

These headers expose entry points already implemented in the candidate
library.  They are separate from the declaration-only group so symbol parity
does not get mistaken for implementation work.

`malloc.h` (`malloc`, `valloc`, `memalign`, `malloc_usable_size`),
`arpa/nameser_compat.h` (the `ns_*` resolver parser functions),
`sys/auxv.h` (`getauxval`), `sys/epoll.h` (`epoll_*`),
`sys/eventfd.h` (`eventfd*`), `sys/file.h` (`flock`),
`sys/inotify.h` (`inotify_*`), `sys/membarrier.h` (`membarrier`),
`sys/personality.h` (`personality`), `sys/prctl.h` (`prctl`),
`sys/random.h` (`getrandom`), `sys/sendfile.h` (`sendfile`),
`sys/signalfd.h` (`signalfd`), `sys/statfs.h` (`statfs`, `fstatfs`),
`sys/timerfd.h` (`timerfd_*`), `sys/vfs.h` (the `sys/statfs.h` view),
`stdio_ext.h` (the `__f*` stream-state functions), and `utime.h` (`utime`).

## Runtime follow-up boundaries (19)

All of these now have candidate declarations. They remain runtime follow-up
records where a declaration is backed by a kernel/protocol behavior not yet
exercised by a focused workload. The probe supplies the native Linux UAPI
include directory for headers that depend on kernel declarations.

| Header(s) | Exact blocker |
| --- | --- |
| `arpa/ftp.h`, `arpa/telnet.h`, `arpa/tftp.h` | Protocol constants/types are checked in the focused header fixtures, but there is no candidate protocol runtime; no function symbols are claimed. |
| `net/route.h` | Route/netlink constants and layouts are header-tested, but route ioctl/netlink semantics have no focused AArch64 workload. |
| `scsi/scsi.h`, `scsi/scsi_ioctl.h`, `scsi/sg.h` | Device ioctl declarations and encodings are header-tested, but no SCSI device runtime is exercised. |
| `sys/cachectl.h` | Declarations are present, but `cachectl`, `cacheflush`, and `_flush_cache` are absent from both archives. |
| `sys/io.h` | Declarations are present, but `iopl`/`ioperm` and architecture-private I/O behavior are absent from both archives. |
| `sys/kd.h`, `sys/soundcard.h`, `sys/vt.h` | The native `/usr/include` Linux UAPI input is supplied to both compiler invocations; focused checks cover the public console constants and ioctl encodings. |
| `sys/procfs.h`, `sys/reg.h`, `sys/user.h` | AArch64 register/core-dump declarations and selected layouts are header-tested, but broader kernel semantics are not runtime-evidenced. |
| `ucontext.h`, `sys/ucontext.h` | Named AArch64 `mcontext_t`/`ucontext_t` declarations and offsets match; neither archive exports `getcontext`, `makecontext`, `setcontext`, or `swapcontext`, and no fake exports are added. |

## Evidence

Run the native probe with its report outside the source tree:

```sh
./scripts/dev.sh abi-probe --probe stat --output /tmp/crabc-aarch64-abi.json
```

The full matrix is the default when `--probe` is omitted.  The generated
report records the pinned/reference header count, candidate counterpart count,
candidate-only headers, every per-header compile status, and header-specific
archive symbol evidence. The closure pass measured 183 pinned headers, 190
candidate headers, 183 `compile_ok` records, zero missing candidate counterparts,
and 7 candidate-only headers.  The report records the required native Linux
UAPI input at `inputs.linux_uapi` (default `/usr/include`) and passes it to
both reference and candidate header compilation; a missing UAPI directory
remains an explicit `missing_input` failure.
