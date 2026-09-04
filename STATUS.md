# Project status

The current implementation program is staged native Linux/x86-64 little-endian
runtime parity, defined by [`x86-64.md`](x86-64.md). It covers `crabc-core`,
`crabc-libc`, `crabc-ldso`, CRT/sysroot artifacts, and `crabc-rs`, beginning
with explicit target-specific foundations and native evidence. Public support
remains Linux/AArch64 little-endian until every x86 promotion gate passes.

Native x86-64 mimalloc implementation and qualification are also active under
[`native-mimalloc.md`](native-mimalloc.md), in parallel with runtime parity.
AArch64 allocator work is paused, with its imported implementation and
exact-revision evidence preserved. [`plan.md`](plan.md) coordinates both
programs; neither program's partial results close the other's gates, and the
accepted C allocator remains default until qualified x86 backend promotion.

The private `libc-rand-r` and `libc-pthread-*` static commands extend only
leaf-level accounting: caller-owned `rand_r` state; condattr pshared/clock;
mutexattr robust/protocol/pshared/type queries and type setting; mutex
priority-ceiling status; pthread concurrency query/set status; and
`pthread_attr_t` record initialization, validation, and metadata queries.
Their artifacts remain in planned `libc.posix-runtime` or
`libc.pthread-tls`; they do not complete pthread/TLS, the C runtime, an owned
sysroot, dynamic runtime, family promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-network-byte-order` is a private
`static-c-network-byte-order` artifact inside planned `libc.posix-runtime`.
Its pinned-musl and true-static candidate fixture selects only `htonl`,
`htons`, `ntohl`, and `ntohs`: fixed-width little-endian 32-bit/16-bit byte
reversal, network-byte output, inverse round trips, and zero/all-one values.
It has no errno, TLS, syscall, allocation, resolver configuration, DNS,
netdb/database, Ethernet/interface, address-codec, or socket-transport path;
it is not resolver/network completion, family promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-in6addr-any` is a private
`static-c-in6addr-any` data-object artifact inside still-planned
`libc.posix-runtime`. Its project-header fixture first executes through pinned
musl 1.2.6 and then through an archive-free `-nostdlib -static` candidate
linked from exactly one extracted object, never `libc.a`. It selects only the
immutable 16-byte all-zero `in6addr_any` object from musl
`src/network/in6addr_any.c`; its separate final-octet-one
`in6addr_loopback.c` sibling is independently selected but excluded from this
candidate. The shared socket-header C/C++ gate also proves musl's union-backed
align-4 `struct in6_addr` layout and unmangled C++ data references. This has no
code, errno, TLS, address conversion, socket transport, `/etc/hosts`,
`/etc/resolv.conf`, resolver/DNS/netdb, interface, or Ethernet behavior; it is
not network completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-in6addr-loopback` is a separate private
`static-c-in6addr-loopback` data-object artifact inside still-planned
`libc.posix-runtime`. Its project-header fixture first executes through pinned
musl 1.2.6 and then through an archive-free `-nostdlib -static` candidate
linked from exactly one extracted object, never `libc.a`. It selects only the
immutable 16-byte fifteen-zero-final-one `in6addr_loopback` object from musl
`src/network/in6addr_loopback.c`; its all-zero `in6addr_any.c` sibling remains
outside this candidate. The shared C/C++ header gate proves the exact const
data declaration and unmangled linkage. This has no code, errno, TLS, address
conversion, socket transport, `/etc/hosts`, `/etc/resolv.conf`, resolver/DNS/
netdb, interface, or Ethernet behavior; it is not network completion,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-inet-ntoa` is a private
`static-c-inet-ntoa-scratch` artifact inside still-planned `libc.resolver`.
Its project-header C fixture first executes through pinned musl 1.2.6 and then
through an archive-free true static candidate: an archive ratchet proves the
export, while the final `-nostdlib -static` link takes only its one extracted
`inet_ntoa` object, never `libc.a`. It preserves musl's single shared static
16-byte dotted-IPv4 buffer, same returned pointer, and next-call overwrite;
the source `snprintf` is equivalently inlined for four bounded decimal octets.
It neither reads nor writes `h_errno` or `errno` and has no h_errno/errno
storage, TLS, numeric netdb, resolver configuration, DNS, `/etc/hosts`,
`/etc/resolv.conf`, conventional network database, interface, socket,
allocation, syscall, stdio, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-inet-classful` is a separate private
`static-c-inet-classful` artifact inside still-planned `libc.resolver`. Its
project-header C fixture first executes through pinned musl 1.2.6 and then
through an archive-free true static candidate: an archive ratchet proves
`inet_makeaddr` and `inet_lnaof`, while the final `-nostdlib -static` link
takes only their one extracted object, never `libc.a`. Pinned musl keeps those
two raw classful IPv4 arithmetic functions beside `inet_network` and
`inet_netof` in `inet_legacy.c`; this slice explicitly leaves both neighbors
and `inet_network`'s `inet_addr` dependency out. It covers the exact
`n < 256`/`n < 65536` construction shifts and the raw `s_addr` <128/<192/else
local-part masks. It has no byte-order helper, `inet_ntoa` storage, h_errno or
errno state, TLS, allocation, syscall, stdio, `/etc/hosts`, `/etc/resolv.conf`,
resolver/DNS, netdb, interface, socket, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-hstrerror` is a private `static-c-hstrerror`
artifact inside still-planned `libc.resolver`. Its project-header C fixture
first executes through pinned musl 1.2.6 and then through a true static
candidate, selecting only musl's immutable `hstrerror` messages and stable
process-static pointers. The selected C/POSIX/C.UTF-8 profiles make
`LCTRANS_CUR` identity-only; the leaf neither reads nor writes `h_errno` or
`errno` and has no h_errno storage, TLS, locale catalogs, allocation, stdio,
or syscall path. It does not inspect `/etc/hosts` or `/etc/resolv.conf`,
configure or send DNS, consult a network database/NSS, touch interfaces or
sockets, complete the resolver family, promote x86, or claim public support.

`./scripts/dev-x86_64.sh libc-h-errno` is a separate private
`static-c-h-errno` status-slot artifact inside still-planned `libc.resolver`.
The paired `h-errno-header-abi` gate compares seven isolated project/musl
`<netdb.h>` C/C++ feature profiles for the accessor macro, `int *` result, and
unmangled C++ linkage. Its pinned-musl and true `-nostdlib -static` fixture
proves only the four-byte link-visible `h_errno` fallback plus
`__h_errno_location`: the bootstrapped main task uses that object and a
selected pthread worker uses one direct initial-TLS slot. Musl normally reaches
worker state through its full TCB; this selected port deliberately proves only
the observed selected-worker semantics, not a general TCB or foreign-thread
contract. It does not complete `process.globals`, resolver behavior, family
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-getsubopt` is a private `static-c-getsubopt`
artifact inside still-planned `libc.text-math-locale-stdio`. It isolates the
already-selected `getsubopt` export into a direct pinned-musl 1.2.6
`src/misc/getsubopt.c` mapping, with a strict/feature-selected project
`<stdlib.h>` C/C++ ABI matrix and a true `-nostdlib -static` differential. The
leaf has only caller-owned mutable input, key vector, cursor, and value slots:
it covers in-place comma splitting, ordered NUL-or-`=` matching, empty
keys/tokens, and interleaved cursors. It writes no errno and owns no TLS,
locale, environment, allocator, stdio, syscall, byte-string dependency, or
parser state. It is not a second capability selection, parser/environment/
locale completion, text/math/locale/stdio family promotion, or public x86
support claim.

`./scripts/dev-x86_64.sh libc-endservent` is a separate private
`static-c-endservent` artifact inside still-planned `libc.c-abi-compat`, not
service-database or resolver behavior. Its pinned-musl/project `<netdb.h>`
C/C++ matrix proves the unconditional no-argument `void endservent(void)`
declaration and unmangled C++ linkage in strict, POSIX, X/Open, and GNU
profiles. The project-header fixture then executes through pinned musl 1.2.6
and an archive-free `-nostdlib -static` candidate linked from exactly one
extracted object, never `libc.a`. It selects only the empty
`src/network/serv.c::endservent` body: direct and function-pointer calls have
no mutable service cursor, errno, h_errno, TLS, allocation, syscall,
`/etc/services`, resolver configuration, DNS, socket, or network-database
path. It does not select `setservent`, `getservent`, service lookup, NSS,
family completion, promotion, or public x86 support.
`./scripts/dev-x86_64.sh libc-dn-skipname` is a private
`static-c-dn-skipname` artifact inside still-planned `libc.resolver`. Its
companion `./scripts/dev-x86_64.sh nameser-header-abi` gate proves the exact
C/C++ `dn_skipname(const unsigned char *, const unsigned char *)` and
`dn_expand(const unsigned char *, const unsigned char *, const unsigned char *, char *, int)`,
`ns_get16(const unsigned char *)`, `ns_get32(const unsigned char *)`, and
`ns_put16(unsigned, unsigned char *)` declarations, plus the eight-byte
align-4 `{ int mask; int shift; }` `_ns_flagdata` record, its `const struct
_ns_flagdata *` array-decay type, and unmangled C++ data reference. It also
proves the `NS_CMPRSFLGS`/name-size constants. The static
fixture then runs through pinned musl 1.2.6 and an archive-free
`-nostdlib -static` candidate linked from exactly one extracted object, never
`libc.a`. It selects only musl `src/network/dn_skipname.c`'s caller-owned
wire-name span walk: root consumption, two-byte disposition for an octet at
least 192 without following its pointer, truncated-span failure, and the
deliberate 64-through-191 label-length behavior. It has no resolver state,
`h_errno`, `errno`, TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS packet
I/O, socket, netdb/database, parser sibling, allocation, syscall, interface,
or Ethernet dependency; it is not resolver completion, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh libc-dn-expand` is a private `static-c-dn-expand`
artifact inside still-planned `libc.resolver`. It uses the shared
`./scripts/dev-x86_64.sh nameser-header-abi` declaration gate, then executes
its project-header C fixture through pinned musl 1.2.6 and an archive-free
`-nostdlib -static` candidate linked from exactly one extracted object, never
`libc.a`. It selects only musl `src/network/dn_expand.c`'s dependency-free
292-byte caller-owned wire-name decoder: hidden global `__dn_expand` and weak
default `dn_expand` remain the same address; roots and labels expand to dotted
text; compressed, noncanonical top-bit, and high-offset pointers follow within
`base..end`; the initial encoded span is returned; usable output caps at 254 bytes; and
truncated, out-of-range, and looping input returns -1. It has no resolver
state, `h_errno`, `errno`, TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS
packet I/O, socket, netdb/database, parser, nameser read/write helper,
allocation, syscall, interface, or Ethernet dependency; it is not resolver
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-ns-flagdata` is a private
`static-c-ns-flagdata` artifact inside still-planned `libc.resolver`. Its
shared `./scripts/dev-x86_64.sh nameser-header-abi` gate proves the exact
C/C++ `_ns_flagdata` data declaration and record layout. Its project-header C
fixture then executes through pinned musl 1.2.6 and an archive-free
`-nostdlib -static` candidate linked from exactly one extracted object, never
`libc.a`. It selects only the global default read-only 128-byte sixteen-record
`_ns_flagdata` section in musl `src/network/ns_parse.c`: the separate
`.rodata._ns_flagdata` section has no relocation despite its co-resident parser
code, the first ten `(mask, shift)` pairs drive `ns_msg_getflag` QR/opcode/AA/
TC/RD/RA/Z/AD/CD/rcode extraction, and the final six records are zero. It has
no parser, resolver state, `h_errno`, `errno`, TLS, `/etc/hosts` or
`/etc/resolv.conf` access, DNS packet I/O, socket, netdb/database, nameser
helper, allocation, syscall, interface, or Ethernet dependency; it is not
resolver completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-ns-get16` is a private `static-c-ns-get16`
artifact inside still-planned `libc.resolver`. The shared
`./scripts/dev-x86_64.sh nameser-header-abi` gate proves the exact C/C++
`ns_get16(const unsigned char *)` declaration and unmangled C++ linkage beside
`dn_skipname`, `dn_expand`, `_ns_flagdata`, `ns_get32`, and `ns_put16`. Its
static fixture then runs through
pinned musl 1.2.6 and an archive-free `-nostdlib -static` candidate linked from
exactly one extracted object, never `libc.a`. It selects only the 11-byte
call-free `ns_get16` text section in musl `src/network/ns_parse.c`: two
caller-owned bytes form an unaligned network-order 16-bit unsigned value,
while `NS_GET16` advances its caller-owned cursor by two. It has no resolver
state, `h_errno`, `errno`, TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS
packet I/O, socket, netdb/database, parser sibling, integer byte-order helper,
allocation, syscall, interface, or Ethernet dependency; it is not resolver
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-ns-get32` is a private `static-c-ns-get32`
artifact inside still-planned `libc.resolver`. The shared
`./scripts/dev-x86_64.sh nameser-header-abi` gate proves the exact C/C++
`ns_get32(const unsigned char *)` declaration and unmangled C++ linkage beside
`dn_skipname`, `dn_expand`, `_ns_flagdata`, `ns_get16`, and `ns_put16`. Its
static fixture then runs through
pinned musl 1.2.6 and an archive-free `-nostdlib -static` candidate linked from
exactly one extracted object, never `libc.a`. It selects only the seven-byte
call-free `ns_get32` text section in musl `src/network/ns_parse.c`: four
caller-owned bytes form an unaligned network-order 32-bit value widened to
LP64 C `unsigned long`, while `NS_GET32` advances its caller-owned cursor by
four. It has no resolver state, `h_errno`, `errno`, TLS, `/etc/hosts` or
`/etc/resolv.conf` access, DNS packet I/O, socket, netdb/database, parser
sibling, integer byte-order helper, allocation, syscall, interface, or
Ethernet dependency; it is not resolver completion, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-ns-put16` is a private `static-c-ns-put16`
artifact inside still-planned `libc.resolver`. The shared
`./scripts/dev-x86_64.sh nameser-header-abi` gate proves the exact C/C++
`ns_put16(unsigned, unsigned char *)` declaration and unmangled C++ linkage
beside `dn_skipname`, `dn_expand`, `_ns_flagdata`, `ns_get16`, and `ns_get32`.
Its static fixture then runs
through pinned musl 1.2.6 and an archive-free `-nostdlib -static` candidate
linked from exactly one extracted object, never `libc.a`. It selects only the
10-byte call-free `ns_put16` text section in musl `src/network/ns_parse.c`: C
`unsigned`'s low 16 bits become two unaligned caller-owned network-order bytes,
while `NS_PUT16` advances its caller-owned cursor by two. It has no resolver
state, `h_errno`, `errno`, TLS, `/etc/hosts` or `/etc/resolv.conf` access, DNS
packet I/O, socket, netdb/database, parser sibling, integer byte-order helper,
allocation, syscall, interface, or Ethernet dependency; it is not resolver
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-l64a` is a private `static-c-l64a` artifact
inside still-planned `libc.c-abi-compat`. It isolates only the `l64a` half of
pinned musl 1.2.6 `src/misc/a64l.c`: a one-symbol true `-nostdlib -static`
candidate proves low-32-bit, low-to-high radix-64 encoding into the shared
seven-byte result, the same returned address, and overwrite by a later call.
Callers must synchronize concurrent result access and copy the result before a
later call; the shared-source decoder remains absent from that encoder
artifact.

`./scripts/dev-x86_64.sh libc-login-name` is a private
`static-c-login-name` artifact inside planned `libc.posix-runtime`. Its
pinned-musl and freestanding-static routes compose the selected bounded
environment owner with exactly `getlogin` and `getlogin_r`. The first
`LOGNAME` entry supplies a borrowed `getlogin` pointer, including
caller-owned `putenv` aliasing and later mutation; `getlogin_r` returns direct
`ENXIO` when absent, returns direct `ERANGE` without a write when the complete
value does not fit, and otherwise copies the value plus NUL, including an
empty value. Both forms preserve incoming `errno`. The leaf owns no storage,
allocator, lock, passwd/utmp parser, terminal/session lookup, credential or
secure-execution policy. Caller-coordinated environment writers, direct
`environ` assignment, and caller-owned string lifetime remain required. It
does not select process creation, exec/spawn inheritance, supervision,
family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-ctermid` is a separate private
`static-c-ctermid` artifact inside still-planned `libc.posix-runtime`. Its
pinned-musl/project-header C/C++ gate proves that `<stdio.h>` exposes
`char *ctermid(char *)` and `L_ctermid == 20` only in POSIX/XSI-style profiles,
with unmangled C++ linkage and strict-mode hiding. Its pinned-musl and
freestanding-static routes then select only the fixed `/dev/tty` spelling:
the null form returns a borrowed immutable literal, while a caller-owned
`L_ctermid` buffer receives its nine bytes including NUL and retains its
remaining tail. The leaf opens no pathname and has no syscall, terminal,
errno/TLS, allocation, string-helper, or authority boundary. It does not
select terminal policy, PTY/session/termios/tty discovery, getpass, generic
filesystem behavior, temporary-file families, filesystem handles, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-grantpt` is a separate private
`static-c-grantpt` artifact inside still-planned `libc.posix-runtime`. Its
pinned-musl/project-header C/C++ gate proves the exact X/Open/GNU/BSD
`int grantpt(int)` declaration, strict/POSIX hiding, and unmangled C++
linkage. Its pinned-musl and freestanding-static routes then prove only musl's
legacy zero-return compatibility wrapper for `-1`, `INT32_MIN`, `0`, and
`INT32_MAX`, with stale errno unchanged in the musl route. The candidate does
not inspect the descriptor, access errno/TLS, allocate, call helpers, or issue
a syscall. It does not select PTY allocation/grant/unlock/naming, descriptor
authority, terminal discovery or session policy, `posix_openpt`, `unlockpt`,
`ptsname`/`ptsname_r`, openpty/forkpty/login_tty/vhangup, generic ioctl,
family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-unlockpt` is a separate private
`static-c-unlockpt` artifact inside still-planned `libc.posix-runtime`. Its
pinned-musl/project-header C/C++ gate proves the exact X/Open/GNU/BSD
`int unlockpt(int)` declaration, strict/POSIX hiding, and unmangled C++
linkage. Its pinned-musl and freestanding-static routes then prove only musl's
fixed `TIOCSPTLCK=0x40045431` bridge: `EBADF` and non-PTY `ENOTTY` become `-1`
with errno, while a call on one fresh raw-opened devpts master succeeds with
stale errno preserved and permits fixture-only peer observation. The wrapper
owns one private zero `int`, the fixed ioctl request, and existing errno
translation; it adds no generic ioctl API, PTY opening/grant/naming, descriptor
ownership, terminal discovery, termios state, or terminal/session/process
policy. `posix_openpt`, `grantpt`, `ptsname`/`ptsname_r`,
openpty/forkpty/login_tty/vhangup, family completion, promotion, and public x86
support remain excluded.

`./scripts/dev-x86_64.sh libc-gethostid` is a private `static-c-gethostid`
artifact inside still-planned `libc.c-abi-compat`. Its pinned-musl/project
X/Open C/C++ header gate proves `long gethostid(void)` visibility only under
X/Open, GNU, and BSD selection, strict/POSIX hiding, and unmangled C++
linkage. Its equivalent pinned-musl and freestanding-static routes prove the
exact zero `long` result with no TLS/errno, syscall, allocation, hostname,
domain-name, configuration-file, namespace, or authority path. It does not
select host identity policy, secure-execution policy, the broad
`system.kernel-admin` capability, family completion, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-issetugid` is a separate private
`static-c-issetugid` artifact inside still-planned `libc.c-abi-compat`. Its
pinned-musl/project GNU/BSD-only C/C++ `<unistd.h>` gate proves
`int issetugid(void)`, strict/POSIX/X/Open hiding, and unmangled linkage.
Musl's `src/misc/issetugid.c` returns `libc.secure`; the x86 archive reads only
the immutable initial-startup cache selected from final
AT_SECURE/UID/EUID/GID/EGID records. Its ordinary pinned-musl and three
freestanding-static routes prove ordinary zero plus bounded fixture-only
final-AT_SECURE and UID/EUID-mismatch one results with errno preserved. It
does not select credential mutation or policy, environment/raw-auxv or
`secure_getenv` APIs, loader policy, process.globals, family completion,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh legacy-misc-header-abi` and
`./scripts/dev-x86_64.sh libc-legacy-misc` now evidence the exact frozen
eight-symbol `legacy.misc` capability as a selected-private slice inside the
still-planned `libc.c-abi-compat` family. The unfeatured selected-static
archive remains frozen: its existing system-information and `issetugid`
owners retain `get_avphys_pages`, `get_nprocs`, `get_nprocs_conf`,
`get_phys_pages`, and `issetugid`; only the dependency-free opt-in
`x86-legacy-misc` owner adds `fmtmsg`, `setkey`, and `encrypt`. The C/C++
matrix proves the strict/POSIX, X/Open, and GNU/BSD declaration partition, and
the static aggregate proves bounded musl-derived `MSGVERB`/stderr/console/error
`fmtmsg` behavior plus archive and ELF closure. `setkey` and `encrypt` are
only inert link-compatible ABI names: they neither dereference nor mutate
caller storage and select no DES, cipher, PRNG, crypto service, default export,
legacy runtime, family promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-gettid` is a private `static-c-gettid` artifact
inside still-planned `libc.c-abi-compat`. Its focused GNU-only `<unistd.h>`
C/C++ matrix proves the four-byte `pid_t gettid(void)` declaration,
strict/POSIX/X/Open/BSD hiding, and unmangled linkage. Pinned musl 1.2.6 reads
the current TCB's tid; this one-symbol static candidate deliberately has no
TCB and compares its direct `gettid=186` syscall result with the equivalent
pinned-musl current-task result. It selects no process identity/session
aggregate, scheduler behavior, pthread/TLS lifecycle, errno, process.globals,
family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-posix-close` is a separate private
`static-c-posix-close` artifact inside still-planned `libc.c-abi-compat`. Its
pinned-musl/project C/C++ `<unistd.h>` matrix proves unconditional
`int posix_close(int, int)` visibility and unmangled linkage under strict,
POSIX, X/Open, and GNU profiles. Musl 1.2.6 ignores the flags word and
delegates to close; the isolated true-static adapter retains only direct
`close=3`, no-retry `EINTR` success, stale-errno preservation, and invalid-fd
`EBADF` behavior through direct and function-pointer calls. It does not select
`close`, generic descriptor I/O, descriptor lifetime or ownership policy,
cancellation/AIO coordination, filesystem policy, family completion,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-endhostent` is a separate private
`static-c-endhostent` artifact inside still-planned `libc.c-abi-compat`. Its
pinned-musl/project `<netdb.h>` C/C++ matrix proves unconditional
`void endhostent(void)` and `void endnetent(void)` declarations under strict,
POSIX, X/Open, and GNU profiles, with exact no-argument function-pointer
types and unmangled C++ linkage. Pinned musl 1.2.6 `src/network/ent.c` makes
`endhostent` a no-op and emits `endnetent` as its weak same-address alias; the
true-static fixture proves direct and function-pointer calls plus that exact
strong/weak address identity. It selects no host/network enumeration, legacy
database state, `/etc/hosts` or `/etc/networks` files, NSS, resolver behavior,
errno/TLS, allocation, syscall, family completion, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-isatty` is a separate private `static-c-isatty`
artifact inside still-planned `libc.posix-runtime`. Its strict/POSIX/X/Open/GNU/
BSD C/C++ declaration gate and pinned-musl/static C fixture select only
`isatty(int)` descriptor observation: musl's fixed `ioctl=16`/
`TIOCGWINSZ=0x5413` private winsize scratch and `syscall(...) + 1` conversion,
tty success with preserved errno, invalid-fd `EBADF`, and `/dev/null` `ENOTTY`.
The raw devpts setup is fixture-only. It neither opens nor names a terminal and
does not select terminal discovery, termios mutation/control, PTY/session
policy, `ttyname`, `getpass`, generic ioctl, family completion, promotion, or
public x86 support.

`./scripts/dev-x86_64.sh libc-ttyname-r` is a separate private
`static-c-ttyname-r` artifact inside still-planned `libc.posix-runtime`. Its
strict/POSIX/X/Open/GNU/BSD C/C++ declaration gate and pinned-musl/static C
fixture select only caller-buffered `int ttyname_r(int, char *, size_t)`:
musl's existing `isatty` observation, fixed private `/proc/self/fd/<fd>`
spelling, zero-capacity private readlink scratch, fitting NUL termination, and
private `stat`/`fstat` device/inode equality. The fixture proves one devpts
name, preserved errno on success and bounded `ERANGE`, plus direct `EFAULT`,
`EBADF`, and `ENOTTY`. It does not select `ttyname` static storage, generic
readlink/stat/fstat or filesystem-path behavior, terminal/session policy,
generic ioctl, family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-legacy-memory` is a separate private
`static-c-legacy-memory` artifact inside still-planned `libc.posix-runtime`.
Its pinned-musl/project-header C fixture selects only the historical
`bcopy`/`bzero` adapters: `bcopy(source, destination, length)` forwards to
overlap-safe `memmove(destination, source, length)`, while
`bzero(destination, length)` forwards to `memset(destination, 0, length)`.
The true `-nostdlib -static` candidate extracts only that adapter object and
the already selected bulk-memory object, ratchets the direct
`memmove`/`memset` closure, and proves zero-length plus bounded overlapping
copy and caller-buffer clearing. It has no errno/TLS, allocator, locale,
syscall, dynamic-runtime, CRT, loader, or sysroot path. It does not promote
Rust-subsumed `memory.bytes-basic`, general C memory behavior,
`mempcpy`/`explicit_bzero`, allocator lifecycle/interposition, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-memccpy` is a separate private
`static-c-memccpy` artifact inside still-planned `libc.posix-runtime`. Its
dedicated project-header/pinned-musl C/C++ gate proves XOPEN/GNU/BSD visibility,
strict/POSIX hiding, the exact unmangled `memccpy` signature, and header
provenance. Its pinned-musl and true `-nostdlib -static` routes then extract
exactly one `memccpy` object with no runtime dependencies and prove
copy-through-first-target behavior across source/destination alignments,
length boundaries, and narrowed signed/wide `int c` values. It has no
errno/TLS, allocator, locale, syscall, dynamic-runtime, CRT, loader, or
sysroot path. It does not promote Rust-subsumed `memory.bytes-basic`, general
bulk-memory behavior, `mempcpy`/`explicit_bzero`, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-tcgetpgrp` is a separate private
`static-c-tcgetpgrp` artifact inside still-planned `libc.posix-runtime`. Its
strict/POSIX/X/Open/GNU/BSD C/C++ declaration gate and pinned-musl/static C
fixture select only `pid_t tcgetpgrp(int)` foreground-group observation:
musl's fixed `ioctl=16`/`TIOCGPGRP=0x540f` private int scratch, a successful
foreground pid with preserved errno, invalid-fd `EBADF`, and `/dev/null`
`ENOTTY`. A child-only raw devpts `fork`/`setsid`/`TIOCSCTTY` setup merely
establishes the kernel test precondition; it is not an archive API or
session/process-control policy. The leaf excludes terminal discovery, termios
mutation/control, PTY/session policy, `tcsetpgrp`, `tcgetsid`, `ttyname`,
`getpass`, generic ioctl, family completion, promotion, and public x86 support.

`./scripts/dev-x86_64.sh libc-tcsetpgrp` is a separate private
`static-c-tcsetpgrp` artifact inside still-planned `libc.posix-runtime`. Its
strict/POSIX/X/Open/GNU/BSD C/C++ declaration gate and pinned-musl/static C
fixture select only `int tcsetpgrp(int, pid_t)` foreground-group assignment:
musl's fixed `ioctl=16`/`TIOCSPGRP=0x5410` private `int` copy, successful
assignment of one distinct in-session group with preserved errno, invalid-fd
`EBADF`, and `/dev/null` `ENOTTY`. A child-only raw devpts
`fork`/`setsid`/`TIOCSCTTY`/`setpgid` transition supplies the controlling
terminal and target group only; raw `TIOCGPGRP` is a fixture postcondition,
not an archive observation API. The leaf neither creates a session nor chooses
a group, changes process membership, or establishes a controlling terminal.
It excludes terminal discovery, termios mutation/control, PTY/session policy,
`tcgetpgrp`, `tcgetsid`, `ttyname`, `getpass`, generic ioctl, family
completion, promotion, and public x86 support.

`./scripts/dev-x86_64.sh libc-mempcpy` is a separate private
`static-c-mempcpy` adapter inside still-planned `libc.posix-runtime`. Its
dedicated project-header/pinned-musl C/C++ gate proves GNU-only visibility,
default/strict/POSIX/XOPEN/BSD C hiding, the exact unmangled `mempcpy` signature, and
header provenance. Its pinned-musl and true `-nostdlib -static` routes extract
exactly one `mempcpy` adapter together with the established `memcpy` owner,
ratchet that one direct relocation, and prove returned destination-plus-length
pointers and exact copied/untouched bytes across source/destination residues
and length boundaries including zero. It has no errno/TLS, allocator, locale,
syscall, dynamic-runtime, CRT, loader, or sysroot path beyond that preselected
bulk-memory owner. It does not promote Rust-subsumed `memory.bytes-basic`,
general bulk-memory behavior, `memccpy`/`explicit_bzero`, allocator
lifecycle/interposition, family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-strsep` is a separate private
`static-c-strsep` artifact inside still-planned `libc.posix-runtime`. Its
dedicated project-header/pinned-musl C/C++ gate proves GNU/BSD visibility,
default/strict/POSIX/XOPEN C hiding, the exact unmangled
`char *strsep(char **, const char *)` signature, and header provenance. Its
pinned-musl and true `-nostdlib -static` routes extract exactly one `strsep`
object with no undefined closure. They prove caller-buffer and `char **` state
mutation across leading/consecutive/trailing delimiters, multi-byte delimiter
sets, empty/no-match terminal clearing, and high-bit delimiter bytes. The leaf
has no errno/TLS, allocator, locale, syscall, dynamic-runtime, CRT, loader, or
sysroot path. It does not promote Rust-subsumed `memory.bytes-basic`, general
string/tokenization, `strtok`/`strtok_r`, memory-search, `mempcpy`, getsubopt,
allocator lifecycle/interposition, family completion, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-strtok` is a separate private
`static-c-strtok` artifact inside still-planned `libc.posix-runtime`. Its
project-first/pinned-musl C/C++ `<string.h>` gate proves the unconditional
unmangled `char *(char *, const char *)` ABI under strict, POSIX, X/Open, GNU,
and BSD selectors. Its pinned-musl and true `-nostdlib -static` routes extract
one `strtok` object from musl `src/string/strtok.c`, with no undefined closure.
They prove leading-delimiter skipping, in-place NUL splitting, empty input and
empty delimiter behavior, high-bit delimiters, replacement of a previous
continuation by new input, and musl's one shared non-TLS cursor across
interleaved sequences. That cursor is intentionally historical and
non-thread-safe: concurrent unsynchronized calls are outside the C contract.
The leaf has no errno/TLS, allocator, locale, syscall, dynamic-runtime, CRT,
loader, or sysroot path. It does not select `strtok_r`, general
string/tokenization or thread-safe text behavior, `memory.bytes-basic`, family
completion, promotion, or public x86 support; the generic AArch64 export is
unchanged.

`./scripts/dev-x86_64.sh libc-posix-spawnattr-init` is a separate private
`static-c-posix-spawnattr-init` artifact inside still-planned
`libc.posix-runtime`, not a process-spawn or process-control capability. Its
pinned-musl/project C/C++ `<spawn.h>` gate proves the unconditional
`int posix_spawnattr_init(posix_spawnattr_t *)` ABI, unmangled C++ linkage,
and the x86 336-byte/eight-byte-aligned record layout. The shared fixture first
executes musl 1.2.6 `src/process/posix_spawnattr_init.c`, then a true
`-nostdlib -static` candidate extracted from exactly one Rust object. It proves
that direct and function-pointer calls fully zero byte-filled caller-owned
records, preserve adjacent guards, and leave stale `errno` unchanged on the
ordinary musl route. The candidate is a fixed 42-word direct-store loop with
no undefined helper, call, syscall, errno/TLS, allocator, dynamic runtime,
CRT, loader, or sysroot path. It does not select `posix_spawn`/`posix_spawnp`,
other attribute APIs, file actions, fork/vfork/clone, exec, child lifecycle,
signals, scheduler policy, family completion, promotion, or public x86
support; the generic AArch64 export remains unchanged.

`./scripts/dev-x86_64.sh posix-spawn-file-actions-header-abi` and
`./scripts/dev-x86_64.sh libc-posix-spawn-file-actions` record a separate
private `static-c-posix-spawn-file-actions` artifact inside still-planned
`libc.posix-runtime`. The six opt-in adding/destruction names use musl's
80-byte caller record and 40-byte fdop allocation/list representation; the
default static archive continues to own only initialization. The native
candidate deliberately has a mixed static closure: it selects the action
provider, initializer, allocator wrapper, errno owner, and bundled mimalloc
backend, while pinned musl supplies remaining startup/process/syscall
prerequisites and the link map rejects musl action/allocator objects. It
proves action-list construction and destruction only, including positive
EBADF/ENOMEM results and the dangling-head reinitialization rule. It does not
execute a spawn action or select posix_spawn/posix_spawnp, fork/vfork/clone,
exec, attributes, allocator completion, default-archive change, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh process-exec-header-abi` and
`./scripts/dev-x86_64.sh libc-process-exec` record the private opt-in
`static-c-process-exec` slice in still-planned `libc.posix-runtime`. It adds
only `execl`, `execle`, `execlp`, `execv`, `execve`, `execvp`, `execvpe`, and
`fexecve`; direct `execveat=322`/`AT_EMPTY_PATH` fexecve intentionally has no
procfd fallback, so seccomp `ENOSYS` remains visible. The slice retains musl
PATH/EACCES/ENOEXEC and finite vararg semantics, with strong `__execvpe` and
weak same-address `execvpe`, while leaving the default archive, broad
`process.control`, family promotion, and public x86 support unchanged.
The PATH forms inherit default `environment.rs`, including its 1,048,576-entry
`getenv` lookup and bounded mutation semantics; ordinary valid finite
environment forwarding is selected, while unrestricted musl environment parity
is not claimed.

`./scripts/dev-x86_64.sh libc-posix-spawnattr-getpgroup` is a separate private
`static-c-posix-spawnattr-getpgroup` artifact inside still-planned
`libc.posix-runtime`, not a process-spawn or process-control capability. Its
pinned-musl/project C/C++ `<spawn.h>` gate proves the unconditional
`int posix_spawnattr_getpgroup(const posix_spawnattr_t *, pid_t *)` ABI,
unmangled C++ linkage, signed four-byte `pid_t` output, and the x86
offset-four `__pgrp` member. The shared fixture first executes musl 1.2.6
`src/process/posix_spawnattr_getpgroup.c`, then a true `-nostdlib -static`
candidate extracted from exactly one Rust object. It proves direct and
function-pointer positive/negative process-group readback from byte-filled
336-byte caller records, byte-exact input preservation, intact input/output
guards, and stale `errno` preservation on the ordinary musl route. The
candidate has only a fixed offset-four load and output-word store, with no
undefined helper, call, syscall, errno/TLS, allocator, dynamic runtime, CRT,
loader, or sysroot path. It does not select `posix_spawn`/`posix_spawnp`, other
attribute APIs, file actions, fork/vfork/clone, exec, child lifecycle, signals,
scheduler policy, family completion, promotion, or public x86 support; the
generic AArch64 export remains unchanged.

`./scripts/dev-x86_64.sh libc-posix-spawnattr-getschedpolicy` is a separate
private `static-c-posix-spawnattr-getschedpolicy` artifact inside still-planned
`libc.posix-runtime`, not a process-spawn, process-control, or scheduler
capability. Its pinned-musl/project C/C++ `<spawn.h>` gate proves the
unconditional `int posix_spawnattr_getschedpolicy(const posix_spawnattr_t *,
int *)` ABI, unmangled C++ linkage, and the complete x86 336-byte/eight-byte-
aligned attribute type. Musl 1.2.6 `src/process/posix_spawnattr_sched.c`
returns the positive error number `ENOSYS=38` directly: it does not dereference
either pointer or set `errno`. The shared fixture first executes that musl
route, then a true `-nostdlib -static` candidate extracted from exactly one
Rust object. Direct and function-pointer calls cover nonnull, null-attribute,
null-output, and both-null arguments; they retain byte-filled caller records,
guarded output storage, and stale `errno`. The candidate is only an immediate
ENOSYS return with no helper, call, syscall, errno/TLS, allocator, dynamic
runtime, CRT, loader, or sysroot path. It does not select `posix_spawn`/
`posix_spawnp`, other attribute APIs, file actions, fork/vfork/clone, exec,
child lifecycle, signals, scheduler policy/parameter behavior, family
completion, promotion, or public x86 support; the generic AArch64 export
remains unchanged.

`./scripts/dev-x86_64.sh libc-bsearch` is a separate private `static-c-bsearch`
artifact inside still-planned `libc.c-abi-compat`. Its pinned-musl/project
C/C++ `<stdlib.h>` matrix proves the unconditional five-argument declaration
from strict through BSD selection and unmangled C++ linkage. Equivalent
pinned-musl and freestanding-static routes then prove direct/function-pointer
calls, first/last/miss results, musl's duplicate midpoint pointer, a wide
record, and zero-count callback suppression. The selected candidate contains
`bsearch` without qsort/qsort_r/__qsort_r, TLS/errno, allocation, locale,
syscall, or mutable runtime state. It does not change qsort/qsort_r behavior,
select general sorting/searching or callback ownership, family completion,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-linear-search` is a separate private
`static-c-linear-search` artifact inside still-planned `libc.c-abi-compat`.
Its pinned-musl/project C/C++ `<search.h>` matrix proves unconditional exact
five-argument `lfind` and `lsearch` declarations from strict through BSD
selection and unmangled C++ linkage. Equivalent pinned-musl and
freestanding-static routes then prove direct/function-pointer callbacks,
first-match duplicate and miss lookup without count mutation, an existing
`lsearch` hit, a non-int-stride miss copy/count increment, and zero-count
callback suppression. The selected candidate contains only `lfind`/`lsearch`
from this boundary without bsearch/qsort/qsort_r, search containers, byte-copy
helpers, TLS/errno, allocation, locale, syscall, or mutable runtime state. It
does not select general sorting/searching or callback ownership, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-intrusive-queue` is a separate private
`static-c-intrusive-queue` artifact inside still-planned `libc.c-abi-compat`.
Its pinned-musl/project C/C++ `<search.h>` matrix proves unconditional exact
`insque(void *, void *)` and `remque(void *)` declarations from strict through
BSD selection and unmangled C++ linkage. Equivalent pinned-musl and
freestanding-static routes prove caller-owned two-link null-predecessor reset
without stale-neighbor writes, successor splice, payload preservation,
middle-node neighbor repair, and `remque` retaining removed-node links. The
candidate contains only `insque`/`remque`, without bsearch/lfind/lsearch/qsort,
tree/hash helpers, TLS/errno, allocation, callbacks, locale, syscall, or
mutable runtime state. It does not select general search/tree/list/container
behavior, alter `search.tree-intrusive`, select family completion, promotion,
or public x86 support.

`./scripts/dev-x86_64.sh libc-qsort` is a separate private `static-c-qsort`
artifact inside still-planned `libc.c-abi-compat`. Its pinned-musl/project
C/C++ `<stdlib.h>` matrix proves the unconditional four-argument declaration
from strict through BSD selection and unmangled C++ linkage. Equivalent
pinned-musl and freestanding-static routes then prove direct/function-pointer
comparator calls, duplicate-key sorting, record permutation, a 308-byte
cycling-buffer record, and zero-count callback suppression. The selected
candidate contains `qsort` and its private smoothsort worker without bsearch,
`__qsort_r`/qsort_r, TLS/errno, allocation, locale, syscall, or mutable
runtime state. It preserves the separate qsort_r ABI and does not select
general sorting/searching or callback ownership, family completion, promotion,
or public x86 support.

`./scripts/dev-x86_64.sh libc-getpass` is a separate private
`static-c-getpass` artifact inside still-planned `libc.posix-runtime`. Its
pinned-musl and freestanding-static routes select only the historical C
`getpass` `/dev/tty` input sequence: GNU/BSD declaration visibility, direct
no-controlling-terminal `ENXIO`, canonical no-echo/no-signal `TCSAFLUSH`
input, private fixed drain, prompt/newline output, one 128-byte static result
buffer with 127-byte truncation, and terminal restoration. The devpts setup is
fixture-only; this does not select a C PTY/session API, generic ioctl,
account/session identity, Rust password API, cancellation, secret-memory
erasure, terminal policy, family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-mktemp` is a separate private `static-c-mktemp`
artifact inside still-planned `libc.posix-runtime`. Its GNU/BSD header gate and
pinned-musl/static C fixture cover only a mutable trailing-`XXXXXX` historical
pathname selection: musl's realtime/TID six-byte alphabet, absent-name
`ENOENT`, invalid-template `EINVAL` clearing, and non-missing lookup-error
clearing. It never creates, opens, reserves, or returns authority for the
selected pathname, so it remains inherently racy and is not a Rust temporary
API. It remains a component artifact rather than capability selection by
itself; `mkstemp`/`mkdtemp` forms, `tmpfile`, entropy/crypto policy, generic
filesystem policy, family completion, promotion, and public x86 support remain
outside that leaf.

`./scripts/dev-x86_64.sh file-handles-header-abi` and
`./scripts/dev-x86_64.sh libc-file-handles` record one separate private
`static-c-file-handles` artifact inside still-planned `libc.posix-runtime`.
The GNU C/C++ header gate fixes the 8-byte align-4 variable-tail
`struct file_handle` declaration, while the opt-in `x86-file-handles` static
candidate adds exactly `name_to_handle_at` and `open_by_handle_at` without
changing the frozen default archive. The pinned-musl differential proves the
Linux 5.10 x86 syscall 303/304 boundary, including r10/r8 transfer and
caller-owned pointer/error behavior; filesystem support, mount selection, and
permission results remain kernel authority. It does not allocate or retain
handles, provide a Rust file-handle API or confinement policy, complete the
filesystem family, promote x86, or establish public x86 support.

`./scripts/dev-x86_64.sh temporary-names-header-abi`,
`./scripts/dev-x86_64.sh libc-temporary-names`, and
`./scripts/dev-x86_64.sh libc-filesystem-extensions` compose the frozen
five-spelling `filesystem.extensions` roster: the default-static `mktemp`,
the opt-in `x86-file-handles` `name_to_handle_at`/`open_by_handle_at` pair,
and the opt-in `x86-temporary-names` `tmpnam`/`tempnam` pair over the existing
allocator string-duplication client. The temporary-name header and runtime
gates preserve musl's 20-byte caller/global `tmpnam` storage and
allocator-owned `tempnam` result, including their current-absence probes; they
do not create, reserve, open, or unlink a pathname and remain inherently racy.
The shared suffix helper deliberately uses raw Linux `clock_gettime=228` and
`gettid=186`; a seccomp denial of either takes the target-local fail-closed
route: `tmpnam`/`tempnam` return `NULL` and publish that errno, while `mktemp`
clears its supplied template. Musl may instead succeed through its VDSO-first
clock/TCB path, so this exception is not claimed as musl parity.
The aggregate therefore records `filesystem.extensions` as
`selected-private`, not as a secure temporary-object policy, file-handle
facade, Rust API, family completion, product transition, promotion, or public
x86 support. `libc.posix-runtime` remains planned and nonpublic; all
`mkstemp`/`mkdtemp` forms, `tmpfile`, general pathname/mount/confinement
policy, and a generic filesystem runtime remain separately unselected.

The x86 qualification lane has one bounded same-object static
`memfd_create`/errno differential and one consumed five-transaction POSIX/ABI
admission inventory covering the selected process-context, process-signal,
child-reaping, and pthread/TLS aggregate candidates. These are real native
selected-artifact executions, but both owning compatibility families remain
planned: ABI inventory/symbol closure, the dynamic canonical
OS/libc/pthread/signal suites, their runtime/sysroot prerequisites, and all
other promotion gates are still required.

Within still-planned `libc.text-math-locale-stdio`, the selected-private
`stdio.fopen64-alias` capability is source-only on x86: pinned musl 1.2.6
exposes `fopen64` under `_LARGEFILE64_SOURCE` solely as `#define fopen64
fopen`, with no separate x86 ELF symbol. The C/C++ profile proof
(`./scripts/dev-x86_64.sh fopen64-header-abi`) and freestanding static
candidate proof (`./scripts/dev-x86_64.sh libc-fopen64-alias`) retain that
macro contract while using the existing bounded `fopen` route. They do not
complete `stdio.path-stream`, general stdio, family completion, promotion, or
public x86 support.

Within still-planned `libc.text-math-locale-stdio`, the separate private
`./scripts/dev-x86_64.sh libc-stdio-format-scan` artifact selects only
allocation-free C-locale byte-buffer `snprintf`/`vsnprintf`/`sprintf`/
`vsprintf` and NUL-string `sscanf`/`vsscanf`. Its pinned-musl and true static
candidate fixture proves selected integer/byte-string format and scan grammar,
C99 would-have-written/truncation/NUL/zero-capacity and `EOVERFLOW` behavior,
output and input count stores, integer-prefix admission, and x86 native
`va_list` forwarding.
The sibling `./scripts/dev-x86_64.sh libc-stdio-errno-output` gate proves only
bare GNU/musl `%m`: it reads the existing initial-exec errno slot without
consuming a variadic argument, then formats the already selected immutable
fixed-C-locale error message with bounded string width/precision behavior.
It neither calls public `strerror` nor selects diagnostics, locale translation,
or a broader formatter grammar; `%lm` and positional `%1$m` remain rejected.
`FILE` streams, `printf`/`fprintf`/`scanf`/`fscanf`, decimal/long-double/
wide/scanset/positional/pointer-valued `%p` conversion, allocation, locale objects, all
integer scanner overflow apart from the separate bounded source profiles below,
general stdio, family/platform parity, promotion, and public x86 support remain
excluded.

The separate private `./scripts/dev-x86_64.sh libc-stdio-integer-scan`
artifact adds no export or capability. It fixes evidence to narrow
NUL-terminated byte literals and `%d`/`%i`/`%u`/`%x` scan forms (using `%llu`
only to prove the ULLONG_MAX boundary), then compares pinned musl 1.2.6 with a
true `-nostdlib -static` candidate. It records only the musl
`vfscanf`/`intscan` source-overflow path: 20-digit decimal or 17-digit
hexadecimal input beyond ULLONG_MAX consumes the full source run, sets ERANGE,
saturates, clears a leading minus, and reaches the existing ordinary target
store; `vsscanf` forwarding is included. This is not a portable ISO C
target-overflow, float/wide/scanset/positional/FILE, byte-formatting, general
scanner, general stdio, family-completion, promotion, or public-x86 claim.

The separate private `./scripts/dev-x86_64.sh libc-stdio-octal-hex-scan`
artifact adds no export or capability. It limits a pinned-musl 1.2.6 versus
true `-nostdlib -static` differential to six fixed C-locale narrow byte-string
cases and only `%o`/`%X` (using `%llo`/`%llX` solely for exact ULLONG_MAX).
Its independent C11/C++17 header gate checks only the existing
`sscanf`/`vsscanf` signatures and unmangled C++ C spellings.
Its 22-digit octal and 17-digit uppercase-hex source-overflow witnesses prove
the power-of-two `intscan` path consumes the complete digit run through a
literal or `%22o`/`%17X` boundary, sets ERANGE, saturates, clears a leading
minus, and then reaches musl's ordinary x86 target store; direct and `vsscanf`
calls are both covered. This is pinned-musl source-overflow evidence rather
than a portable ISO C target-overflow, decimal/float/wide/scanset/positional/
FILE, byte-formatting, arbitrary-input, general scanner, general stdio,
family-completion, promotion, or public-x86 claim.

The separate private `./scripts/dev-x86_64.sh libc-stdio-fixed-percent-scan`
artifact adds no export or capability. It narrows a pinned-musl 1.2.6 versus
true `-nostdlib -static` differential to `sscanf`/`vsscanf`'s one fixed
C-locale literal `%%` parser state: it skips input whitespace, consumes one
percent without a destination or assignment, distinguishes matching failure
from whitespace-only/empty-input EOF, and leaves errno stale. Its independent
C11/C++17 header gate proves only the existing `sscanf`/`vsscanf` declarations
and unmangled C++ C spellings. It is not `%n`/`%hhn` count-store,
character/string/scanset/pointer/integer/float/wide, general literal or
format-whitespace, FILE, general scanner, general stdio, family-completion,
promotion, or public-x86 evidence.

The separate private
`./scripts/dev-x86_64.sh libc-stdio-fixed-format-whitespace-scan` artifact
adds no export or capability. It narrows a pinned-musl 1.2.6 versus true
`-nostdlib -static` differential to `sscanf`/`vsscanf`'s top-level C-locale
format-whitespace parser state: a contiguous format-space run consumes zero or
more input-space bytes without a variadic destination, assignment, or va_list
advance. Its fixed direct and `vsscanf` witnesses retain stale errno while
covering all selected C whitespace, zero input whitespace before a following
literal, all-whitespace empty-input success with zero assignments, later
literal EOF, and matching failure. Its independent C11/C++17 header gate
proves only the existing declarations and unmangled C++ C spellings. This is
pinned-musl parser-state evidence, not a general scanf-format-whitespace claim.
Literal-percent `%%` is owned by the separate fixed-percent artifact;
`%n`/`%hhn`, character/string/scanset/pointer/integer/floating/wide forms,
conversion, FILE input, byte formatting, locale objects, a general scanner or
stdio boundary, parity, promotion, and public x86 support remain excluded.

The separate private `./scripts/dev-x86_64.sh libc-stdio-fixed-literal-scan`
artifact adds no export or capability. It narrows a pinned-musl 1.2.6 versus
true `-nostdlib -static` differential to `sscanf`/`vsscanf`'s top-level fixed
non-percent, non-format-whitespace raw-literal parser state: one raw format
byte matches one input byte without a variadic destination, assignment, or
va_list advance. Its direct and `vsscanf` witnesses retain stale errno while
covering complete literals, mismatch after a matched prefix, later-literal and
initial EOF, and first-byte matching failure. Its independent C11/C++17 header
gate proves only the existing declarations and unmangled C++ C spellings. This
is pinned-musl parser-state evidence, not a general scanf-literal claim.
Literal-percent `%%` and C-locale format whitespace remain owned by their
separate fixed profiles; `%n`/`%hhn`, character/string/scanset/pointer/integer/
floating/wide forms, conversions, FILE input, byte formatting, locale objects,
a general scanner or stdio boundary, parity, promotion, and public x86 support
remain excluded.

The separate private `./scripts/dev-x86_64.sh libc-stdio-fixed-empty-format-scan`
artifact adds no export or capability. It narrows a pinned-musl 1.2.6 versus
true `-nostdlib -static` differential to `sscanf`/`vsscanf` with only the
zero-length format. Musl's private NUL-string setup admits the valid fixed
input before `vfscanf` skips its format loop, returning its existing zero
assignment count without entering a literal, percent, whitespace, or
conversion parser state. Direct and `vsscanf` witnesses cover empty and
nonempty input, retain a fixture-only trailing `va_list` sentinel, and keep
errno stale. Its independent C11/C++17 header gate proves only the existing
declarations and unmangled C++ C spellings. This is pinned-musl
format-termination evidence, not a general scanf-empty-format claim. Raw
literals, literal-percent `%%`, and C-locale format whitespace remain owned
by their separate fixed profiles; `%n`/`%hhn`, character/string/scanset/
pointer/integer/floating/wide forms, conversions, external FILE input, byte
formatting, locale objects, a general scanner or stdio boundary, parity,
promotion, and public x86 support remain excluded.

The separate private
`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-character-scan` artifact
adds no export or capability. It narrows a pinned-musl 1.2.6 versus true
`-nostdlib -static` differential to one literal non-wide `%*3c`
`sscanf`/`vsscanf` state: assignment suppression has no variadic destination,
does not advance the fixture-only trailing `va_list` sentinel, increments no
assignment count, and consumes exactly three raw bytes, including leading or
interior C-locale whitespace. Fixed direct and `vsscanf` witnesses distinguish
a nonempty short matching failure from initial EOF, keep a high byte raw, and
preserve stale errno. A following literal merely observes consumed bytes; raw
literal matching remains owned by the fixed-literal profile. Its independent
C11/C++17 header gate proves only the existing declarations and unmangled C++
C spellings. This is pinned-musl assignment-suppression evidence, not a general
scanf-suppression claim. Unsuppressed `%c`, all other widths or suppressed
conversions, literal-percent `%%`, format whitespace, `%n`/`%hhn`,
string/scanset/pointer/integer/floating/wide forms, external FILE input,
byte-formatting, locale objects, a general scanner or stdio boundary, parity,
promotion, and public x86 support remain excluded.

The separate private
`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-string-scan` artifact
adds no export or capability. It narrows a pinned-musl 1.2.6 versus true
`-nostdlib -static` differential to one literal non-wide `%*3s`
`sscanf`/`vsscanf` state: assignment suppression has no variadic destination,
does not advance the fixture-only trailing `va_list` sentinel, writes no
terminator or assignment, and skips C-locale input whitespace before consuming
at most three non-whitespace token bytes. Fixed direct and `vsscanf` witnesses
cover a short nonempty token, exact-width consumption before a following
literal, whitespace-only and initial EOF, a high-byte token byte, and stale
errno. The following literal only observes token consumption; raw literal
matching remains owned by the fixed-literal profile. Its independent C11/C++17
header gate proves only the existing declarations and unmangled C++ C
spellings. This is pinned-musl assignment-suppression evidence, not a general
scanf-suppression claim. Unsuppressed `%s` destination storage, `%c`, all
other widths or suppressed conversions, literal-percent `%%`, format
whitespace, `%n`/`%hhn`, scanset/pointer/integer/floating/wide forms, external
FILE input, byte-formatting, locale objects, a general scanner or stdio
boundary, parity, promotion, and public x86 support remain excluded.

The separate private
`./scripts/dev-x86_64.sh libc-stdio-fixed-suppressed-scanset-scan` artifact
adds no export or capability. It narrows a pinned-musl 1.2.6 versus true
`-nostdlib -static` differential to one literal non-wide `%*3[abc]`
`sscanf`/`vsscanf` state: assignment suppression has no variadic destination,
does not advance the fixture-only trailing `va_list` sentinel, writes no
terminator or assignment, bypasses C-locale input-whitespace skipping, and
consumes at most three raw `a`/`b`/`c` member bytes. Fixed direct and `vsscanf`
witnesses cover a short nonempty member run, exact-width consumption before a
following literal, leading whitespace and a first non-member matching failure,
initial EOF, a high byte retained for a following raw literal, and stale errno.
The following literal only observes member consumption; raw literal matching
remains owned by the fixed-literal profile. Its independent C11/C++17 header
gate proves only the existing declarations and unmangled C++ C spellings. This
is pinned-musl assignment-suppression evidence, not a general scanf-suppression
or scanset claim. Unsuppressed `%3[abc]` storage, all other widths or
suppressed forms, unbounded/leading-zero/range/inverse/allocating/wide scanset
grammar, literal-percent `%%`, format whitespace, `%n`/`%hhn`,
character/string/pointer/integer/floating/wide forms, external FILE input,
byte-formatting, locale objects, a general scanner or stdio boundary, parity,
promotion, and public x86 support remain excluded.

The separate private ./scripts/dev-x86_64.sh
libc-stdio-fixed-suppressed-count-scan artifact adds no export or capability.
It narrows a pinned-musl 1.2.6 versus true -nostdlib -static differential to
literal non-wide %*n through the existing NUL-string sscanf/vsscanf boundary:
the star field supplies no destination, and musl's selected count state reads
no source byte, advances no fixture-only trailing va_list sentinel, performs no
count store, and makes no assignment. Fixed direct and vsscanf witnesses cover
empty-input zero-assignment success, a later-literal zero-assignment mismatch,
no-input consumption exposed by following raw literals, and stale errno. The
following literals only observe the count-state boundary; raw literal matching
remains owned by the fixed-literal profile. Its independent C11/C++17 header
gate proves only the existing declarations and unmangled C++ C spellings. This
is a pinned-musl count-state profile, not a portable ISO C %*n, general
scanf-suppression, or count-conversion claim. Unsuppressed %n/%hhn storage,
other count lengths or widths, character/string/scanset/pointer/integer/
floating/wide forms, literal-percent, format whitespace, external FILE input,
byte formatting, locale objects, a general scanner or stdio boundary, parity,
promotion, and public x86 support remain excluded.

The separate private `./scripts/dev-x86_64.sh libc-stdio-float-hex-output`
artifact adds no export and selects only allocation-free C-locale binary64
`%a`/`%A` byte-buffer output. It preserves musl's no-op `l` modifier,
default/explicit precision, all four selected x86 rounding directions
(ties-to-even in nearest mode), normalized subnormal and special-value
spelling, width/padding/truncation, count stores, and System V XMM
register-save/overflow-area varargs. An impossible `int` return count fails
closed with `EOVERFLOW`; formatter floating-exception side effects, decimal
output, long-double output, positional grammar, and all stream boundaries
remain excluded.

The separate private `./scripts/dev-x86_64.sh libc-interface-discovery`
artifact inside still-planned `libc.posix-runtime` executes the six C interface
name/index and address-snapshot entries through pinned musl 1.2.6 and a true
`-nostdlib -static` candidate in a Docker network-none namespace. It pins
loopback ioctl name/index behavior, terminated `if_nameindex` ownership, and
independent `getifaddrs` snapshots with AF_PACKET plus IPv4/IPv6 loopback and
netmask records. Its dedicated x86 compilation boundary has only private mmap
result storage and raw ioctl/rtnetlink exchange: it excludes numeric netdb,
resolver configuration, DNS packets, conventional network databases, public
`ifreq`, interface mutation, general allocation, dynamic runtime artifacts,
promotion, and public x86 support.

The x86 C runtime also has one opt-in mixed-runtime allocator-wrapper
artifact. It reuses the exact `allocator_mimalloc.rs` wrapper and
`libmimalloc-sys` 0.1.49 backend used by AArch64, extracts only that wrapper,
the x86 initial-TLS errno owner, and the bundled backend object, and proves all
nine `memory.allocator-basic` entries (`malloc`, `calloc`, `realloc`,
`reallocarray`, `free`, `aligned_alloc`, `posix_memalign`, `memalign`, and
`valloc`) against pinned musl while rejecting musl's allocator objects from
the candidate link. Pinned musl still supplies startup and
process primitives, and the backend retains private `mi_*` globals, so this is
not an owned x86 runtime, fixed-v3.5.0 Rust-port promotion, allocator-family
closure, or public x86 support.

The separately opt-in `strdup`/`strndup` client artifact now proves a narrow
allocation-consumer boundary over that same wrapper. Its crate-owned object
has only the weak `malloc` ABI route and initial-TLS errno for the otherwise
unrepresentable size boundary; the candidate rejects musl duplication and all
allocator objects. Pinned-musl/project-header executions cover owned high-byte
copies, bounded and zero-limit duplication, stale errno across `free`, and
full/bounded guarded-page reads. This remains a mixed-runtime client proof:
it does not select `memory.allocator-basic`, stateful-text completion,
allocator lifecycle/interposition/failure injection, a CRT/sysroot, or public
x86 support.

The separate `memory.allocator-observability` capability is now a complete
private x86 slice over the exact AArch64 one-symbol surface. A strong
`malloc_usable_size` owner reuses the active backend's direct `mi_usable_size`
semantics and is exercised with real crabc `crt1.o`/`crti.o`/`crtn.o`, static
startup, Initial TLS v1, bounded environment/program-name/auxv publication,
errno, allocator entries, pthread lifecycle, mapping, clock, and child-reaping
owners. Pinned-musl and active-AArch64 executions cover
null, live, zero-size, aligned, reallocated, remote-thread, and inherited-child
pointers plus repeated observation and errno preservation. The current crabc
startup now supplies `__environ`/`getenv`; a candidate-local pinned `libc.lo`
copy weakens only its duplicate `__progname` globals while retaining its
required `__libc`/`__hwcap` support. The unchanged bundled backend therefore
pulls an exact eleven-object pinned-musl support tail while the final link map
proves crabc ownership of `fputs`, `sleep`, and `__stack_chk_fail`; the gate rejects its
allocator, observer, startup/TLS, pthread, mapping, clock, and wait owners.
`memory.allocator-basic`, public fork/atfork, full runtime
closure, fixed-mimalloc-port promotion, and public x86 support remain
unselected.

The private opt-in `crypto.crypt`/`crypto.crypt-helpers` slice is now covered
by `crypt-header-abi` and `libc-crypt`. The C/C++ gate fixes the exact
260-byte `struct crypt_data`, unmangled `crypt`/`crypt_r`, and strict/POSIX
hiding versus X/Open/GNU/BSD `<unistd.h>` visibility. Its static candidate
executes actual public and private crypt ABI entries, preserving a caller
record's initialized field and bounded input/output overlap. It delegates only
canonical bounded SHA-256-crypt (`$5$`) and SHA-512-crypt (`$6$`) work to the
approved RustCrypto `sha-crypt`/`base64ct` dependencies; no cryptographic
primitive is hand-rolled. The temporary MCF allocation intentionally uses only
the candidate's pinned-musl `malloc`/`aligned_alloc`/`free` route, and the
feature explicitly rejects unproven `x86-allocator-runtime` composition.
Legacy DES/BSDI/MD5/bcrypt crypt semantics, default static exports,
allocator/runtime closure, libc.so, CRT, loader, sysroot, family promotion,
and public x86 support remain unselected. The separate selected-private
`legacy.misc` slice supplies opt-in, inert link-compatible `encrypt`/`setkey`
names only: no DES, cipher, PRNG, crypto service, default-export widening, or
promotion follows from that ABI boundary.

`./scripts/dev-x86_64.sh libc-alloca` is a separate private
allocation-adjacent compiler-builtin/header artifact. It byte-matches pinned
musl 1.2.6's `alloca.h`, checks its C/C++ `__builtin_alloca` macro expansion,
and runs one positive-size/nested-frame fixture through pinned musl and an
archive-free `-nostdlib -static` candidate. The candidate permits only its
fixture and exit syscall shim, proving dynamic stack storage while rejecting a
callable `alloca` symbol, allocator/runtime symbols, TLS, dynamic linkage, and
PLT use. It does not select either allocator capability, heap lifecycle or
interposition, alloca zero-size/VLA/unwind/stack-guard behavior, CRT/sysroot,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-stack-chk-fail` is a separate private static
compiler-support artifact. It retains only musl 1.2.6's terminal x86
`__stack_chk_fail` `hlt` body and its hidden weak same-address
`__stack_chk_fail_local` alias: the pinned-musl primary and both freestanding
`-nostdlib -static` candidate spellings terminate with status 139
(`128 + SIGSEGV`). It does not select guard storage, `__init_ssp`, stack-
protector startup policy, an ambient error/failure handler, TLS, loader/dlfcn,
pthread/lifecycle behavior, public C API/header support, promotion, or public
x86 support.

The x86 loader evidence consists of private ET_DYN interpreter artifacts inside
still-planned `ldso.dynamic-runtime`. `ldso-initial-graph` is limited to
one main PIE -> mid.so -> leaf.so graph, RELATIVE/GLOB_DAT/JUMP_SLOT ELF64
RELA plus one bounded packed leaf `DT_RELR` direct-and-bitmap stream with
independent 512-record/512-target caps; the pre-Rust interpreter bootstrap
remains `DT_RELA`-only. It also covers
dependency-only leaf-before-mid init arrays, final interpreter-and-graph RELRO
sealing, and main/leaf RELRO-fault plus fail-closed malformed-file-range/TLS/
unsupported-relocation/RELR inputs. It deliberately rejects main-image
constructors pending CRT handoff and is not a general loader, CRT/sysroot, or
public x86 support claim.

`ldso-target-root-admission` builds that unchanged fixed graph through the
private feature-gated `crabc-ldso` x86-64 cdylib target and runs it as the
actual ET_DYN `PT_INTERP` candidate. Its Cargo target admission rejects
external runtime edges after building and preserves the pinned-musl graph and
negative-input evidence. It remains a private target-root proof, not x86
loader support, an installed interpreter, libc, CRT/sysroot, or a promotion.

The separate `ldso-general-initial-graph` artifact extends only the private
initial-mapping evidence to one arbitrary bounded non-TLS `DT_NEEDED`
transaction. It opens bare dependency names through ordered absolute RUNPATH
components, identity-deduplicates its graph, relocates/protects/RELRO-seals
every admitted DSO, then derives dependency-first postorder in declared
`DT_NEEDED` order. Its sole lifecycle admission is a mapped dependency's
paired, nonempty, aligned, load-contained 1–16-entry
`DT_INIT_ARRAY`/`DT_INIT_ARRAYSZ`: every relocated callback is preflighted as
nonzero and executable before the first callback, then dispatched once. A
ready cycle or malformed constructor plan fails before callback dispatch and
rolls back only transaction-created mappings; the direct and Cargo target-root
fixtures prove the shared-once diamond, pre-dispatch cycle rejection, and
zero/non-executable/main/legacy-tag rejection. It selects neither a general
loader lifecycle nor main-image/CRT lifecycle, `DT_INIT`/`DT_FINI`/
`DT_PREINIT_ARRAY`/`DT_FINI_ARRAY`, TLS, RuntimeV1, libc, finalization/unload,
dynamic CRT/sysroot, family promotion, or public x86 support.

The common `ldso/src/x86_64_general_initial_loader_state.rs` owner now retains
that bounded general graph's identity/edges, complete object records, and map
provenance across both direct general roots. Its private lifecycle is
`Vacant -> Discovering -> Prepared -> Reserved -> Ready`: all fallible graph
work and constructor preflight finish before reservation, pre-FS rollback
restores `Vacant`, and the non-fallible release commit precedes callbacks.
Kernel-owned main mappings are never transaction rollback targets. This is a
selected-private `runtime.loader` state slice, not general loader completion
or a public-support transition. Its evidence is the existing four direct and
Cargo target-root general graph/TLS commands: `ldso-general-initial-graph`,
`ldso-general-initial-target-root`, `ldso-general-initial-tls`, and
`ldso-general-initial-tls-target-root`.

The separate `ldso-general-initial-tls-materialization` artifact adds initial
TLS materialization only to that bounded dependency transaction. It assigns
loader-order module IDs, validates and lays the main -> left/right -> shared
Variant-II images below TP, copies initialized bytes, zeroes TBSS, and resolves
the bounded DTPMOD/DTPOFF/direct `__tls_get_addr` inputs. Mapping, relocation,
protection, RELRO, registry/template, and dependency `DT_INIT_ARRAY` planning
all complete before `ARCH_SET_FS`; the common graph/object/map-provenance owner
reserves its one private publication slot before that syscall, rolls it back to
`Vacant` on every pre-FS failure, and performs only a nonfallible commit after
a successful install. The TLS record is a registry/allocation sidecar, not a
second graph or object store. The complete dependency-only callback plan is
preflighted before FS installation, and candidate callbacks run only after
that commit; the fixture proves the shared callback occurs once and that the
dependency branches observe ready template/TBSS state. The naked pinned-musl reference intentionally
bypasses CRT constructor dispatch, so it remains an initial-TLS layout/value
oracle rather than a constructor-order differential. This does not select
RuntimeV1, libc attachment, dynamic CRT, pthread/new-thread TLS, DTV
growth/replacement, main/CRT or general loader lifecycle, legacy
init/fini/preinit/fini-array behavior, runtime mapping/dlopen,
finalization/unload, installed dynamic products, family promotion, or public
x86 support.

The separate `loader-libc-general-tls-runtime-v1` artifact is the one-shot
private RuntimeV1 sibling over that bounded arbitrary initial-TLS graph. Its
cfg-selected source and Cargo roots reserve common loader state and the 72-byte
local/hidden descriptor together before `ARCH_SET_FS`; pre-FS failure releases
both. A successful install nonfallibly commits the common owner, fills the
descriptor, release-publishes `READY` last, and only then dispatches the
preflighted dependency constructor plan. The libc evidence consumer remains an
observer: it validates the exact record before `ARCH_GET_FS`, `%fs`, or DTV
access. Direct native evidence checks its writable non-`.dynsym`,
non-page-rounded-RELRO ELF placement, metadata and poisoned-DTV rejection,
constructor attachment, and rejection of strong-main/weak-DSO record imports
before FS installation; the Cargo-root gate replays the positive graph. Musl
remains only the ordinary diamond's initial-TLS layout/value oracle. This is
not a CRT handoff, installed dynamic product, libc startup carrier,
pthread/new-thread implementation, DTV growth/replacement, runtime mapping or
unload, general lifecycle, family/capability promotion, or public x86 support.

`dynamic-main-thread-runtime-v1` is one newer, still-private bridge over that
same common graph/object owner plus attached TLS sidecar and descriptor wire. A separately built Rust `Scrt1.o` attaches the main-resident
RuntimeV1 consumer immediately before a fixture-local dynamic
`__libc_start_main`; its real main and tiny private dynamic libc prove
`PIMFL`, dynamic TLS, and dynamic errno. The loader admits only Scrt1's exact
weak undefined owned-CRT `R_X86_64_GLOB_DAT` slot as null before generic
lookup: strong-main and weak-DSO forms reject before `ARCH_SET_FS`, while a
dependency definition cannot interpose. It validates the real main lifecycle
tag shape but leaves callback dispatch with Scrt1. This is not the planned
owned-CRT carrier, loader finalizer/dependency-lifecycle handoff, installed
interpreter/libc product, normal exit runtime, pthread/new-thread TLS,
DTV growth, `dlopen`/unload, sysroot, promotion, or public x86 support.

The separate `ldso-initial-tls` artifact keeps that original no-TLS proof
unchanged while adding one fixed TLS-free main PIE -> two GNU-Dynamic TLS DSO
graph. It proves checked DSO `PT_TLS` parsing and Variant-II copying,
initialized/TBSS/high-alignment values, a two-entry private DTV, DTPMOD/DTPOFF
and interpreter-owned `__tls_get_addr`, and reject-only TPOFF/static-TLS
inputs. It remains neither a general loader/TLS/pthread implementation nor a
dynamic CRT/sysroot, full x86-64 parity, or public x86 support claim.

The `ldso-owned-crt-handoff` sibling keeps both prior interpreter
artifacts unchanged while proving one fixed no-TLS main PIE -> mid.so -> leaf.so
post-relocation publication to a Rust-produced Scrt1-owned dynamic main. Its
only extra main lookup is the weak `R_X86_64_GLOB_DAT`
`__crabc_x86_64_owned_crt_handoff` v1 record: the self-relocated interpreter
RELRO-seals it, never uses `%rdx`, and defers only the existing leaf-before-mid
init arrays until after executable preinit. The native no-libc fixture proves
`PDdIMFL` under `env -i`; pinned musl proves the absent-record null-finalizer
`A` route; malformed record data and an early finalizer fail status 127. It
does not select another executable/root, general loader lifecycle or DSO
finalization, candidate libc, RuntimeV1, dynamic CRT/sysroot, or public x86
support.

The separate `ldso-fixed-graph-introspection` artifact keeps that no-TLS graph
immutable while release-publishing its actual post-relocation, post-RELRO,
post-constructor object records behind one weak main-image
`R_X86_64_GLOB_DAT` import. Its exact 40-byte private v1 record copies a
three-image snapshot, nearest dynamic-symbol address metadata, and useful
per-image base/dynamic/name information into caller-owned bounded records.
Pinned musl supplies the corresponding `dl_iterate_phdr`, `dladdr`, and
`dlopen`/`dlinfo`/`dlclose` observations; the candidate has no ambient runtime
dependency or PT_TLS, runs under `env -i`, and rejects a malformed record with
status 127. It does not select public dlfcn, handles, graph mutation/unload,
candidate libc, process RuntimeV1 publication, a general loader, dynamic
CRT/sysroot, `ldso.dynamic-runtime` promotion, or public x86 support.

The cfg-isolated `ldso-fixed-graph-dlfcn` sibling consumes that published graph
as loader-owned state through one weak-main 64-byte `RuntimeV1`-ordered record.
It offers only retained main/mid/leaf tokens, explicit atomic references,
handle-scoped ordinary-symbol lookup, and caller-owned copied metadata. Unknown,
forged, stale, global-scope, malformed-record, strong-import, and DSO-import
forms fail closed; close neither finalizes nor unmaps. Its pinned-musl
differential and native ET_DYN evidence remain private: filesystem search,
mapping, global promotion, a public `dl*` ABI, a general loader, dynamic
CRT/sysroot, family promotion, and public x86 support remain excluded.

The x86 static C archive also has a private
`static-c-math-x87-extended` artifact inside still-planned
`libc.text-math-locale-stdio`. It maps 22 pinned-musl x86 binary80 elementary,
rounding, conversion, remainder, absolute-value, and square-root entries into
one target-private assembly leaf without binary64 promotion. The native
function-pointer differential compares 1,260 exact result/exception/quotient
records across all four rounding modes and rejects ambient libm, TLS, dynamic
linkage, and unowned runtime dependencies. It neither completes
`math.elementary-long-double` nor independently selects the special-function
surface. Its `rintl` and
`sqrtl` entries are composed from the separately selected fenv-rounding and
elementary-square-root leaves, so the extended-math source owns the other 20
entries without duplicating archive symbols.

The separate `static-c-math-special` verified slice completes the exact
90-symbol `math.special` capability privately. Ten classifier/sign/binary80
conversion/remainder entries reuse those prior x87 leaves; 80 generated
source-faithful entries map pinned musl 1.2.6's error, Bessel, gamma,
decomposition, stepping, scaling, NaN, and rounding-conversion sources. All
supporting elementary providers are localized, and every long-double boundary
retains SysV binary80 rather than narrowing through binary64. The
project-header gate proves every C++ function-pointer spelling in SSE and x87
modes, while the native differential compares 5,544 exact 32-byte records over
all four rounding modes and same-address `__signgam`/`signgam` state. It does
not itself select numeric parsing, either remaining elementary capability,
the separately selected complex capability, or a general libc/libm. The
enclosing family, x86-64 promotion, full
parity, and public support all remain planned.

The following non-promoting `ldso-public-dlfcn` artifact exposes the seven
musl-shaped public C entry points from the staged x86 static libc archive over
that exact loader record. Its real ET_DYN candidate has no ambient libc edge or
PT_TLS; a bounded 32-live-thread Linux-TID table owns one-shot `dlerror` and
copied `dladdr` names, and dead slots are reclaimed only after `tgkill` reports
`ESRCH`. Pinned-musl plus project-header C/C++ evidence covers ABI layouts,
iteration, link maps, concurrent diagnostics, malformed/absent records, and
stale handles. For a live retained handle within that 32-slot table, the sole
musl `dlinfo` request is `RTLD_DI_LINKMAP`: the `-7` differential leaves its
result pointer untouched, keeps exact `Unsupported request -7` pending through
a succeeding valid query, then consumes it once. Within the same bound, `dlclose(NULL)` returns exactly
one and yields one-shot `Invalid library handle 0`; non-null stale/forged close
handling remains loader-owned. For a live retained non-`RTLD_NEXT` handle,
musl's `dlsym` empty-name branch returns null with one-shot `Symbol not found: `;
the candidate substitutes that exact error only after its bounded loader reports
`loader symbol name is invalid`. Non-empty missing names, null symbol pointers,
and invalid handles retain their existing loader paths. For a writable `Dl_info`,
musl's `dladdr(NULL)` returns zero before modifying it or publishing `dlerror`;
the fixed bridge preserves that null-address no-image observation. For a
non-null address outside every retained fixed-image `PT_LOAD`,
musl's `addr2dso` likewise finds no image and returns zero before touching
`Dl_info` or `dlerror`; the bridge admits only its exact `loader address not
found` result to preserve that observation. Other non-null failure and
unavailable-record paths retain their output-clearing fail-closed handling.
Only in this non-runtime public bridge,
`dlopen(NULL, RTLD_NOLOAD)` returns musl's permanent main handle and leaves
`dlerror` clear before mode processing; its bounded runtime-mapping sibling
continues to reject that bare NULL/NOLOAD initial-object request. Musl
`ldso/dynlink.c:dl_iterate_phdr` calls a callback before it takes the reader
lock for the next image. The public bridge's copied snapshot likewise leaves
both loader and diagnostic-slot locks free, so the first callback can consume
the nonempty pending same-thread diagnostic from the existing unknown-object
failure, return `74`, and leave the next `dlerror` null. This selects only that
diagnostic-state transaction, not callback mapping, graph mutation, or general
loader reentrancy. Search/mapping, graph mutation, `RTLD_NEXT`,
global promotion, finalization, and unload remain excluded, so neither dlfcn capability nor the
dynamic-runtime family or public x86 platform is promoted.

`ldso-dladdr-symbol-bounds` adds one separate private differential over that
same already-loaded no-TLS graph: a four-byte public leaf dynamic object names
its exact/interior bytes, while one-past local mapped padding retains the leaf
identity but clears `dli_sname`/`dli_saddr`, matching pinned musl 1.2.6. It
ratchets the unchanged seven-symbol archive, weak 64-byte record, no-ambient
ELF shape, and malformed/absent fail-closure; it does not add `dlopen`, name
lookup, mapping, handle identity, unload/finalization, capability selection,
or public x86 support.

The cfg-isolated `ldso-bounded-dlopen` sibling then admits one append-only
no-TLS RELA-only ET_DYN mapping through the initial main's absolute RUNPATH,
with only already-retained dependencies, one validated executable legacy
`DT_INIT` entry followed by its bounded constructor array, each exactly once,
one validated executable legacy `DT_FINI` target that remains inert on
ordinary final close, four copied objects, and one generation/addition. Those
legacy tags are available only to the appended DSO; initial main/mid/leaf
`DT_INIT`/`DT_FINI` stay reject-only, malformed runtime targets fail before
publication, and `DT_FINI_ARRAY` remains reject-only. The same fourth DSO may
separately carry one nonempty, aligned 1–16-entry,
load-contained `DT_PREINIT_ARRAY`/`DT_PREINIT_ARRAYSZ` metadata pair. Pinned
musl leaves it inert during `dlopen`; the candidate validates the pair before
publication but neither retains, reads, nor dispatches its entries. An
out-of-load pair fails before publication, and initial main/mid/leaf preinit
tags remain reject-only in this sibling. Its pinned-musl differential also
proves `RTLD_NOLOAD` reference acquisition for that already-loaded plugin.
The candidate accepts that request only with `RTLD_LAZY` or `RTLD_NOW` for the
single appended basename: it returns the existing opaque token without a path
lookup, mapping, constructor, or graph change; an unpresent name, `NULL`, and
named initial main/mid/leaf objects fail closed. The candidate's copied
`dlpi_adds` remains a graph-mutation counter across that reference, while pinned
musl exposes its reference through a changed `dlpi_adds` observation.
`RTLD_NODELETE` is accepted only for that same fourth identity, including its
initial map and later no-load references. Because that mapping is already
process-lifetime owned, it changes neither close/stale-token behavior nor the
absence of an unload path; `NULL` and named initial identities fail closed.
PT_TLS, RELR, recursive mapping,
scope promotion, `DT_FINI_ARRAY`, finalization/unload, and all general
dlfcn/loader behavior remain excluded, so `ldso.dynamic-runtime` and public
x86 support remain planned.

The separate `static-c-math-elementary-long-double` verified slice now
completes the exact private 35-symbol `math.elementary-long-double`
capability. It composes seventeen prior x87 binary80 entries with eighteen
pinned-musl 1.2.6 source-faithful providers, keeping the trigonometric
argument-reduction and binary64 support closure local. The project-header C++
ABI gate ratchets every signature, unmangled linkage, 16-byte align-16
binary80 storage, and GNU `sincosl` pointer boundary. Its freestanding static
differential compares 2,764 exact 40-byte records with pinned musl across all
four rounding modes, retaining only the ten defined binary80 bytes and the
x87/MXCSR exception state. This selects neither fenv-sensitive scalar math,
numeric parsing, the separately selected complex capability/general libm,
family completion, x86 promotion, nor public support.

The separate `static-c-math-complex-complete` verified slice completes the
exact private 66-symbol `math.complex` capability: nine prior
`creal*`/`cimag*`/`conj*` foundation entries plus 57 source-faithful pinned-musl
1.2.6 magnitude, phase, projection, power, root, logarithm, exponential, and
circular/hyperbolic/inverse-complex entries. Its C++ gate ratchets every
function-pointer spelling in default SSE and x87 modes, including the SysV
16-byte binary80 and 32-byte long-complex ABI. Its freestanding differential
compares 5,712 exact 64-byte records across all rounding modes, retaining the
defined ten bytes of each binary80 component and exception state. Local musl
scalar and LLVM compiler-rt complex-multiply support remains non-public; musl's
five FIXME-marked long-complex wrappers retain their source-oracle binary64
internals without narrowing any public binary80 boundary. It selects no
elementary/fenv-sensitive/numeric-parsing capability, general libc/libm,
family completion, x86 promotion, or public support.

The x86 lane retains private static artifacts inside still-planned
`libc.pthread-tls`. `./scripts/dev-x86_64.sh libc-static-tls-v1` passes a
freestanding final-static-executable fixture's untouched Linux entry stack to
a hidden libc hook. That hook validates the final executable's program-header
view and optional `PT_TLS` image, materializes one x86 Variant-II main-thread
image, and retains its immutable template. Its fixture links initialized,
TBSS, and high-alignment TLS definitions from two C translation units plus
libc `errno`; after mutating the main image, two sequential workers prove they
each receive fresh template values. The existing private static
`pthread_create`/`pthread_exit`/`pthread_join` artifacts consume independent
copies of that template for a null-attribute worker that returns normally or
uses the selected worker-only explicit-exit path, with result handoff and
clear-child-tid join reclamation. A fixed private 64-worker registry
serializes explicit-exit publication with join withdrawal and validates
`%fs:0`, the child kernel TID, and its still-live clear-child-tid word; the
candidate-only cap check exhausts all slots and proves reuse after joining.
The same `pthread_create` archive owner also retains musl 1.2.6
`src/thread/pthread_create.c`'s private `weak_alias(dummy_0,
__membarrier_init)` fallback. The pinned AArch64 static manifest records that
binding as weak in `pthread_create.lo` and records the optional strong body in
`membarrier.lo`; the staged archive and normal candidate retain the weak
definition, while a caller-owned private strong spelling wins after
`pthread_create` extracts its owner. This is archive-binding evidence only:
selected worker creation never calls it, so no `membarrier`
syscall/registration, public API, dynamic TLS, loader state, or process-startup
policy is selected.
The separate `./scripts/dev-x86_64.sh libc-pthread-identity` artifact proves
the bounded opaque x86 identity contract: weak same-address
`pthread_self`/`thrd_current` and `pthread_equal`/`thrd_equal` pairs, direct
Variant-II `%fs:0` identity, and canonical one-or-zero macro/function
equality for the main thread plus two live normal workers and one selected
explicit-exit worker. `pthread_create` returns that child TP and
`pthread_join` resolves it under the existing private registry lock; no
dereferenceable TCB or broader C11 thread lifecycle is selected. The separate
`./scripts/dev-x86_64.sh libc-c11-lifecycle` artifact admits only typed
`thrd_create`/`thrd_join`/`thrd_exit` over that same static worker seam. It
preserves normal and explicit signed `int` results, including `INT_MIN` and
`INT_MAX`, and checks the opaque TP identity while the handle is still live.
The pinned-musl portion covers only those standard C11 paths; candidate-only
null-start and bidirectional unsupported C11/pthread-exit crossover checks
fail closed after reclamation without decoding an incompatible result. It does
not select detachment or sleep beyond their separately recorded private artifacts, C11
synchronization/TSS/cancellation, dynamic or loader TLS, or general
pthread/C11 behavior. The separate `./scripts/dev-x86_64.sh
libc-pthread-detach` artifact selects only prompt state-only
`pthread_detach`/`thrd_detach` ownership for those selected workers. A
successful detach neither waits nor reclaims the still-live worker mappings;
only a later selected create/join boundary may reap an exited detached worker
after `CLONE_CHILD_CLEARTID` clears its child TID. Its pinned-musl comparison
covers external workers before and after the fixture's callback-completion
signal, not a detach call after kernel exit. Self-detach, null/repeated/racing
ownership attempts, join-after-detach, and 64-slot delayed reuse are
candidate-only diagnostics, not pthread/C11 parity. The separate
`./scripts/dev-x86_64.sh libc-thrd-sleep` artifact selects only the direct C11
`thrd_sleep` status adapter over the existing non-cancellation
`clock_nanosleep(CLOCK_REALTIME, 0, ...)` seam: zero succeeds, `EINTR` maps to
`-1`, and invalid or null duration requests map to `-2` without changing
`errno`. Its pinned-musl/reference and static-candidate route also proves a
SIGALRM interruption with a positive remaining interval. It does not select
`thrd_yield`, cancellation cleanup, C11 lifecycle/synchronization/TSS,
dynamic/loader TLS, CRT, sysroot, or public x86 support. The separate
`./scripts/dev-x86_64.sh libc-thrd-yield` artifact is a twentieth private
static artifact in the same still-planned family. It selects only C11
`thrd_yield`'s no-argument Linux `sched_yield=24` syscall: normal invocation
and a fixture-local seccomp-forced `EPERM` both discard their raw result and
preserve C `errno`, as musl's void entry does. It guarantees no scheduler
handoff, fairness, or peer progress. The POSIX `sched_yield` C API, scheduler
policy/parameters, affinity and pthread scheduling attributes, C11
lifecycle/synchronization/TSS/cancellation, dynamic/loader TLS, CRT, sysroot,
family completion, promotion, and public x86 support remain excluded.

The separate `./scripts/dev-x86_64.sh libc-pthread-cpuclock` artifact is a
twenty-first private static artifact in that same still-planned family. It
selects only `pthread_getcpuclockid` for the bootstrapped process-main task's
own `pthread_self()` handle. Musl obtains its TID from a full pthread TCB;
this static leaf instead verifies the existing `%fs:0` plus Linux-TID main-task
identity, reads direct `gettid=186`, and uses the same 32-bit Linux CPU-clock
encoding without dereferencing a public handle. The shared fixture proves the
exact returned ID, its acceptance by the separately selected `clock_gettime`,
and preserved errno. Candidate-only null or non-self handles return `ESRCH`
without touching output or errno. Worker, foreign, completed, or general
handles; `clock_getcpuclockid` and general C clocks; scheduling or affinity
attributes; lifecycle, cancellation, synchronization, TSS, a TCB/thread list,
dynamic/loader TLS, CRT, sysroot, family completion, promotion, and public x86
support remain excluded.

The separate `./scripts/dev-x86_64.sh libc-pthread-name` artifact is a
twenty-second private static artifact in that same still-planned family. It
selects only GNU `pthread_setname_np`/`pthread_getname_np` for the
bootstrapped process-main task's own `pthread_self()` handle. Musl's self path
uses a 16-byte task-comm window through `prctl`; the static candidate validates
its existing `%fs:0` initial-main identity and calls direct `prctl=157` with
`PR_SET_NAME=15` or `PR_GET_NAME=16`, without a dereferenceable pthread TCB.
The shared fixture proves self set/get, raw getter observation, the exact
16-byte boundary, and preserved errno; candidate-only non-self calls return
`ESRCH` before either name buffer is observed. Worker/foreign naming, musl's
procfs route, cancellation, a general prctl API, scheduling/affinity
attributes, lifecycle/synchronization/TSS, dynamic/loader TLS, CRT, sysroot,
family completion, promotion, and public x86 support remain excluded.

The separate `./scripts/dev-x86_64.sh libc-pthread-attributes` artifact is a
private `pthread_attr_t` record-metadata leaf in the same still-planned
`libc.pthread-tls` family. Its project-header fixture first runs against pinned
musl 1.2.6 and then through a `-nostdlib -static` candidate. The private
`libc/src/c_abi/x86_64/pthread_attr.rs` owner supplies exactly the 18 standard
entries: `pthread_attr_init`/`pthread_attr_destroy` and the set/get pairs for
detach state, stack size, stack, guard size, scope, inherit-scheduler state,
scheduler policy, and scheduler parameters. It preserves musl's 56-byte,
align-eight record defaults (131072-byte stack and 8192-byte guard), direct
status validation for detach/inherit, stack, guard, and scope inputs, raw
scheduler metadata, and `pthread_attr_getstack`'s no-output-on-unset rule.
`pthread_create` remains null-attribute-only: this leaf does not consume the
record. Custom stacks, detached-at-create behavior, scheduler or guard runtime
effects, GNU default attributes, `pthread_getattr_np`, live-thread inspection,
TLS/runtime state, family completion, promotion, and public x86 support remain
excluded.

The separate `./scripts/dev-x86_64.sh libc-pthread-barrierattr-pshared`
artifact remains a record-only private static leaf in that same still-planned
family. It selects only `pthread_barrierattr_setpshared` and
`pthread_barrierattr_getpshared` over the public four-byte attribute word:
musl's accepted `0`/`1` values replace it with `0`/`INT_MIN`, invalid inputs
leave it unchanged, and any nonzero raw word reads back as shared. The fixture
uses caller-owned raw storage without a lifecycle call or the separately
selected barrier block. Its record-only proof therefore does not establish
barrier initialization, waiting, destruction, or process-shared barrier
operation; threads, TLS, synchronization, cancellation, CRT, loader, sysroot,
family completion, promotion, and public x86 support remain excluded.

The separate `./scripts/dev-x86_64.sh libc-pthread-barrier` artifact selects
the complete seven-name public barrier surface inside that same still-planned
family: attribute lifecycle/pshared records, count validation, two reusable
private selected-worker rounds with exactly one serial result each, and one
shared-futex cross-fork round followed by quiescent destroy. Its true static
candidate ports musl's private stack-instance and shared vmlock protocols over
the exact 32-byte, align-eight public record. Fixture-local mapping, fork,
wait, clock, and exit plumbing does not select a C process runtime. Arbitrary
destroy races, broad pthread synchronization/lifecycle, cancellation,
dynamic/loader TLS, CRT/sysroot integration, family completion, promotion,
x86-64 parity, and public x86 support remain excluded.

The separate `./scripts/dev-x86_64.sh pthread-spin-destroy-header-abi` and
`./scripts/dev-x86_64.sh libc-pthread-spin-destroy` gates add a separately
recorded private static artifact in that same still-planned family. They compare the
unconditional C/C++ `pthread_spin_destroy(pthread_spinlock_t *)` declaration
and unmangled linkage with pinned musl, then isolate musl's source-closed
return-zero object and one extracted crabc object in an archive-free static
candidate. Direct and function-pointer calls return zero without changing a
caller-owned sentinel word. That is non-observation evidence only: it selects
neither spin initialization, lock/trylock/unlock, a valid spin lifecycle or
state, synchronization, atomics, threads, cancellation, general pthread/TLS
behavior, family completion, promotion, x86-64 parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-pthread-mutex-normal` artifact is a tenth private static
`verified_artifact` in the same still-planned `libc.pthread-tls` family. It admits only an all-zero or
`pthread_mutex_init(..., NULL)` process-private `PTHREAD_MUTEX_NORMAL` record
through `pthread_mutex_init`/`destroy`/`lock`/`trylock`/`unlock`. Its exact
lock word progresses from `0` to `EBUSY` and, under contention, to
`EBUSY|INT_MIN`; private `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE` handoff
coordinates the selected workers. The pinned-musl and true static-candidate
fixture proves held-lock `EBUSY`, caller-`errno` preservation, and mutual
exclusion across six bounded two-worker rounds. Non-null attributes or a
nonzero type word return `ENOTSUP` rather than selecting another mutex type.
It excludes mutex attributes, recursive/error-checking/robust/PI/
process-shared/timed mutexes, C11 mutex or condition behavior beyond the
separately selected plain adapter, general condition variables, cancellation,
dynamic/loader TLS, CRT/sysroot integration, general pthread synchronization,
full pthread/TLS or x86-64 parity, and public x86 support. The separate
`./scripts/dev-x86_64.sh libc-pthread-rwlock` artifact is a fifteenth private
static `verified_artifact` in the same still-planned `libc.pthread-tls`
family. Its pinned-musl/reference and true static-candidate routes select the
complete installed `pthread_rwlock_*` and `pthread_rwlockattr_*` family over
the 56-byte, eight-byte-aligned rwlock and eight-byte, four-byte-aligned
attribute records: init/destroy, reader and writer lock/try/timed-lock,
unlock, and attribute init/destroy/get/set process sharing. The seven
lock-operation public names are weak same-address aliases of hidden
`__pthread_rwlock_*` definitions. The fixture proves static and private or
process-shared initialization, concurrent readers, reader/writer exclusion,
expired and future absolute `CLOCK_REALTIME` timeout status including musl's
initial-try ordering, wake-before-deadline handoff, caller-`errno` preservation, and
cross-process shared-futex reader and writer wakeups. Its raw time, mapping,
fork, wait, and exit plumbing is fixture-local rather than a C process-runtime
claim. It does not select cancellation, priority or fairness guarantees,
general pthread synchronization or runtime ownership, dynamic/loader TLS,
CRT/sysroot integration, full pthread/TLS or x86-64 parity, promotion, or
public x86 support. The separate
`./scripts/dev-x86_64.sh libc-pthread-cond-private` artifact is an eleventh
private static `verified_artifact` in that same still-planned
`libc.pthread-tls` family. It admits only a 48-byte, eight-byte-aligned
all-zero or `pthread_cond_init(..., NULL)` process-private condition record,
paired only with the selected all-zero or NULL-initialized normal mutex. Its
pinned-musl/reference and true static-candidate routes preserve the private
stack waiter/list/barrier/requeue protocol and use
`FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`/`FUTEX_REQUEUE_PRIVATE` for the
selected handoff. They prove static and NULL initialization, one deterministic
signal, a two-waiter broadcast, four bounded 64-handoff ping-pong rounds,
caller-`errno` preservation, and quiescent destruction. Candidate-only
evidence requires every non-NULL condition attribute to return `ENOTSUP`;
that rejection is a selected-boundary diagnostic, not a musl-parity claim.
Condition attributes, process-shared or timed waits, cancellation, C11
condition behavior beyond the selected plain adapter, general condition
behavior, non-selected mutex kinds, destruction with live
waiters, dynamic/loader TLS, CRT/sysroot integration, general pthread
synchronization, full pthread/TLS or x86-64 parity, promotion, and public x86
support remain excluded. The separate `./scripts/dev-x86_64.sh
libc-c11-plain-sync` artifact is a twelfth private static
`verified_artifact` in that same still-planned `libc.pthread-tls` family. It
admits only the installed header's distinct 40-byte, eight-byte-aligned
`mtx_t` and 48-byte, eight-byte-aligned `cnd_t` records: `mtx_plain`
initialization, mutex init/destroy/lock/trylock/unlock, and condition
init/destroy/wait/signal/broadcast. The C11 boundary routes directly through
the selected private normal-mutex and condition waiter/barrier/requeue engines
without calling an interposable pthread C symbol; a held trylock maps to
`thrd_busy`. Recursive and timed kinds are candidate-only `thrd_error`
rejections before their records are interpreted, not musl-differential
behavior. Timed calls, static C11 initialization, cancellation, TSS, once,
process-shared synchronization, C11-family completion, pthread/TLS or x86-64
parity, promotion, and public x86 support remain excluded. The separate
`./scripts/dev-x86_64.sh libc-pthread-c11-once` artifact is a thirteenth private
static `verified_artifact` in that same still-planned `libc.pthread-tls`
family. Its pinned-musl/reference and true static-candidate routes select only
the normal-return `pthread_once` and C11 `call_once` path for the installed
four-byte, zero-initialized `pthread_once_t` and `once_flag` records. The
shared private state machine changes `0` to initializer state `1`; two selected
contenders start while the control reaches state `3` and selected waiters use
`FUTEX_WAIT_PRIVATE`; a normal
initializer release-publishes state `2` and uses `FUTEX_WAKE_PRIVATE` only
when waiters were recorded. Static and local zero initialization, exactly one
initializer, post-completion relaxed-payload visibility without a separate
release/acquire edge, and caller-`errno`
preservation are evidence boundaries; `call_once` reaches the shared private
machine rather than an interposable pthread C symbol. Cancellation reset,
initializer `pthread_exit`/`thrd_exit`, recursive same-control entry,
fork/atfork, TSS, dynamic/loader TLS, musl's weak `pthread_once` ELF binding,
general pthread/C11 synchronization,
full pthread/TLS or x86-64 parity, promotion, and public x86 support remain
excluded. The separate `./scripts/dev-x86_64.sh libc-pthread-c11-tsd` artifact
is a fourteenth private static `verified_artifact` in the same still-planned
`libc.pthread-tls` family. It selects only
`pthread_key_create`/`pthread_key_delete`/`pthread_getspecific`/
`pthread_setspecific` and `tss_create`/`tss_delete`/`tss_get`/`tss_set` over
a private 128-key table, a process-main value table, and one value table in
each already selected worker control. A null destructor still reserves its
key; deletion clears only those selected value tables and calls no old
destructor. For normal pthread/C11 return, `pthread_exit`, and `thrd_exit`,
the worker clears a non-null value before calling its destructor, releases the
private metadata lock for that callback, allows rearming for at most four
ascending-key passes, and completes the phase before publishing the join result
or reaching `SYS_exit`. The pinned-musl/reference and true static-candidate
fixture proves main/worker isolation, 128-key exhaustion and numeric-slot
reuse after deletion, four clear-before-callback rearming passes, and all four
selected exit routes. Invalid/deleted keys and non-selected callers fail
closed deliberately rather than inheriting musl's unchecked internal fast
paths; selected-main admission requires the bootstrapped `%fs:0` plus Linux
TID pair, so an inherited FS base alone is insufficient. Main-thread
process-exit destructors, foreign threads beyond that admission boundary,
cancellation and cleanup handlers, concurrent key-deletion/destructor
interaction, fork/atfork, detached-thread lifecycle beyond the existing
selected-worker exit seam, dynamic/loader TLS/DTV, allocator ordering, a
general TCB or all-thread list, weak/same-address TSD aliases, exact ELF
parity, general pthread/C11 behavior, full pthread/TLS or x86-64 parity,
promotion, and public x86 support remain excluded.

The sixteenth private static artifact,
`./scripts/dev-x86_64.sh libc-pthread-cancel-deferred`, selects one
pointer-returning selected-worker deferred-cancellation route only. A creator
records `pthread_cancel`; explicit `pthread_testcancel` returns while
`PTHREAD_CANCEL_DISABLE` or `PTHREAD_CANCEL_MASKED` is active, and re-enabling
leaves the request pending until the one selected explicit delivery point. On
delivery, the worker disables cancellation before LIFO cleanup handlers, then
runs the selected TSD destructor phase before publishing `PTHREAD_CANCELED` to
the existing clear-child-tid join path. The fixture proves those state
transitions, errno preservation, cleanup/TSD order, the candidate-only
asynchronous `ENOTSUP` boundary, and a project-header C/C++ `struct __ptcb` /
cleanup-macro ABI matrix. It excludes cancellation signals, syscall
interruption or implicit cancellation points, C11/detached/main/foreign-worker
cancellation, general pthread cancellation, full pthread/TLS or x86-64 parity,
promotion, and public x86 support.

The separate `./scripts/dev-x86_64.sh libc-pthread-tls-aggregate` artifact is
a seventeenth private static composition proof in the same planned family. Its
two selected workers compose only the existing Static Initial TLS v1,
create/join, normal mutex/condition, rwlock, once, and TSD leaves: both hold
shared reads and publish through the condition before a parent broadcast, then
perform clear-before-callback destructors before their distinct join results.
The parent observes writer exclusion while those reads are live and writer
acquisition after join. It neither exercises nor extends the separate
deferred-cancellation route, and adds no attributes, timed/shared
synchronization, C11 adapter, detached/foreign-thread, dynamic/loader TLS,
CRT/sysroot, parity, promotion, or public-support claim.

`./scripts/dev-x86_64.sh libc-pthread-atfork` is an eighteenth private static
artifact in that same still-planned family. It selects only one fixed-capacity,
single-threaded 32-record `pthread_atfork`/`fork` route: reverse prepare,
forward parent/child callbacks after raw Linux `fork=57`, and the parent route
before errno publication on a deterministic `EPERM` raw-fork failure. The
child-only proof composes one bounded ordinary-exit callback after child hooks.
A selected-worker reservation or live mapping fails closed with `EAGAIN`
before callbacks; successful join reopens admission for another complete
fork/child-exit lifecycle. Recursive callbacks and callback-driven worker
creation; foreign/concurrent threads, registration/fork callers, and
selected-worker lifecycle callers; signal
masks/safety; allocator, TSD, cancellation, synchronization, or loader reset;
dynamic TLS; CRT/sysroot integration; general fork/atfork/process-exit/pthread
behavior; family completion; promotion; and public x86 support remain excluded.

The same static archive now also retains musl 1.2.6
`src/process/fork.c`'s private `weak_alias(dummy, __ldso_atfork)` and
`weak_alias(dummy, __aio_atfork)` fallbacks: the pinned AArch64 static manifest
records both in `fork.lo` as weak and records the separate strong
`__aio_atfork` body in `aio.lo`. The staged archive and normal freestanding
candidate preserve that default-visible weak definition, while a caller-owned
strong private `__aio_atfork` spelling wins after a `fork` reference extracts
the archive member and traps on any later dispatch while the selected fork
proof completes. This is archive-binding evidence only. Neither fallback is
invoked, so it adds no loader-lock, loader-reset, mapping, finalization, AIO
queue/lock, request-cancellation, file-descriptor coordination, public AIO,
or general atfork claim.

`./scripts/dev-x86_64.sh libc-pthread-affinity` is a nineteenth private static
artifact in that same still-planned family. It selects only GNU
`pthread_getaffinity_np`/`pthread_setaffinity_np` over the musl-shaped
128-byte, 1024-bit `cpu_set_t`: the bootstrapped process-main task through its
own `pthread_self()` handle and one executing selected worker through its
opaque-TP registry mapping while its parent-written `CLONE_PARENT_SETTID` word
is positive. Direct Linux `sched_getaffinity=204` preserves the initialized
kernel prefix and clears the caller-owned tail exactly as musl does;
`sched_setaffinity=203` changes the admitted task mask. The fixture proves
main/worker get and set, tail clearing, undersized/empty `EINVAL`, preserved
`errno`, and post-join `ESRCH`. Affinity attributes, `sched_*` C APIs, `CPU_*`
helpers, `pthread_getattr_np`, non-self-main and foreign/general handles,
target completion or concurrent join/detach/reaping, scheduler policy, dynamic
or loader TLS, family completion, promotion, and public x86 support remain
excluded.

The CRT-composition artifact,
`./scripts/dev-x86_64.sh libc-crt-static-tls`, composes
the real `rcrt1.o`/`crti.o`/`crtn.o` with that hidden libc owner: after checked
relocation and RELRO, `rcrt1.o` calls
`__crabc_x86_static_tls_bootstrap(original_entry_stack)` before libc's bounded
static `__libc_start_main`. It proves one initialized/TBSS/high-alignment
`PT_TLS` image, preinit/init/main/ordinary-exit/fini order, a 32-registration
no-allocation LIFO callback block, one fresh selected worker, and malformed
`PT_TLS.p_filesz` rejection. `libc.pthread-tls` remains planned: this is not
general pthread/TLS parity, dynamic or loader TLS, a general CRT/libc startup
ABI, broader C11 lifecycle or synchronization, stdio/C++/DSO or concurrent-exit
lifecycle, sysroot support, or public x86 support.

The same static-startup archive owner also retains musl 1.2.6
`src/env/__libc_start_main.c`'s private `weak_alias(dummy1, __init_ssp)`
fallback. The pinned AArch64 static manifest records it as weak in
`__libc_start_main.lo`; the staged archive and normal static-PIE candidate
retain that default-visible binding, while a caller-owned strong private
definition wins after real CRT startup extracts the archive member. This is
archive-binding evidence only: the fallback ignores its entropy pointer and
the selected startup never dispatches it, so it does not initialize a canary,
consume `AT_RANDOM`, select stack-protector startup, or add loader/process
state.

The same static-startup/ordinary-exit owner also retains musl 1.2.6
`src/exit/exit.c`'s private `weak_alias(dummy, __stdio_exit)` fallback. The
pinned AArch64 static manifest records it as weak in `exit.lo` and the separate
strong stream-finalization body in `__stdio_exit.lo`; the staged archive and
static-PIE candidate retain the weak binding, while a caller-owned private
strong spelling wins after real CRT startup extracts the owner. That override
traps on any later dispatch while the full PIMBCAF lifecycle completes, proving
selected ordinary exit never invokes it. This is archive-binding evidence only:
no stream flush, `FILE` inspection, stdio lock/finalization, allocator, loader,
or general process-exit policy is selected.

`./scripts/dev-x86_64.sh libc-crt1-static-tls` is the companion private
ordinary-static composition artifact. It links real Rust
`crt1.o`/`crti.o`/`crtn.o` into an `ET_EXEC` final executable, proves the
archive-free link fails at both hidden TLS and archive-startup boundaries, and
then proves the same TLS-first shared handoff before archive-owned bounded
preinit/init/main/ordinary-exit/fini. Its two-C-unit initialized/TBSS/4096-byte
aligned `PT_TLS` image, fixed 32-registration no-allocation LIFO callback
block, fresh selected worker, and malformed `PT_TLS.p_filesz` status-127
rejection are private evidence only. It does not complete general CRT or libc
startup ABI, pthread/TLS parity, loader TLS, a sysroot, or public x86 support.

`./scripts/dev-x86_64.sh owned-static-sysroot` is the first private installed
artifact shared by the still-planned `sysroot.static-tls` and
`sysroot.owned-artifact` families. It builds two byte-identical trees holding
only the regular-file project headers, five Rust CRT objects, a reconstructed
Rust-member `libc.a`, bounded Rust-only compiler helpers, and normalized
provenance. One real `-nostdinc`/direct-LLD consumer executes the existing
`PIMBCAF` Static Initial TLS v1, pthread, and ordinary-exit lifecycle while
forcing installed `__udivti3`; dependency and linker traces reject ambient
headers, CRT, target libc, compiler runtime, and loader paths. The final
`ET_EXEC` has no interpreter or dynamic dependency and preserves malformed
`PT_TLS.p_filesz` status-127 rejection. No driver, shared libc, loader,
dynamic modes, complete archive closure, distribution/extracted-smoke proof,
family completion, promotion, or public x86 support is selected.

`./scripts/dev-x86_64.sh consumer-static-pie-lto` is a private native
compiler/link/runtime consumer artifact inside still-planned
`consumer.rust-std-lto`. The same no-std `crabc-rs` application plus four
dependency crates are linked as an O3 control and through full LLD
linker-plugin LTO using only deterministic Rust CRT objects, exact pinned
target `libcore`, selected x86
bulk-memory leaf, locked Rust inputs, and owned one-member
`libcrabc-builtins.a`. Both static PIEs execute twice with fixed output;
symbol evidence shows only the full-LTO route internalizes the cross-crate
helper. This does not establish stock Rust `std`, an owned sysroot, libc or
loader integration, source build, family completion, promotion, or public x86
support.

The static archive also has one private C ABI compatibility artifact,
`./scripts/dev-x86_64.sh libc-process-globals-getopt`, inside still-planned
`libc.c-abi-compat`. Its bounded startup publishes validated `argv[0]`-derived
full and short program names before the init callback and main. A common
project-header body runs through pinned static musl and a true freestanding
x86 candidate, proving the four weak same-address program-name/getopt aliases,
mutable alias writes, short and GNU-long parsing, all reset routes, UTF-8
options under `C.UTF-8`, permutation, ambiguity, optional/required arguments,
and long-only precedence. The x86 leaf composes the established AArch64
musl-derived parser through target-local errno/multibyte/string/permanent-stream
adapters only. It deliberately owns no environment object or mutation API,
direct auxv observation beyond the separate `static-c-auxv-observation`
artifact, secure state, loader startup, general locale/stdio, allocator, libc.so,
CRT family, sysroot, C ABI closure, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-auxv-observation` is the adjacent private
`static-c-auxv-observation` artifact in the same still-planned family. Its
project-header C body runs through pinned static musl and a true
`-nostdlib -static` candidate. The selected static startup validates the
initial envp/auxv delimiters, release-publishes at most 4096 kernel-owned
auxiliary-vector pairs before constructors, and exposes only strong
`__getauxval` with weak same-address `getauxval`. The gate proves raw
`AT_PAGESZ`, `AT_PHENT`, and `AT_PHNUM` lookup, zero-valued `AT_SECURE`
stale-errno preservation, and `AT_NULL`/`ENOENT` absence behavior. It does not
select a raw auxv object, secure-execution policy, `secure_getenv`, environment
ownership, auxv-derived system configuration, loader startup, CRT completion,
or public x86 support.

`./scripts/dev-x86_64.sh libc-secure-environment` is a separate private
`static-c-secure-environment` artifact inside still-planned
`libc.posix-runtime`. It composes the already-qualified raw auxv owner with a
private musl-shaped secure-state cache before init callbacks, then exports GNU
`secure_getenv` only. The normal pinned-musl/candidate case and synthetic
final-`AT_SECURE` and UID/EUID-mismatch vectors prove that secure mode returns
null without reading an invalid name while normal mode returns the selected
borrowed `getenv` value. It does not change raw `getauxval`, sanitize
descriptors, mutate credentials or environment state, create or execute
processes, install signal behavior, select loader policy, complete CRT/runtime
families, promote x86, or claim public support.

The same still-planned C ABI family also now selects only the private
`numeric.qsort-helper` ABI leaf. It accounts for musl's strong, uninstalled
`__qsort_r` smoothsort helper and weak same-address `qsort_r` alias through
the existing callback-algorithms static candidate, including direct helper
sorting and a caller strong-alias override. Public `qsort`/`qsort_r` behavior
remains under `numeric.scalar-legacy-callback`; this adds no general sorting,
allocator/runtime, C longjmp/C++ exception, libc.so, CRT, loader, sysroot,
promotion, or public-x86 claim.

The same still-planned C ABI family now has a private selected
`search.tree-intrusive` slice. `./scripts/dev-x86_64.sh
libc-search-tree-intrusive` compares pinned musl's AVL callbacks with a true
freestanding x86 archive: strong `tdelete`/`tdestroy`/`tfind`/`tsearch`/`twalk`
and hidden global `__tsearch_balance`, GNU-only `tdestroy`/`struct qelem`,
AVL rotations and traversal, duplicate/parent-return deletion semantics,
optional key destruction, allocation-failure rollback, and private
mmap/munmap node release. It remains allocation-API-free and does not select
general containers, libc.so, CRT, loader, sysroot, family promotion, or public
x86 support.

The same still-planned C ABI family now also selects the private
`search.hash-table` slice. `./scripts/dev-x86_64.sh libc-search-hash-table`
compares musl 1.2.6's strong ordinary and weak GNU reentrant `<search.h>`
table ABI with a true freestanding x86 archive. The six-profile C/C++ header
matrix keeps `hcreate`/`hdestroy`/`hsearch` unconditional while
`hsearch_data` and `_r` forms remain GNU-only, including under BSD. The common
runtime differential proves zero-capacity construction, unsigned-byte
hashing, duplicate first-entry retention, global/caller-record independence,
grow-and-rehash rollback/retry, repeated-create overwrite/leak, idempotent
destroy, and private mmap/munmap lifecycle via RLIMIT_AS/mincore. It adds no
C allocator export and does not select callback trees, general containers,
process/environment state, libc.so, CRT, loader, sysroot, family promotion, or
public x86 support.

The same still-planned C ABI family now also selects the bounded private
`catalog.gettext` slice. `./scripts/dev-x86_64.sh libc-gettext-catalog` runs
the six-profile pinned-musl/project C/C++ `<libintl.h>`/`<nl_types.h>` matrix
and a static no-catalog reference beside a freestanding x86 candidate. It
proves identity/plural fallback, errno preservation, default/current/validated
domain and binding state, UTF-8-only codesets, and direct missing-catalog
`ENOENT`. The candidate's four permanent bindings, caller-default `catgets`,
and no-op `catclose` are explicit bounded behavior. It does not load or parse
catalog files, read NLSPATH/LANG or locale maps, evaluate plural rules, use
mmap/allocator state, or claim general gettext/catalog translation, family
completion, promotion, or public x86 support.

The same private C ABI family now also selects `error.strsignal`.
`./scripts/dev-x86_64.sh libc-strsignal` proves the pinned-musl fixed
C/POSIX/C.UTF-8 `strsignal` table against a freestanding x86 static archive:
ordinary Linux signals, `RT32` through `RT64`, shared `Unknown signal`
storage, and a `-4..=68` digest. Its strict/POSIX/XOPEN/GNU/BSD C/C++
`<string.h>` matrix keeps the feature gate and unmangled linkage explicit. It
does not select locale/catalog translation, `strerror`/`strerror_l`,
`psignal` or diagnostic printing, signal delivery/disposition, process
termination, errno/TLS, allocation, syscall, general diagnostics, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh consumer-native-facade-lto` is the second private
artifact in that family. It compiles an AArch64-native-facade-shaped no-std
x86 workload—getpid, `/dev/null`, pipe, eventfd, descriptor flags, read/write,
and close—entirely as linker-plugin inputs and links full LTO through the same
closed static-PIE boundary. The separately hashed x86 fixture does not claim
same-source parity because it owns the current static startup and pinned-core
panic seams. Native execution twice, ELF closure, helper internalization, and
owned `__udivti3` attribution prove a real broader facade consumer without an
ambient CRT, libc, loader, or compiler runtime. Stock Rust `std`, an installed
owned sysroot, dynamic libc/loader integration, the complete AArch64 gate,
source build, family completion, promotion, and public x86 support remain
unproved.

The x86 direct Rust facade also has verified allocation-free
`pattern::{fnmatch, FnmatchFlags}` and alloc-gated explicit-root
`pattern::{GlobPath, glob, glob_at}` slices. Their x86 no-std archive proofs
reject C pattern, directory-stream, errno-TLS, and public C allocator
boundaries; the glob probe intentionally supplies a fixed Rust allocator.
They remain private Rust-facade evidence, not C `fnmatch`/`glob`/`globfree` ABI
support, complete facade/platform parity, or public x86 support.

The x86 static C archive separately has one bounded `regex.h` artifact:
`./scripts/dev-x86_64.sh libc-regex` proves the musl-shaped `regex_t`,
`regmatch_t`, flags, result codes, and the four `regcomp`/`regexec`/`regerror`/
`regfree` entries for a fixed-capacity C-locale byte grammar. Unsupported
groups, alternation, counted repetition, backreferences, named character classes,
collating/equivalence elements, and non-ASCII pattern bytes fail at compile
time instead of receiving approximate semantics. This private artifact does
not complete `pattern.regex`, select `wordexp`, expose a Rust regex API or C
allocator, or promote the still-planned text/math/locale/stdio family or
public x86 support.

The private `static-c-math-complex-foundation` artifact now includes the
stateless C99 `cproj*` projection vertical alongside the existing
classification/sign, accessor, and conjugation foundation. Its pinned-musl and
freestanding default-SSE/`-mfpmath=387` fixture proves float/double/binary80
ordinary, either-infinite-component, signed-imaginary-zero, and NaN-only
behavior. The x87 long-double ABI remains target-private while the semantic
rule is mapped to AArch64's binary128 `complex_basic_exports.rs`; `cabs*`,
`carg*`, powers, transcendentals, general complex completion, promotion, and
public x86 support remain unselected.

The x86 static C archive now also has one private
`static-c-elementary-sqrt-fenv` artifact inside still-planned
`libc.text-math-locale-stdio`:
`./scripts/dev-x86_64.sh libc-elementary-sqrt-fenv` runs the same project-header
C fixture through pinned musl and a dependency-free freestanding candidate.
It selects exactly `sqrt`, `sqrtf`, and x87 binary80 `sqrtl`, preserving the
split MXCSR/x87 rounding and exception state and proving all four modes,
inexact results, signed zero, infinities, NaNs, and negative-domain
`FE_INVALID`. It does not select another elementary function, math errno
policy, general scalar/complex math, libc.so, CRT/TLS lifecycle, loader,
sysroot, family completion, promotion, full x86-64 parity, or public x86
support.

The separate private `static-c-fenv-sensitive-rounding` artifact is the first
actual x86 slice of `math.elementary-fenv-sensitive`:
`./scripts/dev-x86_64.sh libc-fenv-rounding` proves `rint*` and `nearbyint*`
for binary32, binary64, and x87 binary80 against pinned musl. All six obey all
four MXCSR/x87 rounding modes and preserve signed zero; `rint*` raises
`FE_INEXACT`, while `nearbyint*` suppresses only a newly raised inexact and
retains preexisting exception flags. It is mapped to the AArch64
`math_lrint.rs`/`math_compat.rs` contract but keeps the binary80 ABI and
instruction order target-private. `exp10*`/`pow10*`, `fdim*`, integer-result
rounding, category/family completion, promotion, and public x86 support remain
outside this individual artifact. The separately selected aggregate described
below composes its `rint*`/`nearbyint*` proof with the corresponding `fdim*`
and `exp10*`/`pow10*` components to select exactly
`math.elementary-fenv-sensitive`.

The separate private `static-c-math-bit-sign` artifact records only binary64/
binary32 `fabs`/`fabsf` and `copysign`/`copysignf`:
`./scripts/dev-x86_64.sh libc-math-bit-sign` runs project-header C and
default-SSE/`-mfpmath=387` C++ function-pointer fixtures through pinned musl
and one freestanding static candidate. It proves ordinary values, signed zero,
infinity, raw quiet/signaling-NaN payload and sign propagation, no new
`FE_INVALID`, and all-four-mode/preexisting-`FE_DIVBYZERO` preservation. The
target leaf uses SSE logical masks only, while final ELF evidence requires
strong crabc-owned definitions and rejects weak compiler-builtins fallback,
binary80 siblings, fdim, fmax/fmin, rounding, special math, family completion,
promotion, and public x86 support.

The separate private `static-c-math-trunc` artifact records only binary64/
binary32 `trunc`/`truncf`: `./scripts/dev-x86_64.sh libc-math-trunc` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. It proves ordinary
and integral values, signed zero, infinity, raw quiet/signaling-NaN payloads,
ordinary and raw-subnormal fractional values, musl's required `FE_INEXACT`
without `FE_INVALID`, all four MXCSR modes, and preexisting-`FE_DIVBYZERO`
preservation. The target leaf retains only musl's raw exponent/fraction masks
and volatile force-evaluation addition; it does not select `truncl`, fenv
rounding, special/complex/binary80 math, family completion, promotion, or
public x86 support.

The separate private `static-c-math-fmod` artifact records only binary64
`fmod` and binary32 `fmodf`: `./scripts/dev-x86_64.sh libc-math-fmod` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its direct musl
1.2.6 `fmod.c`/`fmodf.c` mapping normalizes and repeatedly subtracts raw IEEE
significands, preserving x's sign, signed zero, and subnormal remainders. It
also pins the deliberate `(x*y)/(x*y)` invalid-domain path for zero divisors,
infinite x, and signaling NaNs, plus all four MXCSR modes and preexisting
`FE_DIVBYZERO`. Strong target-owned definitions and final ELF checks reject
weak compiler-builtins fallback, `fmodl`, remainder/remquo/modf, static
rounding/truncation, special/complex/binary80 math, family completion,
promotion, and public x86 support.

The separate private `static-c-math-cbrt` artifact records only binary64
`cbrt` and binary32 `cbrtf`: `./scripts/dev-x86_64.sh libc-math-cbrt` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `cbrt.c`/`cbrtf.c` retains the binary64
estimate/Newton operation order and `cbrtf`'s MXCSR-directed final conversion.
The 168-record differential covers signed zero, normal and subnormal bounds,
ordinary powers, maximum finite values, infinities, quiet/signaling NaNs, all
four requested-and-observed rounding directions, and exception flags. Strong
target-owned definitions and final ELF checks reject weak compiler-builtins
fallback, `cbrtl`, fma, fmod/remainder/modf, static rounding/truncation,
bit-sign/minmax/fdim, special/complex/binary80 math, family completion,
promotion, and public x86 support.

The separate private `static-c-math-exp2` artifact records only binary64
`exp2` and binary32 `exp2f`: `./scripts/dev-x86_64.sh libc-math-exp2` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `exp2.c`/`exp2f.c` localizes the binary64 and
binary32 tables plus all overflow/underflow range helpers, so it neither calls
ambient libm nor shares selected `math.special` state. The 232-record
differential covers signed zero, tiny/subnormal and range-boundary inputs,
ordinary reduction values, infinities, quiet/signaling NaNs, results, flags,
and all four requested-and-observed MXCSR rounding directions. Strong
target-owned definitions and final ELF checks reject weak compiler-builtins
fallback, `exp2l`, adjacent exp/log/pow functions, fenv API/policy,
special/complex/binary80 math, family completion, promotion, and public x86
support.

The separate private `static-c-math-expm1` artifact records only binary64
`expm1` and binary32 `expm1f`: `./scripts/dev-x86_64.sh libc-math-expm1` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `expm1.c`/`expm1f.c` is a direct no-call
closure retaining binary64/binary32 range reduction, polynomial reconstruction,
raw-subnormal `FORCE_EVAL`, and overflow scaling without tables, ambient libm,
or selected `math.special` state. The 248-record differential covers signed
zero, tiny/subnormal and normal bounds, reduction and overflow thresholds,
infinities, quiet/signaling NaNs, results, flags, and all four requested-and-
observed MXCSR rounding directions. Strong target-owned definitions and final
ELF checks reject weak compiler-builtins fallback, `expm1l`, adjacent exp/log/
pow functions, fenv API/policy, special/complex/binary80 math, family
completion, promotion, and public x86 support.

The separate private `static-c-math-log10` artifact records only binary64
`log10` and binary32 `log10f`: `./scripts/dev-x86_64.sh libc-math-log10` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `log10.c`/`log10f.c` is a direct no-call
closure retaining raw classification, subnormal scaling, reduction,
polynomial reconstruction, and zero/negative domain arithmetic without
tables, ambient libm, or selected `math.special` state. The 224-record
differential covers signed-zero divide-by-zero, negative-domain invalid,
tiny/subnormal and normal bounds, reduction points, finite extrema,
infinities, quiet/signaling NaNs, results, flags, and all four requested-and-
observed MXCSR rounding directions. Strong target-owned definitions and final
ELF checks reject weak compiler-builtins fallback, `log10l`, adjacent log/exp/
pow functions, fenv API/policy, special/complex/binary80 math, family
completion, promotion, and public x86 support.

The separate private `static-c-math-ceil` artifact records only binary64
`ceil` and binary32 `ceilf`: `./scripts/dev-x86_64.sh libc-math-ceil` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `ceil.c`/`ceilf.c` retains binary64 raw IEEE
classification plus `toint` add/subtract order and binary32 raw masking plus
volatile `FORCE_EVAL`. The 216-record differential covers signed zero, normal
and subnormal bounds, integral neighbors, large finite values, infinities,
quiet/signaling NaNs, all four requested-and-observed rounding directions,
and exception flags. Strong target-owned definitions and final ELF checks
reject weak compiler-builtins fallback, `ceill`, floor, fma, fmod, cbrt,
fenv policy, special/complex/binary80 math, family completion, promotion, and
public x86 support.

The separate private `static-c-math-floor` artifact records only binary64
`floor` and binary32 `floorf`: `./scripts/dev-x86_64.sh libc-math-floor` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `floor.c`/`floorf.c` retains binary64 raw
IEEE classification plus `toint` add/subtract order and binary32 raw masking
plus volatile `FORCE_EVAL`. The 216-record differential covers signed zero,
normal and subnormal bounds, integral neighbors, large finite values,
infinities, quiet/signaling NaNs, all four requested-and-observed rounding
directions, and exception flags. Strong target-owned definitions and final ELF
checks reject weak compiler-builtins fallback, `floorl`, ceiling, fma, fmod,
cbrt, fenv policy, special/complex/binary80 math, family completion,
promotion, and public x86 support.

The separate private `static-c-math-round` artifact records only binary64
`round` and binary32 `roundf`: `./scripts/dev-x86_64.sh libc-math-round` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `round.c`/`roundf.c` retains sign
normalization, `toint` add/subtract order, and ties-away correction. The
216-record differential covers signed zero, normal and subnormal bounds,
integral neighbors and exact halfway values, large finite values, infinities,
quiet/signaling NaNs, all four requested-and-observed rounding directions,
and exception flags, including musl's tiny-nonzero `FE_INEXACT` path. Strong
target-owned definitions and final ELF checks reject weak compiler-builtins
fallback, `roundl`, fenv API/policy, `rint`/`nearbyint`, truncation, directed
ceiling/floor, fma, fmod, cbrt, special/complex/binary80 math, family
completion, promotion, and public x86 support.

The separate private `static-c-math-log2` artifact records only binary64
`log2` and binary32 `log2f`: `./scripts/dev-x86_64.sh libc-math-log2` runs
project-header C and default-SSE/`-mfpmath=387` C++ function-pointer fixtures
through pinned musl and one freestanding static candidate. Its checked GCC
15.2.0 translation of musl 1.2.6 `log2.c`/`log2f.c`, their two tables, and
four IEEE error helpers preserves close-to-one reconstruction, subnormal
normalization, table reduction, exact powers of two, and zero/domain
expressions. The eight-source closure is localized, so only `log2`/`log2f`
remain public from that closure. The 216-record differential covers signed zero,
normal and subnormal bounds, power-of-two neighbors, high finite values,
infinities, quiet/signaling NaNs, all four requested-and-observed rounding
directions, and exception flags. Strong target-owned definitions and final ELF
checks reject weak compiler-builtins fallback, public source helpers, `log2l`,
other log/exp families, fenv API/policy, special/complex/binary80 math,
family completion, promotion, and public x86 support.

The x86 static archive now also has one private allocation-free wide-character
core: `./scripts/dev-x86_64.sh libc-wide-character` runs an exact
`_XOPEN_SOURCE=700` C/C++ ABI gate and one shared pinned-musl/freestanding
static runtime fixture for 46 wide string/memory, code-point collation,
Unicode classification/simple-case, descriptor, and display-width entries.
Its compressed tables are mechanically transcribed from pinned musl 1.2.6,
and an exhaustive U+0000-through-U+110000 fingerprint prevents Unicode-table
drift. This core adds no locale database, legacy encoding, `wcsdup`,
locale-object or `_l` behavior, wide stdio/format/time surface, allocation,
family completion, promotion, or public x86 support. Wide numeric parsing and
the locale-object/localized-wide surface are separately selected and are not
exercised by this artifact.

A separate `static-c-wcswcs` artifact now records only musl's unconditional
legacy wide-substring alias: `./scripts/dev-x86_64.sh wcswcs-header-abi` proves
the exact strict/POSIX/X/Open/GNU/BSD C11/C++17 `<wchar.h>` spelling and
unmangled linkage, while `./scripts/dev-x86_64.sh libc-wcswcs` first executes
the same project-header fixture with pinned musl and then a true
`-nostdlib -static` candidate. It covers empty-needle identity, first-suffix
selection, null misses, signed full-width `wchar_t` units, and no input
mutation. Its local scalar `wcswcs.c -> wcsstr.c` closure deliberately does
not select `wcsstr`, the broad wide-character object, locale/Unicode policy,
multibyte conversion, general wide text/search, family completion, promotion,
or public x86 support.

A separate private x86 built-in locale-object/localized-wide artifact is now
verified by `./scripts/dev-x86_64.sh libc-locale-object-wide`. Immutable
allocation-free `C`/`POSIX` and `C.UTF-8` tokens, fixed C/POSIX langinfo, and
all 22 wide `_l` entries compose with selected-main/selected-worker Static
Initial TLS v1 `uselocale` state. The pinned-musl/static fixture proves a new
worker begins global-following, parent/worker overrides remain isolated,
multibyte CODESET follows the calling thread, and the exhaustive localized
Unicode classification/case fingerprint matches musl 1.2.6. Arbitrary locale
names, environment and locale maps, allocation/refcounts, gettext, legacy
encodings, bounded multibyte extensions, narrow `_l` APIs, locale-specific
numeric parsing, wide stdio/format/time conversion, family completion,
promotion, and public x86 support remain excluded.

The companion private x86 fixed-locale narrow-text artifact is verified by
`./scripts/dev-x86_64.sh libc-locale-narrow`. Its exact C/C++ ABI and shared
pinned-musl/static fixture cover all 14 narrow ctype/case `_l` entries,
`strcasecmp{,_l}`/`strncasecmp{,_l}`, and unsigned-byte
`strcoll{,_l}`/`strxfrm{,_l}` across `C`, `POSIX`, and `C.UTF-8` tokens.
The exhaustive EOF-plus-256-byte fingerprint and all-or-no-write `strxfrm`
capacity checks compose with the existing calling-thread Static Initial TLS
v1 locale override without adding TLS or locale data. The x86 implementation
follows musl's no-short-write `strxfrm` contract rather than the current
AArch64 helper's truncated-prefix behavior. Arbitrary locale names/maps,
general locale or legacy-encoding databases, Unicode narrow classification,
normalization, allocation, gettext, localized numeric parsing, wide
stdio/format/time conversion, family completion, promotion, and public x86
support remain excluded.

The separate private `static-c-fdim` artifact is the binary64/binary32
positive-difference component of `math.elementary-fenv-sensitive` inside the
still-planned `libc.text-math-locale-stdio` family:
`./scripts/dev-x86_64.sh libc-fdim` differentially executes parenthesized
`fdim`/`fdimf` C calls and default-SSE/`-mfpmath=387` C++ ABI probes against
pinned musl and one freestanding static candidate. It proves ordinary/+0,
left-to-right quiet/signaling-NaN payload, all-four-MXCSR-mode/inexact, and
overflow behavior, while requiring strong target-owned definitions rather than
the weak compiler-builtins fallback. That individual artifact retains only
the binary32/binary64 pair. The separately selected private
`static-c-math-elementary-fenv-sensitive` aggregate reruns it with the
existing `rint*`/`nearbyint*`, `exp10`/`pow10`, `exp10f`/`pow10f`, and opt-in
binary80 `fdiml`/`exp10l`/`pow10l` gates. Its one all-fifteen-call candidate
and per-leaf pinned-musl differentials select exactly
`math.elementary-fenv-sensitive`; the containing family, promotion, and
public x86 support remain unselected.

The adjacent private `static-c-math-minmax` artifact is a distinct
binary64/binary32 extrema proof inside the same still-planned math family:
`./scripts/dev-x86_64.sh libc-math-minmax` runs parenthesized
`fmax`/`fmaxf`/`fmin`/`fminf` C calls and default-SSE/`-mfpmath=387` C++ ABI
probes against pinned musl and one freestanding static candidate. It proves
ordinary/infinite values, Annex-F +0/-0 selection for opposing signs,
left-to-right quiet/signaling-NaN operand return without `FE_INVALID`, all
four MXCSR modes, and preservation of preexisting `FE_DIVBYZERO`. The
target-private leaf classifies raw IEEE bits before SSE comparison; `fmaxl`,
`fminl`, fdim, bit-sign, fenv-rounding, binary80/x87, special/complex math,
family completion, promotion, and public x86 support remain excluded.

The adjacent private x86 ABI-only ctype locator artifact is verified by
`./scripts/dev-x86_64.sh libc-locale-ctype-locators`. It provides exactly
`__ctype_b_loc`, `__ctype_tolower_loc`, and `__ctype_toupper_loc`: stable
pointer-to-pointer locators over immutable 384-entry tables biased by 128.
The shared pinned-musl/static fixture checks every `-128..255` index, the
little-endian representation of musl's network-order class bits, and one
eight-byte table fingerprint while a true static candidate rejects PT_TLS,
errno, allocation, locale-object, and ambient-runtime dependencies. Those
symbols intentionally remain outside installed `ctype.h`; they are an
ABI-compatibility sub-slice toward, but not a selection of, `locale.core`.
It does not add locale selection/maps, legacy encodings, Unicode narrow
classification, localized string or numeric formatting, wide I/O/time
conversion, family completion, promotion, or public x86 support.

The separate private x86 `static-c-locale-error-strings` artifact is verified
by `./scripts/dev-x86_64.sh libc-locale-error-strings`. It adds only strong
`__strerror_l` and musl's weak same-address `strerror_l` alias over the
existing immutable error table. The project/pinned-musl C11/C++17 declaration
matrix and shared static fixture prove the feature-gated public declaration,
unmangled C++ linkage, all nonnegative errno indices `0..=134`, C/POSIX/C.UTF-8
locale objects, selected-thread/global-following stability, pointer equality
with `strerror`, preserved `errno`, and the final ELF binding/address pair.
`LC_GLOBAL_LOCALE` is used only with `uselocale`, not as a `strerror_l`
argument, matching musl. This is a non-promoting ABI sub-slice toward
`locale.core`: it adds no locale map/catalog/environment handling, gettext,
`strfmon`, numeric/wide/iconv text behavior, diagnostic family, general
locale completion, promotion, or public x86 support.

The distinct x86 `locale-profile-header-abi` and `libc-locale-profile` gates
now select the private fixed-profile `locale.core` seam, and only that seam:
`setlocale` and `localeconv`. A strict C11/C++17 pinned-musl/project-header
matrix fixes the unconditional category constants, the 96-byte `struct lconv`
layout, both declarations, and C++ linkage. Its shared C fixture then runs
against pinned musl 1.2.6 and a true `-nostdlib -static --gc-sections`
candidate, proving initial C state, `C`/`POSIX`/`C.UTF-8` queries and
selection, exact `C.UTF-8;C;C;C;C;C` LC_ALL serialization, and the stable
POSIX `lconv` record (`.`/empty text fields/fourteen `CHAR_MAX` monetary
fields). Candidate-only checks reject empty environment selection, arbitrary
map names, and unreturned mixed forms without state mutation. The AArch64
source/export manifests establish existing project ownership of the two C ABI
spellings; pinned musl remains the exact behavior oracle. The candidate rejects
TLS, conversion, locale objects, allocation, environment lookup, gettext,
numeric/time/stdio, and ambient runtime dependencies. This changes only the
inventory state of `locale.core` to selected-private: general locale or
legacy-encoding databases, all other broad locale-core compatibility entries,
family completion, promotion, and public x86 support remain excluded.

The x86 static C archive also has one private caller-owned mapping-core
artifact: `./scripts/dev-x86_64.sh libc-mapping-core` runs the project-header
C/C++ `sys/mman.h` gate and then one pinned-musl/freestanding-static proof for
exactly `mmap`, `munmap`, `mprotect`, `madvise`, `posix_madvise`, and `mincore`.
It preserves the selected musl mapping prechecks/fallback, page-rounded
`mprotect`, POSIX advice convention, and residency behavior. Its `__vm_wait`
site is deliberately local/no-op because the archive does not own loader or
allocator VM state. This is a bounded `static-c-mman-mapping-core` artifact
inside planned `libc.posix-runtime`, not full `sys/mman.h`, C-runtime,
family/platform parity, or public x86 support; its separate direct `msync`
sibling still excludes musl cancellation, while `mremap`, shared memory, and
process-wide VM synchronization remain unselected.

The same archive separately has a private planned mapping-synchronization
evidence artifact: `./scripts/dev-x86_64.sh memory-sync-header-abi` and
`./scripts/dev-x86_64.sh libc-memory-sync` compare unconditional C/C++
`msync`/`MS_*` declarations across eight project-header/pinned-musl profiles,
then run one pinned-musl/freestanding-static candidate. It proves only the
direct no-cancellation x86 `msync=26` route, stale-`errno` success, and Linux
5.10's flag and page-alignment validation before a zero-length success on a
disposable private anonymous mapping. Pinned musl's `syscall_cp` cancellation
path is deliberately absent. This bounded `static-c-memory-sync` artifact is
not full musl `msync`, file-backed shared-map writeback or invalidation,
persistence or durability, complete `sys/mman.h`, C-runtime/family/platform
parity, promotion, or public x86 support.

The same archive separately has a private per-range memory-locking artifact:
`./scripts/dev-x86_64.sh memory-locking-header-abi` and
`./scripts/dev-x86_64.sh libc-memory-locking` prove exactly `mlock`,
`munlock`, and GNU `mlock2(MLOCK_ONFAULT)` through a six-profile
project-header/pinned-musl C/C++ declaration matrix plus one
pinned-musl/freestanding-static candidate. It retains musl's `flags=0`
`mlock2` delegation to `mlock`, direct x86 `mlock=149`, `munlock=150`, and
`mlock2=325`, stale-errno success, first-fault locking, and Linux's
environment-dependent `EPERM`/`EAGAIN`/`ENOMEM` memlock outcome. This is a
bounded `static-c-memory-locking` artifact inside planned
`libc.posix-runtime`, not full `sys/mman.h`, C-runtime, family/platform parity,
or public x86 support; `mlockall`/`munlockall`, the separate direct `msync`
sibling, `mremap`, cancellation, and mapping policy remain unselected here.

The same archive also has a private planned GNU memory-file-descriptor
creation evidence artifact: `./scripts/dev-x86_64.sh memfd-create-header-abi`
and `./scripts/dev-x86_64.sh libc-memfd-create` compare the GNU-only
`memfd_create`/`MFD_*` C/C++ surface across eight project-header/pinned-musl
profiles, including non-GNU hiding and unmangled C++ linkage, then run one
pinned-musl/freestanding-static candidate. It proves only direct x86
`memfd_create=319`, the selected initial-TLS `errno` boundary, ordinary and
249-byte labels, creation-flag forwarding, and Linux's 250-byte/all-ones flag
word `EINVAL` and invalid-pointer `EFAULT` outcomes. This bounded
`static-c-memfd-create` artifact does not establish sealing or C `fcntl`
behavior, `memfd_secret`, huge-page resource/page-size policy, descriptor
lifecycle or close ownership, broad filesystem behavior, C-runtime/family/
platform parity, promotion, or public x86 support.

The same archive has a private rejected-ID clock-adjustment error-ABI
artifact: `./scripts/dev-x86_64.sh clock-adjtime-header-abi` and
`./scripts/dev-x86_64.sh libc-clock-adjtime` map exactly to pinned musl 1.2.6
`src/linux/clock_adjtime.c`'s LP64 non-`CLOCK_REALTIME` direct
`clock_adjtime=305` wrapper. Strict/POSIX/XOPEN/GNU C11/C++17 `<sys/timex.h>`
profiles prove its unconditional exact C/C++ declaration, record layout, and
unmangled linkage. The shared musl/static fixture calls only rejected `-1` and
`CLOCK_MONOTONIC` IDs with a writable zero `struct timex`, accepting Linux's
`EINVAL`, capability-first `EPERM`, or direct `EOPNOTSUPP` result and never
issuing a valid `CLOCK_REALTIME` adjustment. The wrapper has no added
authority guard, so a valid caller remains outside this evidence; this does
not claim clock-adjustment authority, successful discipline/state semantics,
valid-record behavior, clock observation, calendar/timezone/timer behavior, C
time-family completion, promotion, or public x86 support.

The same archive has a private rejected-request clock-setting error-ABI
artifact: `./scripts/dev-x86_64.sh clock-settime-header-abi` and
`./scripts/dev-x86_64.sh libc-clock-settime` map exactly to pinned musl 1.2.6
`src/time/clock_settime.c`'s direct `clock_settime=227` wrapper. The
strict C/C++ `<time.h>` profile hides the POSIX spelling; POSIX/XOPEN/GNU
profiles prove its exact C/C++ declaration and linkage. The shared musl/static
fixture calls only rejected `-1` and `CLOCK_MONOTONIC` IDs with a readable zero
timespec, accepting Linux's `EINVAL` or capability-first `EPERM` ordering and
never issuing a valid `CLOCK_REALTIME` update. The exported direct wrapper has
no added authority guard, so a valid caller remains outside this evidence;
this does not claim clock-setting authority, successful state mutation,
calendar/timezone/timer behavior, C time-family completion, promotion, or
public x86 support.

The same archive has a private rejected-handle POSIX-timer error-ABI artifact:
`./scripts/dev-x86_64.sh timer-getoverrun-header-abi` and
`./scripts/dev-x86_64.sh libc-timer-getoverrun` map exactly to pinned musl
1.2.6 `src/time/timer_getoverrun.c`'s nonnegative direct
`timer_getoverrun=225` wrapper. Strict C11/C++17 `<time.h>` profiles hide the
POSIX spelling; POSIX/XOPEN/GNU profiles prove its exact opaque C/C++ external-C
declaration and linkage. The shared musl/static fixture calls only
nonnegative opaque `timer_t` values `0` and `INT_MAX`, requiring Linux
`EINVAL` without creating, arming, querying, deleting, or observing a valid
POSIX timer. Musl's negative tagged `timer_t` branch requires private
`pthread_impl` state and is explicitly excluded: this leaf never decodes or
dereferences a timer handle. It does not claim timer ownership, overrun values,
valid timer state, signal delivery, calendar/timezone behavior, C time-family
completion, promotion, or public x86 support.

The same archive has a separate private raw-error `timer_delete` artifact:
`./scripts/dev-x86_64.sh timer-delete-header-abi` and
`./scripts/dev-x86_64.sh libc-timer-delete` map exactly to pinned musl 1.2.6
`src/time/timer_delete.c`'s nonnegative direct `timer_delete=226` branch. Its
strict C11/C++17 `<time.h>` profiles hide the POSIX spelling;
POSIX/XOPEN/GNU profiles prove the exact opaque C/C++ external-C declaration
and linkage. In a fresh process that creates no POSIX timers, the shared
musl/static fixture calls only nonnegative opaque `timer_t` values `0` and
`INT_MAX`, requiring raw `-EINVAL` while the caller errno sentinel remains
unchanged. Musl's negative tagged `timer_t` branch requires private
`pthread_impl` state, atomic timer-ID marking, and `SIGTIMER`; it is explicitly
excluded, so this leaf never decodes or dereferences a timer handle. It does
not establish valid timer-deletion semantics, timer ownership/state, signal delivery,
calendar/timezone behavior, C time-family completion, promotion, or public x86
support.

The same archive has a separate private rejected-handle output-preservation
`timer_gettime` artifact: `./scripts/dev-x86_64.sh timer-gettime-header-abi`
and `./scripts/dev-x86_64.sh libc-timer-gettime` map exactly to pinned musl
1.2.6 `src/time/timer_gettime.c`'s nonnegative direct
`timer_gettime=224` rdi/rsi branch. Strict C11/C++17 `<time.h>` profiles hide
the POSIX spelling; POSIX/XOPEN/GNU profiles prove the exact opaque C/C++
external-C declaration, timespec/itimerspec layout, and linkage. In a fresh
process that creates no POSIX timers, the shared musl/static fixture sends only
nonnegative opaque `timer_t` values `0` and `INT_MAX` with initialized writable
output records, requiring `-1`/`EINVAL` and leaving every record unchanged.
Musl's negative tagged `timer_t` branch reconstructs private `pthread_impl`
state and is explicitly excluded, so this leaf never decodes or dereferences a
timer handle. It does not establish valid timer query values, timer ownership
or state, lifecycle, clock/calendar/timezone behavior, signal delivery,
cancellation, C time-family completion, promotion, or public x86 support.

The same archive has a separate private rejected-handle input/output-
preservation `timer_settime` artifact:
`./scripts/dev-x86_64.sh timer-settime-header-abi` and
`./scripts/dev-x86_64.sh libc-timer-settime` map exactly to pinned musl 1.2.6
`src/time/timer_settime.c`'s nonnegative direct `timer_settime=223` branch.
Strict C11/C++17 `<time.h>` profiles hide the POSIX spelling; POSIX/XOPEN/GNU
profiles prove the exact opaque C/C++ external-C declaration, flags argument,
timespec/itimerspec layout, and linkage. In a fresh process that creates no
POSIX timers, the shared musl/static fixture sends only nonnegative opaque
`timer_t` values `0` and `INT_MAX`, flags zero, a valid nonzero request, and
initialized old-value storage, requiring `-1`/`EINVAL` and leaving both records
unchanged. The raw fourth argument is placed in `r10`. Musl's negative tagged
`timer_t` branch reconstructs private `pthread_impl` state and is explicitly
excluded, so this leaf never decodes or dereferences a timer handle. It does
not establish valid timer-control values, timer ownership/state/lifecycle,
signal delivery, clock/calendar/timezone behavior, cancellation, C time-family
completion, promotion, or public x86 support.

The same archive has a private direct time-observation artifact:
`./scripts/dev-x86_64.sh libc-time-observation` proves only `clock`, `time`,
C11 `timespec_get`, `clock_getres`, and `gettimeofday` through a pinned-musl
reference plus freestanding-static candidate. It records the direct x86
`clock_gettime=228`, `clock_getres=229`, and `gettimeofday=96` paths,
normalized outputs, stale-errno behavior, invalid-clock handling, and the
`TIME_UTC`/unsupported-base boundary. It has no vDSO resolver, calendar or
timezone state, clock mutation, POSIX timer, cancellation, libc.so, CRT,
loader, sysroot, family/platform parity, or public-x86-support claim.

`./scripts/dev-x86_64.sh libc-difftime` is a separate private
`static-c-difftime-binary64` artifact in still-planned `libc.posix-runtime`.
Its pinned-musl and true-static C fixture selects only scalar `difftime`:
ordinary positive/negative/zero results, INT64_MAX/INT64_MIN endpoint values,
and the 2047 subtract-before-binary64-conversion boundary. Musl's signed C
subtraction has no cross-endpoint integer-overflow contract, so that case is
not promoted. The leaf has no syscall, errno/TLS, clock observation,
timezone/calendar policy, formatting, timer, or floating-environment policy;
it does not complete the C time family, promote x86, or claim public support.

`./scripts/dev-x86_64.sh libc-sched-yield` is a separate private
`static-c-sched-yield` artifact in planned `libc.posix-runtime`, not a
process-accounting or C11-thread artifact. Its strict/POSIX/XOPEN/GNU C/C++
header matrix and pinned-musl/freestanding-static fixture map exactly to musl
1.2.6 `src/sched/sched_yield.c::sched_yield`: the no-argument Linux
`sched_yield=24` syscall returns status, preserving stale `errno` on success
and translating a fixture-local raw `-EPERM` into `-1` with `errno=EPERM`.
The adjacent C11 `thrd_yield` leaf remains a separate void/raw-result boundary.
This artifact makes no scheduler handoff, fairness, or peer-progress claim and
does not select scheduler policy/parameters, affinity, thread lifecycle,
process control, CRT, loader, sysroot, family completion, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh libc-sched-getcpu` is a distinct private
`static-c-sched-getcpu` GNU current-CPU observation artifact, not scheduler or
time support. Its GNU-only C/C++ `<sched.h>` declaration gate and
pinned-musl/true-static fixture map the result and errno convention to musl
1.2.6 `src/sched/sched_getcpu.c::sched_getcpu`. Musl may use a private x86
vDSO resolver/cache before its direct fallback; this static leaf deliberately
uses only the direct `getcpu=309` fallback, with no resolver or dynamic state.
Normal nonnegative observations preserve stale `errno`; a candidate-only
seccomp denial proves that fallback's `-1`/`EPERM` conversion and is not a
comparison of musl's optional vDSO path. CPU/NUMA/cache output, topology or
migration policy, affinity, scheduler policy/parameters/priority/yield,
thread state, clocks/timers/calendar/timezone/environment, CRT, loader,
sysroot, family completion, promotion, and public x86 support remain excluded.

`./scripts/dev-x86_64.sh libc-sched-cpucount` is a distinct private
`static-c-sched-cpucount` GNU caller-buffer bit-count artifact, not scheduler,
affinity, or time support. Its GNU-only C/C++ `<sched.h>` declaration/macro
gate and pinned-musl/true-static fixture map exactly to musl 1.2.6
`src/sched/sched_cpucount.c::__sched_cpucount`: it counts the eight bit
positions of each selected byte in valid caller-owned `cpu_set_t` storage,
including zero, partial, and full 128-byte masks through `CPU_COUNT_S` and
`CPU_COUNT`. It has no syscall, errno/TLS, allocation, CPU-state observation
or mutation, scheduler policy/parameters/priority/yield, or
clock/timer/calendar/timezone/environment path. Invalid storage, count
conversion above `INT_MAX`, CPU-mask construction/allocation/comparison macros,
family completion, promotion, and public x86 support remain excluded.

`./scripts/dev-x86_64.sh libc-sched-priority-bounds` is a separate private
`static-c-sched-priority-bounds` artifact, not scheduler or time support. Its
strict/POSIX/XOPEN/GNU C/C++ `<sched.h>` declaration gate and
pinned-musl/true-static fixture map exactly to musl 1.2.6
`src/sched/sched_get_priority_max.c`: only the read-only
`sched_get_priority_max`/`sched_get_priority_min` scalar queries for
`SCHED_OTHER`, `SCHED_FIFO`, `SCHED_RR`, and invalid `-1` errno translation
are observed. It selects no policy selection/mutation, current policy or
parameter query, affinity, scheduler-progress guarantee, thread state,
clocks/timers/calendar/timezone/environment, family completion, promotion, or
public x86 support.

`./scripts/dev-x86_64.sh libc-timegm` is a distinct private
`static-c-timegm-utc` artifact in still-planned `libc.posix-runtime`. Its
pinned-musl and true-static C fixture selects only GNU/BSD `timegm` as a
fixed-UTC, caller-owned `struct tm` calculation: complete normalizing rewrite,
negative-month correction, leap carry, valid pre-epoch `-1` with preserved
errno, and `EOVERFLOW` with the original record unchanged. It installs only
the fixed `UTC` offset/name result, makes no syscall, and reads neither `TZ`,
the environment, timezone globals, nor zoneinfo. It does not select
`gmtime`/`mktime`, local conversion, calendar formatting/parsing, clock
observation or mutation, POSIX timers, C time-family completion, promotion, or
public x86 support.

`./scripts/dev-x86_64.sh libc-gmtime-r` is a separate private
`static-c-gmtime-r-utc` artifact in the same still-planned family. Its
pinned-musl and true-static C fixture selects only caller-buffered POSIX
`gmtime_r`: epoch, pre-epoch, and leap-day UTC record conversion with stale
errno preserved, plus null/`EOVERFLOW` with the original record unchanged. It
writes only the fixed `UTC` offset/name result, makes no syscall, and reads
neither `TZ`, the environment, timezone globals, nor zoneinfo. It does not
select non-reentrant storage, local conversion, inverse conversion, calendar
formatting/parsing, clock observation or mutation, POSIX timers, C
time-family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-system-information` is a separate private
`static-c-system-information` artifact inside planned `libc.posix-runtime`.
Its project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only `get_nprocs_conf`, `get_nprocs`, `get_phys_pages`, and
`get_avphys_pages`: musl's fixed 128-byte affinity mask and child-forced
affinity-error CPU-zero fallback, plus successful `sysinfo` physical and
free-plus-buffer page arithmetic. The safe selected page-helper error return
does not claim an output contract for musl's uninitialized-record failure
path. This is not processor-affinity control, topology, general `sysconf`,
load observation, a general system-information capability, C-runtime/family
parity, AArch64 parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-getpagesize` is a separate private
`static-c-getpagesize` artifact inside the same planned family. It maps
pinned musl 1.2.6 `src/legacy/getpagesize.c` to the existing
`system_configuration.rs` source owner: x86_64 `PAGESIZE=4096` makes
`int getpagesize(void)` a no-argument constant leaf. Its C/C++ `<unistd.h>`
gate proves GNU/BSD visibility and exact unmangled linkage while
default/strict/POSIX/XOPEN profiles hide it. The true
`-nostdlib -static -Wl,--gc-sections` fixture verifies direct and
function-pointer 4096 results while its final candidate retains only
`getpagesize`, rejecting co-owned `sysconf`, `confstr`, `pathconf`,
`fpathconf`, and `getdtablesize` plus errno/TLS, auxv, filesystem,
allocator, PLT, call, and syscall paths. This does not promote the broader
system-configuration artifact or claim general page-size discovery, C runtime,
CRT, family completion, or public x86 support.

`./scripts/dev-x86_64.sh libc-getloadavg` is a separate private
`static-c-getloadavg` artifact inside the same planned `libc.posix-runtime`
family. Its GNU/BSD-only project-header C/C++ gate and pinned-musl/
freestanding-static fixture prove only historical `getloadavg`: nonpositive
count/no-output/stale-`errno` behavior, the three-entry clamp, and caller
output scaled from one adjacent Linux `sysinfo` snapshot. Musl's failed
`sysinfo` source path reads an uninitialized local record, so it establishes
no output oracle; the safe candidate instead publishes that errno and returns
`-1` without output. This does not select public `sysinfo`/`uname`, `/proc`,
processor or topology policy, general `sysconf`, a general system-information
capability, C-runtime/family parity, AArch64 parity, or public x86 support.

`./scripts/dev-x86_64.sh sleep-header-abi` and
`./scripts/dev-x86_64.sh libc-sleep` are a separate private `static-c-sleep`
artifact in the same planned family. The default/strict-POSIX/X/Open/GNU/BSD
C11/C++17 `<unistd.h>` matrix and one pinned-musl/true-static C fixture map
only musl 1.2.6 `src/unistd/sleep.c`: `sleep(unsigned)` makes one call through
the already selected direct `nanosleep` seam, returning zero on completion or
the interrupted local record's truncated whole seconds. It proves stale-errno
zero duration and a fixture-local SIGALRM/EINTR remainder, plus one wrapper
object export/relocation with no direct syscall or errno/TLS access. The raw
timer and saved signal state are test plumbing only. It does not select
`usleep`, pthread cancellation, wake timing, signal/mask policy, clocks or
timers, C-runtime/family parity, promotion, or public x86 support.
`./scripts/dev-x86_64.sh libc-fcntl-record-locks` is a separate private
`static-c-fcntl-record-locks` artifact inside planned `libc.posix-runtime`.
Its project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only pointer-bearing nonblocking `fcntl(F_GETLK)`/`fcntl(F_SETLK)` over the
public 32-byte `struct flock`: unlocked query, child-observed parent conflict
and PID, release, stale `errno`, and direct `EBADF`/`EINVAL` outcomes. It does
not select `F_SETLKW` cancellation, OFD locks, `lockf`, `flock`, generic
`fcntl`, descriptor/filesystem policy, family/platform parity, or public x86
support.

`./scripts/dev-x86_64.sh libc-flock` is a separate private `static-c-flock`
artifact inside planned `libc.posix-runtime`. Its project-header C/C++ gate and
pinned-musl/freestanding-static fixture prove only direct nonblocking
`flock`: public operation bits, duplicate open-file-description release state,
a separately opened child conflict and later exclusive reacquisition, stale
`errno`, and direct `EWOULDBLOCK`/`EAGAIN`, `EBADF`, and `EINVAL` outcomes. It
does not select `fcntl` record-lock interaction, `lockf`, descriptor/pathname
policy, network/distributed-filesystem semantics, family/platform parity, or
public x86 support.

`./scripts/dev-x86_64.sh libc-sendfile` is a separate private
`static-c-sendfile` artifact inside planned `libc.posix-runtime`. Its
project-header C/C++ gate and pinned-musl/freestanding-static fixture prove
only direct regular-file `sendfile`: an explicit signed `off_t` advances while
leaving the input position unchanged, a null offset advances that shared
position through short-transfer and EOF-zero cases, and stale `errno`,
`EINVAL`, and `EBADF` are translated directly. It does not select pathname,
socket/pipe, splice, copy-file-range, vector-I/O, durability, cancellation,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-tee` is a separate private `static-c-tee`
artifact inside planned `libc.posix-runtime`. Its GNU-only project-header C/C++
gate and pinned-musl/freestanding-static fixture prove only direct pipe-buffer
`tee`: source bytes remain readable after an equal destination-pipe copy,
zero-length success leaves stale `errno`, and a bad source descriptor maps to
`EBADF`. It does not select pipe creation or ownership, generic descriptor
policy, `splice`/`vmsplice` transfer, cancellation, family/platform parity, or
public x86 support.

`./scripts/dev-x86_64.sh libc-splice` is a separate private `static-c-splice`
artifact inside planned `libc.posix-runtime`. Its GNU-only project-header C/C++
gate and pinned-musl/freestanding-static fixture prove only one regular-file-to-
pipe explicit-input-offset `splice=275` request: wrapper/raw result and
pointed-offset agreement, copied pipe bytes, retained file position, stale
`errno` on success, plus direct invalid-flags `EINVAL` and bad-input `EBADF`.
It does not select pathname opening, descriptor or pipe ownership, blocking,
fallback, general pipe/filesystem transfer policy,
`tee`/`vmsplice`/`sendfile`/`copy_file_range`, durability, cancellation,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-sync-file-range` is a separate private
`static-c-sync-file-range` artifact inside planned `libc.posix-runtime`. Its
GNU-only project-header C/C++ gate and pinned-musl/freestanding-static fixture
prove only one direct regular-file `sync_file_range=277` request: exact raw
result/`errno` agreement, retained shared descriptor position, stale `errno` on
success, plus direct invalid-flags `EINVAL` and bad-descriptor `EBADF`. It does
not select pathname opening or descriptor ownership, cache/writeback policy or
durability, `sync`/`syncfs`, `fallocate`, cancellation, family/platform parity,
or public x86 support.

`./scripts/dev-x86_64.sh libc-copy-file-range` is a separate private
`static-c-copy-file-range` artifact inside planned `libc.posix-runtime`. Its
GNU-only project-header C/C++ gate and pinned-musl/freestanding-static fixture
prove only one same-filesystem regular-file explicit-offset
`copy_file_range=326` request: wrapper/raw result and pointed-offset agreement,
copied bytes, retained shared descriptor positions, stale `errno` on success,
plus direct invalid-flags `EINVAL` and bad-input `EBADF`. It does not select
pathname opening or descriptor ownership, copy fallback or cross-filesystem
policy, `sendfile`/`splice`, durability, cancellation, family/platform parity,
or public x86 support.

`./scripts/dev-x86_64.sh libc-posix-fallocate` is a separate private
`static-c-posix-fallocate` artifact inside planned `libc.posix-runtime`. Its
strict and large-file-only project-header C/C++ profiles, plus its
pinned-musl/freestanding-static fixture, prove only mode-zero C
`posix_fallocate`: signed LP64 offset/length forwarding, an unlinked regular
file range [4096, 8192) with retained prefix, zero-filled extension,
and stable position, plus direct positive `EINVAL`/`EBADF` returns that leave
stale `errno` unchanged. It does not select general `fallocate` flags,
pathname allocation, filesystem fallback/policy, durability, cancellation,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-descriptor-advice` is a separate private
`static-c-descriptor-advice` artifact inside the same planned family. Its
strict/no-feature, GNU-only, and large-file-only project-header C/C++
`<fcntl.h>` profiles prove unconditional `posix_fadvise`, the six
`POSIX_FADV_*` values, GNU-only `readahead`, and the LF64-only
`posix_fadvise64` macro alias to the unmangled base. Its pinned-musl and
freestanding-static fixture proves only `fadvise64=221` direct positive
`EINVAL`/`EBADF` returns with stale `errno` unchanged, and `readahead=187`
`-1`/published-`EINVAL`/`EBADF` behavior, across an unlinked regular file
with zero-length advice and stable position/size. It makes no cache-residency
or cache-effect claim. Cache policy/effects, allocation, pathname and
filesystem policy, durability, cancellation, family/platform parity, and
public x86 support remain unselected.

`./scripts/dev-x86_64.sh libc-filesystem-capacity` is a separate private
`static-c-filesystem-capacity` artifact inside planned `libc.posix-runtime`.
Its seven-base-plus-two-LF64 project-header C/C++ `sys/statfs.h`/
`sys/statvfs.h` matrix proves only the four declarations, x86 LP64 records,
mount flags, unmangled C++ references, and LF64 macro aliases. Its
pinned-musl/freestanding-static fixture then proves only `statfs`/`fstatfs`
through `statfs=137`/`fstatfs=138`, plus musl `src/stat/statvfs.c`'s derived
`statvfs`/`fstatvfs` conversion: public statfs zeroing, successful statvfs
zero-and-map results (including fragment-size fallback, `f_favail`, and fsid
mapping), stale errno on success, and direct ENOENT/EBADF errors. It does not
select capacity/quota/accounting policy, pathname behavior, general filesystem
support, family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-vector-io` is a separate private
`static-c-vector-io` artifact inside the same planned family. Its fourteen
project-header/pinned-musl C/C++ `<sys/uio.h>` profiles prove only x86 LP64
`iovec`, `UIO_MAXIOV`, base and GNU/BSD-positioned declarations, GNU-only
v2/RWF/process-vm declarations and hiding, LF64 aliases, and unmangled C++
linkage. Its pinned-musl/freestanding-static fixture proves only direct
`readv`/`writev`/`preadv`/`pwritev`: segment order, unchanged positioned
offsets, invalid count/signed-offset errno results, an independently observed
offset above 4 GiB, and musl's selected pwritev append boundary. It does not
select cancellation, v2/process-vm runtime, scalar descriptor I/O, stdio,
family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh socket-messages-header-abi` and
`./scripts/dev-x86_64.sh libc-socket-messages` are a separate private
`static-c-socket-messages` artifact inside still-planned `libc.posix-runtime`.
The POSIX/GNU/BSD project-header/pinned-musl C/C++ matrix and freestanding
fixture cover exactly `setsockopt`, `getsockopt`, `sendmsg`, `recvmsg`,
`sendmmsg`, `recvmmsg`, and `sockatmark`: the padded public x86 message
records, a bounded 1056-byte ancillary-control copy, `sendmmsg`'s padded
`sendmsg` loop rather than raw `SYS_sendmmsg`, and direct `recvmmsg`/
`SIOCATMARK`. Cancellation, resolver/netdb, generic socket or ioctl behavior,
family/platform parity, and public x86 support remain outside this leaf.

`./scripts/dev-x86_64.sh libc-access` is another private
`static-c-filesystem-access` artifact inside planned `libc.posix-runtime`.
It proves only static C `access`, `faccessat`, `euidaccess`, and weak
same-address `eaccess` through pinned-musl and freestanding-archive runs:
real versus effective credentials, zero-flag legacy and flags-bearing Linux
paths, direct errno behavior, and strong caller alias override. It is not
filesystem capability or C-runtime parity; pathname policy, `fchmodat`,
broader C credential/process behavior, and public x86 support remain planned.

The separate private `libc-lchmod-unsupported` command
(`./scripts/dev-x86_64.sh libc-lchmod-unsupported`) selects only the
GNU/BSD-visible C `lchmod` ABI: a project-header fixture runs a raw-created
dangling symlink through pinned musl and then a `-nostdlib -static` candidate.
Both return `-1` with `EOPNOTSUPP`/`ENOTSUP` 95; the candidate deliberately
does no pathname resolution or syscall, and its candidate-only null-path check
proves that fixed pre-resolution boundary. It does not select `fchmodat`, path or
permission policy, directory/extensions behavior, allocation, cancellation,
family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh mkfifo-header-abi` is a separate eight-profile
C11/C++17 project-header/pinned-musl declaration gate for unconditional
`mkfifo(const char *, mode_t)`, x86 LP64 `mode_t`, FIFO mode constants, and
unmangled C++ linkage. Its paired private `./scripts/dev-x86_64.sh libc-mkfifo`
artifact runs one project-header C fixture through pinned musl 1.2.6 and a
true `-nostdlib -static` archive candidate. It implements only musl's
`mode | S_IFIFO` `mkfifo` behavior through direct Linux x86-64 `mknodat=259`
at `AT_FDCWD=-100` with dev 0; child-local shell `umask 000` makes FIFO type
and requested mode observable while stale-errno success, duplicate `EEXIST`,
and null-path `EFAULT` are checked. It does not select the broader
`filesystem.special-nodes` capability, `mkfifoat`, `mknod`, `mknodat`,
device-node or C-umask policy, pathname/CWD policy, locale/process state,
filesystem-family completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh mkdirat-header-abi` is a distinct eight-profile
C11/C++17 project-header/pinned-musl declaration gate for unconditional
`mkdirat(int, const char *, mode_t)`, x86 LP64 `int`/`mode_t`, directory mode
constants, `SYS_mkdirat=258`, and unmangled C++ linkage. Its paired private
`./scripts/dev-x86_64.sh libc-mkdirat` artifact runs one project-header C
fixture through pinned musl 1.2.6 and a true `-nostdlib -static` archive
candidate. It implements only musl's caller-supplied-dirfd direct Linux
x86-64 `mkdirat=258` body; raw setup opens one fixture-owned directory and
compares selected 0750/0000 modes with a raw 0710 directory while preserving
stale errno on success, duplicate `EEXIST`, invalid-dirfd `EBADF`, null-path
`EFAULT`, and missing-parent `ENOENT`. The child-local shell `umask 000` only
makes requested modes observable. It neither chooses `AT_FDCWD` nor selects
`mkdir`, `mkfifo`, `mkfifoat`, `mknod`, `mknodat`, other pathname operations,
C-umask/CWD/pathname/permission policy, directory streams, allocation,
locale/process state, filesystem-family completion, promotion, or public x86
support.

`./scripts/dev-x86_64.sh mkfifoat-header-abi` is a distinct eight-profile
C11/C++17 project-header/pinned-musl declaration gate for unconditional
`mkfifoat(int, const char *, mode_t)`, x86 LP64 `int`/`mode_t`, FIFO mode
constants, and unmangled C++ linkage. Its paired private
`./scripts/dev-x86_64.sh libc-mkfifoat` artifact runs one project-header C
fixture through pinned musl 1.2.6 and a true `-nostdlib -static` archive
candidate. It implements only musl's caller-supplied-dirfd `mode | S_IFIFO`
behavior through direct Linux x86-64 `mknodat=259` with dev 0; raw setup opens
one fixture-owned directory and validates relative creation, stale-errno
success, duplicate `EEXIST`, invalid-dirfd `EBADF`, and null-path `EFAULT`.
The child-local shell `umask 000` only makes the requested FIFO mode observable.
It neither chooses `AT_FDCWD` nor selects `mkfifo`, `mknod`, `mknodat`,
device-node/C-umask/CWD/pathname policy, locale/process state, the broader
`filesystem.special-nodes` capability, family completion, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh readlinkat-header-abi` is a separate eight-profile
C11/C++17 project-header/pinned-musl declaration gate for
`readlinkat(int, const char *, char *, size_t)`. Its paired private
`./scripts/dev-x86_64.sh libc-readlinkat` artifact maps only musl 1.2.6's
direct Linux x86-64 `readlinkat=267` body. Its raw-owned fixture proves
full/truncated non-NUL caller bytes, stale-errno success, the direct
`ENOENT`/`EINVAL`/`EBADF`/`EFAULT` paths, and musl's zero-capacity private
one-byte dummy: that call returns zero while preserving the caller buffer,
where a raw zero-capacity request returns `EINVAL`. Ordinary `readlink`, other
*at entries, pathname/CWD policy, directory streams, allocation, cancellation,
a Rust facade, promotion, and public x86 support remain excluded.

`./scripts/dev-x86_64.sh linkat-header-abi` is a distinct eight-profile
C11/C++17 project-header/pinned-musl declaration gate for unconditional
`linkat(int, const char *, int, const char *, int)`, x86 LP64 scalar spelling,
and unmangled C++ linkage. Its paired private
`./scripts/dev-x86_64.sh libc-linkat` artifact maps only musl 1.2.6's direct
Linux x86-64 `linkat=265` body. A raw-owned fixture opens two caller-supplied
fixture directory descriptors and a regular source, then proves the selected
call creates a descriptor-relative same-inode hard link against a raw request.
A raw-created source symlink proves forwarding `AT_SYMLINK_FOLLOW`; the fixture
also checks stale-errno success, duplicate `EEXIST`, bad old/new dirfds
`EBADF`, null old/new paths `EFAULT`, a missing source `ENOENT`, and invalid
flags `EINVAL`. It excludes ordinary `link`, every other *at entry, pathname/
CWD/namespace policy, directory streams, allocation, cancellation, a Rust
facade, filesystem capability completion, promotion, and public x86 support.

`./scripts/dev-x86_64.sh lchown-header-abi` is a separate eight-profile
C11/C++17 project-header/pinned-musl declaration gate for unconditional
`lchown(const char *, uid_t, gid_t)`, x86 four-byte unsigned `uid_t`/`gid_t`
spelling, and unmangled C++ linkage. Its paired private
`./scripts/dev-x86_64.sh libc-lchown` artifact selects only musl 1.2.6's
direct Linux x86-64 `lchown=94` branch. A raw-owned fixture creates and
observes a dangling symlink, then uses all-ones no-change owner/group words:
candidate stale-errno success and one raw request establish final-component
no-follow behavior without requiring `CAP_CHOWN`; missing/empty `ENOENT` and
null `EFAULT` are pinned too. It excludes `chown`, `fchown`, `fchownat`,
musl's non-x86 fallback, credential/ownership policy, another pathname entry,
pathname/CWD/namespace policy, allocation, a Rust facade, filesystem
capability completion, promotion, and public x86 support.

`./scripts/dev-x86_64.sh hasmntopt-header-abi` is a separate eight-profile
C11/C++17 project-header/pinned-musl gate for unconditional
`hasmntopt(const struct mntent *, const char *)`, the x86 LP64 40-byte,
8-byte-aligned `struct mntent` record with 0/8/16/24/32/36 field offsets, and
unmangled C++ linkage. The paired private
`./scripts/dev-x86_64.sh libc-hasmntopt` artifact maps only pinned musl 1.2.6
`src/misc/mntent.c::hasmntopt`: caller-owned `mnt_opts` bytes match only at a
NUL/comma/equals boundary and return the exact borrowed element pointer. Its
one-object `-nostdlib -static` fixture compares comma/equals matches,
prefix/absent negatives, empty-first-element behavior, and unchanged bytes;
it rejects syscall/call, TLS, errno, helper-string, FILE/stdio, allocation,
and mount state closures. It does not select `setmntent`, `endmntent`,
`getmntent`, `getmntent_r`, `addmntent`, `/etc/mtab` lookup, mount parsing,
general string APIs, locale objects/environment/catalogs/general locale,
pathname/CWD policy, a Rust facade, family completion, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh libc-descriptor-lifecycle` is a separate private
`static-c-descriptor-lifecycle` composition artifact inside that same planned
family. It runs one project-header C body through pinned musl and then a
freestanding static archive, composing the already selected descriptor-entry,
fcntl-status, descriptor-I/O, and `fstat`/`fstatat` leaves through a
PID-isolated relative-directory lifecycle. Raw syscalls only make and remove
the test directory. It proves no descriptor/filesystem capability, general
C runtime, cancellation behavior, family completion, AArch64 parity, or
public x86 support.

`./scripts/dev-x86_64.sh libc-timestamp-updates` is a separate private
`static-c-timestamp-updates` artifact inside planned `libc.posix-runtime`.
It runs one project-header C body through pinned musl and then through the
archive-owned `rcrt1`/`crti`/`crtn` static-PIE startup route. It proves only
`utimensat`, `futimens`, strong `__futimesat` with its weak same-address
`futimesat` alias, `futimes`, `lutimes`, `utimes`, and `utime`, including the
selected `UTIME_NOW`/`UTIME_OMIT` and legacy conversion boundaries. It does
not establish filesystem policy, a general C runtime, dynamic libc, loader,
CRT/sysroot, family completion, AArch64 parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-signal-altstack` is one separate private
`static-c-signal-altstack` artifact inside planned `libc.posix-runtime`. Its
pinned-musl/freestanding-static C proof covers the 24-byte x86 `stack_t`
query/install/disable boundary, fixed-minimum `ENOMEM`/`EINVAL` prechecks, and
one `SA_ONSTACK` handler entry/return through the existing restorer. It preserves
musl's size-before-`SS_ONSTACK` ordering while explicitly retaining the
selected fixed `MINSIGSTKSZ=2048`, not musl's startup-auxv dynamic minimum. It
does not select stack allocation/ownership, generic delivery, waits/queues,
pthread signal policy, libc.so, CRT, loader, sysroot, family/platform parity,
or public x86 support.

`./scripts/dev-x86_64.sh libc-signal-execution` is one further private
`static-c-process-signal-execution` artifact inside planned
`libc.posix-runtime`. Its pinned-musl/freestanding-static C proof composes the
existing simple signal action/set/mask boundary with exactly `kill`, `killpg`,
`raise`, `sigqueue`, `sigtimedwait`, `sigwaitinfo`, and `sigwait`, including
the application-signal mask transaction, queued `siginfo_t` layout, stale
`errno`, EINTR retry, and musl `sigwait` `-1`/`errno` failure convention. A
fixture-only raw child makes the interrupted wait deterministic. It does not
select general process lifecycle, `tgkill`, alternate stacks outside their
separate artifact, signalfd, legacy
signal APIs, pthread signal policy, libc.so, CRT, loader, sysroot, family or
platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-timerfd` is a separate private
`static-c-timerfd` artifact inside planned `libc.posix-runtime`. Its 16-row
pinned-musl/project `<sys/timerfd.h>` C/C++ matrix keeps strict-profile
incomplete `itimerspec` pointer declarations distinct from the POSIX-profile
32-byte align-8 record definition. Its pinned-musl/freestanding-static C proof
exposes exactly `timerfd_create`, `timerfd_settime`, and `timerfd_gettime`;
proves x86 `283`/`286`/`287` direct syscall paths, initial-TLS errno,
`TFD_NONBLOCK`/`TFD_CLOEXEC`, invalid clock/flag and null-pointer errors,
one-shot eight-byte expiration reads, periodic query/disarm, and
`TFD_TIMER_ABSTIME`/`TFD_TIMER_CANCEL_ON_SET` acceptance. It does not select
POSIX process timers, signal policy, callbacks/timer registry, a generic event
loop/readiness policy, pthread cancellation, libc.so, CRT, loader, sysroot,
family/platform parity, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-signalfd` is a separate private
`static-c-signalfd` artifact inside planned `libc.posix-runtime`. Its 16-row
pinned-musl/project `<sys/signalfd.h>` C/C++ matrix proves the public
declaration, unmangled C++ spelling, 128-byte align-8 `sigset_t`, and 128-byte
align-8 `signalfd_siginfo` layout. Its pinned-musl/freestanding-static C proof
exposes exactly `signalfd`; proves Linux `signalfd4=289`, the eight-byte kernel
signal-set argument in `rdx`, initial-TLS errno, invalid creation-flag/null-mask
errors, `SFD_NONBLOCK`/`SFD_CLOEXEC`, stale errno, empty `EAGAIN`, queued
`SIGUSR1`/`SIGUSR2` records, and flags ignored while updating an existing
descriptor. It does not select signal-mask/disposition policy, generic process
signaling, timer/readiness policy, a general event loop, pthread cancellation,
libc.so, CRT, loader, sysroot, family/platform parity, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-sigpause` is a separate private
`static-c-sigpause` artifact inside planned `libc.posix-runtime`. Its one-symbol
pinned-musl/freestanding-static C proof follows musl 1.2.6's current-mask query,
removal of exactly one valid application signal from a private eight-byte kernel
word, and `rt_sigsuspend=130` wait. A runner-owned FIFO queues blocked
`SIGUSR1`; it proves `sigpause(0)` `EINVAL`, valid `-1`/`EINTR` handler return,
and restoration of the original `SIGUSR1`/`SIGUSR2` mask. It does not select a
public signal mask/action interface, generic delivery or process control,
queues/signalfd, timers/readiness policy, pthread cancellation, libc.so, CRT,
loader, sysroot, family/platform parity, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-sigisemptyset` is a separate private
`static-c-sigisemptyset` artifact inside planned `libc.posix-runtime`. Its
one-symbol pinned-musl/freestanding-static C proof follows musl 1.2.6's GNU
`sigisemptyset`: x86 `_NSIG=65` yields one selected unsigned-long word, so it
returns one iff the first eight-byte public `sigset_t` word is zero and ignores
the remaining fifteen words. The fixture proves tail-only nonzero storage,
first-word nonzero storage, no caller writes, and stale-`errno` preservation;
the shared header gate proves GNU visibility and strict-POSIX hiding. It does
not itself select the separately bounded `sigandset`/`sigorset` leaf,
handlers/actions, mask or process signaling, waits, queues, descriptors,
timers, pthread policy, libc.so, CRT, loader, sysroot, family/platform parity,
promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-sigandset-sigorset` is a separate private
`static-c-sigandset-sigorset` artifact inside planned `libc.posix-runtime`.
Its two-symbol pinned-musl/freestanding-static C proof follows musl 1.2.6's
GNU `sigandset` and `sigorset`: x86 `_NSIG=65` makes `SST_SIZE` one, so each
helper reads the left and right first eight-byte public `sigset_t` words and
writes only the destination first word with AND or OR. The shared C header
gate and paired C++17 declaration/linkage probe keep both signatures GNU-only;
the fixture proves ordinary operations, tail preservation, destination-equals-
left AND, destination-equals-right OR, zero returns, stale `errno`, and no
syscall. It does not select the `sigisemptyset` predicate, handlers/actions,
mask or process signaling, waits, queues, descriptors, timers, pthread policy,
libc.so, CRT, loader, sysroot, family/platform parity, promotion, or public x86
support.

`./scripts/dev-x86_64.sh libc-sigpending` is a separate private
`static-c-sigpending` artifact inside planned `libc.posix-runtime`. Its
one-symbol pinned-musl/freestanding-static C proof follows musl 1.2.6's POSIX
`sigpending`: Linux `rt_sigpending=127` writes only the first eight-byte public
`sigset_t` word, leaves the fifteen-word tail caller-resident, preserves stale
`errno` on success, and exposes null/non-null `EFAULT`. Fixture-only raw
block-and-`tgkill` setup queues one `SIGUSR1` to observe the returned pending
bit; it selects no C mask, action, delivery, or wait API. The shared C and
paired C++17 proofs retain the exact POSIX declaration and unmangled linkage.
It does not select handlers/actions, signal masks, process signaling, waits,
queues, descriptors, timers, pthread policy, libc.so, CRT, loader, sysroot,
family/platform parity, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-sigrtmax` is a separate private
`static-c-sigrtmax` artifact inside planned `libc.posix-runtime`. Its
one-symbol pinned-musl/freestanding-static C proof follows
`src/signal/sigrtmax.c`: x86 `_NSIG=65` makes the POSIX-family
`__libc_current_sigrtmax(void)` bridge and the public `SIGRTMAX` macro return
64. It proves direct/macro equality, a repeated result, stale `errno`, and no
call or syscall; the shared C signal gate plus C++17 POSIX/GNU matrix retain
the exact unmangled declaration. It leaves the separately selected realtime
minimum bridge out of its candidate and does not select handlers/actions,
masks, process signaling, waits, queues, descriptors, timers, pthread policy,
libc.so, CRT, loader, sysroot, family/platform parity, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh libc-sigrtmin` is a separate private
`static-c-sigrtmin` artifact inside planned `libc.posix-runtime`. Its
one-symbol pinned-musl/freestanding-static C proof follows
`src/signal/sigrtmin.c`: direct POSIX-family
`__libc_current_sigrtmin(void)` returns fixed 35. It proves direct/public
`SIGRTMIN` value equality, a repeated result, stale `errno`, and no call or
syscall; the shared C signal gate plus C++17 POSIX/GNU matrix retain the exact
unmangled declaration. The project header deliberately retains its
pre-existing fixed x86 `SIGRTMIN` spelling; this selected bridge does not turn
that into a general header rewrite. It leaves the separate realtime-maximum
bridge out of its candidate and does not select handlers/actions, masks,
process signaling, waits, queues, descriptors, timers, pthread policy,
libc.so, CRT, loader, sysroot, family/platform parity, promotion, or public
x86 support.

`./scripts/dev-x86_64.sh libc-process-signal` now composes the frozen
34-spelling `process.signal` roster as one selected-private slice in the same
still-planned family. It reruns the 16 existing signal component gates, then
checks that the frozen default selected-static archive remains unchanged while
the exact opt-in `x86-signal-legacy-aliases`, `x86-signal-sysv-helpers`, and
`x86-signal-reporting` closure adds only `__sysv_signal`, `bsd_signal`,
`psiginfo`, `psignal`, `sighold`, `sigignore`, `sigrelse`, and `sigset`.
`psignal-header-abi` and `libc-psignal` add the reporting pair's strict-versus-
POSIX/X/Open/GNU/BSD C/C++ declarations plus pinned-musl/static proof of
normal/null-prefix output, `si_signo` forwarding, success-only errno
restoration, and closed-stderr/nonblocking failure behavior. The selected
permanent-stream boundary requires external stderr serialization; it is not
async-signal-safe and does not claim general FILE locking, locale/orientation,
or musl partial-short-write buffering parity. This does not complete signal
management, process lifecycle, pthread/cancellation policy, libc.so, CRT,
loader, sysroot, the family, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-sched-getscheduler` is a separate private
`static-c-sched-getscheduler` artifact inside planned `libc.posix-runtime`.
Pinned musl 1.2.6's `src/sched/sched_getscheduler.c` intentionally turns the
POSIX process-facing `sched_getscheduler(pid_t)` spelling into `-1`/`ENOSYS`
for every input rather than forwarding Linux x86 raw syscall 145, whose target
is a thread. Its true-static C body first proves raw current-task success and
raw invalid `-EINVAL`, then proves the musl C ABI result for 0, -1, and
INT_MAX. The strict/POSIX/X/Open/GNU C/C++ header matrix retains the exact
unmangled declaration. This is not scheduler support: mutation, parameters,
priority bounds, `sched_yield`, affinity, pthread scheduling attributes,
lifecycle, family/platform parity, promotion, and public x86 support remain
outside the artifact.

`./scripts/dev-x86_64.sh libc-sched-setaffinity` is a separate private
`static-c-sched-setaffinity` artifact inside planned `libc.posix-runtime`.
Its GNU-only C/C++ header gate retains exactly
`sched_setaffinity(pid_t, size_t, const cpu_set_t *)` and the 128-byte,
align-8 `cpu_set_t` layout while strict/POSIX/X/Open profiles hide it. Its
pinned-musl/true-static C body maps only musl 1.2.6
`src/sched/affinity.c::sched_setaffinity`: direct Linux x86 syscall 203
preserves stale `errno` on success and translates raw errors through the
initial-TLS C slot. The fixture obtains a valid current mask only through a
fixture-local raw observation, reapplies that exact nonempty mask without
broadening it, and proves `EINVAL` for an empty mask, `ESRCH` for `INT_MAX`,
and `EFAULT` for a null full-size mask. It does not select `sched_getaffinity`,
CPU helpers, scheduler policy/parameters, pthread affinity/lifecycle, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-alarm` is a separate private `static-c-alarm`
artifact inside planned `libc.posix-runtime`. Its one-symbol
pinned-musl/freestanding-static C proof maps only musl 1.2.6
`src/unistd/alarm.c` plus the x86 LP64 direct branch of
`src/signal/setitimer.c`: `time_t` and `long` are both eight bytes, so it
replaces `ITIMER_REAL` with a zero-interval whole-second record, ignores the
raw `setitimer=38` C return after its ordinary errno side effect, and returns
the old `tv_sec + !!tv_usec`. A
fixture-private raw syscall seeds and inspects a far-future record to prove
the `604800.999999` to `604801` ceiling, one-shot replacement, disarm return,
and stale `errno`; the shared C11/C++17 unistd matrix retains the unconditional
`unsigned int alarm(unsigned int)` declaration and C++ linkage. It exports
neither public `setitimer` nor `ualarm` and does not select handlers/actions,
signal masks, waits, delivery policy, timer-family completion, pthread policy,
libc.so, CRT, loader, sysroot, family/platform parity, promotion, or public x86
support.

`./scripts/dev-x86_64.sh ualarm-header-abi` and
`./scripts/dev-x86_64.sh libc-ualarm` are the paired private opt-in
`x86-ualarm` `static-c-ualarm` evidence inside planned `libc.posix-runtime`.
The project-first/pinned-musl C11/C++17 `<unistd.h>` matrix proves only
`unsigned int ualarm(unsigned int, unsigned int)`: GNU/BSD/XOPEN<700 exposes
the declaration with unmangled C++ linkage, while default, strict, POSIX, and
XOPEN=700 hide it. The feature archive maps only musl 1.2.6
`src/unistd/ualarm.c` and the x86 LP64 direct branch of
`src/signal/setitimer.c`; valid microsecond `ITIMER_REAL` replacement and
return behavior run through pinned musl and a `-nostdlib -static` candidate,
while the one-million-microsecond error checks `EINVAL` and preserved timer
state without inspecting musl's indeterminate failure return. `x86-ualarm`
adds exactly `ualarm` only to its feature archive; the default selected-static
archive and `static_c_abi_exports.txt` remain unchanged. This adds no
capability, family completion, promotion, timer/signal policy, or public x86
support claim.

`./scripts/dev-x86_64.sh libc-usleep` is a separate private `static-c-usleep`
artifact inside planned `libc.posix-runtime`. Its one-symbol pinned-musl and
freestanding-static C proof maps only musl 1.2.6 `src/unistd/usleep.c`: an
unsigned microsecond argument normalizes to one LP64 `timespec`, then reaches
the separately selected `nanosleep(&tv, &tv)` seam. The project-first/pinned-
musl C/C++ matrix proves GNU/BSD/XOPEN<700 declaration visibility and
unmangled linkage. The shared fixture proves zero/short stale-errno completion
plus fixture-only raw-SIGALRM `EINTR` for 1000000, 1000001, and `UINT_MAX`.
It does not select `sleep`, alarms, timer control, signal actions/masks,
process signaling, waits, descriptors, pthread policy, libc.so, CRT, loader,
sysroot, family/platform parity, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-sigaddset-sigdelset-sigfillset` is a separate
private `static-c-sigset-mutation` artifact inside planned
`libc.posix-runtime`. Its three-symbol pinned-musl/freestanding-static C proof
follows `sigaddset`, `sigdelset`, and `sigfillset`: x86 `_NSIG=65` makes the
selected set extent one unsigned-long word, so fill writes
`0xfffffffc7fffffff`, valid add/delete touch only that first word, and all
fifteen tail words remain caller-resident. It proves stale `errno` on success
and `-1`/`EINVAL` before dereferencing for 0, musl-reserved 32--34, and 65;
the C GNU/POSIX gate plus C++ POSIX/GNU feature matrix retain the exact
unmangled declarations. It does not select handlers/actions, masks, process
signaling, waits, queues, descriptors, timers, pthread policy, libc.so, CRT,
loader, sysroot, family/platform parity, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-ioctl` is a private
`static-c-generic-ioctl` artifact inside planned `libc.posix-runtime`. It
proves the direct signed `int ioctl(int, int, ...)` C boundary through pinned
musl and a freestanding static archive for `FIONREAD`, `FIONBIO`, and the two
safe no-vararg calls `FIOCLEX`/`FIONCLEX`; its assembly shim supplies `rdx=0`
only for those two forms. It does not establish generic device/request
behavior, terminal/session policy, socket options, C-runtime parity, family
completion, or public x86 support.

`./scripts/dev-x86_64.sh sysv-semaphore-header-abi` is the paired
eight-profile C11/C++17 project-header/pinned-musl `sys/ipc.h` and `sys/sem.h`
gate: selected declarations, feature visibility, command values, x86 LP64
records, and unmangled C++ references. The accompanying
`./scripts/dev-x86_64.sh libc-sysv-semaphore` command records the private
`static-c-sysv-semaphore` artifact inside planned `libc.posix-runtime`. Its
pinned-musl and freestanding-static C fixture selects exactly `semget`,
`semop`, GNU `semtimedop`, and variadic `semctl`, including the application
`union semun` scalar/pointer forms, no-vararg cleanup, the musl oversized-count
precheck, direct syscall/errno behavior, and the x86 fourth-argument route.
It is a bounded semaphore ABI/archive vertical, not closure of
`libc.headers-layouts` or `libc.posix-runtime`. The paired
`./scripts/dev-x86_64.sh posix-semaphore-header-abi` gate compares the
project/pinned-musl `semaphore.h` C/C++ declaration surface, its 32-byte
align-4 volatile-word `sem_t`, LP64 `timespec` dependency, and C linkage.
`./scripts/dev-x86_64.sh libc-posix-semaphore` records the separate private
`static-c-posix-semaphore` artifact: its pinned-musl and freestanding-static C
fixture selects exactly unnamed `sem_init`, `sem_destroy`, `sem_getvalue`,
`sem_trywait`, `sem_wait`, and `sem_post`, including stale errno/error
translation, the `SEM_VALUE_MAX` overflow boundary, and one caller-owned
`MAP_SHARED` pshared futex handoff. It deliberately does not select
`sem_timedwait`, named semaphores, cancellation cleanup, signal-action restart
policy, destruction races, or general POSIX IPC. The paired
`./scripts/dev-x86_64.sh mq-setattr-header-abi` gate is the separate
project-header/pinned-musl C/C++ declaration/layout proof for only signed
four-byte `mqd_t`, 64-byte align-8 `mq_attr`, `mq_getsetattr=245`, and C
linkage. Its accompanying `./scripts/dev-x86_64.sh libc-mq-setattr` command
records the private `static-c-mq-setattr` artifact: one pinned-musl and true
freestanding `-nostdlib -static` C body selects only
`mq_setattr(mqd_t, const struct mq_attr *, struct mq_attr *)`,
`O_NONBLOCK` replacement, optional old-attribute output, stale errno on
success, and direct `EINVAL`/`EBADF`. It excludes queue open/close/unlink,
message transfer, notification, timed operations, general IPC, Rust facade
behavior, cancellation, dynamic runtime, family completion, and public x86
support. The paired
`./scripts/dev-x86_64.sh sysv-message-shared-memory-header-abi` gate now
compares selected `sys/ipc.h`/`sys/msg.h`/`sys/shm.h` declarations,
feature-visible member spellings, x86 LP64 layouts and constants, and C++
linkage across the same eight project-header/pinned-musl profiles. Its
accompanying `./scripts/dev-x86_64.sh libc-sysv-message-shared-memory` command
records the separate private `static-c-sysv-message-shared-memory` artifact
inside planned `libc.posix-runtime`: its pinned-musl and freestanding-static C
fixture selects exactly `ftok`, `msgget`, `msgsnd`, `msgrcv`, `msgctl`,
`shmget`, `shmat`, `shmdt`, and `shmctl`. It proves one local nonblocking
message-queue lifecycle, one local shared-memory attach/status/detach/remove
lifecycle, raw errors and stale `errno`, the x86 `r10`/`r8` message argument
paths, musl's oversized-`shmget` rewrite, and `shmat`'s `(void *)-1` failure
sentinel. The direct `msgsnd`/`msgrcv` leaves intentionally omit musl's
pthread cancellation machinery. These are three bounded private ABI/archive
verticals, not complete SysV IPC or closure of either planned family: POSIX
message queues/shared memory and named/timed semaphores, broader SysV operations and
namespace/permission policy, `SEM_UNDO` lifecycle, cancellation, libc.so,
CRT, loader, sysroot, family or platform parity, promotion, full x86-64
parity, and public x86 support remain unselected.

`./scripts/dev-x86_64.sh event-descriptors-header-abi` adds an artifact-local
eight-profile C/C++ project-header/pinned-musl matrix. It records that the
selected direct `sys/eventfd.h` and `sys/inotify.h` surface is unconditional,
with x86 LP64 `eventfd_t`/`inotify_event` layouts, selected direct flags, and
header-requested unmangled C++ C-linkage spellings. Because both headers
immediately include `fcntl.h`, the same narrow matrix records only
`AT_EMPTY_PATH` as GNU/BSD/default-C-visible and strict/POSIX/XOPEN-hidden,
including macro-free C++17. Its `nm` check is only header-requested external
symbol spelling, not actual callable artifact linkage; the global
feature-visibility facet remains planned. The existing `epoll-header-abi`
matrix remains its own packed `sys/epoll.h` proof. The paired
`./scripts/dev-x86_64.sh libc-event-descriptors` command records a separate
private `static-c-event-descriptors` artifact in planned `libc.posix-runtime`.
Its pinned-musl and freestanding-static C fixture selects exactly
`epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`,
`eventfd`, `eventfd_read`, `eventfd_write`, `inotify_init`, `inotify_init1`,
`inotify_add_watch`, and `inotify_rm_watch`. It proves the packed 12-byte x86
epoll record, the `epoll_ctl` fourth argument in `r10`, and the `epoll_pwait`
`r10`/`r8`/`r9` path with BPF-verified temporary-mask pointer and eight-byte
kernel sigset size, plus bounded eventfd/inotify lifecycles. This direct static
leaf intentionally omits pthread cancellation and musl's pre-Linux-5.10
`ENOSYS` fallbacks. It is a private non-promoting artifact, not
event-descriptor-family closure: `epoll_pwait2`, fanotify, AIO, watcher policy,
libc.so, startup, allocator, loader, sysroot, family or platform parity, and
public x86 support remain unselected. The separately selected timerfd and
signalfd archive leaves are not part of this event-descriptor candidate.

`./scripts/dev-x86_64.sh pathname-lifecycle-header-abi` adds an artifact-local
eight-profile C11/C++17 project-header/pinned-musl matrix for `fcntl.h`,
`stdio.h`, `sys/stat.h`, and `unistd.h` pathname declarations, LP64 types,
selected mode/`O_PATH` constants, and unmangled C++ references. The paired
`./scripts/dev-x86_64.sh libc-pathname-lifecycle` command records a separate
private `static-c-pathname-lifecycle` artifact in planned
`libc.posix-runtime`. Its pinned-musl and freestanding-static C fixture selects
only `chdir`, caller-buffer `getcwd`, `mkdir`, `unlink`, `rmdir`, `remove`,
`rename`, `link`, `symlink`, `readlink`, `chmod`, `fchmod`, and `truncate`.
It proves direct x86 syscall paths, `remove`'s raw-`EISDIR` retry,
zero-capacity `readlink`, and a live-`O_PATH` `fchmod` procfs fallback. The
no-allocation candidate intentionally rejects musl's null-buffer `getcwd`
extension with `EINVAL`. This remains a bounded private ABI/archive vertical,
not general pathname/canonicalization, directory, xattr/ACL, mount/namespace,
filesystem-family, C-runtime, AArch64-parity, or public-x86-support evidence.

`./scripts/dev-x86_64.sh fchdir-header-abi` and
`./scripts/dev-x86_64.sh libc-fchdir` add a separate private
`static-c-fchdir` artifact within the same planned `libc.posix-runtime`
family. The all-profile C11/C++17 `<unistd.h>` gate proves the unconditional
`int fchdir(int)` declaration and unmangled C++ reference. The matching
pinned-musl/true-static fixture proves only musl 1.2.6's direct `fchdir=81`
path and its live-O_PATH `EBADF` → `fcntl(F_GETFD)` → fixed
`/proc/self/fd/<decimal>` → `chdir=80` fallback. It restores the child CWD,
checks a non-directory O_PATH `ENOTDIR` result and invalid `EBADF`, and keeps
all raw setup/observation outside the C ABI claim. It does not select public C
`chdir`/`getcwd`, general descriptor/procfs/pathname behavior, CWD capability
completion, family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh ulimit-header-abi` and
`./scripts/dev-x86_64.sh libc-ulimit` add a separate capability-free
`static-c-ulimit` artifact in the same planned `libc.posix-runtime` family.
The default/strict/POSIX/X/Open/GNU/BSD C11/C++17 `<ulimit.h>` matrix fixes
only unconditional `long ulimit(int, ...)` linkage. Its pinned-musl and true
`-nostdlib -static` fixture maps musl 1.2.6 `src/legacy/ulimit.c` exactly:
`UL_GETFSIZE` and unknown commands make the no-vararg `RLIMIT_FSIZE` query,
while only `UL_SETFSIZE` consumes a long and applies the `512ULL` block
conversion through direct `prlimit64=302`. Disposable processes preserve stale
errno on success and check the hard limit remains unchanged. This does not
select public C `getrlimit`/`setrlimit`/`prlimit`, general resources,
accounting, scheduler or file-size policy, filesystem behavior, family
completion, promotion, or public x86 support.

`./scripts/dev-x86_64.sh libc-header-layouts-baseline` now adds one private
`static-c-header-layouts-baseline` artifact within still-planned
`libc.headers-layouts`. It composes the existing selected archive through a
project-header C fixture and a separately compiled freestanding C++17
companion, after both pass with pinned musl. The C++ entry has unmangled C
linkage and is called from C; the evidence rejects C++ runtime, constructor,
exception, RTTI, and dynamic-TLS paths while retaining only existing selected
C API references. It adds no export or installed-header edit, and is not
all-header closure, general C/C++ runtime support, libc.so, CRT, loader,
sysroot, family/platform parity, or public x86 support.

`./scripts/dev-x86_64.sh libc-uio-cxx-linkage` adds one narrower private
`static-cxx-uio-archive-linkage` artifact within still-planned
`libc.headers-layouts`: a freestanding C++17 `<sys/uio.h>` companion first
links and runs against pinned musl, then against the selected static archive
through an unmangled C entry. It proves the selected `readv`/`writev`/
`preadv`/`pwritev` declarations resolve into that archive while retaining
initial-TLS errno and rejecting C++ runtime, constructor, exception, RTTI,
and dynamic-TLS paths. This is one C++ consumer linkage seam, not general C++
support, complete `<sys/uio.h>` linkage or runtime coverage, header-family
completion, promotion, or public x86 support.

`compat/x86_64/headers-layouts-foundation.toml` is now the separate planned
v8 accounting contract for eventually closing that header family. It resolves
the 183 pinned-musl paths and eight project-only headers into exact classes,
names `sys/kd.h` -> `linux/kd.h`, `sys/soundcard.h` ->
`linux/soundcard.h`, and `sys/vt.h` -> `linux/vt.h` through one fixed Linux
5.10 x86 UAPI export: the source SHA-256, 935 exported-header count, and
derived header-manifest SHA-256 are owned by
`compat/upstreams.toml#linux_5_10_uapi` and independently checked in the image
and at runtime. Its 21-row `uapi-wrapper-matrix` resolves the three direct
wrappers across five C11 and two C++17 feature profiles through both pinned
musl and raw-GCC project-header-first roots, checking selected constants, ioctl
encodings, and x86 LP64 layouts. Its separate seven-row `ioctl-header-abi`
matrix resolves direct `sys/ioctl.h`'s signed `int ioctl(int, int, ...)`
declaration, C++ C-linkage spelling, selected `_IOC` composition, direct
8-byte align-2 `struct winsize`, and selected request values only; it does not
prove artifact linkage or generic device/request behavior. Its separate
seven-row `epoll-header-abi`
matrix resolves only `sys/epoll.h`'s packed x86 event record, selected
declarations/values, and the direct `_IOC`/`_IOR`/`_IOW` encoding subset from
`sys/ioctl.h`. Its separate 16-row `event-descriptors-header-abi` matrix
resolves the selected direct `sys/eventfd.h` and `sys/inotify.h` surface as
unconditional across default-C plus seven C11/C++17 profiles, with x86 LP64
`eventfd_t`/`inotify_event` layouts, selected direct constants, and
header-requested C++ C-linkage spelling. Both headers immediately include
`fcntl.h`, so it also records only `AT_EMPTY_PATH` as
GNU/BSD/default-C-visible and strict/POSIX/XOPEN-hidden, including macro-free
C++17; this leaves the global feature-visibility facet planned. Its separate
private `dirent-header-abi` matrix
(`./scripts/dev-x86_64.sh dirent-header-abi`) compares the project-header-first
candidate with pinned musl 1.2.6 across seven base C11/C++17 profiles and
four `_LARGEFILE64_SOURCE` profiles: GNU and strict C11/C++17. It checks only
selected `<dirent.h>` declarations, feature visibility, x86 LP64 `dirent` and
`posix_dent` layouts, and the C spellings requested by C++ declarations. The
fixed boundary includes C++ `extern "C"` declaration spelling, the `d_fileno`
compatibility spelling, GNU-only `versionsort`, and the large-file aliases:
strict LFS exposes the aliases without exposing `seekdir`/`telldir`, `getdents`,
or `versionsort`. `IFTODT`, `DTTOIF`, and `getdents` are GNU-or-BSD-visible,
while `versionsort` is GNU-only. The C++ `nm` inspection proves only
header-requested unmangled C names. This compile-only header slice excludes
actual archive linkage, directory-stream runtime behavior, header-family
completion or promotion, and public x86 support; full x86-64 parity remains
the stated promotion goal.
The separate private `ftw-header-abi` matrix
(`./scripts/dev-x86_64.sh ftw-header-abi`) compares project-header-first and
pinned-musl 1.2.6 `<ftw.h>` declarations across seven base C11/C++17 profiles
plus GNU C11/C++17 `_LARGEFILE64_SOURCE` alias profiles. Pinned musl and the
project header expose `ftw` in every profile. `nftw` likewise remains visible
in every profile, and both LFS
profiles prove `ftw64`/`nftw64` macro aliases plus unmangled C++ C-linkage
spelling. The matrix is declaration evidence only,
not archive-linkage, traversal-runtime, promotion, or public-support evidence.
The separate private `libc-directory-streams` command
(`./scripts/dev-x86_64.sh libc-directory-streams`) adds one actual static C
runtime leaf after that header matrix: the same project-header C body runs
through pinned musl and then a `-nostdlib -static` `crabc-libc` candidate. It
checks only `opendir`/`fdopendir`/`closedir`/`dirfd`,
`readdir`/`readdir_r`/cursor operations, C-locale `alphasort`, GNU
`versionsort`, and `getdents`/`posix_getdents`, including 255-byte names,
close-on-exec transfer,
raw record framing, and the x86 `openat=257`, `fstat=5`, `fcntl=72`, `mmap=9`,
`munmap=11`, `close=3`, `getdents64=217`, and `lseek=8` paths. The private
`DIR` state uses one anonymous mapping rather than selecting a C allocator;
`scandir`, walking policy, broad collation, cancellation, and the rest of C
directory/POSIX runtime parity remain out of this leaf. It does not complete
either the header or POSIX-runtime family, change promotion status, or
establish public x86 support.
The separately opt-in `libc-filesystem-traversal` command
(`./scripts/dev-x86_64.sh libc-filesystem-traversal`) adds the allocation-free
`x86-filesystem-traversal` static C artifact for exactly `ftw` and `nftw`; the
default archive remains unchanged. Its project-header fixture first executes
ordinary traversal through pinned musl, then proves physical/depth/mount,
descriptor-limit, callback-return, and symlink behavior through the selected
archive. The frozen `FTW_CHDIR` behavior is candidate-only evidence because
musl 1.2.6 ignores that flag; the candidate also repairs callback CWD mutation
and restores CWD on normal and abort exits. It selects neither `scandir` nor a
C allocator, and callbacks must return normally because C++ exceptions and C
`longjmp` cannot cross the Rust boundary. Cancellation policy, general
filesystem policy, libc.so, CRT, loader, sysroot, family promotion, and public
x86 support remain outside this artifact.
The private `libc-filesystem-directory` aggregate
(`./scripts/dev-x86_64.sh libc-filesystem-directory`) reruns the directory
stream, `scandir`, and traversal artifacts and then verifies that the combined
`x86-scandir,x86-filesystem-traversal` archive owns `alphasort`, `ftw`, `nftw`,
`readdir_r`, `scandir`, `telldir`, and `versionsort`. It therefore selects the
frozen `filesystem.directory` capability as `selected-private` while
preserving the default static archive. `libc.posix-runtime` remains planned
and nonpublic: this aggregate does not claim family completion, promotion, or
general x86 runtime support.
Its separate
35-row `timeval-transitive-header-abi` matrix
checks five fixed headers (`sys/time.h`, `utmpx.h`, `utmp.h`, `lastlog.h`, and
`sys/timex.h`) across seven isolated C11/C++17 profiles for complete
`struct timeval` visibility and named x86 LP64 embedded-record layouts only.
It does not require an identical private include graph or dependent feature
surface.
It excludes direct `sys/time.h` callable declaration/linkage, other
`sys/time.h` feature or macro parity, dependent-header callable linkage, and
runtime behavior. Its separate seven-row `sys-time-direct-header-abi` matrix
checks selected unconditional and GNU/BSD/GNU-only declarations, x86 LP64
`timeval`/`itimerval`/`timezone` layouts, interval-timer values,
timer/conversion macros, and C++ declaration C-linkage spelling. That spelling
check proves only the external name requested by a header declaration, not a
crabc artifact export. Its separate eight-row `access-header-abi` matrix
checks selected `access`/`faccessat` declarations, access and `AT_*` values,
GNU-only `eaccess`/`euidaccess` visibility across default-C and isolated
C11/C++17 profiles, and C++ declaration C-linkage spelling. It likewise
proves only header-requested names, not an artifact export. All seven are
compile-only evidence: callable linkage,
device behavior, all-header closure, runtime completion, family promotion, and
public x86 support all remain planned. Its live `candidate-header-closure`
diagnostic now resolves 1,337 rows across seven isolated C11/C++17 profiles
for all 183 pinned-musl paths and eight project-only headers. It records
exactly two auditable pinned-musl `reference-not-applicable` rows
(`aio.h:c11-strict` and `aio.h:cxx17-strict`), while requiring the candidate
arm to compile them. This verifies isolated empty-TU consumer closure only;
feature visibility, declaration/layout parity, callable linkage, runtime
completion, family promotion, and public x86 support remain planned.

The separate private `installed-header-tree-closure` artifact materializes the
same 191 candidate headers into a temporary `usr/include` tree and resolves
the same 1,337 empty-TU rows across `c11-gnu`, `cxx17-gnu`, `c11-strict`,
`c11-posix-2008`, `c11-xopen-700`, `c11-bsd`, and `cxx17-strict`. Its candidate
include traces reject repository `include/` source-tree leakage and every host
include path: only the temporary installed tree, raw-GCC builtin headers, and
the fixed Linux 5.10 UAPI root are admitted. The two pinned-musl strict
`aio.h` `reference-not-applicable` rows remain explicit, never a candidate
waiver. This is a header-tree closure artifact distinct from source-tree
closure, not full declaration, layout, feature-visibility, or linkage parity;
an archive/runtime artifact; CRT, loader, driver, or owned-sysroot evidence;
promotion; or public x86 support.

Fixed Rust mimalloc work is paused. Its AArch64 and private native x86-64
evidence remains preserved in [`native-mimalloc.md`](native-mimalloc.md),
[`docs/design/allocator.md`](docs/design/allocator.md), and
[`compat/allocator/README.md`](compat/allocator/README.md); the detailed
allocator checkpoint record below is retained context, not an active backlog.
The pause does not reopen allocator invention, emulation, or a generic
portability layer. [`COMPATIBILITY.md`](COMPATIBILITY.md) remains the generated
record of current compatibility evidence and measurements; it is not edited by
hand.

Within that allocator program, the direct native-engine owner-exit lifecycle
Gate 5C is complete: `allocator --full` executes the reviewed
[`native-owner-exit-lifecycle-v3.5.0.json`](compat/allocator/native-owner-exit-lifecycle-v3.5.0.json)
suite and records its source-shaped traversal/terminal-release evidence as
passed. Milestone 5 remains open because Gate 5D churn/stability and Gate 5E
selected shadow-ABI acceptance are still blocked; the C allocator remains the
default backend.

The Rust-owned Linux/AArch64 application CRT/sysroot is also complete current
evidence. `./scripts/dev.sh sysroot` produces two clean reproducible installed
trees with `crabc-cc`, Rust CRT objects, Rust compiler helpers, the canonical
crabc loader, and explicit source/dependency/link/artifact purity accounting.
`./scripts/dev.sh lua` consumes that installed tree for the pinned Lua
source-build gate; the static pthread/TLS gate and static integration fixtures
do the same. This completed boundary is documented in
[`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md). It is
precisely **CRT/sysroot** purity: the report keeps complete target-runtime
purity `blocked_by_native_allocator` until the separate mimalloc port replaces
the current `libmimalloc-sys` backend. The sole recorded native closure is the
pinned allocator source and its direct pinned `cc` compiler-discovery helper;
the sysroot audit rejects any other native production input, including
compiler-rt target objects.

The same native x86-64 profile has a 75-field direct C/Rust fundamental trace
that includes the fixed no-padding `mi_expand` nonzero null-pointer, zero-size,
below-half, exact-fit, oversize, and state-preservation cases plus checked
`mi_recalloc` growth/tail-zeroing, zero-product, and overflow-preservation
outcomes. This remains private engine evidence, not public allocator API or
AArch64 production evidence.

It also has one separate 25-field native C/Rust differential for two
live-owner remote-free publications from one quiescent `pthread` followed by
the pinned private owner false collector. It proves only the source-specific
owner-bit, LIFO, exact-used-count, and post-join local-list merge transition;
it is not general remote-free routing or concurrent collection, abandonment,
thread teardown, public `mi_*` API, libc integration, backend, or AArch64
evidence.

A separate 43-field native C/Rust differential now covers one live owner with
a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks,
capacity/reserved 42, eight slices) and one regular successor. A real pinned-C
`pthread` publishes exactly one remote `mi_free` and joins before owner
observation; false collection requeues the full page behind the successor,
then ordinary allocation exhausts the successor's remaining capacity and
reuses the exact remotely freed block. Rust uses only a joined scoped producer
for common typed private facts. This remains private native x86-64 engine
evidence only: it does not claim pthread/TLS ABI parity, generic remote
routing/collection, teardown, abandonment, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence.

A separate 35-field native C/Rust differential now covers one live owner with
a non-abandoning full-medium arena page (10248-byte request, 12288-byte blocks,
capacity/reserved 42, eight slices) and one regular successor. A real pinned-C
`pthread` worker frees all 42 first-page blocks, then `pthread_join()` completes
before the still-live owner observes the non-atomic remote list or invokes
`mi_heap_collect(heap, false)`. The false collector empties the full queue and
releases only the first page's PageMap span, ordinary arena bitmap, and eight
slices, while the successor remains regular and PageMap-published. Rust uses
only 42 joined, staged scoped test workers for shared typed private facts; it
does not claim pthread/TLS ABI parity, thread teardown, or broad remote-free
routing/collection. This remains private native x86-64 engine evidence only,
not public `mi_*` behavior or runtime, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The same native x86-64 profile separately has a 28-field C/Rust differential
for one real small direct-cache page filled to its current capacity, one
joined/quiescent `pthread` remote free, and the owner direct-cache miss falling
through the regular queue search to collect and reuse that exact block. Its
selected normal-release source API assessment also records per-item native
object/dynamic-symbol presence for 194 distinct C functions and marks 183
non-object source forms explicitly. A separate eight-field C/Rust differential
now covers one arena-backed mapped page's queue-detach abandonment and
same-origin nonempty `mi_free` reclaim/requeue transition. A separate 18-value
C/Rust differential covers one arena-backed, same-origin, one-thread nonfull
medium page. The pinned-C next same-heap allocation claims its exact
mapped-abandoned PageMap/ordinary-arena-bitmap-preserved page, clears
bitmap/count state, restores original-Theap association, and requeues it at
the regular tail; Rust models that claim/reassociation with its test-only
consuming handoff immediately before its matching third allocation. This is
private native x86 evidence only, not general or cross-thread
abandonment/adoption, public API/runtime behavior, backend promotion, public
x86 support, or AArch64 evidence. A separate
32-value C/Rust differential covers one arena-backed, same-origin,
same-thread/same-Theap nonfull 1024-byte direct-small page with two live
blocks. `_mi_page_abandon` clears its complete rounded direct-cache range while
retaining PageMap and ordinary-arena-bitmap registration; the pinned C next
same-heap `mi_heap_malloc_small` claims that exact mapped-abandoned page,
clears bitmap/count state, restores the original Theap, requeues at the
regular tail, restores the full range, and allocates the third block. Rust
explicitly consumes its private test-only handoff immediately before its
matching third allocation rather than making generic allocation scan abandoned
pages. This remains private native x86 evidence only, not general or
cross-thread abandonment/adoption, remote routing, lifecycle, public API/runtime
behavior, backend promotion, public x86 support, or AArch64 evidence. A separate
six-mode staged public-header gate compile-links selected C/C++ forms against
the pinned C release shared object, including one C11 compile/link-only probe
that instantiates the five base-header `*_csize` static-inline dispatch helpers,
and records all ELF identities. A further
two-mode static gate observes every selected static archive member and the
`src/static.c` override object's required symbols before C consumer
compile/linking. A separate native CMake gate configures, builds, and installs
the selected normal-release shared profile with Unix Makefiles and musl; it
records resolved cache/compiler selections, installed header bytes and manifest,
and shared-object ELF, SONAME, and dynamic-dependency identity. It does not
compile/link or execute a consumer, establish behavior or Rust implementation
parity, cover static/object or unselected CMake modes, or create public x86 or
AArch64 runtime support. A separate 13-field C/Rust differential covers one real C
full-medium arena page forced from the full queue to unmapped abandonment, then
through the `mi_free` threshold that republishes its mapped bitmap; its Rust
side exercises the same bounded real post-Theap-teardown full-medium route.
A separate 18-field C/Rust differential uses a real pinned-C worker `pthread`
to run `mi_thread_done()` and return; the consumer calls `pthread_join()`
before its two public `mi_free` calls. It records the selected mapped failed-reclaim/unown
transition and terminal checks for
`page_map_unregistered_after_final_free`,
`arena_page_bitmap_clear_after_final_free`, and
`arena_slice_released_after_final_free` on the exact eight-slice medium-page
span. Rust covers only one bounded process-owned mapped regular handoff after
teardown and directly observes its PageMap, ordinary arena-page bitmap, and
free-slice bitmap release.
A separate 21-field native x86-only C/Rust differential is a retired-page
prepass: a real worker-local `mi_free` retires one medium page, real
`mi_thread_done()` and `pthread_join()` force-release it before one distinct
live medium page is mapped-abandoned, and one consumer `mi_free` terminally
releases the live page. It records retired/local-retirement state, retired
teardown PageMap/ordinary arena bitmap/exact slice-span release, then live
mapped-abandoned and terminal PageMap/ordinary bitmap/exact slice-span release
plus an empty route. This is a narrow private native x86 engine antecedent and
does not claim general retirement, teardown, routing or concurrency, public
`mi_*` behavior, libc integration, backend promotion, public x86 support, or
AArch64 evidence.
A separate 25-field native x86-only C/Rust differential covers exactly two
distinct live nonfull medium arena pages in distinct bins. The real worker runs
`mi_thread_done()` and returns; the consumer calls `pthread_join()` before any
free. Both selected pages are mapped-abandoned after teardown. The consumer
frees the second page first and
records only its PageMap unregister, ordinary arena-page bitmap clear, and
exact slice-span release while the first remains PageMap-registered,
arena-bitmap-set, mapped-abandoned, and `used == 1`; the final consumer free
releases the first page and records an empty route. This is a narrow private
native x86 engine trace, not general teardown, routing or concurrency, public
`mi_*` behavior or runtime, libc integration, backend promotion, public x86
support, or AArch64 evidence.
A separate 46-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in a distinct bin. The real worker runs `mi_thread_done()` and returns; the consumer
calls `pthread_join()` before any free. Both selected pages are mapped-abandoned
after teardown. The first A free returns `StillLive`, preserving A, B, and the
route; the B free returns `ReleasedPage`, terminally releasing only B; and the
second A free returns `ReleasedAll`, completing the route. This remains narrow
private native x86 engine evidence, not general teardown, routing or
concurrency, public `mi_*` behavior or runtime, libc integration, backend
promotion, public x86 support, or AArch64 evidence.
A separate 53-field native x86-only C/Rust differential covers two distinct
clients on one nonfull medium arena page A plus a one-client medium arena page
B in the same bin. The real worker fills A before it creates B, locally
restores A to two clients, runs `mi_thread_done()`, and returns; the consumer
calls `pthread_join()` before every free. It proves the selected same-bin
queue count/link/saved-successor traversal before teardown and mapped-abandoned
count/bitmap transitions `2 -> 2 -> 1 -> 0`. A's first free returns
`StillLive`, B's free returns `ReleasedPage`, and A's second free returns
`ReleasedAll`. This remains narrow private native x86 engine evidence, not
general teardown, routing or concurrency, public `mi_*` behavior or runtime,
libc integration, backend promotion, public x86 support, or AArch64 evidence.
A separate 21-value native x86-only pinned-C/Rust differential now covers one
full arena singleton post-exit route: request 524289, 589824-byte block size,
capacity/reserved 1, nine arena slices, real C `mi_thread_done()` and
join-before-terminal-consumer-free ordering, source unmapped/unowned/detached
state, all-nine-slice PageMap and ordinary arena-bitmap preconditions, and
terminal PageMap/bitmap/slice cleanup. Rust observes a scoped test worker and
join while comparing only matching common typed private owner-exit facts,
distinct from the Rust-only route. It does not establish crabc pthread/TLS
callback parity, general lifecycle/routing/concurrency, public x86/crabc
API/runtime, backend promotion, or AArch64 evidence.
These bounded results do not claim general routing or concurrent collection,
general behavior or Rust implementation parity, a Rust full-medium route, general
abandonment/adoption, cross-thread reclaim, general thread teardown, CMake
unselected-mode coverage, consumer execution, public API/runtime support, libc integration,
backend promotion, public x86 support, or AArch64 evidence.

The allocator program currently has one bounded executable vertical slice:
an explicit pinned default theap can allocate, reallocate, and locally free
small, medium, large, singleton, aligned, and offset-aligned blocks from a
caller-managed external arena and page map. Large alignments use separately
owned OS singleton mappings below the source's 256 MiB metadata limit, with
allocation-free retry ownership when an injected terminal unmap fails. The
slice includes checked counted allocation, full-page retention, retirement,
and one private linear scoped `RemoteFreeProducer` for an exact active matching
regular non-huge-bin or `BIN_FULL` allocation. Its exclusive owner borrow
prevents safe allocator mutation while a scoped `Send`/`!Sync` worker may
publish the canonical block or cancel back to the original client pointer.
After caller-proved joined/quiescent publication, regular generic search
(including a small direct-cache miss) consumes the remote list before extension
or full classification, and the non-abandoning full-page pass consumes it
before exact release-or-unfull. Every non-abandoning move to `BIN_FULL` also
performs the source's post-enqueue false-force collection. Detached metadata
sessions have no remote producer path and perform only the local false-force
portion. Any false-force collection error permanently poisons this private
allocator, retaining the exact page, error, and any already-popped block; all
later allocation, inspection, free, producer preparation, and collection
entry points reject without further queue or page-map mutation. This bounded
slice also retains unregister-before-release and injected rollback. Unpinned
external arenas now schedule the pinned 4-second `purge_decommits=1` path
before slice reuse. Forced collection claims the free bitmap while applying a
non-owning decommit, preserves the external mapping owner, and retains retry state after
an injected decommit failure. The ordinary allocator gate
matches 447 Rust-owned layout/configuration values, 378 address-independent
small-allocation trace values, and 51 fundamental-operation values against
exact pinned C v3.5.0. The native x86-64-only 75-field expansion extension
recorded above does not revalidate this AArch64 production-oriented result.
A standalone default-off test package now exports 16
strictly prefixed `crabc_test_*` symbols, passes the existing crabc allocator
fixture, and passes 33 reviewed checks from pinned upstream `test-api.c` in an
explicit creating-thread lifecycle. It exports no `malloc`, `mi_*`, or other
production allocator symbol. Separately, the bounded production metadata-owner
prerequisite from `src/subproc.c:19-88` now has one process-static detached
theap backed by direct OS page-map and external-arena bootstrap state. It
requires a caller-supplied frozen `MemoryConfig`, checks a live AArch64 thread
pointer before its private lock, preserves `MemoryId::Malloc` owner-bound
capabilities, and leaves compiler-TLS roots untouched. It supports zeroed and
aligned zeroed allocation, source-ordered replacement, and serialized
cross-thread free, with deterministic retryable and retained initialization
failure states. It neither attaches a live TLD/theap nor implements the
source's null/needs-no-free/non-Malloc release paths. This is not a production
backend or readiness claim. The active allocator scope includes the exact AArch64
16-bit-index/48-bit-generation TLS key and caller-owned slot contract, its
older caller-storage registry substrate, and one allocator-owned process-global
regular-key registry; five private compiler-TLS roots with direct `TPIDR_EL0`
identity; live-owner and
abandoned-page remote-free head transitions; one private scoped active regular
or full remote producer and caller-proved joined/quiescent false-force regular
candidate/full-collection paths (with the detached no-remote local branch);
a one-page mapped/unmapped
abandonment/adoption protocol with failed-reader bitmap restoration,
clear-once-set quiescence, and the failed-reclaim expected-head/unown tail; an
unsafe current-thread-only regular TLS backing
owner; one bounded source-order process-main initializer; one ticket-zero
process-static main heap/default-Theap attachment; one no-page later-thread
attachment to that shared main Heap; one process-static page-map root
publication owner plus one caller-selected, process-shared single-arena
sidecar; bounded ticket-zero and later-thread page engines over that matched
process pair; one all-free later-main thread-exit drain; nine sole-page
later-main owner-exit handoffs (a full arena singleton, an OS-aligned
singleton that links through `Heap::os_abandoned_pages` and removes that list
member before clipped PageMap/alias/metadata/mapping release, a mapped medium page
with one live block, full medium and full large `BIN_FULL` pages plus full
non-direct-small and direct-small regular-bin pages that remain unmapped until
their mostly-used free boundary then reabandon to the static-main bitmap, and a sole nonfull
small-or-medium page whose process-owned route survives old-Theap/TLD teardown,
and a separately bounded exactly-two-block large page whose complete 64-slice
PageMap span and leading static-arena bit survive until its second client free,
including exact full-medium, full-large, full-non-direct-small, and
full-direct-small predecessors where one joined remote free is force-collected
before immediate mapped publication (the medium and large pages remain in
`BIN_FULL`; the non-direct-small page remains in its ordinary bin with every
direct slot empty; the direct-small page remains in its ordinary bin until its
rounded direct-cache range is cleared during removal));
The historical direct-test suite also covers seven later-main full-page
aggregate post-exit routes: full arena
singleton, full OS singleton, full-medium, full-large, and bounded mixed
medium/large `BIN_FULL` members, plus full non-direct-small and direct-small
members across ordinary bins. The
arena singleton route admits each member's own rounded
`PageKind::Singleton` size with `reserved == used == 1`; the non-direct route requires
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and every direct slot empty;
the direct route requires `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and
the complete direct-cache image naming every populated queue head. The direct
route advances each affected range before its page-count detach and uses
free.c's partial collector; both retain one exact arena slice per member.
Alongside them is one aggregate
regular-pages post-exit registry that can route every qualifying surviving
regular small, medium, or large page through sequential client frees. No full
aggregate keeps a separate raw member registry: each later free re-resolves
its PageMap member. The OS aggregate's private Heap list deliberately reuses
member links until that exact free removes them. The arena singleton aggregate
must take the raw empty failed-reclaim result
and has no static-main abandoned bitmap/count pair; every regular aggregate
independently crosses the source unmapped-to-mapped threshold under its exact
static-main bitmap/count pair, while the large route also proves
each terminal member's complete 64-slice span. When the completed nonfull
aggregate traversal itself
releases every other member and leaves exactly one initial nonfull medium with
an immediate local head, it returns the existing one-page mapped route before
registry construction. A registry that sequential client frees later reduce
to exactly one mapped regular member, with no arena or OS singleton tail, can
also cross one explicit source bitmap claim into a fresh later-main engine;
the opaque selected client never becomes a stored page identity, and no
residual route survives the long PageMap lease. Aggregates with multiple
members, source-unmapped/full/singleton tails, scans, fallbacks, and concurrent
reclamation remain sequential client-free-only. The former pointer-private
runtime ledger and `TicketZeroOwnerExitFreeRoute` are now `#[cfg(test)]`
historical oracles. Selected native post-exit operations derive their source
from the supplied pointer and use PageMap/W03 and abandoned-state behavior;
they do not retain A's admission through B's teardown. A fresh later-main owner can
explicitly reclaim a sole mapped medium route that began owner exit nonfull, or a sole
direct-small route that retains an immediate local free block, the exhausted
fully committed scalar-extension shape, the exact exhausted prefix-covered
extension shape, or the exact exhausted on-demand page-area-commit shape after
source collection; all force-collected full-origin predecessors remain
sequential client-free-only. The reserved fixtures cover both medium and
direct-small prefixes, prefix-covered direct-small reuse without a direct
commit, direct page-area commitment, and failed-commit mapped reabandonment
before a same-candidate retry; non-direct-small, malformed or out-of-profile
no-immediate direct-small metadata, and aggregate registry members outside the
separately recorded final mapped-regular edge remain sequential client-free-only.
The regular owner uses the process-static metadata allocator for the exact
flexible `mi_thread_locals_t` request, source growth rule, header-before-root
publication, generation-checked regular slots, and free-before-dynamic-root-
null teardown. It leaves fast/default/cached roots alone and becomes terminal
after an internal metadata error whose consumption cannot be distinguished,
rather than claiming a false retry capability. The allocator-owned registry
uses the selected main subprocess's aligned Malloc metadata route for one
retained typed bitmap image (plus one temporary replacement while locked),
grows by 1,024 bits through the 64,512-bit/63-block source ceiling, and keeps
`BitmapView` transient under its private registry lock. Ordinary claim uses
`tseq = 0`, advances generation
only after a one-bit claim, and copy growth preserves old claims before marking
only the appended range free. Linear leases require explicit release; bounded
shutdown refuses live leases and late access without writing compiler TLS or
attaching a key to a thread. Allocation failure before commit preserves state;
typed-image invariant or post-commit ownership ambiguity terminally poisons
with retained process-static ownership. This is not the source's full process
shutdown, fast-key management, or key-to-thread integration. Separately,
`subproc.rs` holds one bounded process-static main-subprocess identity: only
relaxed `thread_total_count`, relaxed live `thread_count`, the real first
static TLD slot, and a Rust-only first-ticket selector—not full
`mi_subproc_t`, its heaps/arenas/stats, or a general process-init API. The
unsafe current-thread TLD owner receives an old-counter-value ticket only after
that selector chooses the generic branch; static startup reserves ticket zero
instead. Metadata failure consumes a later source sequence but never a live
registration. The generic TLD image records the same main identity as detached
metadata bootstrap state and its selected arena registry/published arena,
direct `TPIDR_EL0`, Linux NUMA, the exact Unix non-threadpool result, a null
theap list, and exact provenance. It remains **subprocess-attached, no-theap**.

`process_init.rs` is a deliberately bounded source-order coordinator. After a
pure root/current-thread preflight, it reserves static ticket zero, initializes
the static `Heap`, prepares detached metadata without exposing metadata's
private map/arena, publishes the distinct process PageMap, and then attaches
the static TLD/Theap roots. Its `ProcessMainReadyLease` is immutable and it
does not choose options, reserve the process-shared arena, initialize
pthread/TLS keys, route allocation/free, or implement shutdown/fork.
Preflight failure remains cold; every failure after static selection retains
the process image rather than reopening ticket zero.

`runtime_lifecycle.rs` is the intentionally smaller production bridge over
those no-page owners. `__libc_start_main` invokes it after initial TLS and the
stack guard but before constructors, retaining the ticket-zero owner and its
main-thread-minted `MainStaticHeapLease` for the process lifetime. A pthread
child attaches before its user routine; its parent waits for that result and
returns `EAGAIN` if attachment fails. Normal return, `pthread_exit`, and
cancellation finish only after libc cleanup and TSD destructors. The bridge
itself exposes no C symbol, uses no pthread key, routes no C allocation, and
leaves `libmimalloc-sys` as the active backend with its existing private key
outside the 128-key application capacity. The main owner is retained at normal
exit. On libc's direct `fork` path, a private allocation-free gate first
excludes later bridge owners. It preserves the copied original ticket-zero
`TPIDR_EL0` image only when that admission count is zero and the ticket-zero
owner is either still cold or has returned to `AwaitingFreshPage` or
`DormantExistingArena`, with no live native client or PageMap operation. That
child resets the copied gate and may reactivate the dormant owner or attach a
fresh pthread. Any other child disables the bridge without attempting lock,
root, pointer, page, or general fork repair.

The adjacent permanent ticket-zero page owner remains outside that production
bridge. `compat/allocator/runtime-ticket-zero-adapter` is a separate `no_std`
C evidence staticlib, not an installed or selected libc
interface: in one fresh process it exports only nine prefixed operations
(init with `AT_PAGESZ`, a scalar lifecycle audit, malloc, zalloc, realloc,
free, a retained narrow worker witness, a persistent mixed-local worker
witness, and a bounded live-owner remote-free witness)
against that exact owner. The mixed witness
keeps one page engine through simultaneously live small, medium, large,
singleton, and multi-page singleton blocks; frees and reissues local
small/medium requests; then frees every block before normal attachment
teardown. Those mixed-local and live-owner remote-free calls now use the
runtime's typed `READY -> BUSY -> READY` operation; their C ABI remains
unchanged. The remote witness makes a fresh worker A fill one small page, then
starts B/C with opaque publication capabilities for two distinct blocks; after
both join, A's ordinary allocation collects and reuses both blocks before it
tears down. The remaining exact-client owner-exit narrative in this section is
historical `#[cfg(test)]` provenance only: it describes neither current
production behavior nor a C adapter export. Current post-exit free,
reallocation, and usable-size start from the supplied pointer and use PageMap/
W03 or abandoned-state operations; the C fixture schedules only mixed-local
and live-owner remote-free workers. Its Rust state audit proves PageMap registrations, arena ownership,
permanent process/page-owner state, every static-main abandoned count, and the
private OS-abandoned list stay at the retained process baseline while live-TLD,
caller-visible metadata-capability, and later-Theap counts return to baseline
across repeated mixed-local and live-owner remote-free workers. Each mixed audit now attaches and retires B after it
consumes A's opaque route, explicitly holding two admissions, releasing B's
own claim after that finish, and releasing A only from the terminal proof;
both owner-exit metadata high-water marks plateau
after warmup. The C
fixture proves the same repeated pthread boundary, same-arena ticket-zero
reactivation, and successful-path `errno` preservation; its `allocator
--churn` lane executes its two scheduled mixed-local and live-owner
remote-free workers exactly once per 128 bounded C cycles, in a deterministic seed-shuffled order
(`0xd1b54a32d192ed03`) in one fresh process under a 30-second watchdog without
widening the C ABI. Its mixed
owner-exit witness keeps a direct-small page, a non-direct-small page, two
distinct `BIN_FULL` medium pages, a one-client force-empty large page, a
distinct two-client live large page, one live arena singleton, and one live
OS-aligned singleton in one mixed regular workload: one medium has an opaque
pre-exit remote free that source collection makes nonfull, while the
force-empty large page's sole opaque remote client makes that page empty and
releases it during the same traversal; the other full medium remains
source-unmapped. The arena member stays PageMap-only through its raw-terminal
tail, while the OS member stays in the static main Heap's private list through
its clipped-mapping tail.
It moves the combined post-exit route to one joined fresh B without exposing
client addresses. After every regular, arena, and OS member releases, B
completes its own no-page runtime attachment; only that completed B lifecycle
may return A's final typed PageMap-release proof for its worker-admission
claim. On B's first direct post-exit free of an existing direct-small client,
or of one of three remaining clients on the pre-exit-normalized mapped,
non-full medium page, B first claims the source low owner bit and then issues
joined C and D the matching nominal scoped producers for two distinct
same-page private clients. C and D atomically publish them in separate joined
turns; B's existing collector consumes the resulting two-node remote chain
before B may unown or terminally release the page. The direct runtime
regressions pause after the opaque route transfer and prove ticket zero remains
unavailable until B returns that proof; the eight-cycle audit and prefixed C
fixture execute the existing direct-small bounded B/C/D handoff. A missing or
mismatched publisher retains its route rather than falling through B's
ordinary no-page finalizer. A retained route or poisoned wake retains the
process boundary and its exact admission claim. The direct-only
`native_post_exit_failed_os_release` witness makes B's next OS source `munmap`
fail after that same mixed aggregate has detached. It proves the exact free
returns `Retained`, the stable post-exit entry stays terminal after B completes
its own no-page finish, and ticket zero remains unavailable because A's parked
route token and admission claim have no terminal proof. Clearing the injection
cannot create a retry or a fallback. A scalar-only audit proves B's ordinary
finish removes only B's own admission claim while A's exact retained claim
remains counted; the matching successful route reaches zero only after B
consumes the typed completion. The separate
sole-medium witness leaves A with two private medium
clients and one returned local free; source exit collection makes the route's
immediate head before A's Theap/TLD tears down. Its opaque route gives joined B
only the source route, paired process state, and A's admission. B attaches,
adopts and uses the exact page, frees and drains every A/B client, and finishes
its page engine and attachment before its typed proof can release A's claim.
The focused direct-small reclaim witness likewise suspends A's live engine
into `ThreadLifecycleSlot`, but enters the existing
`abandon_mapped_small_or_medium_to_process_route` source boundary: that
boundary validates and clears its rounded direct-cache image plus immediate
local head before B receives the same opaque adoption route. All three active
owner-exit witnesses invoke the ordinary post-destructor finish dispatch; it
resumes only the exact prepared owner. The TLS slot also has one active
generation-checked `CurrentThreadPageOwnerSession`: its private handle resumes
and re-parks the same engine across ordinary allocation, local-free, and
joined pre-exit-publication operations while its bounded linear ledger remains
in TLS. Its consuming `prepare_sequential_exit` transfers every still-local
entry into the typed route without a workload-shaped client list;
source-published entries remain with source collection. For either bounded
source-valid B/C/D interleaving it may instead move exactly three
generation-checked opaque keys and their direct-small or mapped-medium kind
into the scoped post-exit publication group, validating all three before the
transfer can change the parked session ledger. The fixed preparation
path follows the same accounting rule: every allocation must be locally
freed, joined-published before exit, or transferred exactly once into the
route; omitted, duplicate, and over-capacity sets reject before suspension.
An active session with no locally live client takes its own page-drain/
attachment teardown before it releases A's admission: locally freed entries
are already free, while joined source-published entries are force-collected
there before the all-free test. A live session does not permit A to fall
through the no-page finalizer, and neither does a typed post-exit route or its
admission claim. Isolated source-published-session regressions warm ticket
zero, publish either one or two joined private clients, and prove that normal
finish force-collects them before it tears down A and reopens ticket zero.
When a joined source-published client coexists with a distinct live native
client, the native finish still selects the typed route for the live subset:
the source drain consumes the published head before A detaches, and only B's
terminal route proof plus B's own finish releases A's admission. The direct
`native_source_published_live_owner_exit` regression proves that split. Its
selected-C companion
`native_mimalloc_source_published_live_owner_exit_test.c` makes the same
boundary observable through the shadow ABI: B publishes the direct-small
client, fresh C frees only the surviving medium client, and C's normal finish
is required before the initial owner can resume.
The selected-C
`native_mimalloc_post_exit_source_published_successor_test.c` composes that
boundary with B's held terminal proof for an earlier A route: B's own
source-published small client stays with B's source drain while its distinct
medium client enters B's successor route. B's teardown then settles A's proof;
fresh C must terminally free and normally finish B's medium route before
ticket zero resumes. It remains a serialized exact-address witness, not a
general route chain.
The selected-C
`native_mimalloc_post_exit_source_published_all_free_proof_test.c` covers the
complementary no-successor composition: D source-publishes B's only small
client, B terminally frees A's routed medium, and B makes no further allocator
operation. B's typed all-free drain and own teardown complete before it
settles A's proof, after which ticket zero can resume. No B client is exposed
through another route.
While B holds that proof, its local client set is frozen: native allocation
and local `realloc` replacement return unavailable, while an exact local
`free` remains available to complete B's source-defined exit. The direct
local-session regression preserves sentinel bytes across the refused
replacement before it proves the later successor or all-free completion.
The selected C pointer-refusal fixture verifies that a valid foreign request
maps to `ENOMEM` while preserving A's original client and bytes until generic
pointer-first free. It then keeps B-local replacement coverage through B's
TSD destructor, which reallocates and frees B's existing local client before
B's native all-free finish can settle A's proof. B exits through
`pthread_exit`: its cleanup handler makes and frees a new local allocation,
then the TSD destructor continues B's local client before freeing it. The same
selected fixture also proves normal return runs the TSD destructor without a
cleanup handler and repeats the cleanup/TSD ordering through deferred
cancellation at a real cancellation point.
The retired-page session regression separately leaves a normal direct-small page
locally free and retired while one medium client stays live in another source
bin. Its prepared aggregate route releases that retired span before B receives
the remaining opaque medium route. Before B can attempt the existing
final-member reclaim, A records the page's immediate local-head fact while it
still owns the engine; without that private fact B takes ordinary sequential
free, avoiding an irreversible post-claim retention. B's terminal route proof
and independent attachment finish still gate A's admission release and
ticket-zero reactivation. The direct-small path has a held-route Rust lifecycle regression plus eight direct-small
normal-finish/reclaim cycles; its integration test also shuffles all eight
core pointer-private lifecycle routes for eight epochs
from seed `0x9e3779b97f4a7c15` and proves ticket-zero reactivation after each.
The state audit and existing prefixed C reclamation symbol alternate the
direct-small source with the sole-medium source without exposing a
direct-specific C ABI. Those bounded witnesses do not make it a general
later-thread reclamation route. The opt-in `allocator --soak` lane repeats the
same two-worker C schedule 1,024 times from seed `0x94d049bb133111eb` under a
180-second watchdog: two routes per cycle and exactly 2,048 route invocations.
Only a completed run with byte-identical clean Git source states before its
pin, contract, and header reads and immediately before publication atomically
replaces
`.work/reports/allocator/runtime-ticket-zero-soak-1024.json`; it does not
write the shared allocator `latest.json`. The format-1 stable report retains
the live contract digest, pinned archive, adapter archive/shared library,
fixture, oracle/target identity, commands, schedule, and all 13 scalar audit
fields. It re-attests the fixed raw contract/archive/adapter/fixture paths
without symlink indirection, binds the fixture executable/build inputs to those
records, and requires a live pin-matched annotated-tag cache. Every later
cycle and the final ticket-zero allocation/free must match
the first complete cycle's process/page-owner readiness, PageMap
registration/capacity, arena registry, live-TLD, metadata, shared-Theap, and
regular/OS-abandonment baseline. The audit exposes no pointer, page, route,
allocator, or release capability; the separate native-shadow registry
high-water remains owned by the focused Rust regression. This report remains
bounded stability evidence: `allocator --full` only validates and renders its
fixed durable record through the top-level non-executing
`runtime_ticket_zero_soak` consumer. `verified`, `unavailable`, and `rejected`
are provenance classifications only: they satisfy, advance, and unblock no M5
gate, and establish neither a selected/default libc backend nor general
cross-thread/post-exit, upstream pthread, or large-object acceptance.
`allocator --full` additionally runs one
separate source-derived pinned `test/test-stress.c` route through the same
16-symbol test adapter: `NTHREADS=1` and fixed `1 1 2` inputs keep the
upstream allocation/cookie/realloc/retained-transfer cleanup workload on the
creating thread. The patch rejects libc, heap, theap-walk, subprocess, leak,
and large-object modes, and the source scheduler creates no pthread. It is
preliminary scalar upstream stress evidence, not acceptance of upstream
cross-thread transfer, remote-free, thread recreation, or Gate 5D. Its
symbol audit rejects
normal `malloc`/`free` and `mi_*` exports. The permanent session and
arena remain retained after that handoff, so it has no shutdown,
concurrent/general later-thread route, fork repair, pointer-domain fallback,
or backend-promotion meaning.

The same private runtime module also has one lower live-engine scheduling
regression that is deliberately separate from the typed post-exit route
variants in `ThreadLifecycleSlot` and from the C adapter. A later worker may split a live ordinary engine into
an attachment-bound, non-sendable parked token; the runtime moves only
`READY -> BUSY -> PARKED`, continues to reject ticket-zero activation, admits
one all-free non-parkable B operation as `PARKED -> BUSY -> PARKED`, and lets
only A reassemble its exact engine through `PARKED -> BUSY -> READY`. The
tokens carry no client address, raw PageMap, detached-owner finalizer, or
general worker scheduling authority. Drop and unrecoverable handoff failures
retain the permanent page owner.

`main_theap.rs` is the sole static-TLD exception. It owns one private,
process-static owner whose aligned/address-stable `Heap` and default `Theap`
field slots are current-thread-only (`!Send`/`!Sync`). The coordinator splits
static Heap foundation from ticket-zero attachment so the PageMap stage sits
between them. It preflights dynamic as its immutable empty image, fast as null,
and default/cached as the empty Theap before it consumes ticket zero; rejection
therefore does not advance the counter or touch metadata/mapping. Its main
`Heap` uses kind-only `_mi_memid_create(MI_MEM_STATIC)` provenance (zero
union/flags); the TLD and Theap retain concrete pinned/committed static image
memids. It preserves `_mi_theap_init`'s
copy/TLD/refcount/subprocess/options/TLD-list/random-cookie/Release-heap/
heap-list order, then publishes default followed by fast. Cached and dynamic
remain empty. A busy freshly owned TLD/heap list, subsequent list-attachment
failure, or post-mutation private unlock error is terminal
initialization-invalid-owner handling: the already registered static TLD and
live count remain in process-static storage, roots remain pristine when the
TLD-list attach fails before publication, and no teardown owner is returned.
After exact live-root ownership validation, teardown checks zero pages as a
Rust pre-mutation invariant; that rejection preserves every live
root/list/image and registration. After that check passes, the valid path
matches `_mi_thread_done`'s `src/init.c:448-481` call order: it clears fast
through `_mi_thread_locals_thread_done`, then clears default/cached and
detaches heap then TLD lists under their locks, Release-clearing `theap.heap`,
clears links/TLD/random/cookie/subprocess,
invalidates and quiesces the TLD, then releases live registration and
terminally retires the static TLD slot. A post-root-reset private lock/list
failure, including a post-mutation unlock error, requires invalid concurrency
or a kernel/private-lock failure outside the valid owner contract. It is a
terminal invalid-owner state that retains process-static storage and its live
registration rather than retrying or claiming completed teardown. The
represented `Heap` ends at the source `memid`; its abandoned fields remain
valid zero/deferred state, while one separately bounded static page owner may
install an arena's in-place `pages_main` in its source arena-pages table. This
is not a full C-size or heap API claim.

`main_heap_thread.rs` separately owns the source ordinary later-thread
`_mi_thread_init_with_heap(mi_heap_main())` attachment. A borrow-tied lease
serializes short projections of the live static main Heap; each later owner gets
a nonzero metadata TLD and metadata Theap, links it to that heap, and publishes
default then the fixed fast slot while dynamic remains the immutable count-zero
backing and cached remains empty. It allows overlapping later attachments and
gates static teardown on their linked membership. `main_heap_page.rs` may borrow
one such current owner alongside a matched process map/arena pair: it uses the
same static Heap and the arena's in-place `pages_main`, holds the one map
lifecycle through allocation/free and a joined scoped producer, then returns to
the existing post-user-destructor teardown. It can also consume that engine
into one post-fast-slot exit drain: after user destructors it clears the fixed
fast slot, force-collects every queue (including full), and releases only pages
that become all-free through PageMap removal -> `pages_main` clear -> metadata
retirement -> slice release. The pass continues beyond an earlier live page,
then retains that post-fast-slot owner instead of queue-detaching or abandoning
the general live page. Eight explicit sole-page exceptions remain after
fast-slot clear, each requiring no other queue/direct/page state. The full
one-block arena singleton false-collects, detaches, and unmapped-abandons while
retaining its PageMap lifecycle and registration through its exact final client
free; that failed-reclaim empty result performs PageMap removal -> `pages_main`
clear -> metadata retirement -> slice release. The OS-aligned singleton
exception permits the source `BIN_HUGE` route while remaining semantically full,
even for a small ordinary block size: it links its one `MemoryKind::Os` page in
`Heap::os_abandoned_pages` before unown, removes it before clipped PageMap ->
alias -> metadata -> mapping release, and retains an injected failed-unmap
owner terminally. It provides no OS-list search, reuse, or general routing.
The separate medium regular page exception requires `reserved > 1` and `used == 1`, force- then
false-collects, detaches, and publishes its exact main
`pages_abandoned[bin]` bit plus paired `Heap::abandoned_count[bin]`. Its final
client free takes only the source mapped empty-before-reclaim outcome, clears
that bit/identity, consumes the paired count, and performs the same terminal
release; a still-live result is terminally retained rather than reclaimed or
requeued. Normal full medium and full large `BIN_FULL` exceptions force- then
false-collect, queue/page-count-detach, and deliberately become ordinary
unmapped abandonment before old-Theap/TLD teardown. Their separately bounded
one-joined-remote predecessors collect exactly one free while remaining linked
in `BIN_FULL`, then the same removal clears the full flag and immediately
publishes the mapped bit/count pair; the large mapped route retains its full
64-slice terminal-release proof. The full non-direct small exception follows
the normal unmapped tail but detaches from its ordinary small size bin, requires
`block_size > SMALL_SIZE_MAX`, has no direct-cache range, and uses the ordinary
failed-reclaim collector. The full direct small exception is the complementary
ordinary-bin shape: it requires `block_size <= SMALL_SIZE_MAX`, `reserved >=
16`, `used == reserved`, and the complete rounded source direct-cache range
with every other slot empty. Queue removal clears that range before page-count
detach. Its partial collector retains the just-published atomic head, so the
source free count has its one-head lag before the same below-mostly-used
reabandonment decision. Their normal sequential client frees remain unmapped through
`free <= reserved / 8`; the first
below-mostly-used free publishes the exact static-main `pages_abandoned[bin]`
bit plus paired `Heap::abandoned_count[bin]`, and the mapped tail preserves
that pairing until the same terminal release. The full-large route validates
its complete 64-slice span before release. Separately,
`abandon_full_singleton_pages_to_process_route` accepts only two or more full
arena `PageKind::Singleton` members in `BIN_FULL`; each has its own rounded
block size, `reserved == used == 1`, zero retirement countdown, empty local
free list, exact paired-arena span, and every direct slot and other queue
empty. Source force -> false collection then detaches and unmapped-abandons
every member before old-Theap/TLD teardown. Later canonical client frees
re-resolve and validate PageMap membership without a raw list or static-main
bitmap/count pair, take only the raw empty failed-reclaim outcome, and release
one member in PageMap -> `pages_main` first-bit -> metadata -> arena-slice
order. Sole pages, OS or other non-singleton members, allocation-time
adoption/reclaim/requeue, scanning, and concurrent routing remain absent.
Separately,
`abandon_full_os_singleton_pages_to_process_route` accepts only two or more
`MemoryKind::Os` singleton members in `BIN_FULL`, each with its own rounded
block size, `reserved == used == 1`, zero retirement countdowns, empty local free lists,
valid clipped PageMap/alias release images, every direct slot and other queue
empty, and an initially empty static-main `Heap::os_abandoned_pages` list.
Source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown runs for every member before old-Theap/TLD
teardown. Full-queue removal clears `PAGE_IN_FULL_QUEUE`, while the private
list deliberately owns the page's raw intrusive links until an exact later
client free removes that member. Each free re-resolves PageMap membership,
takes only the raw empty failed-reclaim outcome, then releases that one member
in private-list removal -> clipped PageMap -> aliases -> metadata -> mapping
order. A sole page, non-OS member, nonempty initial private list, list
traversal, retry/reclaim/requeue, allocation-time, and concurrent
routing remain absent; collection failure retains the drain and failed `munmap`
retains its `OsAlignedPageOwner` terminally. Separately,
`abandon_full_medium_pages_to_process_route` accepts only two or more full
arena medium members in `BIN_FULL`, each with an independent rounded block
size/bin, every direct slot and other queue empty, zero retirement countdowns,
and an exact paired arena span. Its source force -> false collection then
detaches every member and leaves each source-unmapped before old-Theap/TLD
teardown. Later client frees re-resolve PageMap membership without a raw list,
claim the member low owner bit, then choose that member's exact static-main
bitmap/count capability and unmapped or mapped tail. They release one member at
a time through PageMap -> `pages_main` -> metadata -> slice; a sole full page
rejects before mutation. The separate
`abandon_full_large_pages_to_process_route` has the same bounded aggregate
shape only for `PageKind::Large`: every member has one exact 64-slice
arena/PageMap span, and terminal release proves that complete span before the
same PageMap -> `pages_main` -> metadata -> slice order. The medium route
rejects a mixed class while the large route keeps its large-only full queue
with per-member bins;
neither exposes adoption, reclaim, requeue, allocation-time, or concurrent
routing. Separately,
`abandon_full_non_direct_small_pages_to_process_route` accepts two or more full
arena `PageKind::Small` members across ordinary bins, each with its own
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` and static-main bin, zero
retirement countdown, empty local free list, and exact paired-arena slice.
Every direct slot and `BIN_FULL` must be empty, and no other page class may
occupy a populated ordinary bin. It preserves force -> false collection,
ordinary-bin removal with the proven no-op direct-cache update, page-count
detach, and ordinary unmapped abandonment. Its normal-collector client-free
tail re-resolves each PageMap member, claims its low owner bit before selecting
only that member's paired bit/count and unmapped or mapped tail, and releases
one member at a time. A sole page, direct-small geometry/cache image, mixed
class, or collection failure refuses or retains the route; it grants no
direct-small partial-head, adoption, reclaim, requeue, scanning, or concurrent
authority. The corresponding full non-direct-small and
direct-small aggregate is instead admitted only by
`abandon_full_direct_small_pages_to_process_route`: two or more full arena
`PageKind::Small` members in one ordinary bin with the same rounded
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, zero retirement countdowns,
empty local free lists, and one paired-arena slice each. Its complete rounded
direct-cache range names the current ordinary-queue head while every other
direct slot and queue is empty. It preserves force -> false collection,
ordinary-bin removal, direct-cache-head advance before page-count detach, and
ordinary unmapped abandonment. Later frees re-resolve one PageMap member at a
time, keep the partial collector's just-pushed expected head through the source
accounting lag, then independently publish/release only that member's paired
bit/count and one-slice span. Sole pages, stale/mixed cache images, non-direct
geometry, mixed bins/classes, collection failures, adoption, reclaim, requeue,
scanning, and concurrent routing refuse or retain the route. The corresponding
full non-direct-small and
direct-small one-joined-remote predecessors remain linked in their ordinary
bins while force collection makes them nonfull; the former keeps its empty
direct image, while the latter clears its rounded direct range before
page-count detach. Both immediately publish their mapped bit/count pairs and
remain client-free-only through terminal release. The sole nonfull small-or-medium
process route preserves the same
mapped publication, tears down the old Theap/TLD, and routes its linear client
frees through short PageMap access. A separate client-free-only large route
requires exactly two live blocks and retains its complete 64-slice PageMap and
`pages_main` span until the second free. Its sole mapped medium member, or its sole
direct-small member with an immediate local free block, the exhausted fully
committed scalar-extension shape, the exact exhausted prefix-covered extension
shape, or the exact exhausted on-demand page-area-commit shape after source
collection, may instead be
explicitly consumed by a fresh later-main owner after exact
subprocess/configuration/PageMap-root/static-main-Heap/arena/page-identity
preflight: the short map access becomes one long lifecycle, the matching
bitmap/count member is claimed, source abandoned/live collection and Theap
reassociation run, and the page returns at the target queue tail. A direct-
small target restores its complete rounded direct-cache range before target
page-count increment and immediately reuses that same page; its exhausted fully
committed scalar shape extends after tail insertion, its exact prefix-covered
shape retains its prefix count and extends without direct commitment, while its
exact on-demand shape directly commits its page area before
prefix-count/free-list/capacity publication. The medium slice
accepts an immediate head or an exhausted nonfull medium page
(`capacity < reserved`). A fully committed medium page (`slice_pcommitted == 0`)
extends after tail insertion. The bounded test-only `commit == false` fixtures
instead start from real reserved medium and direct-small pages with source
callback-committed prefixes. Their direct `_mi_os_commit`-shape extensions precede both the
monotonic prefix-count update and free-list/capacity writes. A direct-commit
failure repeats source false collection, queue detach, direct-cache/page-count
repair, and mapped identity/bit/count/unown publication, then permits only a
same-candidate retry through the retained long lifecycle. This is not a
production page-on-demand policy or fresh fallback. A bitmap miss, malformed
state, scalar extension error, or other post-transfer failure remains
terminally retained. Non-direct-small and malformed or out-of-profile
no-immediate direct-small metadata remain client-free-only. A direct small member must prove the exact rounded
source direct-cache range before collection; queue removal clears that range
before page-count detach. The route retains the source `reserved >= 16`
small partial-collection invariant and excludes full small pages through its
explicit `used < reserved` guard; the separate full-small exceptions above own
the direct and non-direct classes.

`abandon_mapped_regular_pages_to_process_route` is the bounded source-traversal
extension: before any mutation, every direct slot must match its source queue
head and every queue member must be either a nonfull regular small, medium, or
large arena page; a full `BIN_FULL` medium or large page; an ordinary-bin
direct/non-direct full small page; or a live full arena singleton in
`BIN_FULL`/`BIN_HUGE`. A joined remote free makes a full regular member nonfull
during source force collection, so removal publishes its ordinary bitmap/count
pair. An unchanged full regular member instead queue-detaches into
source-unmapped abandonment and retains its PageMap span until a later client
free crosses the source mostly-used predicate or releases it. A live arena
singleton remains PageMap-only for its raw terminal release; a live OS-aligned
singleton links through the static main Heap's private list and retains its
clipped-mapping terminal tail. An arena or OS-aligned singleton with one joined
remote free force-empties and follows the ordinary terminal release before the
remaining registry is exposed; a failed OS unmap retains the typed route.
Direct small members retain `reserved >= 16` for the source partial collector;
an empty member is admitted only when normal local free left its source
retirement countdown nonzero. The route
then ports `_mi_theap_collect_retired(theap, true)`'s regular-bin pass, so an
already-empty retired span releases before the remaining
`mi_theap_page_collect` / `_mi_page_abandon` decisions: force-collect, release
pages made all-free, false-collect still-live pages, queue detach, direct-cache
refresh, page-count detach, and either publish the exact static-main mapped
identity/bit/count pair, retain source-unmapped full identity, retain a live
arena singleton's raw PageMap-only tail, or retain a live OS singleton's
private-list/clipped-mapping tail. Its typed aggregate registry
retains no old-Theap pointer or raw page list; every later linear client free
re-resolves one PageMap entry, selects a regular bin only after the source low
owner-bit claim, preserves map/bit/count while nonempty after mapped
publication, and re-derives the selected page's complete regular or singleton
span before the terminal PageMap -> `pages_main` -> metadata -> slice release
on empty. The current small, medium, large, arena-singleton, and OS-singleton
cases therefore prove their one-, 8-, 64-, source-singleton, and clipped-map
releases. The direct-small retirement regression retains the exact rounded
cache image through ordinary local retirement, then proves the source prepass
clears it as the one-slice span releases before a live medium member is
published. If retirement/force collection empties every page, it returns the
ordinary drain. If the completed source traversal instead leaves exactly one
initial nonfull medium page with an immediate local head, it captures that
exact page/span/bin fact before registry construction and returns the existing
one-page mapped route. Its reclaim revalidates the immediate head and cannot
extend, commit, scan, or take a fresh-page fallback. Fresh engines may
serialize independent PageMap operations between client frees, but no current
path can adopt, reclaim, or requeue a live multi-member aggregate registry.
After every sibling and singleton tail has terminally released, its one final
mapped regular member may instead take the separately recorded consuming
bitmap-claim edge into a fresh later-main engine; every other aggregate member
remains sequential client-free-only. That edge neither scans alternative
members nor exposes general reclaim or requeue authority. The general registry
accepts unchanged full regular medium/large/direct-small/non-direct-small
members as its source-unmapped tail plus live arena and OS singletons as their
separate raw-terminal classes. A live OS singleton requires an initially empty
private list and is rejected if that list already owns a member; foreign pages
and malformed direct-cache images still reject before mutation. Its full regular cases are the joined
remote-force `BIN_FULL` medium/large and ordinary-bin direct/non-direct small
mapped cases plus the unchanged full source-unmapped cases; force-empty
arena/OS singleton cases remain private to the traversal.
The separate full-singleton, full-medium, full-large, non-direct-small, and
direct-small aggregates retain their route-specific class and geometry
preflights. Full-medium members may use distinct rounded bins, while stale
direct-cache images and every other remote-force full state remain absent.
Before its retired-page prepass and queue traversal, the aggregate takes the
pinned deferred-free invocation phase while the old Theap/TLD pairing is
still live; the direct small-or-medium and all-free runtime continuations take
the same phase before their first page inspection. The all-free continuation
then shares the aggregate's source `_mi_theap_collect_retired(theap, true)`
prepass before it begins generic force collection, so an already-empty
retired page releases directly rather than consuming a generic collector. If
that release has already detached queue/count or PageMap state before it
fails, the shared prepass records a terminal page-specific lifecycle poison;
neither continuation can retry it or imitate no-page teardown.
Likewise, every source-mutated `RetainedEngine` becomes a terminal retained
drain at the `MainHeapThreadProcessPageExitDrain` wrapper: that boundary
latches the post-fast-slot attachment before the retained drain returns. Its
`finish` method then retains the same PageMap mutation lease instead of
treating an empty old queue/count image as an all-free/no-page result while a
page can remain PageMap-published.
Production advances the Theap heartbeat, and an attachment-local test observer
proves the force flag, recursion guard, and ordering. Public callback
registration/re-entry, arena collection, and retry/reuse as a normal allocator
remain outside this owner.
Only an empty drain permits
`finish_after_page_drain` to reset default/cached, detach its shared heap list
member before its TLD list member, and retire metadata/TLD. A force/release
failure or root/list mismatch remains terminally retained; this is not general
abandonment, later-free/reclaim, concurrent routing, or a `pthread` lifecycle.

The source-valid sole-immediate-medium result is deliberately distinct from
that aggregate registry. Its typed route now moves from A to a fresh B OS
thread, where B reclaims the exact PageMap/arena identity, reuses its immediate
head, frees A's inherited clients, drains B's page engine, and completes B's
ordinary attachment before a typed terminal proof can release A's admission.
That is the bounded cross-thread adoption witness. Separately, the direct
mixed-route regression proves an aggregate's final mapped regular member can
transfer only after every sibling terminally releases. The same pointer-private
runtime route now exercises that one edge after its arena/OS singleton
subregistries have terminally cleared; it still exposes no client identity,
page scan, general allocation, or later-thread routing surface.

The later-main drain also has one separate mixed full singleton/regular route:
`abandon_full_singleton_or_regular_pages_to_process_route` accepts only a
complete `BIN_FULL` image with two or more arena members, at least one
`PageKind::Singleton`, and at least one regular `PageKind::Medium` or
`PageKind::Large`. Singleton geometry remains `BIN_HUGE` with `reserved ==
used == 1`; regular geometry remains ordinary-bin with `reserved > 1` and
`used == reserved`; every direct entry and other queue must be empty. The
source transition force- then false-collects, detaches, and unmapped-abandons
each member before old-Theap/TLD teardown. Its composed route keeps no raw
member list: a singleton takes only the raw terminal-empty tail, while a
regular member claims its low owner bit before selecting its exact static-main
bitmap/count pair and normal collector tail. Each terminal free releases only
its own PageMap -> `pages_main` -> metadata -> exact arena span; the map route
closes only after both source tails release. This does not authorize a general
heterogeneous queue traversal, regular-only mix, allocation-time adoption,
reclaim/requeue, producer, or concurrent-free path.

`process_page_map.rs` owns the global source-page-map prerequisite. It freezes
one `MemoryConfig` and selected main subprocess, initializes a `PageMap` in
its final static slot, and Release-publishes its root exactly once.
`process_arena.rs` retains one caller-selected, complete external in-place
arena mapping and adds one explicit caller-selected regular OS reservation
after binding either form to that same map/root/configuration/subprocess tuple.
The regular entry accepts only a nonzero request that rounds to exactly one
complete arena and normal reserved or committed mapping access; it records
`MemoryKind::Os`. Its separately bounded `reserve_default_os_arena` entry
ports the first lazy `mi_arena_reserve` decision: source max-page headroom, the
frozen 1-GiB Linux/AArch64 default, the overcommit eager-map condition, and the
128-MiB retry after an unpublished attempt returns COLD.
`MainStaticFirstArenaPageAllocator` now calls it only for an empty ticket-zero
Theap's first valid ordinary fresh-page miss: it derives the exact
small/medium/large/singleton span, revalidates the zero-page static image before
mapping, retains the PageMap lifecycle through activation, then delegates to
the established static engine. `ProcessMainThread` is the owner’s only
production-shaped factory, transferring its retained attachment plus the
immutable ready-map witness without reserving or mapping at startup. It is not
called at process startup. An
unpublished metadata failure unmaps that exact regular map before leaving the
sidecar cold for a matching retry, while a failed unmap retains the mapping
terminally. The external entry continues to return an unpublished rejected map
to its caller. A reserved map first enters the final owner slot, so the retained
arena callback commits metadata and later selected ranges through the exact
same `Mapping`; frozen Linux decommit reports no recommit requirement. This
establishes the external-map ownership prerequisite, one bounded first
fresh-page connection, and one narrow paired direct page-area commit operation;
it does not enable existing-arena search, later arena scaling, option mutation,
large-page/exclusive/NUMA policy, page-on-demand policy, or itself maintain
`slice_pcommitted` or page reabandonment.
`ProcessPageArenaLease` proves that exact tuple before `main_static_page.rs`
or `main_heap_page.rs` may bind an already selected source Theap to it. The
private ticket-zero and later-thread engines each hold the only process-map
plain-entry lifecycle for their complete engine and joined scoped producer,
install the arena's embedded `pages_main` bitmap in the shared static Heap, and
use the existing engine's source bitmap -> map publication and map -> bitmap ->
metadata -> slice release order. They reject a foreign subprocess before page
mutation, and an unfinished engine terminally poisons both owners rather than
manufacturing cleanup. Their normal `realloc` delegates preserve source
failure ownership and replacement copying; only the ticket-zero null case may
activate the completed first-arena policy. This remains a caller-initialized, single-arena,
sequential-owner slice. The bounded coordinator can now provide its map
predecessor, the private ticket-zero owner can make the first fresh-page
connection to the completed default reservation, and a completed reservation
can reconstruct only its immutable matching pair for one subsequent bounded
owner. That pair does not scan arenas, select free slices, reserve, or map.
The coordinator still supplies neither
the C static empty-map pre-root, existing-arena search, later automatic arena
reservation, concurrent or general later-thread page routing, general
abandonment/owner exit, process destruction, pthread integration, nor public
allocator routing. Map setup failure is once-terminal rather than a null root
or retry.

`dynamic_theap.rs` adds one private later-ticket current-thread attachment.
It atomically refuses ticket zero, then retains the caller-pinned first-class
Heap, metadata TLD/live registration, typed Malloc Theap, dynamic backing, and
linear regular-key lease. Dynamic `_mi_theap_init` completes TLD-list/random/
cookie/Release-heap/heap-list order, then publishes the regular TLS slot and
the cached root from the canonical empty source image, with the exact dynamic
Theap reference transition `1 -> 2`; default and fast remain unchanged. Begin
rejects any other cached predecessor before ticket issuance. No-page teardown
prevalidates that slot/root/refcount pair, clears the slot and backing, restores
that exact canonical empty cached root with `2 -> 1`, then detaches lists and
frees metadata. Root/list/page failures before mutation leave authority
unchanged; an after-publication or after-root-reset private failure returns a
retained poisoned owner with only known-valid capabilities. The one retryable
exception is a pre-mutation key-release lock error after other teardown: it
retains only the lease until `AwaitingKeyRelease` succeeds. General cached-root
switching/refcount ownership, general remote-free routing/concurrency, general
page routing or abandonment integration, full heap/Theap/arena/subprocess APIs,
pthread/fork/process shutdown, stats/options/callbacks, and public ABI remain
open. Ordinary dynamic begin stores the source abandoning `true`/`2` profile
and rejects a page session. A crate-private unsafe non-abandoning begin instead
stores `false`/`-1` before Release heap publication; its sealed borrowed
`DynamicTheapPageSession` alone instantiates the shared private
`PageAllocatorEngine`. Consuming finish requires a drained page lifecycle, and
an unfinished engine Drop terminally latches the attachment rather than
allowing teardown to claim quiescence.

The exact ordinary `true`/`2` queue image is also admitted through a
`cfg(test)`-only fixture for a source-shaped `MI_ABANDON` aggregate proof. That
fixture leaves `DynamicTheapAttachment::page_session` unchanged: production
ordinary dynamic attachments still cannot create a general page engine.

Its post-TLS `DrainingPages` state is now also a bounded source owner-exit
state, not an alternate allocator. It clears the regular dynamic backing before
page abandonment while retaining the cached root, TLD/Heap list membership,
PageMap, and heap-local arena image. `DynamicThreadExitDrain` first
force-collects an already-retired all-free regular page. Its singleton
transition admits one full one-block arena or OS-aligned page; the source
force-only local-list append is unreachable under its `reserved == used == 1`
and no-producer proof. The raw local-list substrate now separately ports and
tests that force append, including cycle rejection before relinking; the
separately recorded later-main all-free exit drain invokes it, but no current
page-engine lifecycle invokes it for a general traversal. The singleton
handoff queue-detaches and unmapped-abandons its page, then a final client free
necessarily fails reclaim through the cleared regular slot and owns its raw
all-free release. The OS form additionally links/removes its exact dynamic
`Heap::os_abandoned_pages` member around clipped PageMap -> alias -> primary
metadata -> mapping release.

For exactly one arena-backed full singleton, a separate Rust-only
`DynamicThreadExitArenaSingletonPostExitRoute` now completes the source-side
dynamic TLS, cached-root, Theap/TLD, and key teardown before it exists. The
source worker transfers only an inert pinned Heap plus its one dynamic arena
image; after the worker joins and the caller proves whole-PageMap quiescence,
one receiver may consume the exact client free and release PageMap -> dynamic
arena bit -> metadata -> arena span -> image -> Heap binding. The live
`DynamicTheapAttachment` and its ordinary singleton handoff remain `!Send`;
this is not a crabc pthread/TLS callback, C/Rust
destructor differential, general client routing, concurrent collection, or
public x86/runtime claim.

`DynamicThreadExitDrain::abandon_full_singleton_pages` separately admits one
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Singleton` members in `BIN_FULL`, each with its own rounded block
size, `reserved == used == 1`, zero retirement countdown, an empty local free
list, exact arena span, and no other queue/direct state. It follows source
force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullSingletonPagesRoute`
retains the existing dynamic drain instead of a raw member list or dynamic
bitmap/count pair; each sequential canonical free re-resolves and validates
the PageMap entry, takes only the raw empty failed-reclaim result, and releases
that member through PageMap -> dynamic ordinary bit -> metadata -> arena
slices. The final free returns the empty drain for existing teardown. Sole,
non-singleton, OS-backed, allocation-time, reclaim/adoption/requeue, scan, and
concurrent cases reject before detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_os_singleton_pages` separately admits a
bounded homogeneous dynamic aggregate: two or more same-rounded-size full
`MemoryKind::Os` singleton members in `BIN_FULL`, each with
`reserved == used == 1`, zero retirement countdown, empty local free list,
valid clipped PageMap/alias release image, an initially empty dynamic
`Heap::os_abandoned_pages` list, and no other queue/direct state. It preserves
source force -> false collection -> full-queue/page-count detach -> private
OS-list insertion -> unmapped unown for every member.
`DynamicThreadExitFullOsSingletonPagesRoute` retains only the dynamic drain
and member count; every sequential canonical free re-resolves
PageMap, takes only the raw empty failed-reclaim result, removes its exact
private-list member, then releases its clipped PageMap -> alias -> primary
metadata -> mapping image. The final free returns the empty drain for existing
teardown. Sole, arena-backed, mixed-size, non-singleton, preexisting-list,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, huge,
and general owner-exit cases reject before detach; collection, list, or mapping
release failure retains the only owner terminally.

`DynamicThreadExitDrain::abandon_full_medium_pages` separately admits a third
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Medium` members in `BIN_FULL`, each with an independent rounded
block size and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdown, empty local free list, exact arena span, and matching dynamic
bitmap/count capability. No other queue/direct state is admitted. It follows
source force -> false collection -> full-queue/page-count detach -> unmapped
abandonment for every member. `DynamicThreadExitFullMediumPagesRoute` retains
the existing dynamic drain rather than raw member pointers or per-member mapped
state; each sequential canonical free re-resolves PageMap, claims its member
low owner bit, then selects that member's exact dynamic bitmap/count capability
and unmapped or mapped failed-reclaim tail. It releases that member through
PageMap -> dynamic ordinary bit -> metadata -> arena slices. The final free
returns the empty drain for existing teardown. Sole, mixed-class, non-medium,
OS-backed, allocation-time,
reclaim/adoption/requeue, scan, producer, and concurrent cases reject before
detach; a collection failure retains the drain.

`DynamicThreadExitDrain::abandon_full_large_pages` separately admits a fourth
bounded dynamic aggregate: two or more full `MemoryKind::Arena`
`PageKind::Large` members in `BIN_FULL`, each with its own rounded block size
and regular bin, `reserved > 1`, `used == reserved`, zero retirement
countdowns, empty local free lists, the matching dynamic bitmap/count
capability for every member, no other queue/direct state, and every member's exact 64-slice
arena/PageMap span. It follows source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullLargePagesRoute` retains the existing dynamic drain
rather than raw member pointers or per-member mapped state; each sequential
canonical free re-resolves PageMap, claims its member low owner bit, then
selects its exact dynamic bitmap/count capability and unmapped or mapped
full-large failed-reclaim tail, and releases that member through PageMap -> dynamic ordinary bit -> metadata ->
its complete 64-slice arena span. The final free returns the empty drain for
existing teardown. Sole, mixed-class, non-large, OS-backed,
malformed-span, allocation-time, reclaim/adoption/requeue, scan, producer,
and concurrent cases reject before detach; a collection failure retains the
drain.

`DynamicThreadExitDrain::abandon_full_singleton_or_regular_pages` separately
admits one bounded mixed dynamic aggregate: two or more full
`MemoryKind::Arena` members in `BIN_FULL`, including at least one
`PageKind::Singleton` and at least one regular `PageKind::Medium` or
`PageKind::Large` member. Every direct slot and other queue is empty. Each
singleton proves `BIN_HUGE`, `reserved == used == 1`, and its own rounded arena
span; each regular member proves its rounded regular bin, `reserved > 1`,
`used == reserved`, matching dynamic bitmap/count capability, and exact
one-slice medium or 64-slice large span. Source force -> false collection ->
full-queue/page-count detach -> unmapped abandonment runs for every member.
`DynamicThreadExitFullSingletonOrRegularPagesRoute` retains only the dynamic
drain and a count. Each canonical free re-resolves PageMap: singleton members
take the raw terminal failed-reclaim tail, while regular members claim the low
owner bit before selecting their normal unmapped-or-mapped tail. Each releases
only its PageMap -> dynamic ordinary bit -> metadata -> exact arena span.
Homogeneous queues, regular-only mixed medium/large queues, small/direct-small,
OS, malformed spans, allocation-time, reclaim/adoption/requeue, scan,
producer, concurrent, and general owner-exit cases remain absent; a collection
or terminal-release failure retains the sole owner.

`DynamicThreadExitDrain::abandon_full_non_direct_small_pages` separately admits
a sixth bounded per-member dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members across ordinary bins, each with its own rounded
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, zero retirement countdown, empty local free list, exact
one-slice arena/PageMap span, and matching dynamic bitmap/count capability. No
direct-cache entry or `BIN_FULL` member may remain, and a populated ordinary
bin may contain no other page class. It preserves source force -> false
collection -> ordinary-bin removal with the proven no-op direct-cache update ->
page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullNonDirectSmallPagesRoute` retains the dynamic drain, not
a raw member list or per-member mapped state. Each sequential canonical free
re-resolves PageMap, claims its abandoned identity, then derives its normal
unmapped or mapped failed-reclaim tail and dynamic bitmap/count capability; it
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice. The final free returns the empty drain for existing
teardown. Sole, mixed-class, direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, and concurrent cases
reject before detach; a collection failure retains the drain. This does not
expose ordinary dynamic allocation or a
general owner-exit traversal.

`DynamicThreadExitDrain::abandon_full_direct_small_pages` separately admits a
seventh bounded homogeneous dynamic aggregate, proved only through that exact
ordinary source fixture: two or more full `MemoryKind::Arena` `PageKind::Small`
members in one ordinary bin, with one rounded `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, zero retirement countdowns, empty local
free lists, exact one-slice arena/PageMap spans, matching dynamic bitmap/count
capabilities, and the complete rounded direct-cache range naming the ordinary
queue head while every other direct entry and queue is empty. It preserves
source force -> false collection -> ordinary-bin removal -> direct-cache
refresh before page-count detach -> unmapped abandonment for every member.
`DynamicThreadExitFullDirectSmallPagesRoute` retains the dynamic drain, not a
raw member list, cached direct image, or per-member mapped state. Each
sequential canonical free re-resolves PageMap, uses its claimed abandoned
identity to select the partial-collector unmapped or mapped failed-reclaim
tail, preserves the just-pushed head through the source accounting lag, and
releases only that member through PageMap -> dynamic ordinary bit -> metadata
-> one arena slice; the final free returns the empty drain for existing
teardown. A member remains unmapped through `reserved / 8 + 1` frees; only the
next may publish its matching dynamic bitmap/count pair. Sole, stale/mixed
direct-cache, mixed-bin/class, non-direct-small, `BIN_FULL`, OS-backed,
allocation-time, reclaim/adoption/requeue, scan, producer, concurrent, and
joined-remote nonfull cases reject before detach; a collection failure retains
the drain. This does not expose ordinary dynamic allocation or a general
owner-exit traversal.

`DynamicThreadExitDrain::abandon_nonfull_medium_pages_distinct_bins` separately
admits exactly two initially nonfull `MemoryKind::Arena` `PageKind::Medium`
pages in distinct ordinary non-`BIN_FULL` bins. The source image is exactly
`allow_page_abandon == true` and `page_full_retain == 2`; each member has one
live client, `reserved > 1`, zero retirement countdown, a canonical eight-slice
span, a clear matching dynamic map/count capability, and an owner-only empty
remote-free word. Source force -> false collection -> queue/count detach ->
dynamic map/count publication -> unown creates a route with sealed witnesses,
not a raw page list. Its two sequential terminal frees release one member and
then return the drain. Full, direct-small, same-bin, retired, nonterminal,
adoption, reclaim, requeue, allocation-scan, producer, and concurrent cases
remain outside this private owner-exit model.

`DynamicThreadExitDrain::abandon_full_medium` separately admits one sole full
`MemoryKind::Arena` medium page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullMediumHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> arena-slice release.
This one route neither reclaims, adopts, requeues, scans, nor covers full
large, non-direct-small, direct-small, multi-page, or general dynamic owner
exit.

`DynamicThreadExitDrain::abandon_full_large` separately admits one sole full
`MemoryKind::Arena` large page in `BIN_FULL`, with `reserved > 1` and
`used == reserved`. It preserves source force -> false collection ->
full-queue/page-count detach -> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullLargeHandoff` consumes sequential failed-reclaim frees:
the page stays unmapped through the source mostly-used prefix, the first free
beyond `reserved / 8` publishes the matching dynamic `pages_abandoned[bin]`
bit plus `Heap::abandoned_count[bin]`, and the mapped tail clears that pair
before PageMap -> dynamic ordinary bit -> metadata -> complete 64-slice
arena release. This one route neither reclaims, adopts, requeues, scans, nor
covers full medium/non-direct-small/direct-small, multi-page, or general
dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_medium_after_force_collect_to_mapped`
separately preserves the source full-medium branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullMediumHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the ordinary arena release. It does not add multiple frees, other
classes, reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_large_after_force_collect_to_mapped`
separately preserves the source full-large branch with exactly one joined
remote free. The sole `BIN_FULL` page starts with `used == reserved`; force
collection consumes that free but leaves the member linked and marked full with
`used == reserved - 1`; false collection preserves it; full-queue/page-count
detach clears the full flag; and mapped abandonment immediately publishes its
dynamic bitmap/count pair. The returned `DynamicThreadExitFullLargeHandoff`
starts mapped and consumes sequential failed-reclaim frees only, clearing that
pair before the complete 64-slice release. It does not add multiple frees,
other classes, reclaim, adoption, requeue, scans, or general dynamic owner
exit.

The native x86-only track also has a separate 31-field dynamic full-large
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full `BIN_FULL` large arena page (request 86706, 98304-byte blocks,
capacity/reserved 42, a 64-slice arena span with 63 PageMap-registered source
page-area slices), publishes exactly one joined remote
`mi_free`, runs real `mi_thread_done()`, and joins before consumer frees.
Rust uses only the corresponding private typed drain. Force collection records
`used == 41`, mapped dynamic abandonment, and terminal PageMap, ordinary arena
bitmap, dynamic bitmap/count, and complete 64-slice release; the final
PageMap-null arena slice is slack but remains terminally released. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, public x86 support, backend
promotion, or AArch64 evidence.

The native x86-only track also has a separate 34-field dynamic full-large
unmapped-reabandon differential. The pinned-C oracle's worker fills one sole full
`BIN_FULL` large arena page from request 86706 (98304-byte blocks,
capacity/reserved 42, 64 arena slices); only 63 source page-area slices are
PageMap-registered, and the final PageMap-null arena slice is slack but remains
part of terminal release. In the C oracle, no remote `mi_free` is published;
real `mi_thread_done()` and `pthread_join()` precede sequential consumer frees.
Rust independently executes the bounded typed owner-exit route on its owning
test thread and does not claim a literal worker-thread/join counterpart.
Five normal-collector frees retain unmapped abandonment at `used == 37` with
dynamic bitmap/count zero, then the sixth maps it at `used == 36` with dynamic
bitmap/count one. The mapped tail clears PageMap, the ordinary arena bitmap,
and dynamic bitmap/count before releasing the complete 64-slice span. This is
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public API or
runtime, public x86 support, libc integration, backend promotion, or AArch64
evidence.

The native x86-only track now also has a separate 51-field dynamic homogeneous
full-singleton aggregate differential. Its pinned-C worker fills exactly two
same-size full `BIN_FULL` arena singleton pages from request 524289 (589824-byte
blocks, capacity/reserved 1, nine arena slices each), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned, unowned, PageMap-registered across all nine
slices, ordinary-arena-bitmap-set, and full-queue-detached; no dynamic
abandoned bitmap/count is involved. The first terminal free releases only page
0 while page 1 remains PageMap-registered, unmapped-abandoned, unowned, and
`used == 1`; the second terminal free releases page 1 and closes the route.
Rust exercises only the corresponding typed current-thread owner-exit model and
does not claim a Rust worker thread or join. This is private native x86-64
engine evidence only: it does not establish general lifecycle, routing,
concurrency, abandonment/adoption, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The native x86-only track now also has a separate dynamic homogeneous
full-large aggregate differential. Its pinned-C worker fills exactly two
same-bin full `BIN_FULL` arena large pages from request 86706 (98304-byte
blocks, capacity/reserved 42, 64 arena slices each, with 63 registered
PageMap source slices and one null slack slice), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete 64-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 67-field dynamic homogeneous
full-medium aggregate differential. Its pinned-C worker fills exactly two same-bin full
`BIN_FULL` arena medium pages from request 10248 (12288-byte blocks,
capacity/reserved 42, eight arena slices each), performs real
`mi_thread_done()`, and the consumer joins before any sequential free. Both
members begin unmapped-abandoned with dynamic abandoned bitmap/count clear;
each member independently remains at `used == 37` after five frees, maps at
`used == 36` on the sixth with its dynamic bitmap/count publication, then
releases its complete eight-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 69-field dynamic homogeneous
full non-direct-small aggregate differential. Its pinned-C worker fills exactly
two same-bin full ordinary-bin arena pages from request 1032 (1280-byte blocks,
capacity/reserved 51, one arena slice each), performs real `mi_thread_done()`,
and the consumer joins before any sequential free. Both members begin
ordinarily unmapped-abandoned with dynamic abandoned bitmap/count clear; each
member independently remains at `used == 45` after six normal-collector frees,
maps at `used == 44` on the seventh with its dynamic bitmap/count publication,
then releases its one-slice PageMap/arena span. Rust exercises only the
corresponding bounded dynamic aggregate owner-exit route. This is private
native x86-64 engine evidence only and does not establish general lifecycle,
routing, concurrency, abandonment/adoption, public x86 support, backend
promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 67-field later-main homogeneous
full direct-small aggregate differential. Its real pinned-C pthread worker fills
exactly two same-bin full ordinary regular-bin arena pages from request/block
size 1024 (capacity/reserved 64, one arena slice each), verifies the complete
direct-cache range `[113, 128]` with no remote free, runs `mi_thread_done()`,
and the consumer joins before every sequential free. Both members begin
unmapped-abandoned with PageMap and ordinary arena bitmap retained and ordinary
queues detached. The C source dynamic and Rust typed later-main static-main
abandoned bitmap/count are both clear through each nine-free partial-collector
prefix at `used == 56`, then both publish the normalized common `abandoned_*`
state at the mapped `used == 54` boundary. Page 0 releases independently before
page 1 closes the route. Rust observes only a scoped test worker and join for
common typed private facts, not crabc pthread/TLS callback parity. This private
native x86-64 engine evidence does not establish general lifecycle, routing,
concurrency, abandonment/adoption, allocation-time claim/reclaim/requeue,
public x86 support, backend promotion, libc integration, or AArch64 evidence.

The native x86-only track also has a separate 43-field dynamic nonfull
regular-pages distinct-bin aggregate differential. Its pinned-C probe uses a
real worker pthread to establish exactly two initially nonfull arena medium
pages in distinct ordinary bins, runs real `mi_thread_done()`, and joins before
the consumer frees either page. Rust exercises only the matching private typed
dynamic owner-exit model; it does not claim a Rust pthread/TLS callback or
general process/pthread/TLS lifecycle integration. This remains private native
x86-64 engine evidence only and does not establish public `mi_*` behavior,
runtime integration, public x86 support, backend promotion, or AArch64
evidence.

The native x86-only track also has a separate 37-field pinned-C automatic
pthread-destructor probe. Its worker creates two live 10241-byte clients on
one private arena medium page, verifies mimalloc's real pthread key points at
the initialized default Theap, then returns naturally without an explicit
`mi_thread_done()` or `pthread_exit()` call. After `pthread_join()`, the probe
records the mapped-abandoned, PageMap-registered, arena-bitmap-set, detached,
unowned page and its two-free terminal release. This source-anchored evidence
is C-oracle-only: it does not compare Rust or establish a crabc pthread/TLS
callback, Rust/private-runtime lifecycle integration, general destructor
ordering, public `mi_*` behavior, public x86 support, libc integration,
backend promotion, or AArch64 evidence.

The native x86-only track also has a separate 46-field pinned-C
cancellation-triggered automatic pthread-destructor probe. Its worker keeps
cancellation disabled through allocator setup, then enables only deferred
cancellation before publishing an atomic-ready gate. The consumer issues one
`pthread_cancel()` and opens that gate; the worker reaches one explicit
`pthread_testcancel()`, and `pthread_join()` returns `PTHREAD_CANCELED` before
the same mapped-abandoned, PageMap/arena-bitmap, detached/unowned, and
two-free terminal observations. This is also C-oracle-only: it does not prove
crabc pthread cancellation or TLS callback parity, Rust/private-runtime
lifecycle integration, general cancellation or destructor ordering, public
`mi_*` behavior, public x86 support, libc integration, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 32-field dynamic full direct-small
one-remote force-collect-to-mapped differential. A pinned-C worker fills one
sole full direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records
`used == 63`, mapped dynamic abandonment, and dynamic bitmap/count state.
Pinned source anchors plus the Rust handoff establish direct-cache
clear-before-page-count-detach; only the source partial collector serves the
mapped tail through terminal PageMap, ordinary arena bitmap, dynamic
bitmap/count, and one-slice release. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 38-field dynamic full direct-small
unmapped-reabandon differential. A pinned-C worker fills one sole full
direct-small ordinary regular-bin arena page (request/block size 1024,
capacity/reserved 64, one slice) and preflights its exact rounded direct-cache
range `[113, 128]`. No remote `mi_free` is published; the worker runs real
`mi_thread_done()`, and the consumer joins before sequential frees. Force then
false collection clears that range before page-count detach and leaves the page
unmapped-abandoned with PageMap and ordinary arena bitmap retained, ordinary
queue detached, dynamic bitmap/count clear, and `used == 64`. The first
partial-collector consumer free retains `used == 64`; nine partial-collector
frees retain that route at `used == 56`; the tenth partial collector takes
`used` to 55, then generic unown consumes the retained current head and maps
it at `used == 54` with dynamic bitmap/count one. The mapped tail clears
PageMap, ordinary arena bitmap, dynamic bitmap/count, and the one slice. This
remains private native x86-64 engine evidence only: it does not establish
general lifecycle/routing/concurrent collection, abandonment/adoption, public
x86 support, backend promotion, or AArch64 evidence.

The native x86-only track also has a separate 30-field dynamic full
non-direct-small one-remote force-collect-to-mapped differential. A pinned-C
worker fills one sole full non-direct-small ordinary regular-bin arena page
(request 1032, 1280-byte blocks, capacity/reserved 51, one slice, and an empty
direct-cache image). The consumer/main thread publishes exactly one joined
remote `mi_free`; the worker later runs real `mi_thread_done()`, and the
consumer joins before sequential frees; Rust uses only the corresponding
private typed drain. Force collection records `used == 50`, mapped dynamic
abandonment, and bitmap/count state. The first sequential failed-reclaim free
follows normal `used + 2 == reserved` geometry while retaining the mapped
route; the final free clears PageMap, ordinary arena bitmap, dynamic
bitmap/count, and the one slice. This remains private native x86-64 engine
evidence only: it does not establish general lifecycle/routing/concurrent
collection, abandonment/adoption, public x86 support, backend promotion, or
AArch64 evidence.

The native x86-only track also has a separate 35-field dynamic full
non-direct-small unmapped-reabandon differential. A pinned-C worker fills one
sole full non-direct-small ordinary regular-bin arena page (request 1032,
1280-byte blocks, capacity/reserved 51, one slice, and an empty direct-cache
image), publishes no remote free, runs real `mi_thread_done()`, and the
consumer joins before sequential frees. It initially remains full and
unmapped-abandoned with PageMap and ordinary arena bitmap retained, dynamic
bitmap/count clear, and `used == 51`. Six normal-collector frees retain the
unmapped route at `used == 45`; the seventh maps it at `used == 44` and sets
the dynamic bitmap/count to one. The terminal mapped tail clears PageMap,
ordinary arena bitmap, dynamic bitmap/count, and the one slice. This remains
private native x86-64 engine evidence only: it does not establish general
lifecycle/routing/concurrent collection, abandonment/adoption, public x86
support, backend promotion, or AArch64 evidence.

`DynamicThreadExitDrain::abandon_full_non_direct_small` is a sixth, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with
`SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE`, `reserved > 1`,
`used == reserved`, `!page_is_in_full`, and an empty direct-cache image.
It preserves source force -> false collection -> regular-bin/page-count detach
-> ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullNonDirectSmallHandoff` consumes sequential normal
failed-reclaim frees: the page stays unmapped through the source mostly-used
prefix, the first free beyond `reserved / 8` publishes the matching dynamic
`pages_abandoned[bin]` bit plus `Heap::abandoned_count[bin]`, and the mapped
tail clears that pair before PageMap -> dynamic ordinary bit -> metadata ->
arena-slice release. It rejects direct-small before collection and neither
reclaims, adopts, requeues, scans, nor covers full medium/direct-small/large,
multi-page, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_non_direct_small_after_force_collect_to_mapped`
separately preserves the source full non-direct-small branch with exactly one
joined remote free. The sole ordinary-bin page starts with `used == reserved`;
force collection consumes that free while retaining its queue membership with
`used == reserved - 1`; false collection preserves it; regular-bin/page-count
detach leaves the page nonfull; and mapped abandonment immediately publishes
its dynamic bitmap/count pair. The returned
`DynamicThreadExitFullNonDirectSmallHandoff` starts mapped and consumes
sequential failed-reclaim frees only, clearing that pair before the ordinary
arena release. Its source direct-cache update is a no-op because the rounded
block size exceeds `SMALL_SIZE_MAX` and the full preflight requires an empty
direct image. It does not add multiple frees, direct-small or other classes,
reclaim, adoption, requeue, scans, or general dynamic owner exit.

`DynamicThreadExitDrain::abandon_full_direct_small` is a seventh, separate
dynamic full-page endpoint. It admits one sole full `MemoryKind::Arena` small
page only in its ordinary regular bin, with `block_size <= SMALL_SIZE_MAX`,
`reserved >= 16`, `used == reserved`, `!page_is_in_full`, and its complete
rounded direct-cache range naming the page while every other direct slot is
empty. Source force -> false collection -> ordinary-bin removal clears that
range before page-count detach, then ordinary unmapped abandonment. Its linear
`DynamicThreadExitFullDirectSmallHandoff` uses the source partial
failed-reclaim collector: the retained just-published head keeps the page
unmapped for one additional client free before the below-mostly-used boundary
publishes the matching dynamic `pages_abandoned[bin]` bit plus
`Heap::abandoned_count[bin]`. The mapped tail clears that pair before PageMap
-> dynamic ordinary bit -> metadata -> arena-slice release. A stale cache
range, non-direct small, additional page, or collection failure cannot bypass
the pre-detach contract. This one route neither reclaims, adopts, requeues,
scans, nor covers full medium/non-direct-small/large, multi-page, or general
dynamic owner exit.

A separate `DynamicThreadExitMappedOneBlockHandoff` accepts only a sole,
nonfull `MemoryKind::Arena` medium, large, non-direct-small, or direct-small
page with `reserved > 1`, `used == 1`, and one regular queue member. The
medium endpoint remains `DynamicThreadExitDrain::abandon_mapped_one_block`;
the large endpoint is `DynamicThreadExitDrain::abandon_mapped_one_block_large`
and retains its complete 64-slice span; the non-direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_non_direct_small` and
requires `SMALL_SIZE_MAX < block_size <= SMALL_MAX_OBJ_SIZE` with an empty
direct-cache image; the direct-small endpoint is
`DynamicThreadExitDrain::abandon_mapped_one_block_direct_small` and requires
`block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, and its complete rounded
source direct-cache range. Direct-small preflight rejects a stale cache image
before collection or detach, then source queue removal clears that exact range
before page-count detach. The handoff keeps the post-TLS dynamic arena image
only long enough to form the exact heap-local `pages_abandoned[bin]` bit plus
paired `Heap::abandoned_count[bin]`. Source force then false collection
precedes queue/page-count detach and mapped identity/bit/count/unown
publication. Its exact final free reaches empty before any source reclaim
branch—through the normal collector for medium/large/non-direct small and the
partial collector for direct small—clears the dynamic bit/count pair, then
releases PageMap -> dynamic ordinary bit -> metadata -> arena slices. The
large endpoint validates its 63 PageMap-registered source page-area slices;
the final PageMap-null arena slice is slack but remains part of the terminal
64-slice release. Neither dynamic handoff scans, reclaims, adopts, requeues,
accepts a second free, or generalizes thread exit. Only an empty drain may
resume the existing cached-root/list/key teardown.

`DynamicThreadExitDrain::abandon_mapped_two_block_medium` is a separate
post-TLS dynamic handoff for exactly one sole nonfull `MemoryKind::Arena`
`PageKind::Medium` page with `block_size > SMALL_SIZE_MAX`, `reserved > 2`,
`used == 2`, zero retirement countdown, one regular queue member, an empty
direct-cache image, and no other queue/direct entry. It preserves source force
-> false collection -> queue removal -> page-count decrement -> non-direct
no-op cache update -> dynamic mapped identity/bit/count/unown. The private
handoff retains no client pointer/list: its first exact canonical free must
produce `UnownedMapped` and keep the bit/count with one live block, while only
the final free may produce `Empty`, clear that pair, and release the
queue-detached PageMap -> dynamic ordinary bit -> metadata -> arena-slice
span. One or three live blocks, another page, other source classes, reclaim,
adoption, requeue, scanning, producers, concurrency, and general owner exit
remain excluded.

`DynamicThreadExitDrain::abandon_mapped_medium_pair` now records one separate
bounded post-TLS aggregate: exactly two nonfull `MemoryKind::Arena`
`PageKind::Medium` pages in distinct regular bins, one with `reserved > 2`,
`used == 2` and one with `reserved > 1`, `used == 1`. Preflight proves both
sole queue members, their arena spans and dynamic bitmap/count capabilities,
the total three live blocks, an empty direct image, and no other queue/page
before source bin-order force -> false collection -> queue removal ->
page-count decrement -> non-direct no-op update -> mapped publication. The
returned `DynamicThreadExitMappedMediumPairRoute` keeps only the drain plus
remaining page/free counts; every client free re-resolves PageMap membership
and acquires the source low owner bit before selecting its dynamic map. An
`UnownedMapped` result retains the route, while each `Empty` result clears its
exact pair and releases only that member; the final release returns the empty
drain. It adds no raw member registry, scan, reclaim/adoption/requeue,
allocation-time, producer, concurrent, or general owner-exit routing.

The first fresh page in that private non-abandoning dynamic session now owns
one exact source-shaped heap-local `mi_arena_pages_t` image. Creation first
requires the registry-published arena's non-null `Arena::subprocess` to equal
the attachment's selected main subprocess; the retained BCHUNK-aligned
metadata capability is then Release-published only in the bound Heap's exact
arena slot and is used for fresh/rollback/release page bits. It remains
disjoint from the arena's `pages_main`. Empty attachment
teardown removes the exact slot before freeing it, while a nonempty image is a
pre-mutation rejection and post-mutation lock/free ambiguity terminally
retains owner state. One consuming same-owner handoff now moves a mapped
regular dynamic arena page through its heap-local abandoned bitmap/count. The
same token can adopt it or consume one still-live client block through the
source mapped `allow_collect=true` same-origin remote-free branch: the small
path preserves its published head until reassociation, clears the exact
bitmap/count, live-collects, and requeues. Its all-free dynamic-arena outcome
now releases in source order—PageMap span, heap-local ordinary bit, metadata,
then arena slices—and returns the drained engine; an existing owner remains a
terminal handoff. Separately, `free_unmapped_after_failed_reclaim` remains the
source terminal-empty/reabandon/unown substrate after failed reclaim, including
the expected-head CAS and no-second-reclaim conflict path. The post-TLS full
singleton and full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small
aggregates above, the separate dynamic full-medium, full-large,
full-non-direct-small, and full direct-small handoffs, and the bounded later-main normal full-medium,
full-large, full non-direct-small, and full direct-small process routes are its lifecycle-integrated raw-release
callers; other regular or
nonempty unmapped pages, general producer routing, terminal reuse, multi-arena dynamic heap
support, and general heap destruction remain absent.

Separately, the exact source-layout `mi_random_ctx_t` image now lives directly
in `Theap::random`: it preserves source input/output word order, counter
carries, consumed-output clearing, direct random-field-address nonce identity,
and in-place split. It calls direct Linux `getrandom` and continues weakly on
an error or short read, then retries only while weak. The source local
`_mi_random_shuffle` core is deliberately replaced by one domain-separated
approved RustCrypto expansion of transparent weak observations; this
non-entropy-adding degraded-path difference is recorded in
`compat/allocator/known-differences.md`. The static main-Theap slice initializes
this exact image; both static and private dynamic Theap attachment use it, and
the narrow non-abandoning dynamic session reuses the private page engine.
General allocator routing and page-bearing production thread/process
integration remain absent. The default libc bridge is bounded to no-page
owners, while the separate suspended-owner route is test-only evidence. The
nondefault `crabc-libc` `native-mimalloc-shadow` feature is the one narrow
exception: `libc/src/allocator_native_mimalloc.rs` routes the initial thread's
malloc family and bounded attached workers' tracked local malloc/free/realloc/
aligned/usable-size operations to the Rust runtime, with no C fallback. The
same selected boundary lets an attached worker free one exact still-live
ticket-zero normal or aligned client through the source atomic remote head.
That client keeps its page registered while the worker uses only the immutable
PageMap witness, initial owner identity, and source-constant aligned geometry;
it borrows no page engine, scheduler claim, or stored client capability, and
ticket zero collects the published head during its next ordinary operation.
This remote-publication route is free-only, not cross-thread reallocation,
owner exit, or abandoned-page routing. `native_usable_size` separately reads
an exact live client's PageMap extent without this route. The
selected evidence retains the parked session and private `NativePostExitRoute`
scenario only as `#[cfg(test)]` historical oracle code. Selected native
post-exit behavior begins from the pointer: a fresh worker can read the
source-recorded usable extent, free through generic pointer-first PageMap/W03
behavior, or perform a valid foreign `realloc` through allocate/copy/generic-
free. It does not receive an old-owner client, page, route, scheduler token,
or admission capability, and its normal teardown settles only its own
lifecycle.
The selected aggregate fixture verifies that an A-side TSD destructor can
allocate and free locally before this handoff through normal return,
`pthread_exit`, and deferred cancellation. Cancellation first runs a cleanup
handler that also allocates and frees, then the destructor, while the same
route carries direct-small, non-direct-small, medium, regular-large,
arena-singleton, and OS-singleton C clients.
Exact live remote-free witnesses now use the allocation's persistent
PageMap/page state directly. Independently attached B/C workers can read the
exact immutable usable extent or atomically publish an exact live block to its
source page's remote head without claiming A's TLS session, a scheduler token,
or a client ledger. The matching source owner collects that head during its
ordinary operation or finish. The direct and selected-C
`native_mimalloc_two_live_remote_owners` witnesses keep two independent
source pointers live while B1/B2 each operate only on the pointer they were
given. The historical `native_live_remote_owner_registry_reuse` target is
now an ungated repeated persistent-PageMap epoch witness: it exercises four
A1/A2/B1/B2 epochs without an audit or reusable owner metadata. The separate
`native_mimalloc_parallel_local_workers` fixture remains a local-admission
witness; B frees only its own client and ticket zero reactivates after both
ordinary finishes. None of these tests establishes general concurrent worker
allocation, pointer routing, or PageMap mutation.
At the direct pointer boundary, a synchronized B first derives an exact A
client's PageMap facts. `native_reallocate` rejects the foreign source as
unavailable (the C ABI reports `ENOMEM`), leaves its bytes intact, and never
allocates, copies, claims a route, or borrows A's torn-down Theap. Generic
pointer-first free is the only detached-owner continuation; B's later local
`realloc` uses only B's current owner. `native_usable_size` returns the
captured PageMap extent for any exact live native client. General single-page
adoption/reclaim exits, arbitrary concurrent worker allocation beyond the
bounded live-entry witnesses, and pointer routing beyond exact-live ticket-zero
free remain unavailable.
`./scripts/dev.sh allocator-shadow` is the artifact-order-safe allocator ABI,
pthread local-allocation, bounded owner-exit, and bounded live-remote-free
evidence. It does not close the remaining general libc, remote-free,
owner-exit, fork, or promotion gates.
Five bounded Loom
schedules execute the shared live-owner and abandoned owner-claim/unown head
transitions. The compiler-TLS evidence proves private initial-exec AArch64 code
generation in a dedicated crate probe and proves that the pinned compiler
default would instead emit TLSDESC. The bridge applies initial-exec target-wide
in both normal and sealed-sysroot Rust flags; its installed static archive is
audited for the named `THREAD_LIFECYCLE` TLSIE root, and final `libc.so` must
use TPREL relocations with no TLSDESC or `__tls_get_addr`. The bounded
dynamic engine consumes one stable, queue-detached mapped regular handoff and
one same-origin mapped `allow_collect` remote free; its all-free dynamic-arena
result performs the bounded PageMap/ordinary-bit/metadata/slice release while
an existing-owner result remains terminal. It additionally proves one post-TLS
  dynamic owner-exit singleton, full-singleton/homogeneous-full-OS-singleton/full-medium/full-large/full-non-direct-small/full-direct-small aggregates,
  sole full-medium, full-large, full-non-direct-small, and
  full-direct-small normal unmapped-to-mapped handoffs, four one-joined-remote
  full-medium/full-large/full-non-direct-small/full-direct-small immediate-mapped predecessors, and sole mapped
medium/large/non-direct-small/direct-small
one-block handoffs: clearing the regular backing prevents reclaim; the singleton
  final free takes the raw failed-reclaim all-free release, the four normal
  full routes cross the source mostly-used boundary before dynamic bitmap
  publication, and the medium/large `BIN_FULL` plus non-direct-small/direct-
  small ordinary-bin one-remote full routes map immediately after source
  force/false collection and queue detach, with direct-small clearing its
  rounded cache range before count detach. Each mapped
  endpoint clears its dynamic bitmap/count before terminal arena release. The raw
protocol remains
otherwise unintegrated: regular/nonempty pages, general producer routing,
terminal reuse, actual process/thread lifecycle hooks, full teardown traversal,
and reusable abandoned-page lifetime remain absent.
The bounded two-block dynamic owner-exit evidence is likewise split by source
class: medium and one-slice non-direct-small each admit only a sole nonfull
arena page with `reserved > 2`, `used == 2`, an empty direct image, and exactly
two sequential canonical frees. The first retains the dynamic mapped
bit/count through `UnownedMapped`; the final `Empty` free alone releases the
page. The separate large handoff admits only `PageKind::Large` geometry with
`MEDIUM_MAX_OBJ_SIZE < block_size <= LARGE_MAX_OBJ_SIZE`, an empty direct
image, and an exact 64-slice arena/PageMap span; its normal first free retains
that entire mapped span with `used == 1`, and its final `Empty` free alone
clears the pair and releases all 64 slices. The separate direct-small handoff
admits only `block_size <= SMALL_SIZE_MAX`, `reserved >= 16`, its complete
rounded direct-cache range, and `used == 2`; it clears that range before
page-count detach. Its first partial-collector free deliberately leaves the
published head atomic and the observed `used` count at two, then the final free
consumes both heads and releases the page. Extra live blocks/pages, stale/mixed
cache images, reclaim, adoption, requeue, scans, producers, and concurrent
traversal remain open.
Process state, general allocator TLS lifecycle, full/singleton/unmapped/huge
later-thread owner exit beyond the bounded sole
full-medium/full-large/full-non-direct-small/full-direct-small routes, seven
bounded full-page aggregates, sole small-or-medium route, and regular-pages
aggregate, allocation-time
claim/reclaim/requeue after later-thread exit beyond the exact mapped one- and
two-block handoffs, general dynamic heap/Theap
attachment and remote-free routing, complete concurrency modeling and stress,
libc integration, the remaining upstream suites, and performance promotion
gates remain open.

Future acceptance contracts are deliberately specific:

- [`docs/roadmap/performance-completion.md`](docs/roadmap/performance-completion.md)
  governs performance completion.
- [`docs/roadmap/software-corpus-validation.md`](docs/roadmap/software-corpus-validation.md)
  governs real-software and native-application validation.
- [`docs/roadmap/source-build.md`](docs/roadmap/source-build.md) governs the
  remaining CPython source-build progression on the completed sysroot.

Historical documents preserve provenance only; they are never an active
backlog. No chronological microtask list is a project authority. Read the
governing scope and compatibility profile before selecting work, then use the
relevant roadmap or machine-readable contract for its acceptance boundary.
