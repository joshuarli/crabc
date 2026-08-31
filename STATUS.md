# Project status

The current implementation program is staged native Linux/x86-64 little-endian
runtime parity, defined by [`x86-64.md`](x86-64.md). It covers `crabc-core`,
`crabc-libc`, `crabc-ldso`, CRT/sysroot artifacts, and `crabc-rs`, beginning
with explicit target-specific foundations and native evidence. Public support
remains Linux/AArch64 little-endian until every x86 promotion gate passes.

`./scripts/dev-x86_64.sh libc-network-byte-order` is a private
`static-c-network-byte-order` artifact inside planned `libc.posix-runtime`.
Its pinned-musl and true-static candidate fixture selects only `htonl`,
`htons`, `ntohl`, and `ntohs`: fixed-width little-endian 32-bit/16-bit byte
reversal, network-byte output, inverse round trips, and zero/all-one values.
It has no errno, TLS, syscall, allocation, resolver configuration, DNS,
netdb/database, Ethernet/interface, address-codec, or socket-transport path;
it is not resolver/network completion, family promotion, or public x86
support.

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
API. `tmpnam`, `tempnam`, all `mkstemp`/`mkdtemp` forms, `tmpfile`, file-handle
APIs, entropy/crypto policy, generic filesystem policy, family completion,
promotion, and public x86 support remain excluded.

The x86 qualification lane has one bounded same-object static
`memfd_create`/errno differential and one consumed five-transaction POSIX/ABI
admission inventory covering the selected process-context, process-signal,
child-reaping, and pthread/TLS aggregate candidates. These are real native
selected-artifact executions, but both owning compatibility families remain
planned: ABI inventory/symbol closure, the dynamic canonical
OS/libc/pthread/signal suites, their runtime/sysroot prerequisites, and all
other promotion gates are still required.

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
pulls an exact fourteen-object pinned-musl support tail; the gate rejects its
allocator, observer, startup/TLS, pthread, mapping, clock, and wait owners.
`memory.allocator-basic`, public fork/atfork, full runtime
closure, fixed-mimalloc-port promotion, and public x86 support remain
unselected.

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

The x86 lane has five private ET_DYN interpreter artifacts inside still-planned
`ldso.dynamic-runtime`. `ldso-initial-graph` is limited to
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
stale handles. Search/mapping, graph mutation, `RTLD_NEXT`, global promotion,
finalization, and unload remain excluded, so neither dlfcn capability nor the
dynamic-runtime family or public x86 platform is promoted.

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

The x86 lane now has twenty-two private static artifacts inside still-planned
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
unselected.

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
positive-difference slice of still-planned `math.elementary-fenv-sensitive`:
`./scripts/dev-x86_64.sh libc-fdim` differentially executes parenthesized
`fdim`/`fdimf` C calls and default-SSE/`-mfpmath=387` C++ ABI probes against
pinned musl and one freestanding static candidate. It proves ordinary/+0,
left-to-right quiet/signaling-NaN payload, all-four-MXCSR-mode/inexact, and
overflow behavior, while requiring strong target-owned definitions rather than
the weak compiler-builtins fallback. `fdiml`, `exp10*`/`pow10*`,
current/integer-result rounding, special/binary80 math, category/family
completion, promotion, and public x86 support remain unselected.

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

The same archive has a private direct time-observation artifact:
`./scripts/dev-x86_64.sh libc-time-observation` proves only `clock`, `time`,
`difftime`, C11 `timespec_get`, `clock_getres`, and `gettimeofday` through a
pinned-musl/reference plus freestanding-static candidate. It records the
direct x86 `clock_gettime=228`, `clock_getres=229`, and `gettimeofday=96`
paths, normalized outputs, stale-errno behavior, invalid-clock handling, and
the `TIME_UTC`/unsupported-base boundary. It has no vDSO resolver, calendar or
timezone state, clock mutation, POSIX timer, cancellation, libc.so, CRT,
loader, sysroot, family/platform parity, or public-x86-support claim.

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
not select `sigandset`/`sigorset`, handlers/actions, mask or process signaling,
waits, queues, descriptors, timers, pthread policy, libc.so, CRT, loader,
sysroot, family/platform parity, promotion, or public x86 support.

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
The separate private `libc-directory-streams` command
(`./scripts/dev-x86_64.sh libc-directory-streams`) adds one actual static C
runtime leaf after that header matrix: the same project-header C body runs
through pinned musl and then a `-nostdlib -static` `crabc-libc` candidate. It
checks only `opendir`/`fdopendir`/`closedir`/`dirfd`,
`readdir`/`readdir_r`/cursor operations, C-locale `alphasort`, and
`getdents`/`posix_getdents`, including 255-byte names, close-on-exec transfer,
raw record framing, and the x86 `openat=257`, `fstat=5`, `fcntl=72`, `mmap=9`,
`munmap=11`, `close=3`, `getdents64=217`, and `lseek=8` paths. The private
`DIR` state uses one anonymous mapping rather than selecting a C allocator;
`scandir`, `versionsort`, walking policy, broad collation, cancellation, and
the rest of C directory/POSIX runtime parity remain out of this leaf. It does
not complete either the header or POSIX-runtime family, change promotion
status, or establish public x86 support.
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
and seven separate later-main full-page aggregate post-exit routes: full arena
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
registry construction; multi-member routes and routes later reduced to one
member remain sequential client-free-only. A fresh later-main owner can
explicitly reclaim a sole mapped medium route that began owner exit nonfull, or a sole
direct-small route that retains an immediate local free block, the exhausted
fully committed scalar-extension shape, the exact exhausted prefix-covered
extension shape, or the exact exhausted on-demand page-area-commit shape after
source collection; all force-collected full-origin predecessors remain
sequential client-free-only. The reserved fixtures cover both medium and
direct-small prefixes, prefix-covered direct-small reuse without a direct
commit, direct page-area commitment, and failed-commit mapped reabandonment
before a same-candidate retry; non-direct-small, malformed or out-of-profile
no-immediate direct-small metadata, and aggregate registry members remain
sequential client-free-only.
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
exit. On libc's direct `fork` path, a private allocation-free gate preserves a
copied no-page process owner only for the original ticket-zero `TPIDR_EL0`
image with zero live or retained later bridge owners; that child can attach a
fresh pthread. Any other child disables the bridge without attempting lock,
root, page, or general fork repair.

The adjacent permanent ticket-zero page owner remains outside that production
bridge. `compat/allocator/runtime-ticket-zero-adapter` is a separate `no_std`
C evidence staticlib, not an installed or selected libc
interface: in one fresh process it exports only six prefixed operations
(init with `AT_PAGESZ`, malloc, zalloc, realloc, free, and a pointer-free
worker round trip) against that exact owner. Its fixture proves first-page
activation, realloc prefix copying, zeroing, exact free, the all-free release
of only the Rust PageMap lifecycle lease, one fresh worker's scoped page
engine and normal attachment teardown, same-arena ticket-zero reactivation,
and successful-path `errno` preservation; its symbol audit rejects normal
`malloc`/`free` and `mi_*` exports. The permanent session and arena remain
retained after that handoff, so it has no shutdown, concurrent/general
later-thread route, fork repair, pointer-domain fallback, or backend-promotion
meaning.

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
head and every queue member must be a nonfull regular small, medium, or large
arena page. Direct small members retain `reserved >= 16` for the source partial
collector; an empty member is admitted only when normal local free left its
source retirement countdown nonzero. The route
then ports `_mi_theap_collect_retired(theap, true)`'s regular-bin pass, so an
already-empty retired span releases before the remaining
`mi_theap_page_collect` / `_mi_page_abandon` decisions: force-collect, release
pages made all-free, false-collect still-live pages, queue detach, direct-cache
refresh, page-count detach, and publish the exact static-main mapped
identity/bit/count pair. Its typed
aggregate registry retains no old-Theap pointer or raw page list; every later
linear client free re-resolves one PageMap entry, selects its bin only after
the source low owner-bit claim, preserves map/bit/count while nonempty, and
re-derives the supported page's complete regular span before the terminal
PageMap -> `pages_main` -> metadata -> slice release on empty. The current
small, medium, and large cases therefore prove their one-, 8-, and 64-slice
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
path can adopt, reclaim, or requeue an aggregate registry member, including a
registry later reduced to one member by a client free. The nonfull regular
registry continues to reject full/singleton/unmapped/huge/foreign pages and
malformed direct-cache images; the separate full-singleton,
full-medium, full-large, non-direct-small, and direct-small aggregates enforce
their route-specific class and geometry preflights; full-medium members may use
distinct rounded bins, while stale direct-cache images and remote-force nonfull
state remain absent. Concurrent client routes, deferred callbacks, arena
collection, and retry/reuse
as a normal allocator remain outside this owner. Only an empty drain permits
`finish_after_page_drain` to reset default/cached, detach its shared heap list
member before its TLD list member, and retire metadata/TLD. A force/release
failure or root/list mismatch remains terminally retained; this is not general
abandonment, later-free/reclaim, concurrent routing, or a `pthread` lifecycle.

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
integration remain absent; only the bounded no-page lifecycle bridge is live.
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
