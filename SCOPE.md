# Scope reset: keep `crabc` a small modern Unix runtime

You are actively working on `crabc`.

Apply the following project doctrine to all ongoing and future implementation decisions.

This is **not** a request to rewrite working code or restart the project. Preserve completed, correct work. The purpose is to prevent `crabc` from gradually becoming “glibc rewritten in Rust.”

The central principle is:

> **crabc implements the useful modern Unix runtime contract, not every historical facility that accumulated inside libc.**

And for the native Rust facade:

> **crabc-rs exposes useful operating-system/runtime capabilities idiomatically; it does not mechanically translate C baggage into Rust APIs.**

Optimize for:

```text
small
auditable
modern
AArch64-focused
behaviorally correct
low-dependency
LTO-friendly
useful to real Rust software
```

not maximal historical compatibility at any cost.

---

## 1. Platform scope is intentionally narrow

For `crabc` itself, target:

```text
Linux AArch64 only
```

Do not work on:

```text
x86_64
RISC-V
32-bit architectures
big-endian targets
non-Linux kernels
```

until explicitly requested later.

Do not introduce architecture abstractions merely for hypothetical future ports.

Implement the cleanest correct AArch64 design first.

`crabc-rs` may separately gain a macOS AArch64 backend through libSystem, but **that does not make crabc itself portable**.

Keep these concepts distinct.

---

## 2. Establish a Linux kernel MSRV

Target:

```text
Linux >= 5.10
```

Treat Linux 5.10 as the project's kernel MSRV unless strong evidence justifies raising it.

This is a deliberate project feature.

Do not implement compatibility code for ancient kernels merely because musl or glibc historically supports them.

For every kernel-facing implementation:

1. determine whether the preferred mechanism exists in Linux 5.10;
2. use the clean modern mechanism when it does;
3. do not add fallback paths for pre-5.10 kernels;
4. document any API that requires a newer kernel;
5. only raise the kernel MSRV deliberately and centrally.

Prefer removing archaeological fallback complexity over maximizing kernel-version coverage.

Maintain the kernel MSRV prominently in project documentation and tests.

---

## 3. Distinguish ABI compatibility from project scope

Crabc may expose libc-compatible symbols because existing C and Rust `std` software expects them.

That does **not** imply every historical libc subsystem deserves unlimited implementation complexity.

For each capability classify it as one of:

```text
core Unix runtime
useful POSIX/runtime functionality
C ABI compatibility machinery
better served by an existing Rust facility
deliberately unsupported legacy functionality
```

A symbol may need to exist for ABI reasons without becoming an important first-class subsystem.

Do not let:

```text
"musl has this"
```

be sufficient justification for importing an entire secondary ecosystem into crabc.

Where crabc deliberately implements a narrower semantic profile than musl, document it precisely rather than hiding the difference.

---

## 4. Do not hand-roll cryptography

This is a hard boundary.

Do not implement:

```text
cryptographic hashes
TLS
X.509
certificate validation
password hashing
PRNG/DRBG algorithms
public-key cryptography
symmetric cryptography
```

inside crabc.

OS entropy interfaces are in scope:

```text
getrandom
OS-provided secure randomness
```

because those are operating-system primitives.

If some historical libc API would require substantial cryptographic machinery, prefer:

```text
a proven focused dependency
or
explicitly limited compatibility
```

rather than implementing cryptography here.

This applies equally to compatibility ports. Preserve the surrounding state
machine and observable contract, but obtain every cryptographic permutation,
round function, hash, cipher, MAC, password primitive, and PRNG/DRBG core from
a reviewed focused dependency. Source fidelity is never permission to
translate or maintain the cryptographic algorithm locally.

---

## 5. A fixed allocator port is compatibility work, not research

Allocator invention, including a novel pure-Rust `malloc`, is explicitly out
of scope.

There is one narrow exception: `crabc` may maintain a pure-Rust semantic port
of a fixed, mature allocator when that port removes the allocator's C
implementation from the production dependency graph. The initial fixed target
is mimalloc v3.5.0; its immutable upstream provenance is recorded in
[`crabc-mimalloc/UPSTREAM.md`](crabc-mimalloc/UPSTREAM.md). This is
compatibility engineering, not an allocator-design project:

- Preserve upstream algorithms, data structures, memory orderings, lifecycle
  behavior, and valid-program observable behavior until parity is established.
- Implement only Linux/AArch64 little-endian. Do not add architecture or
  operating-system abstractions for a possible port.
- An algorithmic divergence needs a written design note, deterministic
  differential evidence, and performance evidence before it is accepted.
- The exact pinned C implementation remains a mandatory test and differential
  oracle after it leaves the production dependency graph.

Do not spend project effort inventing:

```text
malloc
free
realloc
arena algorithms
size classes
thread caches
page allocators
```

Work needed to audit, translate, integrate, and validate that pinned semantic
port is in scope. Replacing its design with a more idiomatic but materially
different allocator is not.

For native Rust users:

```text
crabc-rs
```

should use normal Rust allocation facilities.

Do not expose `malloc/free` as an idiomatic crabc-rs allocation API.

Allocation is intentionally outside the project's main novelty.

---

## 6. Locale support is deliberately tiny

Support exactly the modern useful baseline:

```text
C
POSIX
C.UTF-8
```

Optionally accept:

```text
en_US.UTF-8
```

and similarly obvious UTF-8 aliases if doing so is extremely cheap, but normalize them to the same UTF-8 behavior.

Preserve the important distinction:

```text
C / POSIX
    byte-oriented traditional locale

C.UTF-8
    UTF-8 Unicode locale
```

Do not collapse those semantics accidentally.

Do not implement a general international locale database.

Explicitly do not build:

```text
CLDR
locale packs
country-specific collation
localized date/month databases
localized monetary formats
localized numeric punctuation
language-specific case rules beyond required Unicode/basic behavior
```

Crabc is not an internationalization framework.

Unsupported locale names should fail according to the relevant API contract rather than silently pretending to support them.

---

## 7. UTF-8 is the native text model

For Rust-facing APIs, assume modern UTF-8 wherever a text abstraction is appropriate.

Do not build a legacy encoding museum.

For libc compatibility, support the mechanically important encodings where justified:

```text
ASCII
UTF-8
UTF-16LE
UTF-16BE
UTF-32LE
UTF-32BE
```

Do not eagerly implement:

```text
Shift-JIS
Big5
GB legacy encodings
DOS codepages
ISO-8859 zoo
other historical charset tables
```

merely for completeness.

If compatibility requirements later demonstrate a real need, reassess then.

Document this as an intentional compatibility restriction.

---

## 8. Focused SIMD dependencies are welcome

Do not interpret “small runtime” as “hand-write every optimized primitive.”

A dependency such as:

```text
simdutf8
```

is exactly the kind of dependency that can be appropriate:

```text
focused
pure Rust
small
well-tested
fuzzed
no runtime ownership
AArch64-aware
```

Likewise:

```text
memchr
```

is preferable to maintaining another bespoke SIMD scanning implementation unless crabc has a compelling reason otherwise.

The SIMD rule is:

> **Scalar semantics are canonical; SIMD is an independently verified optimization.**

Where we own both implementations:

```text
scalar/reference implementation
        ↓
differential/property/fuzz tests
        ↓
SIMD implementation
```

Do not create a generic internal SIMD framework.

Use focused kernels.

---

## 9. No NSS

Do not implement an NSS/plugin ecosystem.

Explicitly reject complexity equivalent to:

```text
nsswitch plugin loading
LDAP NSS
SSSD integration
PAM-based lookup
dynamic identity-provider plugins
systemd-specific name-service plugins
```

For the Linux runtime, simple conventional sources are sufficient:

```text
users/groups:
    /etc/passwd
    /etc/group

hosts:
    /etc/hosts

DNS:
    resolv.conf + DNS

services:
    /etc/services

protocols:
    /etc/protocols
```

Keep lookup behavior deterministic, inspectable, and statically usable.

No plugin architecture.

---

## 10. Keep DNS small

Implement the libc resolver functionality necessary for normal software.

Do not evolve it into a modern application DNS stack.

In scope:

```text
/etc/hosts
/etc/resolv.conf
A
AAAA
CNAME
search domains
normal getaddrinfo/getnameinfo behavior
UDP DNS
TCP fallback where required
basic resolver retries/failover
```

Out of scope as crabc-native features:

```text
DNSSEC validation
DNS-over-HTTPS
DNS-over-TLS
service discovery frameworks
mDNS frameworks
advanced recursive resolver behavior
```

Do not implement IDNA/punycode policy inside the libc resolver initially.

DNS names are fundamentally DNS names.

Applications requiring internationalized domain processing can perform IDNA above this layer.

---

## 11. Do not bundle timezone data

Implement timezone runtime behavior by consuming normal system zoneinfo files.

Support:

```text
TZ
POSIX TZ syntax
tzfile parsing
standard zoneinfo paths
```

Do not embed or maintain tzdata.

Crabc understands the file format.

The operating system/distribution supplies the database.

---

## 12. No gettext/localization framework

Do not implement or expand:

```text
gettext
message catalogs
translation-file management
locale resource discovery
```

as a native crabc subsystem.

If ABI compatibility requires small compatibility entry points, treat them as compatibility machinery.

Do not expose gettext as an important crabc-rs facility.

Localization belongs above this layer.

---

## 13. POSIX regex/glob/fnmatch are compatibility facilities

Implement required POSIX semantics faithfully where they are part of the chosen compatibility target.

But do not attempt to create a new Rust regex ecosystem.

For `crabc-rs`:

```text
fnmatch
glob
```

may deserve small useful Rust-native APIs.

POSIX regex may be exposed as an optional compatibility-oriented RAII interface if useful.

Do not try to replace:

```text
regex
regex-lite
```

for normal Rust applications.

Do not substitute Rust regex implementations for POSIX regex unless semantic equivalence is proven.

---

## 14. Math should be ported, not invented

For libc/libm functions, use:

```text
proven musl algorithms
or
focused proven Rust implementations with equivalent semantics
```

Do not invent novel implementations of:

```text
sin
cos
exp
log
pow
gamma
Bessel functions
complex functions
```

for fun or apparent simplicity.

Correct behavior around:

```text
NaN
infinity
signed zero
subnormals
rounding modes
floating-point exceptions
```

matters more than cleverness.

Treat libm as mature numerical code that should be translated/tested, not redesigned.

---

## 15. No async runtime

Crabc and crabc-rs are synchronous operating-system substrate.

They may expose:

```text
nonblocking file descriptors
poll
epoll
kqueue on macOS crabc-rs
timers
event primitives
```

Do not add:

```text
Future
Stream
async fn
executor
reactor
task scheduler
timer wheel
Tokio
smol
async-io
```

Higher-level async ecosystems should build above crabc-rs.

---

## 16. No process-management framework

Provide low-level process facilities:

```text
fork
exec
posix_spawn
wait
process groups
sessions
credentials
signals
rlimits
prepared fork/exec
```

Do not grow:

```text
restart policies
process supervisors
logging/capture frameworks
shell pipelines
job DAGs
service management
daemon managers
```

into crabc-rs.

A small prepared fork/exec abstraction that makes safe process spawning practical is appropriate.

A process framework is not.

---

## 17. No security-policy framework

Expose useful kernel mechanisms when they belong at the OS-interface layer.

Linux-specific examples may include:

```text
seccomp primitives
credentials
namespaces
prctl
resource controls
```

where justified.

Do not build:

```text
sandbox policy languages
security profiles
capability DSLs
permissions frameworks
container policy engines
```

inside crabc-rs.

Mechanism belongs here.

Policy belongs above.

---

## 18. No portability theater

Crabc itself is Linux AArch64.

Crabc-rs may expose common Linux/macOS APIs later, but only where semantics genuinely overlap.

Do not emulate platform-native mechanisms simply to claim portability.

For example:

```text
Linux:
    crabc_rs::linux::epoll

macOS:
    crabc_rs::darwin::kqueue
```

Do not create:

```text
PortableEventLoop
```

in this foundational layer.

Likewise do not emulate:

```text
eventfd
timerfd
signalfd
pidfd
```

on macOS with pipes/kqueue tricks inside crabc-rs.

Expose OS reality.

Higher layers can provide portable policy.

---

## 19. Keep crabc-rs semantic, not C-shaped

Maintain a strict classification for underlying libc capabilities:

### A. Operating-system capability

Expose idiomatically.

Examples:

```text
openat
mmap
socket
poll
signals
fork
exec
```

### B. Useful POSIX/runtime capability

Expose idiomatically if Rust benefits from it.

Examples:

```text
resolver
dynamic loading
glob
user/group lookup
```

### C. C compatibility machinery

Implement in crabc for ABI purposes but normally do not expose as a first-class crabc-rs API.

Examples:

```text
strcpy
printf varargs
FILE internals
```

### D. Better Rust-native facility already exists

Do not duplicate it.

Examples:

```text
memcpy
    → slices / ptr

qsort
    → slice sorting

malloc
    → Rust allocation

printf
    → formatting traits/macros

strlen-style utilities
    → Rust string/slice facilities
```

Preserve the existing machine-readable crabc-rs capability inventory.

Every crabc capability should remain accounted for.

But “100% coverage” means:

> **100% semantic accounting, not a Rust wrapper around every C symbol.**

---

## 20. Keep unsafe interfaces honest

Do not contort APIs merely to call them safe.

Operations such as:

```text
fork
signal handlers
raw mmap/address manipulation
mprotect interactions with live references
raw ioctl
dynamic symbol typing
certain pthread cancellation operations
```

may legitimately require `unsafe`.

Prefer:

```text
small explicit unsafe boundary
+
excellent documentation
```

over a superficially safe abstraction with impossible invariants.

Every public unsafe API must document concrete caller obligations.

---

## 21. Dependency policy: small and excellent, not zero at all costs

Zero dependencies is **not** a goal by itself.

A focused external crate is preferable to a local reimplementation when the dependency is:

* pure Rust where practical;
* narrowly scoped;
* small;
* low/no transitive dependency count;
* no proc-macro framework;
* `no_std` compatible when required;
* mature;
* fuzzed/tested;
* independently useful;
* easier to audit than our replacement;
* compatible with whole-program optimization.

Examples of dependencies that fit the philosophy:

```text
bitflags
memchr
simdutf8
atomic-wait
```

when the actual subsystem needs them.

Do not reimplement these merely to claim zero dependencies.

Cryptographic algorithms are a mandatory dependency boundary, not a
dependency-minimization tradeoff. `crabc` may implement the direct OS entropy
acquisition and the domain-specific state/lifecycle around a primitive, but
the cryptographic primitive itself must come from a reviewed focused crate.
If no suitable dependency exists, the feature remains explicitly limited.

Dependencies meeting the criteria above have standing project approval; they
do not require a case-by-case permission round trip. That authority does not
remove the audit record below. Ask before importing a framework-scale,
native-code, unusually broad, or otherwise difficult-to-audit dependency.

---

## 22. Dependencies that should trigger scrutiny

Be cautious about dependencies such as:

```text
regex
hashbrown
smallvec
parking_lot
serde
thiserror
once_cell
syn
quote
proc-macro ecosystems
async runtimes
general-purpose framework crates
```

This is not because these projects are poor.

Many are excellent.

At this layer they frequently signal that the abstraction is becoming too broad.

Before adding one, ask whether:

```text
core
alloc
existing internal machinery
or
a smaller focused crate
```

is enough.

---

## 23. Every new production dependency needs a short recorded justification

For every normal dependency, answer:

```text
What exact primitive does it provide?

Why isn't core/alloc enough?

How many transitive normal dependencies does it add?

Does it use proc macros?

Does it use build.rs?

Does it contain native C/C++ code?

Does it allocate?

Does it create threads or global runtime state?

Is it no_std-compatible where required?

Does it preserve LLVM/LTO visibility?

Is maintaining our own implementation genuinely lower risk?
```

Do not reject a dependency because it saves only 500 bytes.

Do reject it if it imports an ecosystem to save 80 trivial lines.

---

## 24. Prefer functionality-focused dependencies over abstraction dependencies

Good dependency:

```text
simdutf8
    performs one difficult optimized primitive
```

Less attractive dependency:

```text
general framework
    establishes a large abstraction model
    which crabc must now conform to
```

Crabc should own its architecture.

Dependencies should provide kernels/primitives, not frameworks.

---

## 25. Preserve LTO friendliness

One major reason crabc is interesting is the possibility of optimizing:

```text
application
+
Rust dependencies
+
Rust std
+
crabc
```

deeply through LLVM.

When choosing implementation structure or dependencies:

* prefer Rust code over opaque precompiled native libraries where equivalent;
* prefer `rlib`/LLVM-visible Rust implementation paths;
* keep wrappers inlineable;
* avoid unnecessary dynamic dispatch;
* avoid C ABI round trips inside Rust-native APIs;
* preserve simple call graphs.

Do not compromise correctness for theoretical LTO gains.

But avoid gratuitously destroying the opportunity.

The pinned allocator semantic port is an accepted exception to the normal rule
against allocator implementation work; it does not permit allocator invention.

---

## 26. Keep hot primitives lean

For foundational operations such as:

```text
memchr/search
UTF-8 validation
string/memory operations
syscall wrappers
fd operations
```

inspect optimized AArch64 assembly periodically.

Look for:

```text
unnecessary allocation
indirect calls
C ABI round-trips
redundant bounds conversion
unnecessary errno TLS accesses
uninlined wrappers
```

Do not micro-optimize everything.

Do keep extremely hot primitives obviously cheap.

Use the optimization ladder deliberately:

1. remove avoidable syscalls, allocations, indirection, and algorithmic work;
2. choose and prove the best simple scalar algorithm and representation;
3. inspect the resulting AArch64 code; then
4. add narrow SIMD only when a measured remaining gap justifies its complexity.

SIMD is valuable for selected hot primitives, but it is normally the last
step—not a substitute for a vDSO path, a hash index, or an algorithmic fix.
Math may justify an earlier, established vector kernel where its numerical
contract is fully proved. Cryptography never does: use a focused approved
RustCrypto dependency rather than hand-rolling a vectorized crypto primitive.

---

## 27. Use the system rather than embedding databases

General principle:

> **Parse standard system state; don't become the owner of system databases.**

Examples:

```text
timezone:
    consume zoneinfo

users:
    consume passwd/group

network:
    consume hosts/resolv.conf

services:
    consume /etc/services
```

Avoid embedding large changing datasets into crabc.

---

## 28. Prefer deterministic static-compatible behavior

Where there is a choice between:

```text
simple filesystem/config lookup
```

and:

```text
runtime plugin discovery
daemon IPC
dynamic service-provider loading
```

prefer the former.

This preserves one of the most valuable properties of a small libc:

```text
static binary
+
small root filesystem
=
works predictably
```

---

## 29. Avoid global registries and plugin systems

Do not introduce generic:

```text
provider registries
backend registries
plugin loading
dynamic hooks
middleware
extension frameworks
```

inside crabc.

If an implementation needs exactly two internal strategies, write two strategies.

Do not build an extensibility framework preemptively.

---

## 30. Avoid generic abstraction until duplication is real

This applies beyond architectures.

Do not create:

```text
ResolverBackend trait
AllocatorProvider trait
LocaleProvider trait
EventBackend trait
Platform abstraction framework
```

because one might theoretically be useful.

Implement the concrete required behavior.

Refactor only when multiple real implementations create meaningful duplication.

---

## 31. Keep feature flags coarse and meaningful

Do not create a feature per libc subsystem or function unless there is a real build/dependency benefit.

Feature flags should primarily control meaningful dependency or environment boundaries, for example:

```text
std interoperability
alloc-dependent convenience
optional focused algorithm dependency
platform-specific extension family
```

Do not make the build configuration itself an operating system.

---

## 32. Keep C-era machinery boring

For compatibility-only code:

```text
stdio
printf/scanf
legacy libc string entry points
POSIX regex
locale facade
```

the goal is:

```text
correct
small
well-tested
stable
```

not architecturally exciting.

Prefer translating mature algorithms.

Do not redesign them unless a concrete correctness/size reason exists.

Spend innovation budget where Rust genuinely changes the interface.

---

## 33. Continue using vertical slices

Do not let this scope reset change the established implementation methodology.

Continue:

```text
inventory
    ↓
implementation
    ↓
ABI verification
    ↓
focused tests
    ↓
musl differential
    ↓
relevant external tests
    ↓
VERIFIED
```

Do not mass-add compatibility surface.

Keep:

```text
exported
implemented
verified
```

close together.

---

## 34. Compatibility exceptions must be explicit

Because this project intentionally rejects some historical libc functionality, maintain a document such as:

```text
COMPATIBILITY-PROFILE.md
```

listing deliberate limitations.

At minimum record decisions around:

```text
Linux kernel >= 5.10
AArch64 only
locale = C/POSIX/C.UTF-8
limited legacy charset support
no NSS/plugin ecosystem
no bundled tzdata
no gettext framework
no IDNA policy
pinned allocator semantic port, not allocator invention
no cryptographic implementation
```

Do not allow these to appear as accidental test failures.

Tests should distinguish:

```text
bug
```

from:

```text
deliberate profile limitation
```

---

## 35. Do not weaken core POSIX/Unix semantics casually

The scope cuts above are targeted.

They are **not** permission to make ordinary Unix functionality approximate.

Remain rigorous about:

```text
filesystem semantics
fds
pipes
signals
fork/exec
pthread/TLS
sockets
mmap
time
stdio basics
resolver behavior within supported profile
dynamic linking
errno
ABI
```

These are the project's substance.

The goal is:

> smaller breadth around peripheral historical features, not lower quality in core runtime behavior.

---

# Completed scope-reset checklist

> Completed on 2026-08-21. This records the reset that governed the native-capability and LTO delivery sequence; it
> is not an open implementation checklist. Current completion and future
> acceptance contracts are routed by [`STATUS.md`](STATUS.md).

Before continuing broad implementation work:

1. audit the current crabc roadmap/backlog against this doctrine;
2. classify existing unfinished work as:

   * core;
   * compatibility-required;
   * Rust-subsumed;
   * deliberately out of scope;
3. update project documentation with:

   * Linux AArch64-only scope;
   * Linux kernel MSRV 5.10;
   * locale profile;
   * charset profile;
   * NSS exclusion;
   * allocator strategy and provenance;
   * crypto exclusion;
   * timezone strategy;
   * dependency philosophy;
4. remove planned work that exists solely for unsupported legacy breadth;
5. do **not** remove already-correct functionality merely because it exceeds the new minimum scope unless maintaining it has real ongoing cost;
6. continue the current vertical slice using these principles.

Do not spend a large engineering cycle deleting harmless finished code.

This is primarily a rule for **where future effort goes**.

---

# Decision test for future work

Whenever a new requirement appears, ask:

```text
Is this required for the modern Unix runtime contract?

Is it required by real Rust std / Alpine / application compatibility?

Is it core POSIX/Linux behavior?

Does it expose a useful OS capability?

Does Rust already have a better native facility?

Is this historical libc baggage?

Would implementing it import a new large domain?

Can a tiny focused Rust dependency solve the difficult kernel cleanly?

Are we supporting this only because glibc/musl accumulated it historically?

Does Linux 5.10 let us delete an old compatibility path?
```

Favor the smaller design unless concrete compatibility evidence argues otherwise.

---

# Project doctrine

The intended identity is:

> **crabc is a small modern Rust Unix runtime for contemporary Linux AArch64. It implements the operating-system and POSIX substrate real software needs while deliberately constraining legacy compatibility domains such as internationalization, encoding catalogs, NSS, cryptography, allocation research, and ancient-kernel support.**

And:

> **crabc-rs exposes that substrate through thin, idiomatic Rust APIs, leaving functionality already better expressed by Rust itself to Rust.**

Focused dependencies are welcome when they remove difficult implementation risk without importing an ecosystem.

Examples:

```text
bitflags
memchr
simdutf8
atomic-wait
```

are philosophically compatible.

A large framework dependency added merely for convenience is not.

Keep the runtime complete where completeness matters.

Keep everything else ruthlessly small.
