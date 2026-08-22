# Implement `crabc-rs`: a focused idiomatic Rust interface to crabc

You are extending the measured Linux/AArch64 `crabc` implementation with a new public crate:

```text
crabc-rs
```

Rust crate name:

```rust
crabc_rs
```

`crabc-rs` is the **native idiomatic Rust interface to crabc**.

The existing crabc C/POSIX ABI remains intact for compatibility with musl-linked software.

The new architecture should become conceptually:

```text
                            crabc implementation
                                   │
                     ┌─────────────┴─────────────┐
                     │                           │
                 C/POSIX ABI                native Rust API
                     │                           │
                   libc.so                    crabc-rs
                     │                           │
              C / Rust std               Rust applications
                     │                           │
                     └─────────────┬─────────────┘
                                   │
                          shared Rust internals
                                   │
                          Linux AArch64 kernel
```

The goal is **not** to wrap crabc's exported libc functions through FFI.

The goal is to expose the same underlying Rust implementation through two different interfaces:

```text
C compatibility facade
+
idiomatic Rust facade
```

The platform boundary is deliberate. `crabc` itself is a Linux/AArch64
runtime. `crabc-rs` has a required Linux/AArch64 backend and may later gain an
optional, separately implemented macOS/AArch64 backend through libSystem. A
macOS `crabc-rs` backend does not make `crabc` portable, and neither backend
justifies a speculative portability framework.

---

# Ground truth and assumptions

The target for `crabc` is **Linux/AArch64, little-endian**, with a Linux kernel
MSRV of **5.10**. The required `crabc-rs` backend has the same target. macOS/
AArch64 is currently only a development host; an optional `crabc-rs` backend
may use macOS libSystem later, but it is not a `crabc` target or a Linux
compatibility requirement. All present target builds and runtime measurements
run in the native Linux/AArch64 Docker laboratory.

Milestone 10.5 is the accepted C-runtime baseline for this work. It establishes
the following bounded, reproducible evidence against pinned musl 1.2.6:

| Area | Current evidence |
| --- | --- |
| Dynamic public ABI | 1,647 expected symbols; 1,669 candidate exports; no missing names or metadata mismatches; 22 documented candidate-only exports. |
| libc-test | 420 total cases: 406 pass; no fail, build error, or timeout; 14 individually evidenced exceptions. |
| OS/runtime | 10/10 selected OS profiles pass; pthread/TLS stress 10/10; signal/process 12/12; resolver/network 22 contract items. |
| Loader | 20/20 bounded native-AArch64 pinned-musl differential cases; generated loader inventory is reproducible. |
| ABI/header/static | 183/183 header declaration probes and 9 layout/constant probes pass; static archive comparison is retained as explicit informational triage, not a claim of archive identity. |
| Real workloads | 34/34 Alpine raw comparisons, including 12 stateful Tier B–D cases; stock Rust `std` and a dependency-bearing Rust program match pinned musl exactly. |
| LTO | The A/B/C scenarios built and ran; the D scenario is intentionally invalid by link-map evidence. Cross-boundary LTO is not claimed. |

This is a strong maturity baseline, not a proof that every possible musl
interface or arbitrary DSO graph has been exercised. Keep musl as the C/POSIX
semantic oracle. Rustix is an independent Rust API and behavior oracle only
for the overlapping native-Rust surface; glibc and its semantics are not a
compatibility oracle or fallback.

Do not reopen these foundations merely to redesign them. Reopen a boundary only
when `crabc-rs` work produces a focused regression or reveals a contract the
current evidence does not cover.

The kernel MSRV is part of the contract: use mechanisms available in Linux
5.10, do not add fallback paths for older kernels, and document any API that
deliberately requires a newer kernel.

---

# Explicitly out of scope

For `crabc` itself, do not implement:

```text
x86_64
riscv64
32-bit architectures
big-endian targets
non-Linux kernels
other Unix platforms
Windows
```

For the required Linux `crabc-rs` backend, do not implement x86_64, RISC-V,
32-bit, big-endian, non-Linux, or Windows targets. Do not create portability
abstractions in anticipation of them. An optional macOS/AArch64 `crabc-rs`
backend may be considered separately through libSystem; it is not part of the
`crabc` implementation, the current Linux acceptance gate, or a promise of
cross-platform semantics.

Target exactly:

```text
Linux AArch64, little-endian (`aarch64-unknown-linux-musl`)
```

Linux arm64 big-endian is dead upstream, so this project maintains the
little-endian target only. `aarch64_be` is out of scope; do not add
endian-parametric internal abstractions, build targets, fixtures, or
compatibility branches in anticipation of it. Continue to encode protocol and
on-disk byte order explicitly where the relevant interface requires it.

Do not implement a new allocator.

The project's libc allocator strategy is already decided separately.

In particular:

> **Do not build a pure-Rust malloc merely to support crabc-rs.**

If crabc's libc ABI uses mimalloc or another established allocator backend, preserve that arrangement.

Rust-native callers should normally allocate through ordinary Rust allocation facilities rather than `malloc`/`free`.

## Scope-reset interpretation

Earlier roadmap language about x86 support, portable Unix backends, a complete
Rust twin of every C export, or mechanically wrapping the full libc surface is
historical planning context. It remains useful provenance for why the M0–M10
evidence and inventories exist, but it is superseded for active work. Preserve
completed evidence; do not preserve those ambitions as implementation scope.

The coverage ledger remains mandatory, but “complete coverage” means semantic
accounting. Each meaningful capability is either represented by an idiomatic
safe, unsafe, or higher-level API, explicitly subsumed by a better Rust
facility, or recorded as a deliberate compatibility/runtime exception. It does
not mean one public Rust wrapper per C symbol.

Future peripheral compatibility follows this bounded profile:

* Locale support is limited to `C`, `POSIX`, and `C.UTF-8` (with cheap obvious
  UTF-8 aliases optional). Preserve the byte-oriented versus UTF-8 distinction;
  do not build CLDR, locale packs, localized databases, or broad language-
  specific rules.
* UTF-8 is the native text model. Compatibility work may cover ASCII, UTF-8,
  UTF-16LE/BE, and UTF-32LE/BE where justified. Existing M10 codec evidence is
  preserved, but it is not a commitment to grow a legacy charset catalog.
* There is no NSS or plugin ecosystem. User/group, host, service, and protocol
  lookup consumes conventional system files; DNS remains a small `/etc/hosts`,
  `/etc/resolv.conf`, A/AAAA/CNAME, UDP/TCP-fallback resolver.
* Do not add DNSSEC, DoH/DoT, mDNS, service-discovery frameworks, recursive-
  resolver machinery, or IDNA policy to the runtime resolver.
* Timezone behavior consumes system `TZ`/zoneinfo and POSIX TZ syntax; crabc
  does not bundle or maintain tzdata. Gettext, message catalogs, and a
  localization framework remain above this layer (or narrow ABI compatibility
  only).
* Do not implement cryptographic algorithms, TLS, X.509, password hashing, or
  cryptographic PRNG/DRBGs inside crabc. Kernel entropy such as `getrandom` is
  an operating-system primitive and remains in scope.
* The runtime stays synchronous. It exposes low-level process and security
  mechanisms, including prepared fork/exec and justified kernel primitives,
  but does not become an async runtime, process supervisor, or security-policy
  framework.

Public unsafe APIs remain honest: use a small documented unsafe boundary where
fork, signal handlers, raw mappings, ioctl, dynamic symbol typing, or similar
operations cannot uphold Rust invariants for every caller. Do not make an API
superficially safe to improve wrapper counts.

---

# Mission

Build an API which initially reaches practical parity with the relevant Linux/AArch64 surface of:

```text
bytecodealliance/rustix
```

and then continues substantially beyond rustix until:

> **Every meaningful in-scope capability implemented by mature crabc has an idiomatic Rust representation or an explicitly justified Rust-native equivalent.**

The development sequence is:

```text
shared implementation architecture
        ↓
rustix inventory
        ↓
rustix differential harness
        ↓
fd/io vertical slice
        ↓
fs vertical slice
        ↓
pipe/time/rand
        ↓
event/net/mm
        ↓
process/thread/system
        ↓
remaining useful rustix overlap
        ↓
────────── RUSTIX PARITY ──────────
        ↓
inventory all remaining crabc capabilities
        ↓
signals/process/fork
        ↓
full pthread facilities
        ↓
resolver/netdb
        ↓
stdio
        ↓
dynamic loading
        ↓
bounded locale/text/iconv compatibility
        ↓
pattern APIs
        ↓
user/group databases
        ↓
math/complex/fenv
        ↓
timezone and other useful runtime capabilities
        ↓
──── 100% IN-SCOPE SEMANTIC ACCOUNTING ────
```

The sequence is a planning aid, not a commitment to implement every
historical libc domain. Locale, charset, resolver, timezone, and gettext work
must remain within the bounded profile above; ABI-only compatibility is not a
reason to create a new Rust framework. “100%” is the coverage-ledger invariant,
not a count of mechanically mirrored C functions.

Do not implement this horizontally.

Work in vertically verified slices.

---

# 1. First inspect the repository

Before editing, inventory the mature crabc repository.

At the start of this project, the workspace contains the loader binary, the
`libc` crate (whose Rust crate name is `c` and whose artifacts are
`libc.so`/`libc.a`), and the `ldso` crate. There is not yet a `crabc-rs` or
`crabc-core` crate. `libc/src/lib.rs` is a monolithic `no_std` crate with
incrementally included subsystem source; its direct syscall layer currently
uses negative Linux errno values before the C facade converts them through
`syscall_result` into C sentinel returns and TLS `errno`.

Identify:

* workspace crates;
* libc implementation modules;
* syscall layer;
* vDSO support;
* error representation;
* errno machinery;
* fd handling;
* path/C-string handling;
* allocator boundary;
* pthread implementation;
* signal implementation;
* resolver;
* stdio;
* locale/text;
* math;
* loader/dlfcn implementation;
* public libc symbol manifest;
* compatibility reports;
* tests;
* existing internal Rust APIs.

Also inspect the current upstream rustix repository.

Pin the exact rustix revision used as the initial design and test reference.
The initial local review is against Rustix 1.1.4 at
`cf67411d572468d5fc39e8ac8b4e649ae3e5e9ec`; the checked-in pin must identify
the upstream repository and revision, not a developer's absolute clone path.

Record it in something like:

```text
compat/rustix/upstream.toml
```

Do not make comparisons against an unpinned moving branch.

---

# 2. Do not start by adding hundreds of wrappers

The first deliverable is architecture plus measurement.

Before broad API implementation exists, establish:

```text
shared implementation boundary
rustix API inventory
API correspondence manifest
dual-backend compatibility harness
coverage ratchet
assembly/performance fixture
```

Only then begin expanding the public API.

---

# 3. Production `crabc-rs` must never depend on rustix

This is non-negotiable.

Allowed:

```text
dev-dependency
test fixture
benchmark reference
API reference
source/test reference with proper provenance
```

Forbidden:

```text
normal dependency
optional production dependency
re-exported rustix types
calling rustix internally
using rustix as the syscall backend
```

A production dependency graph must show:

```text
crabc-rs
   ├── bitflags
   └── shared crabc implementation
          ↓
        kernel
```

not:

```text
crabc-rs
   ↓
rustix
   ↓
kernel
```

---

# 4. Do not call crabc's public C/POSIX ABI from crabc-rs

Also non-negotiable.

The strict rule applies to public libc/POSIX entry points and an `errno`
round-trip. It is not an assertion that two separately linked Rust artifacts
magically share process-global state.

Bad:

```text
crabc-rs
   ↓
extern "C" openat
   ↓
set/read errno
   ↓
crabc libc
   ↓
implementation
```

This throws away the exact benefits we want from a native Rust facade:

* ownership;
* references;
* provenance;
* `Result`;
* inlining;
* direct LLVM visibility;
* no public C ABI transition;
* no errno TLS round-trip.

Instead:

```text
                  shared implementation
                         │
              ┌──────────┴──────────┐
              │                     │
          libc facade            crabc-rs
              │                     │
        C ABI translation      Rust types
        errno translation       Result
        pointer validation      ownership
```

For example, conceptually:

```rust
fn openat_impl(
    dir: RawFd,
    path: &CStr,
    flags: OpenFlags,
    mode: Mode,
) -> Result<RawFd, Errno>;
```

The libc facade may translate that to:

```text
raw pointers
integer flags
-1
errno
```

while crabc-rs translates it to:

```text
AsFd
&CStr / path argument
typed flags
OwnedFd
Result
```

The underlying operation must only be implemented once.

## Private singleton-runtime boundary

Building a shared Rust `rlib` into both `libc.so` and an application does not
make its Rust statics, TLS, or locks singleton process state. Stateless kernel
operations can share source and invariants that way. Stateful capabilities
cannot silently rely on it.

For loader, `dlopen`/`dlsym`/`dlclose`, stdio, locale, resolver, environment,
or pthread state, record the owner of the existing singleton state before
exposing a Rust API. If a native facade must reach state owned by `libc.so` or
`libldso.so`, it may use a narrowly versioned **private runtime ABI or handle
boundary**. That exception must be explicit and must define:

```text
state owner
wire types and ownership
synchronization and TLS rules
version/compatibility policy
failure behavior
focused boundary tests
```

It is never the public C/POSIX ABI, never an `errno` transport, and never a
way to hide missing native coverage. Syscall-like APIs remain on the direct
typed path above and must not cross this boundary.

---

# 5. Introduce one shared implementation layer if necessary

The existing mature repository may not already have the correct crate boundary.

If required, introduce one internal crate, tentatively:

```text
crabc-core
```

or another name consistent with the repository.

Its role is:

> shared Rust implementation used by both libc and crabc-rs.

Here, *shared* means shared source, types, and operation invariants. It does
not imply shared process-singleton state after the `rlib` is linked into two
artifacts. Keep the first extracted seam stateless and explicitly typed. For
each later stateful capability, document its owner and either keep the complete
state on one side or use the audited private runtime boundary from section 4.

Do not make `crabc-core` a large public API commitment.

It may contain:

```text
syscalls
vDSO access
typed internal errors
filesystem operations
network operations
process operations
thread/runtime operations
resolver implementation
loader helpers
other reusable crabc semantics
```

However:

> **Do not perform a giant up-front migration of the entire mature libc into a new crate.**

Extract internals incrementally.

When implementing:

```text
crabc_rs::fs
```

extract precisely the filesystem functionality necessary for that vertical slice.

Then verify libc has not regressed.

Repeat.

The migration itself should therefore proceed vertically.

---

# 6. Preserve the C ABI continuously

Every internal extraction must preserve existing crabc libc behavior.

Run the existing libc maturity ratchet after each substantial subsystem migration.

`crabc-rs` work must not regress:

```text
libc symbol ABI
libc-test
musl differential tests
Alpine corpus
ldso
pthread/TLS
Rust std compatibility
```

The new project is additive.

Do not sacrifice the proven C compatibility surface to make the Rust API cleaner.

---

# 7. Make `crabc-rs` std-first and `no_std`-capable

The native facade should preserve crabc's low-level usefulness.

Follow Rustix's integration model: `std` is the default feature for ordinary
Rust applications, and enables `alloc` plus standard-library interoperability.
The core API must still compile without default features:

```text
cargo check -p crabc-rs --target aarch64-unknown-linux-musl --no-default-features
```

works in a meaningful `no_std` configuration.

Use:

```text
core
```

for the fundamental API.

Use:

```text
alloc
```

only behind an appropriate feature when an API genuinely requires owned allocation.

Make this feature shape explicit:

```toml
[features]
default = ["std"]
alloc = []
std = ["alloc"]
```

`std` integrations are the normal experience, while the feature-minimal path
remains a hard M0 compilation gate.

Do not require `std` merely for:

```text
fd ownership
syscalls
filesystem operations
sockets
time
memory mapping
signals
```

unless there is a strong technical reason.

---

# 8. Keep normal dependencies focused and small

This is foundational systems infrastructure.

Zero dependencies is not a goal by itself. The normal production graph should
remain small, and a focused dependency is preferable to a bespoke replacement
when it is easier to audit, preserves LTO visibility, and does not import an
ecosystem. The baseline dependency is:

```toml
bitflags = { version = "2.4.0", default-features = false }
```

Use it for typed bit-pattern APIs where it improves correctness and readability.
Focused additions such as `memchr`, `simdutf8`, or `atomic-wait` may be
appropriate when an actual subsystem needs their narrow, tested primitive. Do
not add dependencies merely for convenience; each normal dependency needs a
short architectural justification and dependency-graph review covering its
transitives, proc macros, build scripts, native code, allocation/runtime state,
`no_std` support, and LLVM/LTO visibility.

Explicitly avoid:

```text
libc
rustix
nix
anyhow
thiserror
syn
quote
proc-macro frameworks
serde
tracing
async runtimes
```

in the core production crate.

Testing may use whatever focused tools are justified.

Run:

```text
cargo tree -p crabc-rs -e normal
```

as an acceptance gate: it must show the shared crabc implementation and only
reviewed focused normal dependencies. Frameworks, proc-macro ecosystems,
async runtimes, and opaque native libraries remain out of scope for the core
crate.

---

# 9. Use rustix as the API baseline for overlapping functionality

Rustix has already made many excellent design decisions.

Where crabc-rs exposes the same semantic operation, strongly prefer equivalent or nearly equivalent concepts:

```text
OwnedFd
BorrowedFd
AsFd

Result<T, Errno>

typed bitflags
typed enums

slices instead of pointer+length

CStr/path argument abstractions

typed Pid / Uid / Gid where useful

safe representation of AT_FDCWD

MaybeUninit where initialization is conditional

iterator/RAII abstractions where resources have lifecycle
```

Do not change names or API shapes merely to be different.

If rustix has a mature API for an operation, treat that API as the default design unless there is a concrete reason to improve it.

---

# 10. Source compatibility with rustix is desirable

For the overlapping low-level surface, aim for code like:

```rust
use os::fs::{openat, Mode, OFlags, CWD};
```

to work with either:

```text
os = rustix
```

or:

```text
os = crabc-rs
```

with little or no source change.

Literal full crate compatibility is not required.

But unnecessary divergence is undesirable.

Particularly preserve:

```text
module organization
function naming
argument concepts
return concepts
flag semantics
ownership semantics
error semantics
```

where they fit crabc naturally.

---

# 11. Do not copy rustix's implementation

Rustix is valuable precisely because it is an independent oracle.

For overlapping operations:

```text
rustix:
    linux_raw → kernel

crabc-rs:
    crabc-core → kernel
```

These must remain independent implementations.

It is acceptable to reuse or adapt:

```text
API ideas
public signatures where licensing permits
test cases
test methodology
edge-case knowledge
```

with proper license/provenance handling.

Do not copy the linux_raw backend wholesale.

That would destroy much of the differential-testing value.

---

# 12. Create a rustix correspondence manifest

Create a machine-readable inventory such as:

```text
compat/rustix/api.toml
```

Keep its upstream pin beside the correspondence data, for example:

```toml
# compat/rustix/upstream.toml
[rustix]
repository = "https://github.com/bytecodealliance/rustix"
version = "1.1.4"
revision = "cf67411d572468d5fc39e8ac8b4e649ae3e5e9ec"
target = "aarch64-unknown-linux-musl"

[profile]
default_features = true
features = [
  "event", "fs", "mm", "mount", "net", "param", "pipe", "process",
  "pty", "rand", "shm", "stdio", "system", "termios", "thread", "time",
]
excluded_features = ["runtime", "io_uring"]
```

The local Rustix clone is an inspection convenience. Fixtures must resolve a
locked upstream source independently, and Rustix must remain absent from the
production dependency graph.

For every relevant Linux/AArch64 rustix API entry, record something like:

```toml
[[api]]
rustix = "fs::openat"
crabc = "fs::openat"
status = "verified"
compatibility = "source-compatible"
```

Statuses should include:

```text
missing
implemented
verified
intentional-divergence
not-applicable
deferred
```

Every intentional divergence requires:

```text
reason
tests
documentation
```

Generate:

```text
RUSTIX-COMPAT.md
```

from this data where practical.

---

# 13. Define rustix parity carefully

Do not define parity as:

> every public item in the rustix crate exists.

Rustix contains:

* portability machinery;
* multiple architecture support;
* alternate libc backend support;
* Windows-specific networking concerns;
* implementation/configuration APIs irrelevant to crabc.

Define parity as:

> **all useful syscall-like Linux/AArch64 functionality exposed by rustix has an equivalent crabc-rs interface, except individually justified exclusions.**

The parity manifest must make exclusions explicit.

Do not hide them.

---

# 14. Treat `io_uring` separately

Do not allow `io_uring` to delay the useful rustix-parity milestone unless inspection shows it is already naturally supported by crabc.

Treat it as:

```text
extended Linux surface
```

rather than core libc-native parity.

Either:

* implement it after the primary rustix overlap is mature; or
* classify it explicitly as a later Linux extension.

Do not distort crabc's libc architecture around io_uring.

---

# 15. Build a dual-backend test corpus

Create a compatibility test harness which can run equivalent semantic tests using either:

```text
rustix
```

or:

```text
crabc-rs
```

The abstraction belongs **only in tests**.

Do not introduce a generic backend trait into production crabc-rs.

Conceptually:

```rust
trait TestBackend {
    ...
}
```

may exist inside:

```text
compat/rustix/
```

or tests.

It should allow the same semantic scenario to exercise both libraries.

---

# 16. Also build source-compatibility fixtures

For APIs intended to closely match rustix, compile the same source fixture against each crate.

For example:

```text
compat/rustix/source/
    fs_openat.rs
    pipe.rs
    poll.rs
    socket.rs
    mmap.rs
```

Run each fixture twice:

```text
dependency alias → rustix
dependency alias → crabc-rs
```

This gives concrete evidence of API compatibility.

Compile the two variants as separate dependency-alias builds. This checks
surface compatibility; it does not promise that their public Rust types are
interchangeable in one process or that mutable process-global state can be
shared between the two implementations.

Do not rely only on hand-written correspondence tables.

---

# 17. Differential testing rules

For overlapping functionality, compare externally observable semantics:

```text
return values
Errno
fd ownership
fd flags
filesystem state
metadata
socket behavior
poll readiness
mapping behavior
process status
signal state
time values within appropriate tolerances
```

For destructive or process-global operations, run each backend in an isolated subprocess with equivalent initial conditions.

Do not call rustix and crabc-rs sequentially against mutable shared state and pretend that is differential testing.

Use the roles consistently: musl is the C/POSIX behavior oracle for crabc and
the private runtime boundary; Rustix is the API/behavior comparator for the
overlap. Do not use host glibc or public-network behavior as an oracle.

---

# 18. Use `strace` diagnostically

For difficult mismatches, automatically support:

```text
strace rustix fixture
strace crabc-rs fixture
```

Compare:

```text
syscall
arguments
errno
ordering
```

where useful.

Exact syscall sequence is **not** generally a correctness requirement.

Two correct implementations may use different kernel mechanisms.

Treat strace as diagnosis rather than the primary oracle.

---

# 19. Reuse rustix's tests intelligently

Inspect rustix's test tree.

Classify relevant AArch64 Linux tests as:

```text
portable directly
mechanically adaptable
useful as behavioral inspiration
rustix-internal
multi-platform-only
not applicable
```

Reuse/adapt useful tests where licensing permits.

Preserve provenance for substantially derived tests.

Every known rustix regression affecting an overlapping API should be considered for inclusion in the crabc-rs regression corpus.

Do not copy only happy-path tests.

---

# 20. Specifically mine rustix's historical bugs

Rustix has years of production bug history.

Search:

```text
security advisories
fixed issues
regression tests
edge-case commits
```

for every subsystem being implemented.

Convert applicable historical failures into crabc-rs tests.

This is especially valuable for:

```text
directory iteration
buffer management
fd lifecycle
filesystem races
socket address parsing
memory mapping
termios
polling
```

The objective is to inherit rustix's learned correctness without inheriting its implementation.

---

# 21. Rustix-parity sequencing

Implement the overlap in vertical slices.

Recommended sequence:

```text
Slice 0:
    Errno
    fd ownership
    ffi/path arguments
    basic io
    ioctl foundation

Slice 1:
    filesystem

Slice 2:
    pipe
    time
    random

Slice 3:
    polling/event
    networking
    memory mapping

Slice 4:
    process
    thread-associated operations
    process parameters
    system information

Slice 5:
    stdio fd helpers
    termios
    PTYs
    shared memory
    mount APIs

Slice 6:
    remaining relevant rustix Linux/AArch64 surface

Slice 7:
    optional io_uring
```

Adjust ordering based on actual dependency structure.

---

# 22. Every slice follows the same closure process

For each subsystem:

## Inventory

Map:

```text
rustix APIs
crabc underlying implementation
crabc libc symbols
existing crabc tests
```

## API design

Choose the native Rust shape.

Default to rustix's API when it is already excellent.

## Shared implementation extraction

Expose the underlying crabc operation without going through the C ABI.

## Implement crabc-rs facade

Add ownership, lifetimes, typed values and error handling.

## Compile compatibility

Compile representative shared source against rustix and crabc-rs.

## Differential behavior

Run equivalent tests against both.

## Existing crabc regression

Run the relevant libc tests to prove no C ABI regression.

## Assembly inspection

Inspect representative optimized wrappers.

## Mark verified

Only then advance the correspondence manifest.

---

# 23. Establish the core Rust-native vocabulary early

Do not invent multiple competing representations over time.

Design and stabilize a small vocabulary.

At minimum investigate:

```rust
pub struct Errno(...);

pub struct OwnedFd(...);
pub struct BorrowedFd<'fd>(...);

pub trait AsFd { ... }

pub struct Pid(...);
pub struct Uid(...);
pub struct Gid(...);
```

plus:

```text
path argument abstraction
flag newtypes
socket address representations
time representations
signal identifiers/sets
```

Match std/rustix conventions where sensible.

---

# 24. File descriptor ownership must be rigorous

Safe functions must preserve I/O safety.

Use RAII ownership.

A function returning a newly owned descriptor should return:

```rust
OwnedFd
```

not:

```rust
i32
```

Functions borrowing descriptors should accept an I/O-safe borrowed representation.

No safe API may:

* accidentally double-close;
* implicitly consume a borrowed descriptor;
* create aliasing ownership;
* expose special negative descriptor constants as ordinary owned descriptors.

Provide unsafe raw conversion escape hatches where necessary.

---

# 25. Path handling must support Unix paths correctly

Do not require UTF-8.

Support at least efficient use of:

```text
&CStr
&str when valid
byte-oriented paths
Path/OsStr when std integration is enabled
```

without gratuitous allocation.

An `Arg`-like abstraction modeled after rustix is acceptable.

Avoid forcing every path through:

```text
CString allocation
```

when the input is already NUL-terminated or otherwise cheaply convertible.

Interior NUL must be handled correctly.

---

# 26. Errors should not go through thread-local `errno`

The native API should return errors directly:

```rust
Result<T, Errno>
```

The shared crabc implementation should naturally propagate an error value.

The initial extraction must make this conversion explicit. Existing direct
syscall helpers commonly carry negative Linux errno values until
`syscall_result` converts them for the C facade. Normalize that representation
to the typed native error at the shared-operation boundary, before either
facade returns. Do not let the Rust facade inherit C sentinel/`errno`
translation as an intermediate protocol.

Only the C ABI facade should translate:

```text
Errno
→ TLS errno
→ C sentinel return
```

crabc-rs must not:

1. call libc;
2. inspect errno;
3. turn errno back into `Result`.

That architecture is forbidden.

---

# 27. Prefer typed flags and enums

Do not expose:

```rust
fn open(path: ..., flags: i32)
```

when a sound typed representation is practical.

Use compact newtypes/bitflags.

Preserve unknown future kernel bits where appropriate.

Do not use Rust enums for bit patterns if doing so makes unknown kernel values UB or impossible to represent.

---

# 28. Safe means actually safe

The safety bar should match or exceed rustix:

> Any API exposed as safe must preserve Rust memory safety, I/O safety, ownership, lifetime correctness and pointer provenance for every permitted safe caller.

Do not mark an API safe merely because the underlying C function is commonly called.

Where the system operation inherently permits violating Rust invariants, expose `unsafe`.

---

# 29. Keep unsafe surface explicit and narrow

Examples likely requiring `unsafe` include at least portions of:

```text
fork
raw mmap at caller-controlled address
mprotect interactions with live Rust references
signal handlers
raw thread creation
arbitrary dynamic symbols
some pthread cancellation behavior
process-global environment mutation
raw ioctl variants
```

Do not attempt to win against rustix by claiming more operations are safe.

Win through:

```text
coverage
shared implementation
better high-level facilities
```

not optimistic safety declarations.

---

# 30. `fork` must remain semantically honest

Crabc implements `fork` because libc requires it.

Do not expose unrestricted safe:

```rust
fn fork() -> Result<ForkResult>
```

as though ordinary Rust execution in the child is always sound.

Provide an explicitly unsafe primitive, conceptually:

```rust
pub unsafe fn fork() -> Result<ForkResult, Errno>;
```

with strong documentation about the post-fork child restrictions in a multithreaded process.

Then build a more useful prepared fork/exec API.

For example:

```text
PreparedExec
PreparedForkExec
```

where:

* paths are resolved/encoded before fork;
* argv/env storage is prepared before fork;
* fd actions are prepared before fork;
* child actions are restricted to known async-signal-safe operations;
* no allocation is required in the child;
* success ends in exec;
* failure exits predictably.

This is a major beyond-rustix capability.

Test it brutally.

---

# 31. Rustix parity is only Phase I

Once the relevant rustix correspondence manifest is effectively green, freeze a report:

```text
RUSTIX-COMPAT.md
```

showing:

```text
relevant APIs
source-compatible APIs
behavior-compatible APIs
intentional divergences
deferred Linux extensions
```

Then stop using rustix as the definition of scope.

It remains an oracle for overlapping operations.

It is no longer the roadmap.

---

# PHASE II — COMPLETE IN-SCOPE CRABC CAPABILITY ACCOUNTING

# 32. Generate a complete crabc capability inventory

Start from the measured crabc ABI and implementation inventory. The initial
machine-readable input is all 1,669 current candidate dynamic exports, with
the 1,647-symbol pinned-musl public surface and 22 candidate-only exports
preserved as distinct provenance classes. Add the checked loader/dlfcn runtime
inventory so capabilities not adequately described by a single libc symbol are
also visible.

Every exported public libc symbol must be assigned to a semantic capability
group. This is accounting for the ABI and its meaning, not a demand for a
mechanical Rust wrapper for every export.

Also inventory useful implementation capabilities that are not individually represented as exported symbols.

Create:

```text
compat/crabc-rs/coverage.toml
```

Conceptually:

```toml
[[capability]]
id = "filesystem.open"
symbols = ["open", "open64", "openat", "openat64"]
rust_api = ["fs::open", "fs::openat"]
classification = "native"
status = "verified"
```

Another example:

```toml
[[capability]]
id = "memory.copy"
symbols = ["memcpy", "memmove"]
classification = "rust-subsumed"
rust_equivalent = "slice copying / ptr APIs"
status = "verified"
```

Every public crabc symbol must appear in this accounting, including the
candidate-only exports, whose rationale must remain visible. Static archive
`nm -A` triage is useful implementation evidence but is not a substitute for
this dynamic C/Rust capability accounting.

Small irregular groups use literal `symbols`. Regular exported families may
use `symbol_patterns`, but only as a readable selector for the frozen measured
candidate TSV: the validator expands it, rejects an empty selector, and still
requires exactly one owner for every concrete export. The report records the
expanded group counts, source digests, and full zero-unclassified result. A
pattern is therefore not an open-ended future-symbol catch-all.

Zero unclassified symbols is a hard completion gate. Deliberately unsupported
legacy breadth must be represented as an explicit profile limitation rather
than disguised as an accidental gap or pulled into the native API merely to
make the count larger.

---

# 33. Define coverage classifications precisely

Allowed classifications:

### `native-safe`

A meaningful idiomatic safe crabc-rs API exists.

### `native-unsafe`

An idiomatic Rust API exists, but using the underlying operation cannot honestly be made universally safe.

### `native-higher-level`

Several C interfaces are represented by a safer or more useful Rust abstraction.

Example:

```text
getaddrinfo/freeaddrinfo
→ resolver result/iterator with RAII cleanup
```

### `rust-subsumed`

The capability already has a strictly better language/library-native Rust mechanism and adding a second crabc-rs wrapper would be artificial.

Examples may include:

```text
memcpy
memmove
strlen-like operations
qsort
bsearch
printf-style formatting
```

Every use of this classification requires a written rationale.

### `scope-exception`

A deliberately out-of-scope capability with a versioned policy contract. This
classification is not Rust-subsumption evidence and is not an ABI-only
disposal. The validator currently permits exactly one exception:
`allocator-mimalloc-libc-boundary` v1 for `memory.allocator-basic` and
`memory.allocator-observability`, together owning the complete public malloc
family, including `malloc_usable_size`. It requires documented status,
explicit policy/rationale/evidence fields, and rejects any other capability,
symbol set, or reclassification. The project keeps this family at the libc
boundary under its mimalloc strategy; crabc-rs does not claim C allocator ABI
or usable-size equivalence.

### `abi-only`

The symbol exists solely for C ABI/runtime compatibility and has no meaningful native operation users should invoke.

Use this category very sparingly.

### `internal-runtime`

Loader/startup/compiler runtime plumbing that is not an application-facing capability.

Again, justify it.

---

# 34. 100% semantic coverage does not mean 1400 silly functions

Do not create APIs such as:

```rust
crabc_rs::cstring::strcpy(...)
crabc_rs::memory::malloc(...)
crabc_rs::stdio::printf(...)
```

merely to increase a counter if Rust already has a superior abstraction.

The completion criterion is:

> **Every semantic capability of crabc is either accessible through a good Rust API, explicitly proven to be subsumed by an existing Rust-native mechanism, or covered by the one validator-enforced versioned scope exception.**

There must be no meaningful capability hiding behind:

```text
"ABI-only"
```

just because designing the Rust API is difficult.

---

# 35. Provide a raw escape hatch, but do not count it as native coverage

A narrowly scoped optional module such as:

```rust
crabc_rs::raw
```

may expose low-level representations needed by expert users.

It may be useful for:

* ABI interoperation;
* raw signal work;
* unusual ioctl usage;
* uncommon C compatibility operations.

However:

> Merely re-exporting a C-style function through `raw` does not satisfy the native coverage requirement.

If a meaningful capability can be modeled idiomatically, it needs an idiomatic API.

`raw` is an escape hatch, not a roadmap-completion hack.

---

# 36. Beyond-rustix subsystem order

After rustix parity, proceed approximately:

```text
1. signal/process extensions + fork/exec

2. complete pthread/runtime facilities

3. resolver/netdb

4. dynamic loading

5. stdio FILE abstractions

6. bounded locale/text/iconv compatibility

7. regex/fnmatch/glob/wordexp

8. passwd/group/user database

9. math/complex/fenv

10. miscellaneous POSIX facilities

11. remaining in-scope capability-manifest gaps
```

Adjust based on actual mature crabc contents.

This order does not authorize a general internationalization stack, charset
catalog, NSS/plugin system, timezone database, gettext framework, cryptographic
subsystem, or any other domain excluded by the scope profile. Such entries are
closed with precise compatibility classifications when the C ABI requires
them.

Again: vertical slices only.

---

# 37. Signals

Provide idiomatic representations such as:

```text
Signal
SignalSet
SigAction
SigInfo
Stack
```

where they improve safety.

Operations manipulating signal masks can often be safe.

Installing arbitrary signal handlers generally requires unsafe contracts because the callback must obey async-signal-safety and Rust reentrancy restrictions.

Document this precisely.

Provide process/thread signal APIs through typed IDs and sets.

Differential-test against crabc's C ABI and, where overlap exists, rustix.

---

# 38. Full pthread/runtime facilities

Crabc necessarily contains substantially more pthread functionality than rustix exposes.

Design native Rust facilities around actual useful semantics.

Potential areas:

```text
thread creation/join/detach
mutexes
recursive/error-checking mutexes
robust mutexes
rwlocks
condition variables
barriers
semaphores
once
thread-local keys
TLS destructors
thread cancellation
cleanup semantics
atfork
```

Do not blindly expose C structs.

Use owned/borrowed RAII types where a correct representation is possible.

Do not add std-style poisoning unless there is a compelling reason.

Crabc's primitives should remain low-level and predictable.

---

# 39. Be extremely careful with pthread cancellation

Cancellation interacts with:

```text
resource ownership
cleanup handlers
blocking syscalls
stdio
locks
FFI
```

Do not expose cancellation as a superficially safe Rust convenience if asynchronous effects can violate Rust invariants.

Prefer constrained/unsafe APIs with explicit contracts where necessary.

Use the mature crabc cancellation stress suite as the underlying oracle.

---

# 40. Resolver and netdb

Do not expose `struct addrinfo` linked lists as the primary native interface.

Build something more like:

```text
Resolver result
iterator of addresses/results
RAII ownership
typed socket/protocol information
```

Support relevant crabc functionality including, where implemented:

```text
getaddrinfo
getnameinfo
hosts database
service database
protocol database
resolver APIs
```

The resolver is deliberately small and deterministic. It consumes conventional
system sources only:

```text
users/groups: /etc/passwd and /etc/group (where applicable)
hosts:        /etc/hosts
DNS:          /etc/resolv.conf and DNS A/AAAA/CNAME
services:     /etc/services
protocols:    /etc/protocols
```

There is no NSS/plugin ecosystem, LDAP/SSSD/PAM integration, or systemd name
service provider. Keep UDP DNS, required TCP fallback, search domains, and
normal `getaddrinfo`/`getnameinfo` behavior; do not grow DNSSEC, DoH/DoT,
mDNS, service-discovery, recursive-resolver, or IDNA policy here. No public
Internet should be required by tests.

Reuse the existing deterministic DNS fixture.

---

# 41. Dynamic loading

Crabc contains an audited dynamic loader/dlfcn implementation with bounded
Linux/AArch64 evidence.

Expose an idiomatic RAII API.

Conceptually:

```rust
let lib = Library::open(...)?;
let symbol = unsafe { lib.symbol::<FnType>(...) }?;
```

Properties:

* `Library` owns the handle;
* dropping closes when semantically appropriate;
* `Symbol<'lib, T>` cannot outlive the library;
* arbitrary type interpretation remains unsafe;
* errors are owned/typed rather than borrowed `dlerror()` globals;
* flags are typed.

The loader state is owned by `libldso.so`; the native API therefore must use
the explicit private singleton-runtime boundary from section 4, rather than a
second independently linked copy of loader state or the public `dl*`/`errno`
facade. Define and test the handle ownership and loader-lock/TLS contract
before this module is exposed.

Cover:

```text
open
lookup
close
address lookup
iteration/introspection where useful
scope flags
```

Do not simply mirror `void *`.

---

# 42. Stdio

Rust applications normally should use Rust I/O.

However, crabc contains significant FILE machinery which may matter for:

* C interop;
* no_std environments;
* pipes/process integration;
* memory streams;
* compatibility tooling.

If exposing it natively, build an RAII type such as:

```text
CFile
```

`FILE` state is libc-owned. Do not duplicate it through independently linked
Rust statics; if this module crosses into existing `FILE` machinery, specify
the private singleton-runtime handle boundary and ownership contract first.

with methods for:

```text
read
write
flush
seek
tell
buffering
error/EOF state
memory streams
popen where appropriate
```

Do not reproduce C varargs `printf` as the primary Rust formatting API.

Classify formatting capabilities appropriately in the coverage manifest.

---

# 43. Bounded locale, text and iconv compatibility

UTF-8 is the native text model. Where crabc contains meaningful runtime
machinery, expose owned types such as:

```text
Locale
Converter
MultibyteState
```

rather than C global handles.

Avoid pretending locale mutation is harmless process-global state.

Use RAII where locale handles have lifetime.

Represent conversion buffers with slices rather than raw pointer-to-pointer interfaces.

The supported locale profile is `C`, `POSIX`, and `C.UTF-8`, with an obvious
UTF-8 alias accepted only when it is effectively free. Preserve the distinction
between the byte-oriented C/POSIX locale and the Unicode C.UTF-8 locale; an
unsupported locale name must fail according to the API contract. Do not build
CLDR, locale packs, country-specific collation, localized date/monetary data,
or a gettext/message-catalog framework.

For compatibility, prioritize ASCII, UTF-8, UTF-16LE/BE, and UTF-32LE/BE.
The completed M10 evidence for additional codec tables remains valid historical
evidence, but does not commit future work to a Shift-JIS/Big5/GB/DOS/ISO-8859
catalog or to broad legacy alias behavior. Crabc parses system timezone files
and POSIX `TZ` syntax when timezone APIs are added; it does not embed or own
tzdata.

---

# 44. Regex, fnmatch and glob

If crabc includes POSIX regex:

```text
Regex
Match
Matches
```

should own compiled state and free it on drop.

For:

```text
fnmatch
```

a simple safe function may be enough.

For:

```text
glob
```

provide an owned/iterable result rather than exposing `glob_t`.

For:

```text
wordexp
```

make shell-execution/security semantics explicit.

Memory-safe does not mean injection-safe.

---

# 45. passwd/group databases

Avoid exposing pointers to shared libc static buffers.

Prefer owned results or caller-provided storage abstractions.

Potential public types:

```text
User
Group
Uid
Gid
```

Support lookups and enumeration where the underlying crabc implementation does.

Thread safety must be explicit.

These APIs consume conventional passwd/group files or a caller-supplied
snapshot. They must not grow an NSS/plugin, LDAP, SSSD, PAM, or daemon-backed
identity-provider architecture.

---

# 46. Math

Most libc math functions are naturally safe Rust functions.

Expose useful functions not already adequately represented by core/std.

Avoid duplicating obvious intrinsic methods solely for numerical parity.

But do provide meaningful access to crabc-specific/musl-compatible functionality such as appropriate:

```text
erf family
gamma family
Bessel family
remainder variants
nextafter
scalbn
frexp/modf-style decomposition
```

according to the actual crabc implementation.

Use the mature libc math test oracle.

---

# 47. Complex math

Do not add a large dependency merely for complex numbers.

If needed, define tiny transparent/repr-compatible types such as:

```text
Complex32
Complex64
```

with a minimal useful API.

Then expose crabc's complex math functionality safely.

Do not turn crabc-rs into a numerical-computing framework.

---

# 48. Floating-point environment

Expose:

```text
rounding mode
exception flags
environment save/restore
```

through typed APIs where possible.

A small RAII guard for temporarily changed floating environment may be useful.

Do not overstate guarantees Rust itself does not make about compiler floating-point transformations.

Document those limitations.

---

# 49. Environment mutation

Reading environment state can generally be safe.

Mutation is much more subtle on Unix in multithreaded programs.

Do not expose safe process-global environment mutation if it cannot be made safe against concurrent foreign/Rust access.

Follow current Rust safety reasoning rather than historical libc habits.

---

# 50. Process execution APIs

Beyond raw fork, build useful native facilities around:

```text
execve
execvpe-like behavior if supported
posix_spawn
prepared fork/exec
wait
process groups
sessions
credentials
resource limits
```

Use typed:

```text
Pid
Uid
Gid
ExitStatus-like representations
```

where helpful.

Avoid unnecessary heap work between fork and exec.

Keep this layer at the mechanism boundary. Prepared fork/exec is appropriate;
restart policies, supervisors, shell pipelines, job graphs, logging/capture
frameworks, service management, and daemon orchestration belong above
`crabc-rs`.

---

# 51. Coverage must include Linux/POSIX odd corners

Do not stop after attractive APIs.

The complete crabc capability inventory may include:

```text
SysV IPC
POSIX shared memory
message queues
semaphores
scheduler controls
resource limits
priority
termios
PTY
mount
reboot/system information
xattrs
file locking
advisory APIs
memory locking
CPU affinity
timers
clock APIs
AIO
search/path helpers
```

or other mature crabc functionality.

Do not assume this illustrative list is complete.

The generated capability inventory is authoritative.

---

# 52. Feature design

After the API inventory exists, organize public functionality into coherent Cargo features.

Do not create one feature per function.

A reasonable starting family may resemble:

```text
fs
event
mm
net
pipe
process
signal
thread
time
termios
pty
mount
shm
resolver
stdio
locale
text
pattern
user
dl
math
```

Exact names should follow the actual surface.

Requirements:

* no unrelated subsystem should be pulled in unnecessarily;
* no rustix dependency anywhere;
* `no_std` base should remain possible;
* `alloc` should be separable where practical;
* `std` is enabled by default and should primarily add interoperability/conveniences.

Do not overengineer feature topology around the single approved `bitflags`
dependency.

---

# 53. Interoperate with `std` cleanly

Under a `std` feature, provide conversions and trait interoperability with:

```text
std::fs::File
std::net socket ownership where feasible
std::os::fd::{OwnedFd, BorrowedFd, AsFd, ...}
OsStr
Path
```

Avoid needless copies.

The crate should be pleasant in ordinary Rust applications without sacrificing `no_std` fundamentals.

---

# 54. Do not create a parallel ecosystem unnecessarily

Where Rust already has a universally understood type:

```text
Duration
IpAddr
SocketAddr
CStr
Path
```

use it when doing so is compatible with the `no_std`/feature boundary and semantics.

Do not invent:

```text
CrabcDuration
CrabcIpv4Addr
CrabcPath
```

without reason.

---

# 55. Benchmark the abstraction cost continuously

For syscall-like overlapping functions, compile optimized microfixtures for:

```text
rustix
crabc-rs
```

Inspect:

```text
assembly
.text size
call structure
```

with LLVM tools already present in the development environment.

Representative functions should include:

```text
read
write
close/drop
getpid
clock_gettime
openat
fstat
socket
poll
```

The target is:

> **crabc-rs should compile to code competitive with rustix's linux_raw backend for equivalent operations.**

Do not demand byte-identical assembly.

Do investigate unnecessary:

```text
C ABI calls
errno TLS accesses
allocations
copies
indirect calls
uninlined wrappers
```

---

# 56. Explicitly prove there is no public C ABI/`errno` round-trip

Create an automated assembly or symbol-level check for representative native functions.

For example:

```text
crabc_rs::process::getpid
```

must not compile into a call to exported:

```text
getpid
```

from crabc's libc facade.

Likewise for:

```text
read
write
openat
clock_gettime
```

where appropriate.

This is a hard architectural acceptance criterion.

The checker must also reject `__errno_location` and equivalent public C facade
paths for these syscall-like representatives. Private singleton-runtime
boundaries are not exemptions hidden from this check: list each separately in
an exception ledger, identify its state owner and version, and run its focused
boundary tests. They are never permitted for the representatives above.

---

# 57. Benchmark compile/dependency cost

Record:

```text
normal dependency count
clean check/build time
release binary size
```

for representative minimal programs.

Compare approximately:

```text
rustix
crabc-rs
```

Do not optimize tiny benchmark noise.

Do prevent accidental dependency/framework growth.

---

# 58. Build real application migration fixtures

After rustix parity, select several small programs written against rustix-like APIs.

Port them to crabc-rs.

Eventually make at least one fixture whose dependency switches conceptually from:

```toml
rustix = ...
```

to:

```toml
crabc-rs = ...
```

with minimal source changes.

Then build applications exercising beyond-rustix capabilities:

```text
fork/exec
resolver
dynamic loading
signals
pthread primitives
```

These prove the native facade has practical value beyond a test matrix.

---

# 59. Dogfood crabc-rs inside crabc tools where appropriate

If crabc contains Rust utilities/tests/loader tools that currently use lower-level internal or libc interfaces and can cleanly use crabc-rs, migrate carefully.

Do not force dogfooding where it introduces dependency cycles.

Use it as a design-quality signal:

> if crabc's own Rust tooling dislikes crabc-rs, the API likely needs improvement.

---

# 60. Documentation standards

Every public API needs useful documentation.

For syscall-like APIs document:

```text
operation
ownership
error semantics
kernel/POSIX caveats
safety if unsafe
```

Do not reproduce Linux man pages verbatim.

Link/reference the conceptual underlying operation where appropriate.

For APIs intentionally matching rustix, do not falsely claim compatibility unless covered by the parity harness.

---

# 61. Unsafe documentation is mandatory

Every unsafe public function must contain:

```text
# Safety
```

with concrete caller obligations.

Bad:

```text
Caller must ensure this is safe.
```

Good:

```text
The child of fork must not execute operations which are not
async-signal-safe before exec/_exit when other threads existed
at fork time...
```

Likewise for:

```text
mmap
signal handlers
raw symbols
ioctl
raw pthread behavior
```

---

# 62. Audit unsafe internals

Adding a safe facade increases the importance of underlying unsafe correctness.

For every new safe wrapper, trace:

```text
safe public inputs
→ internal unsafe operations
→ syscall/runtime implementation
```

Document why the safe wrapper upholds the underlying preconditions.

Use Miri on pure/internal abstractions where practical.

Fuzz parsers/variable-length structures where useful.

---

# 63. Property-test ownership transitions

Especially test:

```text
fd duplication
fd transfer
close-on-drop
borrowed fd lifetime
directory iterators
dynamic Library/Symbol lifetime
FILE ownership
locale ownership
regex/glob cleanup
thread handles
```

Resource ownership bugs are among the most dangerous failure modes of this facade.

---

# 64. Test failure paths as aggressively as success paths

Exercise:

```text
EBADF
EINTR
EINVAL
ENOENT
EEXIST
ENOSPC
EMFILE
EPIPE
ECONNRESET
ETIMEDOUT
EAGAIN
ENOMEM where practical
```

plus subsystem-specific failures.

Safe wrappers often fail in cleanup/error transitions rather than happy paths.

---

# 65. Test cancellation and signals around wrappers

For blocking APIs affected by:

```text
EINTR
SA_RESTART
pthread cancellation
```

verify crabc-rs semantics deliberately.

Do not automatically retry every EINTR unless the API contract says to.

Do not accidentally hide cancellation semantics inherited from the underlying runtime.

---

# 66. Do not add an async abstraction layer

`crabc-rs` is synchronous systems substrate.

Do not add:

```text
Future
Stream
async fn
runtime adapters
Tokio
smol
async-io
```

to the foundational crate.

Async runtimes can build on file descriptors/event APIs later.

---

# 67. Do not build capability/security policy

Keep crabc-rs low-level.

Do not add:

```text
sandbox policy
capability filesystem
permissions framework
process supervisor
network client
filesystem walker
```

Those belong above this layer.

---

# 68. Do not turn it into `nix`

Avoid sprawling convenience abstractions detached from the underlying OS/runtime semantics.

The philosophy is:

```text
thin
typed
safe where honestly possible
complete
predictable
low-cost
```

not:

```text
high-level Unix framework
```

---

# 69. Compatibility ratchets

Maintain two independent ratchets.

## Rustix ratchet

Track:

```text
relevant rustix APIs
implemented
verified
source-compatible
intentional divergence
```

Once verified, regressions should fail CI.

## Crabc capability ratchet

Track:

```text
total crabc capability groups
native-safe
native-unsafe
native-higher-level
rust-subsumed
scope-exception
abi-only
internal-runtime
unclassified
verified
```

Hard requirement:

```text
unclassified = 0
```

at completion.

---

# 70. "ABI-only" cannot become a dumping ground

CI/reporting should make the count prominent.

Every `abi-only` classification needs:

```text
symbol(s)
reason
why no meaningful Rust operation exists
reviewed status
```

Periodically review these classifications.

If an ABI-only group represents an actually useful capability, implement it.

---

# 71. "Rust-subsumed" also needs evidence

For each classification, explain the idiomatic Rust equivalent.

Examples:

```text
memcpy
→ slice::copy_from_slice / ptr operations

qsort
→ slice sorting

printf
→ format_args!/Write
```

Do not classify something as subsumed merely because implementing it is inconvenient.
The allocator family is governed by the separate, versioned scope exception
above rather than by this Rust-equivalence rule.

---

# 72. Preserve allocator scope decision

Do not expose a new safe:

```rust
malloc/free
```

API.

Rust-native allocation should use Rust allocation facilities.

The complete public malloc family, including `malloc_usable_size`, is the sole
`scope-exception`: `allocator-mimalloc-libc-boundary` v1. It records the
project's mimalloc-backed libc boundary and is neither `rust-subsumed` nor
`abi-only`; the exact IDs, symbols, metadata, and evidence are validator
enforced.

If raw allocator ABI access is necessary for C interoperability, it may live in the raw/compatibility escape hatch.

Do not implement or redesign allocator internals.

---

# 73. Keep the public crate cohesive

Do not split every subsystem into a crates.io crate.

Prefer:

```text
crabc-rs
```

as one feature-gated public facade.

The only additional **workspace** crate justified by this project is the
internal shared implementation layer if needed. `bitflags` is the one approved
baseline third-party normal dependency; other focused crates require the
dependency review described in section 8. Do not turn that allowance into a
general crate-splitting or dependency-growth policy.

Avoid a 20-crate micro-workspace.

---

# 74. Provenance

Maintain:

```text
UPSTREAM-RUSTIX.md
```

or equivalent.

Record:

* pinned rustix revision;
* API designs substantially modeled after rustix;
* tests substantially adapted from rustix;
* applicable licensing notes.

Also retain existing musl provenance for crabc implementation.

The lineage should be auditable.

---

# 75. Do not let rustix changes destabilize the project

Rustix parity is pinned.

Once initial parity is achieved:

* retain the pinned compatibility baseline;
* optionally add a non-gating tracker against current rustix main/latest;
* consciously adopt useful newer APIs.

Do not make every rustix release a mandatory breaking chase.

---

# 76. Maturity milestone 0 — architecture

Required:

```text
crabc-rs crate exists

no production rustix dependency

default feature is std; no-default-features target check passes

normal dependencies are few, focused, and individually justified

shared implementation strategy proven

representative syscall-like operation does not traverse public C ABI or errno

stateful capabilities name their singleton-state owner and private runtime boundary, if any

rustix API manifest exists

dual-backend test harness works

crabc capability inventory exists
```

Do not start mass implementation before this is green.

---

# 77. Milestone 1 — foundational rustix slice

Status: **complete**.

This slice establishes the narrow direct-kernel foundation for later Rustix
coverage. It is not a claim of broader filesystem or system parity. The
completed surface is:

```text
Errno
fd ownership
basic io
path/ffi representation
ioctl foundation
```

Against:

```text
rustix source compatibility where intended
rustix differential tests
existing crabc libc tests
optimized assembly
```

The focused reproducible gate is `./scripts/dev.sh crabc-rs`. It performs the
native M1 tests, a no-`std` AArch64 static probe, and a Python-stdlib-only
source comparison against the pinned Rustix checkout. The unchanged workspace
test suite remains the broader C-runtime regression gate.
The source fixture is `compat/rustix/source/m1_foundation.rs`; it covers
byte-preserving paths, descriptor ownership, direct I/O, special directory
descriptors, and the FIOCLEX/FIONCLEX/FIONBIO/FIONREAD ioctl requests. The
assembly proof requires direct Linux syscall 29 for ioctl and rejects calls to
the public C ABI or TLS `errno` path.

---

# 78. Milestone 2 — filesystem

Status: **complete**.

The completed Linux/AArch64-little-endian slice is native Rust over
`crabc-core`; it does not route syscall-like operations through the public C
ABI or read TLS `errno`. The verified surface is:

```text
open/openat/openat2 and Linux resolution flags
stat/statat/lstat/fstat
RawDir/RawDirEntry directory iteration
hard links, symbolic links, bounded and allocating readlink
rename/renameat/renameat_with
mkdir/mkdirat/unlink/unlinkat/rmdir
chmod/chmodat/fchmod
utimensat/futimens
path, no-follow-path, and descriptor extended attributes
flock and fcntl whole-file advisory locks
```

`RawDir` retains the relevant historical regression constraints: caller-owned
bounded storage, unaligned buffer support, short and malformed record
rejection, 255-byte names, an entry borrow that prevents advancing while it is
live, and kernel `EINVAL` propagation for an undersized buffer.

The reproducible gate remains `./scripts/dev.sh crabc-rs`. In addition to the
M0/M1 checks, it runs the native M2 filesystem tests; source-compares the seven
fixtures in `compat/rustix/source/m2_*.rs` against pinned Rustix; validates the
expanded Python harness; and inspects a no-`std` AArch64 probe for direct
`openat2`, metadata, directory, lock, and xattr syscalls while rejecting public
C ABI and TLS-errno symbols. The existing C integration tests retain the C
boundary evidence, including the corrected Linux/AArch64 `O_NOFOLLOW` value
and xattr exports routed through the same stateless core seam.

---

# 79. Milestone 3 — core OS surface

Vertically verify:

```text
pipe
time
random
event/poll
networking
memory mapping
```

Keep rustix differential testing active.

**Complete.** M3 is deliberately a vertical kernel slice, not a claim that
every broad Rustix subsystem API is already present. Its native, direct-core
surface is `pipe::{pipe,pipe_with}`, `rand::getrandom`, known
`time::{ClockId,clock_gettime,clock_getres}`, `event::{eventfd,poll}`, Unix
`net::{socketpair,send,recv}`, and
`mm::{mmap_anonymous,mprotect,munmap}`. All use Linux/AArch64 syscalls through
`crabc-core`; no native path calls public C/POSIX entry points or reads TLS
`errno`.

`./scripts/dev.sh crabc-rs` now builds the no-`std` M3 probe, checks the M3
Rust tests, source-compares three isolated fixtures against pinned Rustix, and
requires direct AArch64 evidence for `eventfd2`, `pipe2`, `ppoll`, clock,
socket-pair/send/receive, mapping, protection, unmapping, and random syscalls.
Existing C wrappers for the overlapping operations route through the same core
seams and retain C-only errno/sentinel conversion. Broader interfaces such as
epoll, splice, timerfd, file-backed mappings, Internet address handling,
connect/accept, and socket options remain explicitly deferred in the Rustix
manifest for later verified vertical slices.

---

# 80. Milestone 4 — process/system surface

Verify:

```text
process
thread-associated kernel APIs
parameters
system information
termios
PTY
shared memory
mount-related surface
```

as applicable.

**Complete.** M4 now exposes direct Linux/AArch64 process and thread identity
operations (`Pid`, process-group/session queries, signal-zero/process signal
delivery, `gettid`, and `sched_yield`); the ABI-stable `USER_HZ` clock-tick
parameter; `system::{uname,sysinfo}`; typed terminal and PTY operations;
POSIX shared-memory naming; and mount/unmount entry points. `page_size` remains
explicitly deferred: it must read `AT_PAGESZ` through a future, explicit auxv
initialization boundary rather than incorrectly assuming a 4 KiB AArch64 page.

The terminal boundary is deliberately native rather than a C-struct cast. The
Rust `termios::Termios` records Linux's tty layout and numeric baud rates;
crabc's C facade retains the musl public `struct termios` layout. Both issue
the same direct ioctl core seam, but neither leaks C ABI padding or TLS errno
into Rust callers. This initial terminal slice uses the legacy tty protocol
and its standard encoded baud rates; arbitrary `BOTHER` rates and the wider
Rustix terminal flag/control-code vocabulary remain for the M5 completion
inventory. The C facade's overlapping `getpid`, `kill`, `gettid`,
`sched_yield`, `uname`, `sysinfo`, `mount`, and `umount2` adapters now route
through `crabc-core`, where C-only sentinel/errno translation remains at the
outer boundary.

`./scripts/dev.sh crabc-rs` extends the prior M0–M3 gate with native M4 tests,
an isolated pinned-Rustix source fixture, and a no-`std` archive inspection
which requires direct AArch64 process, scheduler, system, mount, and unmount
syscalls while rejecting public C ABI and TLS-errno symbols. Its PTY and mount
checks are state-contained: PTYs are newly allocated and released, shared
memory names are removed, and mounting is verified only through a missing
target error without changing the mount namespace.

---

# 81. Milestone 5 — primary rustix parity

M5 is an evidence-led completion pass over the pinned Rustix 1.1.4
Linux/AArch64-little-endian profile, rather than a claim that every Linux
extension should be exposed at once. `compat/rustix/api.toml` is the
machine-readable authority: each overlapping Rustix family must have one of
the classifications below, with its exact test or documentation evidence.

| Family | M5 treatment |
| --- | --- |
| `fd`, `buffer`, `ffi`, `path`, `io`, and generic `ioctl` vocabulary | Native base surface; complete Rust `std` integration, ownership transfer, and direct-kernel error semantics are required before claiming compatibility. |
| Core filesystem, pipe, random, poll/eventfd, basic mapping, process identity, system, terminal, PTY, shared memory, and classic mount | Retain the verified M0–M4 direct-core implementations. M5 fills only the explicitly recorded omissions rather than replacing their tested contracts. |
| Descriptor durability/positioning, descriptor flags and duplication, and `stdio` descriptor helpers | Primary M5 direct syscall work. The `stdio` helpers are descriptor operations, not libc `FILE` state. Taking or replacing process-standard descriptors remains explicitly unsafe where ownership or concurrent global use cannot be guaranteed. |
| Epoll, timerfd, and file-backed mapping | Primary M5 readiness/VM work. Each uses typed Linux layouts and a source fixture where the Rustix shape is claimed. Socket lifecycle and address codecs stay explicitly deferred until their typed address contract can be verified as a unit. |
| `param::page_size` and other auxv-derived values | Deferred until a real explicit auxv initialization/ownership boundary exists. Do not guess that every AArch64 process uses 4 KiB pages. |
| Wait/fork/exec, signals, credentials, limits, scheduling, namespaces, and process-wide `prctl` policy | Deliberately deferred to the process/signal milestones. These operations change process-wide state or need child-after-fork rules, so a thin syscall wrapper is not enough evidence. |
| Linux-specialized filesystem, VM, networking, and mount administration (`statx`, inotify, memfd/seals, splice family, userfaultfd, FSD mount APIs, ancillary messages, broad socket options, XDP) | Classified as explicit later Linux extension work, never silently counted as Rustix parity. Each needs its own ABI types and regression scope. |
| `io_uring` and Rustix `runtime` | Not applicable to this foundational synchronous facade. They remain separately documented exclusions. |

The target remains Linux/AArch64 little-endian. This table does not create an
endian-parametric API promise; network and on-disk formats must continue to
state their byte-order handling at the individual operation boundary.

Completion requires:

```text
all relevant Linux/AArch64 rustix APIs classified

all in-scope overlap implemented

all implemented overlap verified

source-compatibility fixtures green where claimed

differential suite green

no production rustix dependency

no public C ABI/errno round-trip for syscall-like APIs

private runtime-boundary exception ledger green
```

### Progress — 2026-08-20 UTC

M5 is complete for its declared Linux/AArch64-little-endian scope. The
machine-readable correspondence ledger now classifies all 89 grouped pinned
Rustix records: 46 verified native/source-compatible records, 14 implemented
partial records, 25 explicit later slices, one deliberate mount-helper
divergence, and the three documented `runtime`/`io_uring`/`try_close`
exclusions. Deferred records are not counted as native parity.

The completed direct slice covers descriptor positioning, `ftruncate`,
`fsync`, `fdatasync`, descriptor flags and duplication, standard-descriptor
helpers, file-backed `mmap`, epoll, and timerfd. The C facades for the
overlapping operations route through the same `crabc-core` seams and alone
perform errno/sentinel conversion. The `dup2(fd, fd)` no-op and contrasting
`dup3(fd, fd, 0)` `EINVAL` rule have both native and dynamically linked C
regression evidence. Socket lifecycle/address codecs, auxv ownership, and
the remaining process-wide or Linux-specialized operations remain explicitly
deferred in the ledger.

`./scripts/dev.sh crabc-rs` passes the no-std build, M0–M5 native tests,
metadata checks, Python harness tests, all source comparisons, and M0–M5
static-boundary proofs with the pinned Rustix 1.1.4 checkout. `./scripts/dev.sh test`
passes the full Docker workspace, including the C façade regression.
The source-comparison gate uses a 60-second compilation timeout so its pinned
reference build is not spuriously classified as a behavioral mismatch under
Docker emulation.

Document deliberate exceptions.

`io_uring` may be a separately documented extended parity item if intentionally deferred.

---

# 82. Milestone 6 — process/signal/fork beyond rustix

Implement and verify the first major extension surface:

```text
complete signal facilities
unsafe raw fork
prepared fork/exec
spawn/exec facilities
atfork semantics
wait/process group/session operations
```

This should demonstrate that crabc-rs is now more than a rustix clone.

### Completion — 2026-08-20 UTC

**Complete for Linux/AArch64 little-endian.** M6 exposes the direct native
process/signal surface through `crabc-core`, without a call through crabc's C
ABI, C sentinel returns, or TLS `errno`.

`signal` now covers application-visible Linux/musl signals (1–31 and 35–64),
typed masks, actions, synchronous waits, queued delivery, thread-targeted
delivery, alternate stacks, and typed `signalfd4` records. Signals 32–34 are
deliberately absent from the safe vocabulary: musl 1.2.6 reserves them and
starts `SIGRTMIN` at 35 (`src/internal/pthread_impl.h` and
`src/signal/sigrtmin.c`). A simple handler cannot accidentally be registered
with `SA_SIGINFO`'s incompatible three-argument ABI. Handler and alternate
stack installation remain explicitly unsafe.

`process` now provides raw and native-atfork fork, allocation-free borrowed
exec, prepared owned fork/exec spawning with a close-on-exec error pipe,
typed child waits and `waitid`, and isolated process-group/session controls.
The native atfork registry is intentionally native-only: `process::fork()`
runs callbacks registered by `process::register_atfork`, while C
`pthread_atfork` remains owned by the C runtime. Crossing that boundary would
violate the direct-native contract, so mixed-registry execution is not
promised.

The C facade uses the same direct core seam for its overlapping AArch64
`waitid`, signal, and `signalfd` calls, and only converts core errors to its
public errno/sentinel convention. The completion also corrects C-side musl
signal semantics: `SIGRTMIN == 35`, reserved set members are rejected by
`sigaddset`/`sigdelset`, returned masks hide 32–34, `sigaction` rejects those
reserved dispositions, and `signal` retains musl's `SA_RESTART` behavior.

POSIX timer creation and timer-generated signal delivery are deliberately a
future native time/runtime capability, not an undocumented M6 omission. They
need typed `SIGEV_SIGNAL`/`SIGEV_THREAD_ID` ownership and `SI_TIMER` decoding.
The existing C signal/process workload remains its regression evidence until
that API has a dedicated native contract. This is separate from implemented
Linux `signalfd`, which has a fixed kernel ABI and no Rustix counterpart.

The pinned Rustix 1.1.4 comparison now verifies the compatible `wait` and
`waitid` shape with an isolated `ECHILD` fixture. Rustix deliberately does not
offer its normal public signal, fork/atfork, exec, or `signalfd` surface, so
those M6 APIs are documented native extensions rather than false Rustix
compatibility claims.

`./scripts/dev.sh crabc-rs` keeps M0–M6 together: it runs the isolated native
process/signal cases, the Python-only harness checks, the M6 source fixture,
and a no-`std` static archive inspection requiring direct AArch64 syscalls
`signalfd4`, `rt_sig*`, `clone`, `execve`, `wait4`, `waitid`, and
`exit_group`, while rejecting public C ABI and TLS-errno symbols. Focused C
fixtures cover the overlapping facade behavior.

---

# 83. Milestone 7 — runtime facilities

Implement native access to:

```text
pthread capabilities
resolver/netdb
dynamic loading
```

with strong ownership/safety semantics.

## M7 native vertical slice — 2026-08-20 UTC

The first runtime slice is complete for Linux/AArch64 little-endian. It adds
native access where crabc has one clear process-state owner, rather than
pretending that C pthread layouts or sentinel/`errno` conventions are Rust
interfaces.

`sync` owns process-private Rust storage and uses only the direct
`crabc-core::thread` futex seam. It supplies non-poisoning `Mutex`, `Condvar`,
`Once`, `Semaphore`, writer-preferring `RwLock`, and reusable `Barrier` types
with non-`Send` guards. Broadcast wakeups use Linux's largest positive futex
count (`i32::MAX`), not the invalid unsigned all-bits value. These primitives
are deliberately not process-shared or robust, and their objects must not be
used across `fork` without application-defined reinitialization.

`runtime_thread` is an opt-in private-singleton facade. `NativeJoinHandle`
supports explicitly unsafe raw C-compatible callbacks, join/detach, current
thread identity, TLS keys, TLS destructors, and carefully unsafe cancellation
state/type/test operations. The `runtime-thread-alloc` extension adds an owned
closure/result `spawn` and typed `JoinHandle`; the raw `runtime-thread` feature
remains meaningful in allocator-free `no_std` programs. Native handles are not
yet `Send` or `Sync`, and cancellation is forbidden for a typed spawned thread
because its join result owns a `Box<T>`.

The runtime facade reaches exactly one versioned private
`__crabc_runtime_v1` table in `libc.so`. The table has no installed C header,
returns positive pthread errors rather than TLS `errno`, and preserves libc as
the owner of thread slots, key slots, and cancellation state. The paired `dl`
facade uses the same table to reach loader-owned state, copying diagnostics and
address metadata into Rust-owned values; it never links a second loader or
calls the public `dl*` ABI.

`resolver` and `netdb` likewise avoid C runtime state: resolver configuration,
DNS results, and text database snapshots are caller-owned. The verified slice
covers typed numeric, A/AAAA, reverse-PTR, and deterministic configured
nameserver resolution plus hosts/services/protocols parsing. System
`resolv.conf` discovery, TCP retry, address sorting, and `AI_ADDRCONFIG` are
not silently approximated; the latter is explicitly rejected until it has a
native state/evidence contract.

The M7 proof is `./scripts/dev.sh crabc-rs`: focused concurrency and resolver
tests, allocator-free static archives, loader/thread C fixtures under
`libldso.so`, and ELF verifiers reject public `pthread_*`, `dl*`, resolver, and
TLS-errno dependencies. The fixtures exercise native loader state,
thread-create/join, per-thread key round trips, and cancellation-configuration
round trips in an actual crabc process.

This does not claim a Rust representation for every C pthread extension.
Recursive/error-checking mutex behavior, robust owner-death recovery,
process-shared synchronization, C cleanup-handler macro scopes, and direct
`pthread_atfork` registry sharing remain explicit capability-accounting work.
The existing M6 native atfork registry is intentionally separate. They may not
be hidden behind raw C structs or counted as native Rust coverage before their
contracts, safety classification, and evidence exist.

---

# 84. Milestone 8 — libc semantic facilities

Implement or classify the mature libc facilities without treating a C export as
native Rust coverage. This milestone is a set of narrow vertical seams, not a
claim that every listed C interface has a Rust twin:

```text
stdio
locale
wchar
iconv
regex
fnmatch
glob
wordexp
passwd/group
math
complex
fenv
```

and remaining mature crabc subsystems.

## M8 completion record — 2026-08-20 UTC

M8 is complete for its stated implement-or-classify scope.

| Facility | M8 disposition | Boundary and evidence |
| --- | --- | --- |
| `fnmatch` | Native-safe | `pattern::fnmatch(&CStr, &CStr, FnmatchFlags)` is allocation-free and byte-oriented. `crabc-core::pattern` is the sole algorithm used by both the native facade and the C adapter; M8 tests cover pathname, period, escape, bracket, case-fold, leading-directory, and non-UTF-8 behavior. |
| Floating environment | Native-safe with an optimizer limitation | `fenv` directly reads and writes calling-thread FPCR/FPSR. `EnvironmentGuard` restores state on drop. It does not promise that arbitrary optimized Rust arithmetic observes dynamic rounding. The static proof requires AArch64 `mrs`/`msr`, not C `fe*` or errno. |
| Buffered memory streams | Native higher-level | `CFile<'buffer>::from_memory` owns a close-on-drop libc `FILE` over an exclusively borrowed buffer. It is opt-in through `runtime-stdio`, reaches only append-only private `RuntimeV1` callbacks, returns typed positive errors, and supplies `std::io::{Read, Write, Seek}` adapters. It is neither `Send` nor `Sync`. |
| Remaining `stdio` | Explicitly deferred | Standard streams, file/path constructors, buffering policy, `popen`, and C varargs remain C/runtime capability-accounting work. Rust formatting is not re-exposed as a C-varargs imitation. The C `fclose` repair now frees dynamic stream/cookie/getline storage while permanently allocated standard streams remain static. |
| `locale`, `wchar`, `iconv` | Explicitly deferred | These need owned locale/converter/state types and an explicit process-global mutation contract. Native code must not borrow libc's mutable locale or `mbstate_t` singleton state. |
| `regex`, `glob`, `wordexp` | Explicitly deferred | POSIX regex currently depends on C-owned allocation-backed opaque state; glob needs owned results and cwd/error policy; word expansion requires an explicit shell-execution and injection-safety contract. No raw `regex_t`/`glob_t` or implicit shell behavior is counted as native coverage. |
| passwd/group | Explicitly deferred | Future native APIs must return owned records rather than libc static buffers and must make enumeration/runtime state explicit. |
| Math and complex | Classified for later extraction | Rust primitives subsume ordinary elementary operations. Musl-specific special, remainder, decomposition, and complex algorithms need a shared implementation seam; they must not become `crabc-rs` wrappers around C/libm. |

The M8 gate runs the native unit suites, three no-std AArch64 static probes,
private-runtime loader fixtures, existing C fenv/fnmatch/stdio regressions, and
Python verifiers. The verifiers reject public C stdio/fenv/fnmatch calls and
TLS-errno dependencies from the Rust-facing path. The remaining rows above are
intentional classifications, not omitted evidence; M9 is still responsible for
the complete machine-readable zero-unclassified accounting of all crabc
capabilities. The implementation landmarks are `crabc-core/src/pattern.rs`,
`crabc-core/src/fenv.rs`, `crabc-rs/src/pattern.rs`, `crabc-rs/src/fenv.rs`,
`crabc-rs/src/cfile.rs`, `libc/src/fenv.rs`, and the private table definition
in `crabc-core/src/lib.rs`.

---

# 85. Milestone 9 — complete capability accounting

The generated coverage report must show:

```text
unclassified public crabc symbols = 0
unclassified crabc capability groups = 0
```

Every meaningful crabc capability must be:

```text
native-safe
native-unsafe
native-higher-level
or genuinely Rust-subsumed
```

Every `abi-only` or `internal-runtime` classification must be explicitly justified.

## M9 completion record — 2026-08-20 UTC

M9 is complete for the measured Linux/AArch64-little-endian dynamic surface.
`compat/crabc-rs/coverage.toml` is now a v2 semantic ledger for all 1,669
candidate exports, with the pinned 1,647-symbol musl baseline and both input
TSV SHA-256 digests checked on every run. It preserves 57 symbol-backed
semantic groupings while separately accounting for non-exported private-runtime
and Linux-native implementation capabilities. The
generated `python3 compat/rustix/run.py --check` report proves:

```text
classified public crabc symbols = 1669 / 1669
unclassified public crabc symbols = 0
unclassified crabc capability groups = 0
candidate-only exports = 22 / 22 with an owning group
```

Status is deliberately independent of classification. `verified` records a
native seam with direct-boundary and behavioral evidence; `deferred` records a
meaningful capability and its intended post-M10 API, reason, and target; and
`documented` records Rust-subsumed, ABI-only, or private-runtime behavior with
the required rationale. At the M9 handoff the ledger had 215 groups: 156
verified, 16 deferred, and 43 documented. Deferred groups are explicitly
post-M10 work; documented C-ABI and Rust-subsumed groups are accounted scope
boundaries, not unclaimed native wrappers. Existing M0–M8 vertical slices
remain evidence for their listed operations.

In particular, the public malloc family is the versioned
`scope-exception` `allocator-mimalloc-libc-boundary` v1 and remains out of
scope for crabc-rs (mimalloc remains the underlying allocator strategy);
`fopen64` is an
Linux/AArch64 ABI alias rather than stdio coverage; private crypt, atfork, and
loader helpers are narrowly ABI/runtime entries; and `tgkill` is recorded as
the verified native-safe `signal::kill_thread` seam. The validator and its
mutation tests reject a missing, duplicate, or extra symbol; an unowned
candidate-only symbol; an unclassified group; native public-C-ABI or
TLS-errno use; and ABI-only records lacking review evidence.

---

# 86. Milestone 10 — semantic capability closure

This is the final semantic gate. The original “100% native capability
coverage” label is retained in the M10 evidence history but is superseded as a
mechanical-wrapper ambition.

The project may claim:

> crabc-rs provides complete in-scope semantic coverage of crabc

only when:

1. every meaningful in-scope underlying capability is reachable through an idiomatic Rust interface, explicitly subsumed by Rust, or covered by a documented compatibility/runtime exception;
2. inherently unsafe operations have explicit unsafe interfaces;
3. operations better represented by existing Rust primitives are documented as such;
4. raw C ABI exposure is not being used to hide missing native API design;
5. the complete machine-readable coverage inventory is green.

### Progress — 2026-08-21 UTC

M10 is **complete**. The green inventory has 215 semantic groups: 156
verified native seams, 16 explicitly deferred post-M10 capability groups, and
43 documented Rust-subsumed, C-ABI, or private-runtime groups. This is
semantic accounting for the Linux/AArch64 profile, not a claim that every C
export deserves a Rust wrapper. In particular, documented groups no longer
hide C errno/exit state, scanners, secure byte operations, callback/intrusive
collections, fenv-sensitive math, locale machinery, or C-only stdio forms.
The sole allocator exception remains explicit: crabc-rs exposes no
malloc-family API, including usable-size introspection, and uses ordinary Rust
allocation while the C ABI remains a mimalloc-backed libc boundary.

The completed terminal-control seam provides typed `tcgetattr`, `tcsetattr`,
`tcgetpgrp`, `tcsetpgrp`, and `tcgetsid` through the direct Linux/AArch64
ioctl boundary and a private kernel-layout record; it neither crosses C
termios nor implies PTY/session construction coverage. The C `crypt` ABI is
now a bounded compatibility profile: SHA-256-crypt and SHA-512-crypt use
pure RustCrypto `sha-crypt` MCF construction; all hand-rolled digest, cipher,
transposition, and password-hash serialization code has been removed. Only
canonical non-empty `Base64ShaCrypt` salt input is accepted, and dependency
output retains its explicit default-rounds spelling. The precise formats,
dependency due diligence, and unsupported legacy forms are recorded in
[`compat/crabc-rs/crypt-profile.md`](compat/crabc-rs/crypt-profile.md).

`fd::OwnedFd::close` consumes its one ownership token before direct Linux
`close`; a Linux `EINTR` is success because the descriptor has already been
released and must never be retried. `fs::lock_from_current` makes the
`lockf` range and operation explicit, avoiding C command integers and signed
length traps while preserving advisory, process-associated lock semantics.
`pipe::{splice, IoSliceRaw, vmsplice}` follows Rustix's borrowed-descriptor
and optional-offset shape. `vmsplice` stays explicitly unsafe: its caller
selects the pipe direction and, for `GIFT`, owns page alignment, actual
page-size, and post-transfer lifetime obligations. The direct AArch64 proof
exercises syscall numbers 25, 57, 59, 62--64, 75, and 76 without a C ABI or
TLS-errno hop.

`memory::ByteOps` covers the four non-basic byte operations through borrowed
Rust slices: `explicit_bzero` performs volatile writes behind compiler fences;
`memccpy` and `mempcpy` return typed suffixes; and `swab` preserves an odd
tail byte. Its AArch64 static archive has no specialized C byte-operation,
allocator, or TLS-errno reference.

`text::{CStrBuilder, CStrWrite, PaddedCopy}` makes C-string writes
invariant-preserving: exact, truncating, padded, and append-prefix forms
always retain their private terminator. Allocation-gated `CString` duplication
preserves non-UTF-8 bytes. ASCII case folding, musl `strverscmp` behavior,
empty-preserving split state, and independent token state replace C global or
pointer-driven contracts. `path::{PathPart, basename, dirname}` uses NUL-free
`CStr` input or checked byte slices and preserves musl's lexical path policy.

`numeric::{EncodedLong, DecodedLong, DecodeStatus}` owns musl's six-byte,
low-32-bit, least-significant-digit radix-64-long representation and makes
NUL termination, invalid bytes, input exhaustion, and the digit limit typed
decode states. `collections::{Search, InsertOutcome, CallbackSort}` replaces
C comparator pointers with ordered typed slices, alloc-gated `Vec` growth,
and explicit mutable comparator context; its ordering remains deliberately
unstable, as with `qsort_r`.

`process::kernel_brk` is an explicit unsafe query/request boundary that never
coordinates an allocator. `mm::{MlockAllFlags, PosixAdvice, mlockall,
munlockall, posix_madvise, remap_file_pages}` keeps process-wide lock policy,
mapped-range provenance, musl's POSIX `DONTNEED` no-op, and legacy remap's
fixed zero compatibility words explicit. The C `brk`/`sbrk` and
`posix_madvise` adapters were corrected to the same musl semantics.

`net::{MMsgHdr, sendmmsg, recvmmsg}` owns private Linux message records while
retaining source/destination borrows, initialized receive prefixes, partial
batch counts, individual result fields, and mutable timeout state. The fixed
`net::sockatmark` ioctl is separately verified as a typed boolean query.

`time::{IntervalTimerValue, setitimer, alarm, ualarm}` controls the explicit
process interval timers with microsecond-validated inputs and complete old
settings. `PosixTimer` owns a kernel timer ID and typed specification/notify
records, supports explicit retryable deletion plus best-effort Drop, and
deliberately excludes `SIGEV_THREAD`; that callback-runtime work remains a
separate deferred implementation capability. `sleep` and `usleep` are
documented as covered by the more expressive `nanosleep(Duration)` boundary.

`time::{CalendarTime, time, difftime, gmtime, timegm}` provides strict,
musl-derived UTC Gregorian conversion without a C `tm` layout, static buffer,
timezone, or TLS errno. Invalid civil fields and C `timegm` normalization are
rejected rather than represented by an invalid native value; local-time,
format/parse, and clock-discipline work remains distinct. `process::chroot`
is Rustix-shaped but explicit about its process-wide root effect, and its
regression only asks the kernel for a nonexistent path. `process::{umask,
setrlimit}` expose their process-global mutations with restoration evidence
and limit-order validation. Their direct AArch64 proof is limited to syscalls
51, 113, 166, and 261. The C `remove` adapter also now matches musl by
retrying `EISDIR` with `AT_REMOVEDIR`; native Rust retains separate typed file
unlink and directory-removal operations.

`fs::{canonicalize_into, canonicalize}` is a byte-preserving physical
canonicalization contract with caller-buffered and alloc-gated owned results.
It resolves lexical components and absolute/relative links through direct
Linux directory operations, caps path expansion at `PATH_MAX` and forty links,
and makes output capacity failure explicit rather than exposing a C result
pointer or implicit allocation.

`time::clock_getcpuclockid` turns musl's encoded process CPU clock ID into a
validated opaque value, rejecting `pid_t` inputs that could wrap to another
clock before reading it through `DynamicClockId::Process`. `clock_settime` now
has the exact Rustix shape over a canonical `Timespec`; tests exercise an
un-settable monotonic clock only, preserving direct `EINVAL`/`EPERM` without
altering wall-clock state.

`param::{page_size, linux_hwcap, linux_minsigstksz, linux_execfn}` reads fixed
auxiliary-vector records directly from `/proc/self/auxv`, matching Rustix's
Linux-raw fallback without borrowing libc's `getauxval` state. Network-device
name/index lookup now has Rustix's descriptor-taking `SIOCGIFINDEX` and
`SIOCGIFNAME` forms over a private 40-byte AArch64 `ifreq` boundary. Reverse
lookup returns owned fixed inline UTF-8 storage or an alloc-gated `String`,
never if_indextoname's caller buffer. Interface address-list enumeration stays
separate.
`net::{IpAddr, Ipv4Addr, Ipv6Addr}` also re-exports Rustix's pure core value
types: constructor, octet, bit, and IPv4/IPv6-variant behavior is available
without claiming C `inet_*` text parsing, static storage, or interface-list
ownership.

`event::pause` matches Rustix's deliberately unit-returning signal-only wait:
Linux/AArch64 uses direct `ppoll(NULL, 0, NULL, NULL)` and its inevitable
`EINTR` becomes the completion condition rather than C `errno` state. It does
not install a handler or alter a signal mask. `termios::{ttyname_into,
ttyname}` adds caller-buffered and alloc-gated terminal-path retrieval. It
requires procfs, validates both character-device and terminal state, and
compares the procfd target's device/inode with the original descriptor before
returning it; C static storage and `ttyname_r`'s integer/buffer convention do
not cross the native boundary.

`termios::{ioctl_tiocexcl, ioctl_tiocnxcl}` follows Rustix's no-argument
exclusive-mode ioctls over a borrowed terminal descriptor. The terminal owns
the setting until explicit release or teardown; privileged opens may bypass its
`EBUSY` restriction. It carries no C terminal-state pointer or errno contract.
`Termios::special_codes` is now the complete Rustix named index vocabulary
over Linux's private 19-byte `NCCS` ioctl region. It deliberately remains a
44-byte Linux terminal record rather than a cast of musl's differently sized
public C `struct termios`; the wider terminal/session policy is still deferred.

`thread::futex::{Flags, Timespec, wait, wake}` is the bounded Rustix-shaped
Linux futex primitive. Borrowing an `AtomicU32` makes the required alignment
and lifetime explicit, and the optional borrowed timeout keeps the kernel's
relative `FUTEX_WAIT` form. `PRIVATE`, `CLOCK_REALTIME`, and future bits are
passed directly to Linux for operation-specific validation; `EAGAIN`, `EINTR`,
timeout, and wake-count results remain direct. Priority inheritance, requeue,
bitset, futex-fd, and waitv operations remain deferred, as does any C pthread
ABI claim.

`thread::{Uid, Gid, set_thread_res_uid, set_thread_res_gid}` exposes Rustix's
Linux `setres*` shape with the actual calling-task-only effect. `None`
is the kernel all-ones no-change sentinel, while an explicit all-ones typed ID
is rejected so it cannot silently change meaning. This is not musl's
process-wide synchronized C credential contract, which remains deferred.

`unsafe process::{set_fs_uid, set_fs_gid}` is a separate Linux extension for
filesystem identity. `None` is the kernel all-ones query word and a typed
all-ones ID is rejected; the returned value is the prior filesystem identity,
including when Linux denies a requested change without an errno result. The
calling-task authority effect is intentionally not presented as musl's
synchronized process credential operation.

`termios::{tcdrain, tcflush, tcflow, tcsendbreak}` is the safe
Rustix-compatible queue-control quartet. It uses closed queue/action types and
direct terminal ioctls over a borrowed descriptor. That evidence does not
promote the separate private termios-record, foreground process/session, or
PTY lifecycle contracts, which remain deferred.

`fs::posix_fallocate` fixes Linux `fallocate` to its POSIX zero-mode
operation. Its borrowed descriptor, checked unsigned byte range, unchanged
file position, and direct `Errno` result make C's integer-error convention and
flag-bearing Linux allocation modes unavailable at this native boundary.

`process::{get_current_dir_name, get_current_dir_name_alloc}` accepts a
caller-owned `PWD` snapshot rather than reading global environment state. It
returns its exact symlink-preserving, non-UTF-8 bytes only when direct device
and inode checks show that an absolute nonempty snapshot is the current
directory; otherwise it uses physical `getcwd`. `lchmod` is ABI-only and
documented: Linux cannot mutate symlink modes, and musl's fixed `ENOTSUP`
result is not a native operation.

`time::timespec_get` is the direct realtime observation corresponding to the
single C11 `TIME_UTC` case. It returns a typed, normalized `Timespec` or a
kernel error—not C's base/zero sentinel—and neither owns timezone state nor
implies the deferred calendar, formatting, or clock-adjustment surfaces.

`time::{RealtimeMillis, realtime_millis}` is the native replacement for musl's
`ftime`: it reads `CLOCK_REALTIME` through direct Linux/AArch64 syscall 113,
retains signed Unix seconds, and truncates a validated nanosecond remainder to
milliseconds. It does not expose C `struct timeb`, timezone state, allocation,
vDSO dispatch, or TLS `errno`; the other local-time, formatting, parsing, and
clock-control symbols remain in deferred `time.clock-calendar`.

`net::parse_ipv4_legacy` has musl's full one-to-four-component base-zero IPv4
grammar over a complete byte slice. `Ipv4Addr` preserves a valid all-ones
address without `inet_addr`'s sentinel ambiguity, and ordinary Rust formatting
replaces `inet_ntoa`'s static buffer. Strict modern parsing and interface
enumeration remain separate deferred contracts; the Ethernet codec is now
covered by its own complete four-symbol group below.

`net::{parse_ipv4_network_number, make_ipv4_address, ipv4_local_number,
ipv4_network_number}` is the separate four-helper classful IPv4 arithmetic
capability corresponding to `inet_network`, `inet_makeaddr`, `inet_lnaof`, and
`inet_netof`. It states `Ipv4Addr`'s logical network-order octets and
host-order `u32` network/host numbers at the API boundary; musl's
`htonl`/`ntohl` semantics make the result independent of AArch64 object
representation. It returns owned values and does not reproduce C sentinel
results, process-global static storage, allocation, or TLS `errno`. Modern
presentation parsing remains separate, while the independent owned
interface-address snapshot and ethers database contracts are accounted for
below; this arithmetic slice does not claim broader legacy address parity.

`net::EthernetAddress` is the complete native counterpart for musl's
`ether_aton`, `ether_aton_r`, `ether_ntoa`, and `ether_ntoa_r` as one verified
capability. `EthernetAddress::parse` consumes a complete borrowed byte slice
with exactly six colon-separated components, preserving musl's
`strtoul(..., 16)` spellings (leading C whitespace per component, an optional
sign, and an optional `0x`/`0X` prefix) while rejecting no-conversion/empty
components, out-of-range octets, missing or extra components, and trailing
bytes. `to_ascii_bytes` and `write_to` produce musl's exact canonical form:
six two-digit uppercase hexadecimal fields separated by colons (`%.2X`,
`:%.2X`), with no terminating NUL and no static buffer. The release AArch64
archive probe exercises parsing, round-trip bytes, uppercase formatting,
short-buffer rejection, and malformed/trailing input; its verifier rejects
the four C codec calls, neighboring address helpers, allocator, and TLS
`errno` references. No C ABI or libc public call is part of this native
boundary.

`fs::{create_temp_dir_into, create_temp_dir, create_temp_dir_at_into,
create_temp_dir_at}` replaces `mkdtemp`'s mutable `XXXXXX` template with an
explicit parent, prefix, caller buffer or alloc-gated result, 96-bit kernel
random suffix, and atomic `mkdirat(..., 0700)` retry loop. The returned path
is not a retained directory capability; callers that coordinate CWD changes
retain a parent descriptor and use the `_at` forms.

The first new M10 native implementation capability is
`text::{TextEncoding, TextConverter}`. It is an allocation-free, borrowed-slice
converter for strict UTF-8, ASCII, UTF-16LE/BE, UTF-32LE/BE, and Linux/AArch64
little-endian `WChar`, plus ISO-8859-2 through -16, with typed resumable
progress, malformed/incomplete input, output-full, and unrepresentable-scalar
results. Its AArch64 static probe rejects `iconv*`, C allocator, and
TLS-errno references. Undefined ISO table slots retain their extracted table
scalar in the native contract. This is intentionally not a claim that the C
`iconv`, `iconv_open`, and `iconv_close` exports or their complete legacy
codec/alias behavior are done: those symbols remain deferred until the C
compatibility adapter and native facade share the full typed implementation.

`text::AsciiClass` and its typed `u8` predicates/conversions complete the
exported byte ctype group under the fixed C/POSIX locale model. High bytes are
valid inputs with an empty classification, while C EOF, negative/out-of-range
integers, locale handles, and wide ctype stay outside this type boundary and
in their separate deferred capability groups.

`stdio::{BoundedFormatter, FormatResult, format_to}` now supplies the native
bounded-formatting seam. Typed `core::fmt::Arguments` write into caller-owned
byte storage, report the complete required UTF-8 byte count, and preserve a
valid UTF-8 prefix on truncation. C varargs, trailing-NUL, locale, allocator,
and errno behavior do not cross this boundary; its AArch64 probe rejects those
C dependencies.

The C iconv adapter has a pinned-musl regression fixture for incomplete
UTF-8, surrogate rejection, and pointer/count progress before `EILSEQ` or
`E2BIG`; those cases now pass. ISO-8859-2 through -16 data lives once in
`crabc_core::iconv` and serves the legacy adapter. This begins the data
migration only: C iconv aliases and all legacy codec behavior remain deferred.

`text::{NumberParser, NumberParseError}` supplies allocation-free full-slice
ASCII integer parsing for an explicit radix from 2 through 36. Its typed
errors distinguish empty input, signs, invalid digits, and overflow. It makes
locale, whitespace, base prefixes, end pointers, and errno unrepresentable;
floating-point, wide-character, and locale-sensitive parsing remain deferred.

`rand::{RandomState, random_u32, getrandom, GetRandomFlags}` makes random
state explicit: a deterministic non-cryptographic SplitMix64 stream is owned
by the caller, while `from_entropy` and `getrandom` use the direct Linux
kernel boundary with typed errors. No C random global, public C ABI, or errno
state participates.

`fs::{StatFs, StatVfs, statfs, fstatfs, statvfs, fstatvfs}` exposes typed
filesystem-capacity observations through direct Linux/AArch64 `statfs` and
`fstatfs` calls. The kernel ABI layout remains private; the POSIX-shaped
`StatVfs` mapping is explicit and conservative. This does not claim the other
path/metadata aliases.

`fs::{fallocate, FallocateFlags}` allocates, preserves size, zeroes, or punches
a checked byte range through the direct Linux/AArch64 syscall. It borrows the
descriptor without changing its offset, accepts only a closed safe mode set,
and rejects unsupported combinations plus signed `loff_t` range overflow
before the kernel boundary. POSIX allocation aliases and temporary-path policy
remain separate work.

`fs::syncfs` borrows an open descriptor to flush its mounted filesystem through
the direct Linux/AArch64 syscall. It is intentionally distinct from per-file
`fsync`/`fdatasync` durability and does not use C state or errno.

`fs::sync` invokes the global Linux writeback syscall with its direct
zero-argument, unit-success contract. Linux waits for kernel/filesystem
writeback completion while POSIX permits scheduling-only behavior; neither
guarantees persistence past a device volatile cache.

`fs::{Advice, fadvise}` makes the six POSIX file-access hints a closed native
type. Its Rustix-shaped range accepts either an explicit nonzero length or the
kernel's zero-length-to-end-of-file convention, checks signed ABI bounds before
the direct `fadvise64` syscall, and deliberately does not reproduce C's
direct-error return convention.

`fs::readahead` makes Linux's advisory cache-read request available over a
borrowed descriptor without moving its file position. Its unsigned offset and
length form a checked half-open range; values or range ends outside the signed
`loff_t` domain return `EINVAL` before the direct syscall rather than being
truncated.

`fs::copy_file_range` copies a requested range between two borrowed
descriptors. Optional mutable offsets preserve Linux's explicit-offset mode;
absent offsets preserve its shared-file-position mode. The wrapper checks every
`loff_t` value and range end before the syscall, exposes short copies, and
commits caller offsets only after a successful kernel return.

`process::{getcwd, getcwd_alloc}` reads the current directory through the
direct Linux/AArch64 syscall. The allocation-free form returns only the
initialized, NUL-terminated prefix of caller-owned storage; the alloc-gated
convenience reuses a vector and grows only after `ERANGE`. It does not expose
C's allocation ownership rule or a raw C buffer contract.

`process::{chdir, fchdir}` changes the process-global current directory through
direct Linux/AArch64 syscalls. The safe Rustix/std-shaped operations do not
isolate threads, so callers must coordinate concurrent pathname work; the
regression restores the original directory through an owned descriptor on an
intentional error path.

`fs::{access, Access}` checks a current-directory pathname with a closed
read/write/execute/existence mode set. It preserves Linux's real-ID
`access()` semantics through the direct three-argument `faccessat` syscall,
but intentionally exposes neither directory-relative nor `faccessat2` flags.

`fs::sendfile` transfers between two borrowed descriptors while preserving
Linux's two input-offset modes: an explicit mutable offset advances itself but
not the input descriptor, whereas `None` advances the input descriptor. It
returns short transfer counts, rejects offsets outside signed `off_t` before
the direct syscall, and never transfers descriptor ownership.

`fs::ftruncate` now rejects byte lengths outside Linux's signed `loff_t` range
before it even borrows a descriptor. The regression preserves the existing
checked direct syscall for representable values while making unsigned cast
wraparound and any accidental file-size mutation impossible for invalid input.

`fs::truncate` gives a pathname-selected file the same checked unsigned byte
count boundary. An unrepresentable length returns `EINVAL` before `Arg` path
conversion or the direct syscall, so it cannot mutate the selected file.

`fs::{Dev, FIFO_DEVICE, mknodat, mkfifo, mkfifoat}` creates Linux filesystem
nodes through direct `mknodat`. The node type, permission/special bits, and
exact `dev_t` are separate inputs: `FileType::Unknown` and caller-provided
file-type bits in `Mode` return `EINVAL` before the syscall. FIFO helpers own
their required zero device word, while device-node privilege and device-number
validation remain kernel error paths rather than unsafe Rust memory behavior.

`fs::{ChownFlags, chown, lchown, fchown, chownat}` uses direct
`fchownat`/`fchown` for Linux/AArch64 ownership changes. `None` alone maps to
the all-ones no-change field; a raw all-ones `Uid` or `Gid` is rejected instead
of silently acquiring that different meaning. The closed ownership flag type
only permits final-symlink no-follow, not unrelated `AT_*` bits.

`thread::sched_getcpu` is the Rustix-shaped, infallible transient CPU
observation. Its direct `getcpu` syscall writes into facade-owned valid stack
storage, so no user-memory error path escapes; the result does not claim CPU
affinity, pinning, or stability across a scheduling event.

`rand::{getentropy, GETENTROPY_MAX_LENGTH}` fills caller-owned storage through
direct Linux/AArch64 `getrandom` with musl's exact 256-byte ceiling. An
oversize request returns `EIO` before the syscall; interruptions retry, and
the API exposes a `MaybeUninit` buffer only after it is wholly initialized.
It does not cross a public C entropy or errno boundary.

`fs::create` is the narrow native equivalent of `creat`: direct `openat` with
write-only, create, and truncate flags and no implicit close-on-exec. It
returns an `OwnedFd`; callers requiring a different creation policy use the
explicitly general `fs::open` API instead.

`system::{Uname, uname}` provides owned Linux kernel-name observations through
`Uname::{nodename, domainname}`. This follows Rustix's `uname`-based hostname
shape and deliberately avoids C caller-buffer sizing, truncation, and errno
semantics while keeping the UTS layout private.

`fs::{fcntl_getfl, fcntl_setfl}` adds the status-flag forms of Linux `fcntl`
over a borrowed descriptor. Observed unknown `OFlags` bits are retained, and
the API explicitly reflects that `F_SETFL` changes the shared open-file
description: duplicate descriptors observe its result. Descriptor-local
close-on-exec remains separate from this contract.

`process::{setpriority_process, setpriority_process_group,
setpriority_user}` sends a closed `Priority` and `PriorityTarget` directly to
Linux/AArch64 `setpriority`. It is Rust-safe but intentionally has scheduling
side effects, so callers coordinate affected tasks; permission and target
errors remain typed kernel results. The native contract does not adopt C
`nice` increment or errno-translation behavior.

`fs::{futimes, Timeval}` provides the descriptor-only microsecond timestamp
operation through the existing direct `utimensat` futimens form. `None`
expresses current time without a nullable pointer; supplied signed seconds are
preserved while invalid microseconds are rejected before nanosecond conversion
or the syscall. Path-based timeval aliases remain separate policy work.

`system::{LoadAverages, load_average}` converts Linux `sysinfo`'s fixed 16.16
one/five/fifteen-minute load words into an owned observation. It deliberately
does not expose C `getloadavg`'s partial caller buffer, count, or sentinel
conventions, and it adds no new C or syscall boundary beyond `sysinfo`.

`fs::{lutimes, Timeval}` updates a final symlink's own timestamps through
direct `utimensat` with the closed no-follow flag. It shares the pre-kernel
microsecond validation and `None` current-time form with `futimes`; target
timestamps remain outside this operation's effect.

`process::getrlimit_for` observes a selected process's current resource limit
through direct `prlimit64`, preserving typed optional-PID selection, kernel
permission/exit races, and the existing unlimited representation. It always
passes a null new-limit pointer, so it is not a limit-mutation API.

`fs::{futimesat, Timeval}` is the directory-relative, final-symlink-following
timeval form. Its owned directory-descriptor borrow, non-null typed path, and
zero `utimensat` flags make that resolution policy explicit; checked
microseconds and `None` current time share the existing timestamp contract.
C's null-path extension, cwd-only form, and no-follow form remain distinct.

`time::process_cpu_time` converts the known Linux process CPU-time clock into
a canonical `Duration` through the existing direct `clock_gettime` seam. It
does not inherit C `clock`'s `clock_t` microsecond unit, overflow sentinel, or
calendar-time behavior.

`time::{DynamicClockId, clock_gettime_dynamic}` adds the Rustix-shaped
fallible dynamic-clock observation. Known clocks and Linux clock-device
descriptors are encoded as typed identifiers, with the descriptor borrow
retaining its owner for the query; syscall 113 writes caller-owned timespec
storage directly. Kernel errors such as `EINVAL` remain `Result` values, and
the slice has no libc, vDSO, or TLS-errno route. Clock mutation remains
deferred.

`fs::{utimes, Timeval}` is the AT_FDCWD, final-symlink-following timeval
form. It reuses checked microseconds and the typed current-time form while
making cwd selection explicit; C nullable pointers remain outside this
contract.

`fs::{utime, Utimbuf}` is the corresponding whole-second timestamp form. Its
typed pair is converted privately to two zero-nanosecond records for direct
`utimensat`; `None` requests Linux current time, and cwd lookup follows a
final symlink. The native value does not promise C layout or nullable-pointer
semantics.

`fs::statx` provides direct extended Linux metadata over a private exact
256-byte output record. `Statx::stx_mask` remains authoritative for optional
fields; the reserved request bit is rejected before the syscall, and direct
kernel errors such as `ENOSYS` remain visible rather than falling back to
`fstatat` or caching process-wide availability.

`process::scheduler_priority_bounds` is a read-only scalar observation over
the closed `SCHED_OTHER`, `SCHED_FIFO`, and `SCHED_RR` policies. It validates
the returned ordering and preserves kernel errors, while scheduler-policy
selection and parameter mutation remain outside this facade.

`thread::sched_rr_get_interval` observes a selected Linux task's round-robin
interval as a validated `Duration`. `None` retains PID-zero current-task
selection, while `Some(Pid)` preserves direct lookup and permission errors;
it neither selects a scheduler policy nor changes any task state.

`fs::accessat` has Rustix's `Access`/`AtFlags` source shape while retaining a
direct Linux/AArch64 kernel boundary: empty flags select `faccessat`, and the
closed `EACCESS`/`SYMLINK_NOFOLLOW` subset selects `faccessat2`. Other
distinguishable at-family bits fail before the syscall; Linux's shared
`REMOVEDIR`/`EACCESS` bit is necessarily interpreted as `EACCESS`. This
deliberately has no musl/Rustix fallback, credential emulation, or
process-global availability cache, so an older kernel's `ENOSYS` remains
visible.

`thread::{CpuSet, sched_getaffinity}` reads a Rustix-shaped fixed 1024-bit CPU
mask through direct syscall 123. `EINVAL` for an insufficient kernel mask is
preserved without allocation, retry, or truncation; a successful short kernel
write has its private tail cleared. `CpuSet`'s local construction and bit
methods change only the value, not task affinity. The result is a transient
affinity snapshot rather than a kernel-mutation API or a cross-call stability
guarantee.

`thread::sched_setaffinity` is the matching direct syscall 122 mutation over a
fixed `CpuSet`. `None` selects the calling task and `Some(Pid)` preserves
kernel task-lookup and permission errors. Linux may intersect the requested
mask with online/cpuset-permitted CPUs, reporting an empty effective mask as
`EINVAL`; the test reapplies the observed mask so it exercises the syscall
without intentionally changing task eligibility.

`io::{pread, pwrite}` adds caller-buffered positioned I/O with borrowed
descriptors, non-negative `u64` offsets, typed errors, and `MaybeUninit` read
support. It preserves the descriptor position and does not claim flag-bearing,
splice, or remaining descriptor operations.

`io::{IoSlice, IoSliceMut, readv, writev}` adds initialized vectored I/O over
the same direct descriptor boundary. Each segment keeps its source or exclusive
destination borrow alive, segments may be advanced explicitly after a short
operation, and empty vectors/segments are valid without allocation. This does
not overclaim positioned-vector, flag-bearing, splice, or sync extensions.

`io::{preadv, pwritev}` makes that same initialized-segment contract positional.
It preserves the shared descriptor offset, retains short-read suffixes, and
encodes the full `u64` offset through the Linux/AArch64 syscall ABI's explicit
low/high 32-bit words. Flag-bearing vectors and splice remain deferred.

`io::{preadv2, pwritev2, ReadWriteFlags}` extends that boundary with the
documented Linux RWF flags. Unknown flags are rejected before the direct
syscall; ordinary offsets retain their exact low/high-word encoding, while the
explicit `u64::MAX` sentinel retains Linux's current-file-offset semantics.

`io::{sync_file_range, SyncFileRangeFlags}` submits the bounded Linux
writeback/wait operation for a borrowed descriptor. Its closed flag set and
checked signed range preserve the Linux/AArch64 ABI, including zero length's
through-EOF meaning, without claiming global `sync` semantics or C errno.

`event::{ppoll, PollFd, PollFlags}` supplies the signal-mask-aware readiness
form through the direct Linux/AArch64 syscall. It borrows a `SignalSet` only
for the call, passes the exact eight-byte kernel mask, and copies the timeout
that Linux may mutate; `poll` remains the explicit no-mask convenience form.

`event::{epoll::create_legacy, epoll::wait_with_mask}` completes the legacy
epoll alias and signal-mask-aware wait over the existing initialized event
buffer. `event::{FdSetElement, FdSetIter, fd_set_*, select, pselect}` exposes
the Linux bit-vector descriptor-set contract in the Rustix shape: the sets are
mutated to ready entries, raw descriptor lifetime is an explicit unsafe
obligation, and the `pselect6` timeout is copied. The C `select` adapter
validates negative timeval fields, normalizes large microsecond fields with
checked seconds arithmetic, and never writes the caller's timeval; C
`pselect` passes the eight-byte kernel signal-set width rather than musl's
public 128-byte sigset representation.

`event::{eventfd_read, eventfd_write}` borrows an event descriptor and keeps
its one eight-byte counter record private as a typed `u64`. Reads retain both
ordinary counter-reset and semaphore behavior; writes preserve Linux's
all-ones rejection and nonblocking overflow error. The readiness ledger now
separately records the complete select-family and epoll alias/mask contracts;
unrelated pause and future readiness extensions remain separate work.

`unsafe mm::{madvise, Advice}` gives Linux a closed set of ordinary mapping
advice policies. Page alignment, range validity, pointer provenance, and the
fact that `LinuxDontNeed` can invalidate contents remain explicit caller
obligations; VM locking, remapping, and broader advice policy remain deferred.

`unsafe mm::{msync, MsyncFlags}` synchronizes a caller-proven mapped range
through the direct Linux/AArch64 syscall. Mapping lifetime, page alignment,
pointer provenance, and the cache effects of invalidation remain explicit
unsafe obligations; synchronization flags are passed as the Rustix-compatible
Linux bit set without a C sentinel or errno conversion.

`unsafe mm::{mincore, MINCORE_PAGE_SIZE}` snapshots page residency into an
exclusive caller-owned byte vector. It checks capacity using the 4 KiB AArch64
page-size lower bound, which safely over-provisions for larger configured page
sizes; mapping alignment, lifetime, provenance, and output disjointness remain
explicit unsafe obligations.

`unsafe mm::{mlock, mlock_with, munlock, MlockFlags}` locks or unlocks one
caller-proven mapped range through the direct Linux/AArch64 `mlock`, `mlock2`,
and `munlock` syscalls. `ONFAULT` is explicit, while rounded-range validity,
mapping lifetime, pointer provenance, and memlock-budget effects remain unsafe
caller obligations. Process-wide `mlockall`/`munlockall` remain deferred.

`unsafe mm::{mremap, mremap_fixed, MremapFlags}` resizes or moves a
caller-owned mapping and returns its successor address. The old range is
consumed on success; the fixed-address form also invalidates any replaced
destination mapping. `MAYMOVE` is the only public flag, with fixed relocation
bound to the explicit destination API and `DONTUNMAP` intentionally deferred.

`fs::{Dir, DirEntry}` is a descriptor-owning, caller-buffered directory stream
above `RawDir`. It opens with controlled read-only/directory/close-on-exec flags,
preserves arbitrary filename bytes, ties entries to the stream borrow, and makes
EOF and the first error terminal. It interoperates with both crabc-rs and
standard Rust descriptor-borrow traits. C stream records, sorting, and walking
remain separate capabilities.

`Dir::{rewind, seek}` and the underlying `RawDir` use opaque Linux `d_off`
cookies, not byte positions, and discard buffered entries on each cursor
operation. Rewind defers direct `lseek(fd, 0, SEEK_SET)` until the next read;
seek returns a direct failure immediately. Both retry `EINTR`. The native
caller-buffered constructor remains distinct from Rustix's allocating `Dir`,
and reentrant C records plus a tell-position API remain separate.

`time::{UnixTime, wall_clock}` reads the UTC wall clock through the direct
Linux/AArch64 `gettimeofday` syscall. The native value preserves signed Unix
seconds with canonical nanoseconds; legacy timezone output, C `timeval`,
vDSO/libc routing, allocation, and TLS errno are absent. Calendar conversion,
formatting, mutation, and other global-time semantics remain deferred.

`time::{getitimer, IntervalTimerKind, IntervalTimerValue, GetitimerError}`
reads but never arms, disarms, or otherwise mutates the three Linux process
interval timers. The closed selector enum and private validated `Duration`
pair reject arbitrary C selectors and malformed signed `timeval` values before
they enter the public API; timer mutation and signal delivery remain separate
work.

`process::{times, ClockTicks, ProcessTimes}` reads the five Linux
process-accounting observations without inventing a `CLK_TCK` conversion. The
four validated private `tms` fields and the syscall's separate elapsed return
remain opaque tick values, so C output storage and calendar semantics stay out
of the native contract.

`time::{nanosleep, SleepOutcome, SleepError}` takes a `core::time::Duration`
and exposes rather than hides interruption: completion and `EINTR` with the
kernel's remaining duration are distinct typed outcomes. It never silently
retries or crosses C sleep/errno state. C duration aliases, timers, callbacks,
and process-global alarm semantics remain separate work.

`time::{clock_nanosleep_relative, clock_nanosleep_absolute}` makes the selected
clock and sleep mode explicit. Relative interruption returns Linux's remaining
duration, while absolute interruption remains a typed `EINTR` without an
invented remainder; malformed absolute nanoseconds are rejected before the
kernel boundary. Calendar conversion, timezone state, and clock mutation stay
separate capabilities.

`process::{getuid, geteuid, getgid, getegid, Uid, Gid}` reads real and
effective Linux identities through direct zero-argument syscalls. The opaque
types preserve exact raw `uid_t`/`gid_t` values while preventing accidental
interchange with unrelated integers; authority-changing credentials and limits
remain separate native work.

`process::{getresuid, getresgid, UidTriple, GidTriple}` adds read-only real,
effective, and saved-set identities through private caller-owned output words.
The triple fields retain those same opaque types; credential mutation remains
outside this capability.

`process::{Resource, Rlimit, getrlimit}` adds read-only observations through
`prlimit64` with PID zero and a null new-limit. The closed resource vocabulary
maps Linux's infinite limit to `None`; changing limits remains an explicitly
separate process-wide contract.

`process::{PidfdFlags, pidfd_open}` creates a Linux process descriptor through
direct syscall 434 and transfers the fresh descriptor to `OwnedFd`. `NONBLOCK`
and retained future flag bits remain kernel-validated; `ENOSYS`, target-lifetime,
permission, descriptor-limit, and flag errors cross unchanged with no fallback
or availability cache. This is a native Rustix extension, not a musl C export.

`process::{ResourceUsageTarget, ResourceUsageTime, ResourceUsage, getrusage}`
reads the three pinned Linux targets through the direct syscall. Its typed
value preserves the two canonical microsecond times and fourteen initialized
counters, while deliberately omitting musl's uninitialized compatibility tail.

`process::{getgroups_count, getgroups, Gid}` exposes the read-only Linux
supplementary-group query/fill protocol through typed caller-owned storage.
It preserves the separate supplementary list rather than adding the effective
group ID, and documents `EINVAL` retry behavior when credentials change
between the sizing and fill calls; no credential mutation is included.

`process::{Priority, PriorityTarget, getpriority}` exposes read-only Linux
nice observations for a process, process group, or user. It translates the
kernel's non-negative `[40, 1]` success representation into the closed
`[-20, 19]` nice range, so a valid C `-1` is never confused with an error;
priority mutation remains deferred.

`process::{getpid, getppid, Pid}` is independently verified as a direct,
read-only identity observation. The caller PID is positive and typed, while
Linux's zero-parent namespace-init/no-visible-parent sentinel maps to `None`.
Process creation, execution, waiting, and mutation remain separate contracts.

`process::{getpgid, getpgrp, getsid}` exposes read-only process-group and
session observations through typed optional `Pid` selectors. `None` retains
Linux's current-process meaning, while `getpgrp` is the independently tested
current-group shorthand over the same direct `getpgid` contract; session/group
mutation, spawning, and C aliases remain deferred.

`thread::gettid` is independently verified as a typed, stable kernel-task
identity. It is neither a pthread handle nor a cancellation/TLS contract, so
the broader pthread and C11 surface remains deferred.

`fs::{memfd_create, MemfdFlags}` creates an anonymous memory file from a
byte-oriented name and moves the fresh descriptor into `OwnedFd`. Its closed
flag set has only stable close-on-exec, sealing, and default-huge-page choices;
page-size encodings and newer exec-policy bits are not silently forwarded.

`fs::{SealFlags, fcntl_get_seals}` is the bounded read-only seal companion.
Direct `fcntl(F_GET_SEALS)` retains all observed Linux seal bits, including
future bits. An allow-sealing memfd begins unsealed, a plain memfd carries
`F_SEAL_SEAL`, and ineligible descriptors retain direct `EINVAL`.

`fs::fcntl_add_seals` is the matching bounded mutator over direct
`fcntl(F_ADD_SEALS)`. It supplies seal bits as the kernel's immediate integer
argument, retains `EPERM` for unsealable or already-finally-sealed memfds, and
leaves the public C `fcntl` ABI in its separate status-flag capability.

`process::{Flock, FlockType, FlockOffsetType, fcntl_getlk}` is the read-only
`fcntl(F_GETLK)` conflict query. It validates the private AArch64 flock record
before exposing `None` for `F_UNLCK` or a typed first conflicting lock. Because
fcntl locks are process-associated, a forked child—not the owning process—is
required to observe the parent's lock; mutation stays separate.

`net::{NetworkU16, NetworkU32}` models network byte order as owned
big-endian bytes, completing the value-only byte-order capability without a C
ABI, static buffer, allocator, or errno state. Interface address-list enumeration and
legacy address/hostname helpers remain deferred.

`net::{socket, Shutdown}` adds direct typed socket construction and directional
shutdown. The construction boundary owns its successful descriptor, uses a
closed `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flag set, and represents non-default
protocols as Rustix-shaped nonzero raw words forwarded bit-for-bit to Linux's
C-`int` slot. Address encoding, connection,
options, ancillary data, and multi-message operations remain separate deferred
capabilities.

`net::{set_socket_reuseaddr, socket_reuseaddr}` adds the bounded
`SOL_SOCKET/SO_REUSEADDR` option as a Rust `bool` over private four-byte kernel
storage. It validates the returned length and preserves kernel errors while
exposing no arbitrary C level/name/pointer/length interface; broader socket
options remain separate capabilities.

`net::sockopt::socket_type` follows Rustix's exact module path for the bounded
`SOL_SOCKET/SO_TYPE` query. The private four-byte kernel result becomes the
existing raw-preserving `SocketType`, so a newer type is not discarded and a
non-socket descriptor retains direct `ENOTSOCK`; broad socket options remain
separate capabilities.

`net::sockopt::socket_protocol` follows the matching Rustix path for
`SOL_SOCKET/SO_PROTOCOL`. Its direct private result maps zero to `None` and
otherwise preserves the matching raw `Protocol` word; non-socket descriptors
retain `ENOTSOCK` and the broad option surface remains separate.

`net::sockopt::socket_cookie` follows the fixed-width Rustix
`SOL_SOCKET/SO_COOKIE` observation. Its private eight-byte storage returns the
kernel's opaque `u64` unchanged; repeated reads on a live socket are stable,
but no stronger lifetime or global-uniqueness claim is made. Non-socket
descriptors retain direct `ENOTSOCK`.

`net::sockopt::socket_domain` follows Rustix's typed `SOL_SOCKET/SO_DOMAIN`
query through fixed private storage. Its signed kernel result is checked before
conversion to the closed `AddressFamily` type; unrepresentable values return
`OPNOTSUPP`, and non-socket descriptors retain direct `ENOTSOCK`.

`net::sockopt::socket_acceptconn` follows Rustix's fixed
`SOL_SOCKET/SO_ACCEPTCONN` observation through private four-byte storage. It
returns whether a borrowed stream socket is listening; the native tests cover
the false-to-true transition around `listen`, while non-socket descriptors
retain `ENOTSOCK`.

`net::sockopt::{set_socket_oobinline, socket_oobinline}` follows Rustix's
fixed `SOL_SOCKET/SO_OOBINLINE` boolean setting through private four-byte
storage. Its tests cover the false-to-true-to-false flag transition and direct
`ENOTSOCK`; urgent-data I/O behavior and broad socket options remain outside
this bounded capability.

`net::sockopt::{set_socket_broadcast, socket_broadcast}` follows Rustix's
fixed `SOL_SOCKET/SO_BROADCAST` boolean setting through private four-byte
storage. The contract tests only the false-to-true-to-false socket flag and
direct `ENOTSOCK`; broadcast packet transmission is not implied.

`pipe::{SpliceFlags, tee}` duplicates up to the requested count from one pipe
to another through direct syscall 77 without consuming the source. It exposes
a short copied count and retains all `SPLICE_F_*` bits for kernel validation;
offset-bearing `splice` and raw-memory `vmsplice` remain separate contracts.

`pipe::fcntl_getpipe_size` reports a pipe's current shared kernel capacity
through direct `fcntl(F_GETPIPE_SZ)` syscall 25. It borrows the descriptor,
preserves kernel errors for non-pipe descriptors, and deliberately makes no
capacity-stability claim when another actor can resize the pipe; `F_SETPIPE_SZ`
remains a separate mutating contract.

`net::{sendmsg, recvmsg, MsgIoSliceMut, RecvMsg}` adds connected, vectored
message I/O without publishing a C `msghdr`. It intentionally excludes message
addresses, ancillary control data, and multi-message calls. Receive results
preserve the full `MSG_TRUNC` byte count and flags while exposing only the
initialized prefixes of caller-owned `MaybeUninit` segments.

`net::{IpAddress, SocketAddress, connect}` makes the allocation-free IPv4/IPv6
endpoint representation available directly to no-std socket code, while
`resolver::{IpAddress, SocketAddress}` remains a source-compatible re-export.
`connect` writes the exact stack Linux address records, rejects invalid IPv4
scope use rather than discarding it, and forwards IPv6 scope IDs; binding,
listening, received-address, and option operations remain separate work.

`net::{bind, getsockname}` shares that same exact IPv4/IPv6 representation for
local-address lifecycle. The decoder validates the returned sockaddr length and
returns `AFNOSUPPORT` for address families not represented by `SocketAddress`;
listening, peers, options, ancillary data, and received-message APIs remain
separate capabilities.

`net::getpeername` reuses that strict endpoint decoder for connected peers.
It preserves `NOTCONN` for an unconnected socket and returns `AFNOSUPPORT`
instead of exposing an opaque record for other address families.

`net::{listen, accept, accept_with, accept4, acceptfrom, acceptfrom_with}`
adds direct server-socket lifecycle over a borrowed listener. Accepted
descriptors transfer unique ownership; `accept4` applies a closed atomic
`CLOEXEC`/`NONBLOCK` flag set; and address-returning forms reuse strict
IPv4/IPv6 decoding, closing a just-created descriptor if another family is
rejected as `AFNOSUPPORT`. Socket options, message addresses, ancillary data,
and multi-message operations remain separate capabilities.

`net::{sendto, recvfrom}` adds addressed IPv4/IPv6 datagrams on the same
borrowed-descriptor boundary. The endpoint codec rejects invalid IPv4 scope
use, received source records decode strictly, and `recvfrom` retains the
existing `Buffer` initialization contract plus `MSG_TRUNC`'s full datagram
length. Unsupported source families return `AFNOSUPPORT` without exposing an
opaque sockaddr.

`net::netdevice::{for_each_link_name, InterfaceNameIndex, if_nameindex,
if_freenameindex}` now covers musl's `if_nameindex` and `if_freenameindex`
semantics. The allocation-free callback yields owned fixed interface-index/name
records, while the alloc-gated exact path performs both
`RTM_GETLINK(AF_UNSPEC)` and `RTM_GETADDR(AF_INET)` netlink dumps, extracts
`IFLA_IFNAME` and `IFA_LABEL`, and suppresses duplicate `(index, name)` pairs
like musl. Its allocation-free no-std AArch64 probe exercises the callback;
the companion alloc-feature probe supplies a private fixed allocator and
exercises the complete owned list. Both require direct `socket`, `sendto`,
`recvfrom`, and `close` syscalls and reject C enumeration/address helpers and
TLS `errno`; the callback also rejects Rust allocator symbols, while the full
list proves it needs no public C allocator. `if_freenameindex` consumes the
owned vector through Rust drop.

`net::netdevice::InterfaceAddresses` is a separate alloc-gated direct
`RTM_GETLINK`/`RTM_GETADDR` snapshot. It owns raw interface names, link-layer
addresses through musl's 24-byte extension, flags, stats bytes, typed
IPv4/IPv6 addresses and masks, broadcast/destination values, and precise
link-local IPv6 scope. It replaces C `struct ifaddrs` and `freeifaddrs` with
Rust-owned records; malformed framing is `BADMSG`, allocation failure is
`NOBUFS`, and unknown families/records without a matching link are skipped.
Its no-std AArch64 probe uses only direct `socket`, `sendto`, `recvfrom`, and
`close` syscalls and rejects C enumeration/address helpers and TLS errno.

`net::ethers` is intentionally different: musl 1.2.6 leaves the three C
ethers host/database calls as stubs, while crabc's mature C facade deliberately
implements real lookup. The Rust API is therefore an explicit crabc extension,
not parity: callers supply bounded bytes to parse raw hostname records or an
alloc-gated, source-ordered `EthernetDatabase`; it never opens
`/etc/ethers` implicitly. Its allocation is fallible, and lookup is first
ASCII-case-insensitive match. `IN6ADDR_ANY`, `IN6ADDR_LOOPBACK`, and
`Ipv6Constants` are documented aliases for the complete standard
`Ipv6Addr::{UNSPECIFIED, LOCALHOST}` values, not a C global-object identity
claim.

---

# 87. Milestone 11 — scope-aligned core-runtime refinement

M11 is complete for its selected three-seam Linux/AArch64 refinement slice.
It remains a refinement milestone, not an architecture expansion and not a
mandate to recreate a broad portable Unix layer. The current ledger has 218
groups: 159 verified, 16 deferred, and 43 documented. The remaining explicit
deferrals stay classified for a later, separately selected milestone:

1. Core runtime: calendar/timezone handling from system zoneinfo, process
   control/credentials/environment/signals, pthread/C11, dynamic loading, and
   filesystem extensions.
2. Core resolver profile: `/etc/hosts`, `/etc/resolv.conf`, A/AAAA/CNAME,
   search, UDP with TCP fallback, retries/failover, and conventional netdb
   files—without NSS, DNSSEC, DoH/DoT, mDNS, or IDNA framework behavior.
3. Useful POSIX: regex/glob compatibility, IPC, PTY/session work, user
   databases, and tightly bounded kernel administration.
4. C ABI profile: C-only stdio, locale, wide text, and long-double families
   remain rigorously documented/tested at the ABI boundary when relevant;
   they do not automatically become `crabc-rs` APIs.

The initial M11 vertical slice makes three narrowly owned contracts explicit.
`timezone::{TimeZone, UtcOffset, OffsetInfo}` parses caller-supplied POSIX TZ
or TZif v1/v2/v3 bytes into immutable rules and answers a supplied UTC instant
without reading `TZ`, the current clock, libc timezone globals, or TLS errno.
It validates TZif structure and continuation rules but does not bundle tzdata,
open a system path, implement local calendar/format/parse APIs, or change
clock state.

The existing explicit `resolver::ResolverConfig` now has a tested transport
contract: each configured server gets one monotonic nonblocking-UDP deadline;
short/malformed/wrong-ID packets are ignored; an accepted truncated response
retries the same request over framed nonblocking TCP; partial I/O and
`SO_ERROR` drive that one deadline; and failed servers advance in configured
order. This does not claim `/etc/resolv.conf` discovery, `/etc/hosts`, search
policy, CNAME completion, or the broad netdb/C resolver ABI.

`dl::{Library, LoaderError, LoaderText, Symbol, AddressInfo}` now exposes the
basic dynamic-loader handle contract through only the private versioned
runtime table. A library owns its reference and is deliberately neither
`Send` nor `Sync`; an unsafe typed symbol is lifetime-bound to that library;
diagnostics and address metadata are copied into Rust-owned data. The
loader-backed C fixture proves distinct DSO constructor/destructor and
reference-count transitions, while the AArch64 static verifier rejects public
`dl*` and TLS-errno linkage. `dlinfo` and `dl_iterate_phdr` deliberately
remain separate deferred introspection contracts.

The completion gate is `./scripts/dev.sh crabc-rs`: it runs the six timezone
rule tests, four deterministic resolver-transport tests, loader-backed C
fixture, no-std builds, the complete ledger check, static boundary verifiers,
and the retained Rustix source-comparison suite in the Dockerized
Linux/AArch64 environment.

Any representative-application proof follows a completed scoped slice. It
must demonstrate the named Linux/AArch64 contract without treating the absence
of `rustix`, `libc`, or `nix` as a portability claim.

---

# 88. Milestone 12 — LTO proof

Reuse the crabc whole-program optimization work.

Build representative applications where:

```text
application
    ↓
crabc-rs
    ↓
shared crabc implementation
    ↓
syscall
```

is visible through LLVM optimization.

Inspect assembly.

Demonstrate that the native facade does not introduce avoidable abstraction boundaries.

Where stock Rust `std` also links against crabc, investigate:

```text
application
+
crabc-rs
+
std
+
crabc
```

under fat LTO.

Do not merely state that this ought to optimize.

Provide evidence.

---

# Acceptance checks

At project completion, the following must hold.

## Platform

```text
crabc: Linux AArch64, little-endian, Linux >= 5.10
crabc-rs: the Linux backend is required; macOS/AArch64 via libSystem is optional
```

No x86_64/RISC-V/non-Linux burden for `crabc`; no speculative portability
framework. An optional macOS `crabc-rs` backend remains a separate concern.

## Architecture

```text
libc facade
      ↘
       shared Rust implementation
      ↗
crabc-rs facade
```

No crabc-rs → public C ABI/errno round-trip for syscall-like APIs. Any explicit
private singleton-runtime boundary is versioned, owned, tested, and listed.

## Rustix

```text
no rustix production dependency; focused normal dependencies are reviewed
dev/test oracle: yes
relevant Linux/AArch64 parity: documented and verified
```

## Safety

```text
I/O-safe descriptors
provenance-preserving APIs
typed errors
typed flags
RAII resources
unsafe only where necessary
```

## Coverage

```text
100% crabc public symbol accounting
100% semantic capability accounting
0 unclassified capabilities
```

These are ledger obligations, not a requirement to expose a mechanical Rust
wrapper for every C symbol. Deliberate profile limitations and ABI-only
machinery must be explicitly classified.

## Dependencies

Extremely small normal dependency graph with focused, individually justified
dependencies.

No framework creep.

## Performance

Equivalent syscall-like APIs competitive with rustix's linux_raw backend.

## libc

Existing C compatibility suite remains green.

## Documentation

Every public unsafe operation has a precise safety contract.

Every excluded/subsumed crabc capability has a rationale.

The documented profile includes the Linux 5.10 MSRV, C/POSIX/C.UTF-8 locale
baseline, limited charset set, no NSS/plugin ecosystem, system-supplied
timezone data, no gettext framework, no internal cryptography, allocator
boundary, and no async/process/security-policy frameworks.

---

# Final report

At the end, produce a rigorous engineering report.

Include:

## Architecture

Show the final crate graph and shared implementation boundary.

## Dependency graph

Show:

```text
cargo tree -p crabc-rs -e normal
```

## Rustix parity

Report:

```text
relevant APIs
verified APIs
source-compatible APIs
intentional divergences
deferred extensions
```

## Crabc coverage

Report counts for:

```text
native-safe
native-unsafe
native-higher-level
rust-subsumed
scope-exception
abi-only
internal-runtime
unclassified
```

List every remaining non-native classification.

## Safety

Summarize public unsafe APIs and their rationale.

## Tests

Report:

```text
dual-backend differential cases
source-compatibility fixtures
ported rustix regressions
crabc libc regression status
stress/fuzz results
```

## Performance

Compare representative:

```text
rustix
crabc-rs
```

for:

```text
assembly
.text
runtime
clean build/check
dependency count
```

## Real programs

List application fixtures successfully using crabc-rs without rustix/libc/nix.

## LTO

Show representative optimized call paths and any observed elimination/inlining across crabc-rs/crabc boundaries.

## Remaining limitations

Only concrete limitations.

No vague "future work."

---

# Working strategy for the coding agent

This is a long-running engineering project.

Do not spend the entire run producing architecture documents.

Begin by:

```text
1. inspect repository
2. pin rustix reference
3. build inventories
4. establish shared implementation seam
5. prove one vertical slice end-to-end
6. continue subsystem-by-subsystem
```

Maintain a machine-generated backlog from:

```text
rustix parity gaps
crabc capability gaps
differential failures
API compatibility failures
safety issues
assembly regressions
```

Work continuously until the defined maturity gates are exhausted.

When an API's correct Rust shape is unclear:

> stop and design the ownership/safety model before implementing it.

When behavior is unclear:

> improve the test oracle rather than guessing.

When a subsystem becomes testable:

> close its known correctness gaps before expanding its breadth.

Do not optimize for number of wrappers written.

Optimize for:

```text
verified semantic coverage
safety
thinness
independent correctness evidence
```

---

# Final engineering principle

`crabc-rs` should begin life as:

> **the crabc-backed answer to rustix on Linux AArch64**

but it should not end there.

The mature shape is:

```text
                           Rust application
                                  │
                              crabc-rs
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
        syscall-like         POSIX/runtime        loader/runtime
        operations           facilities           facilities
             │                    │                    │
             └────────────────────┴────────────────────┘
                                  │
                         shared crabc Rust
                              implementation
                                  │
                           Linux AArch64
```

Rustix provides the first excellent design and correctness oracle.

Crabc provides the larger semantic universe.

The end goal is not merely:

```text
rustix, implemented differently
```

It is:

> **a tiny, idiomatic, safety-conscious Rust interface to the useful in-scope Unix substrate implemented by crabc, with rustix-level quality for the overlap and semantic accounting for the rest.**

Keep the facade thin.

Keep the implementation shared.

Keep the safety claims honest.

Keep the dependency graph austere.

And make every claim of coverage mechanically provable.
