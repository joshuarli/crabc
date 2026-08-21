# Implement `crabc-rs`: a complete idiomatic Rust interface to crabc

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

---

# Ground truth and assumptions

The target is **Linux/AArch64**. macOS/AArch64 is only a development host;
all target builds and runtime measurements run in the native Linux/AArch64
Docker laboratory.

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

---

# Explicitly out of scope

Do not implement:

```text
x86_64
riscv64
macOS
other Unix platforms
Windows
```

Do not create cross-platform abstractions in anticipation of them.

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

---

# Mission

Build an API which initially reaches practical parity with the relevant Linux/AArch64 surface of:

```text
bytecodealliance/rustix
```

and then continues substantially beyond rustix until:

> **Every meaningful capability implemented by mature crabc has an idiomatic Rust representation or an explicitly justified Rust-native equivalent.**

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
locale/text/iconv
        ↓
pattern APIs
        ↓
user/group databases
        ↓
math/complex/fenv
        ↓
other crabc capabilities
        ↓
──── 100% CRABC CAPABILITY COVERAGE ────
```

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

# 8. Keep normal dependencies extremely small

This is foundational systems infrastructure.

The normal production graph is permitted one third-party package:

```toml
bitflags = { version = "2.4.0", default-features = false }
```

Use it for typed bit-pattern APIs where it improves correctness and readability.
Do not add further normal dependencies merely for convenience; each must have a
documented architectural reason and corresponding dependency-graph review.

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

as an acceptance gate: it must show the shared crabc implementation and
`bitflags`, but no other third-party normal dependency.

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

# PHASE II — COMPLETE CRABC CAPABILITY COVERAGE

# 32. Generate a complete crabc capability inventory

Start from the measured crabc ABI and implementation inventory. The initial
machine-readable input is all 1,669 current candidate dynamic exports, with
the 1,647-symbol pinned-musl public surface and 22 candidate-only exports
preserved as distinct provenance classes. Add the checked loader/dlfcn runtime
inventory so capabilities not adequately described by a single libc symbol are
also visible.

Every exported public libc symbol must be assigned to a semantic capability group.

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

Zero unclassified symbols is a hard completion gate.

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
basic allocation
printf-style formatting
```

Every use of this classification requires a written rationale.

### `abi-only`

The symbol exists solely for C ABI/runtime compatibility and has no meaningful native operation users should invoke.

Use this category very sparingly.

### `internal-runtime`

Loader/startup/compiler runtime plumbing that is not an application-facing capability.

Again, justify it.

---

# 34. 100% coverage does not mean 1400 silly functions

Do not create APIs such as:

```rust
crabc_rs::cstring::strcpy(...)
crabc_rs::memory::malloc(...)
crabc_rs::stdio::printf(...)
```

merely to increase a counter if Rust already has a superior abstraction.

The completion criterion is:

> **Every semantic capability of crabc is either accessible through a good Rust API or explicitly proven to be subsumed by an existing Rust-native mechanism.**

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

6. locale/wchar/iconv

7. regex/fnmatch/glob/wordexp

8. passwd/group/user database

9. math/complex/fenv

10. miscellaneous POSIX facilities

11. remaining capability-manifest gaps
```

Adjust based on actual mature crabc contents.

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

No public Internet should be required by tests.

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

# 43. Locale, wchar and iconv

Where crabc contains meaningful runtime machinery, expose owned types such as:

```text
Locale
Converter
MultibyteState
```

rather than C global handles.

Avoid pretending locale mutation is harmless process-global state.

Use RAII where locale handles have lifetime.

Represent conversion buffers with slices rather than raw pointer-to-pointer interfaces.

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

malloc
→ Rust allocator / Box / Vec

printf
→ format_args!/Write
```

Do not classify something as subsumed merely because implementing it is inconvenient.

---

# 72. Preserve allocator scope decision

Do not expose a new safe:

```rust
malloc/free
```

API.

Rust-native allocation should use Rust allocation facilities.

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
third-party normal dependency; do not turn that exception into a general
crate-splitting or dependency-growth policy.

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

bitflags is the only third-party normal dependency

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

---

# 86. Milestone 10 — 100% native capability coverage

This is the final semantic gate.

The project may claim:

> crabc-rs provides complete native Rust coverage of crabc

only when:

1. every meaningful underlying capability is reachable through an idiomatic Rust interface;
2. inherently unsafe operations have explicit unsafe interfaces;
3. operations better represented by existing Rust primitives are documented as such;
4. raw C ABI exposure is not being used to hide missing native API design;
5. the complete machine-readable coverage inventory is green.

---

# 87. Milestone 11 — production proof

Build representative applications that use:

```text
filesystem
networking
polling
mmap
process execution
fork/exec
signals
resolver
dynamic loading
thread primitives
```

without:

```text
rustix
libc
nix
```

as direct dependencies.

Demonstrate that crabc-rs can realistically be the application's Unix systems substrate.

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
Linux AArch64 only
```

No x86_64/RISC-V burden.

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
normal dependency: bitflags only
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

## Dependencies

Extremely small normal dependency graph.

No framework creep.

## Performance

Equivalent syscall-like APIs competitive with rustix's linux_raw backend.

## libc

Existing C compatibility suite remains green.

## Documentation

Every public unsafe operation has a precise safety contract.

Every excluded/subsumed crabc capability has a rationale.

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

> **a tiny, idiomatic, safety-conscious Rust interface to essentially the entire useful Unix userspace substrate already implemented by crabc, with rustix-level quality for the overlap and substantially greater coverage beyond it.**

Keep the facade thin.

Keep the implementation shared.

Keep the safety claims honest.

Keep the dependency graph austere.

And make every claim of coverage mechanically provable.
