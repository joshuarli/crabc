# Implement `crabc-rs`: a complete idiomatic Rust interface to crabc

You are extending an already mature macos aarch64 `crabc` implementation with a new public crate:

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

# Assumptions

Assume the preceding AArch64 crabc maturity project is complete.

In particular, assume:

* Linux AArch64 only;
* crabc is already behaviorally mature against the chosen musl baseline;
* libc ABI parity is established;
* libc-test is effectively green;
* pthread/TLS/signals/process behavior is mature;
* resolver/networking behavior is mature;
* stdio/text/math behavior is mature;
* the crabc dynamic linker is mature;
* representative unmodified Alpine AArch64 binaries work;
* stock Rust `std` compatibility has been demonstrated;
* the Docker/Alpine ARM64 compatibility laboratory already exists.

Do not reopen those foundational projects unless `crabc-rs` work discovers a real bug.

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
Linux AArch64
```

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
   ↓
shared crabc implementation
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

# 4. Do not call crabc's C ABI from crabc-rs

Also non-negotiable.

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
* no C ABI transition;
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

# 7. Make `crabc-rs` `no_std`-capable

The native facade should preserve crabc's low-level usefulness.

Design it so:

```text
cargo check -p crabc-rs --no-default-features
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

Provide optional `std` integrations where useful.

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

Target:

```text
0 normal third-party dependencies
```

where practical.

A tiny dependency such as `bitflags` is acceptable only if it clearly improves correctness/API quality enough to justify itself.

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

as an acceptance gate.

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

Start from the mature crabc ABI and implementation inventory.

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

Every public crabc symbol must appear in this accounting.

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

Crabc contains a mature dynamic loader/dlfcn implementation.

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
* `std` should primarily add interoperability/conveniences.

Do not overengineer feature topology when all code has zero external dependencies.

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

# 56. Explicitly prove there is no C ABI round-trip

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

The only additional crate justified by this project is the internal shared implementation layer if needed.

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

shared implementation strategy proven

representative operation does not traverse C ABI

rustix API manifest exists

dual-backend test harness works

crabc capability inventory exists
```

Do not start mass implementation before this is green.

---

# 77. Milestone 1 — foundational rustix slice

Verify:

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

---

# 78. Milestone 2 — filesystem

Reach verified coverage for the relevant rustix filesystem surface.

Include:

```text
open/openat/openat2 where supported
stat family
directory iteration
links
rename
mkdir/unlink
permissions
timestamps
xattrs where applicable
advisory/locking operations
```

based on actual rustix and crabc inventories.

Port historical directory-iteration regression cases.

Do not advance merely because APIs compile.

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

---

# 81. Milestone 5 — primary rustix parity

Completion requires:

```text
all relevant Linux/AArch64 rustix APIs classified

all in-scope overlap implemented

all implemented overlap verified

source-compatibility fixtures green where claimed

differential suite green

no production rustix dependency

no C ABI round-trip
```

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

---

# 83. Milestone 7 — runtime facilities

Implement native access to:

```text
pthread capabilities
resolver/netdb
dynamic loading
```

with strong ownership/safety semantics.

---

# 84. Milestone 8 — libc semantic facilities

Implement or classify:

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

No crabc-rs → C ABI round-trip.

## Rustix

```text
normal dependency: none
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
