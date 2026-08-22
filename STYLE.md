# Coding style for `crabc` / `crabc-rs`

Write this project as **modern low-level Rust**, not as C transliterated into Rust and not as framework-heavy application code.

The project should take deliberate advantage of the Rust features that now make libc/runtime/system-interface work cleanly expressible.

The priorities, in order, are:

```text
correctness
explicit invariants
soundness
simple generated code
auditability
small dependency surface
performance
brevity
```

Do not optimize for cleverness.

---

## 1. Prefer modern Rust primitives over C idioms

Do not mechanically translate patterns such as:

```rust
let p = x as usize as *mut T;
```

when Rust has a more precise operation.

Prefer modern facilities such as:

```text
Strict Provenance pointer APIs
NonNull
MaybeUninit
addr_of!/addr_of_mut!
offset_of!
slice::from_raw_parts
CStr
core::ffi types
OwnedFd/BorrowedFd
typed enums/newtypes
Result
```

The implementation should communicate what the machine operation actually means.

---

## 2. Use Strict Provenance deliberately

Avoid integer-pointer round trips unless the semantics genuinely require exposing an address.

Prefer:

```rust
ptr.addr()
ptr.with_addr(addr)
ptr.map_addr(...)
```

and appropriate provenance-aware constructors.

Use exposed-provenance APIs only when interacting with interfaces where an address genuinely leaves the Rust abstract machine, such as:

```text
kernel ABI
ELF relocation
auxv
mmap addresses
dynamic loader state
startup stack
```

Do not scatter:

```rust
as usize
as *mut T
```

through the implementation.

Centralize unavoidable provenance transitions and document why they are valid.

---

## 3. Distinguish addresses from pointers

An integer containing an address is not automatically a dereferenceable Rust pointer.

Maintain this conceptual separation rigorously:

```text
address arithmetic
    ≠
pointer provenance
    ≠
object validity
    ≠
reference validity
```

Loader and VM code must be especially disciplined here.

Do arithmetic as integers when it is genuinely address arithmetic.

Create pointers only at the boundary where a valid pointer is required.

Create references only when Rust reference invariants are actually satisfied.

---

## 4. Prefer raw pointers over fake references

Do not create `&T` or `&mut T` merely because it is ergonomically convenient.

If memory:

```text
may be uninitialized
may alias
may be concurrently modified
may have C ownership
may disappear
may not satisfy Rust validity rules
```

keep it as:

```text
*const T
*mut T
NonNull<T>
MaybeUninit<T>
```

until a reference is genuinely justified.

A raw pointer is often the more honest type in libc/runtime code.

---

## 5. Use `MaybeUninit` correctly

Never initialize kernel/FFI output structures with fake zero values merely to satisfy Rust initialization rules unless zero initialization is itself valid and intended.

Prefer:

```rust
let mut out = MaybeUninit::<T>::uninit();
```

then pass:

```rust
out.as_mut_ptr()
```

and call:

```rust
assume_init()
```

only after the operation guarantees initialization.

For arrays or partially initialized structures, track exactly how much initialization occurred.

Do not casually use `mem::zeroed()`.

---

## 6. Use `addr_of!` and `offset_of!`

For ABI/layout-sensitive code, prefer compiler-supported layout operations.

Use:

```rust
core::mem::offset_of!
```

rather than handwritten offset calculations.

Use:

```rust
addr_of!
addr_of_mut!
```

when accessing fields through raw pointers without transiently creating references.

This is particularly important for:

```text
pthread structures
signal frames
ELF structures
FILE internals
startup data
C ABI structs
intrusive data structures
```

---

## 7. Use `CStr` as the native C-string abstraction

Do not pass C strings internally as:

```text
*const c_char + repeated strlen
```

unless required by the ABI boundary.

Convert once, then operate on:

```rust
&CStr
```

where sound.

For `crabc-rs`, expose borrowed path/string abstractions which avoid allocation where possible.

Do not require UTF-8 for Unix paths.

---

## 8. Keep C ABI translation at the outermost layer

Structure libc entry points like:

```text
extern "C" ABI
    ↓
argument validation/conversion
    ↓
typed Rust implementation
    ↓
Result<T, Errno>
    ↓
C return + errno translation
```

The semantic implementation should not internally think in terms of:

```text
-1
NULL
thread-local errno
void *
integer flags everywhere
```

unless those are genuinely part of the operation.

Example shape:

```rust
fn openat_impl(
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: OpenFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno>
```

with the libc facade translating from/to C.

---

## 9. `crabc-rs` must bypass the C facade

Never implement:

```text
crabc-rs
    ↓
extern "C" crabc symbol
    ↓
errno
    ↓
Rust Result
```

Both interfaces must reach shared Rust internals directly:

```text
                   implementation
                  /              \
             libc ABI          crabc-rs
```

This preserves:

```text
ownership
provenance
inlining
direct error propagation
LTO visibility
```

---

## 10. Prefer `Result<T, Errno>` internally

Kernel-facing and runtime operations should naturally return something equivalent to:

```rust
Result<T, Errno>
```

Do not set thread-local errno deep inside implementation code.

Only the libc ABI facade should normally do:

```text
Errno
→ errno TLS
→ sentinel C return
```

This makes the implementation usable directly by `crabc-rs`.

---

## 11. Encode ownership in types

Resources should not float around as anonymous integers.

Prefer:

```text
OwnedFd
BorrowedFd<'a>
Pid
Uid
Gid
Signal
```

and similarly narrow newtypes.

Internally, raw numeric values are fine at syscall boundaries.

At safe API boundaries, ownership semantics should be visible.

Do not accidentally make:

```rust
RawFd
```

mean both borrowed and owned.

---

## 12. Prefer RAII for resources

Use Drop-based ownership for things with clear lifecycle:

```text
file descriptors
mappings where an owned mapping abstraction makes sense
dynamic library handles
regex state
glob results
resolver results
pthread handles where semantically appropriate
locale/conversion handles
```

Do not force RAII where POSIX semantics fundamentally conflict with Rust ownership.

But use it aggressively where it makes illegal states harder to express.

---

## 13. Use typed flags

Prefer:

```rust
bitflags!
```

or equivalent compact newtypes over raw `c_int` masks.

`bitflags` is an acceptable dependency.

Preserve unknown kernel bits where forward compatibility requires it.

Do not use closed Rust enums for open-ended bitfields.

---

## 14. Use enums only for closed domains

A Rust enum is appropriate when the domain is genuinely closed.

It is inappropriate when the kernel may return unknown future values.

Prefer:

```rust
#[repr(transparent)]
struct Something(u32);
```

plus associated constants when future unknown values must remain representable.

Avoid undefined behavior caused by transmuting arbitrary OS integers into Rust enums.

---

## 15. Use stable inline assembly where appropriate

Use:

```rust
core::arch::asm!
```

for tiny architecture-specific operations that genuinely require assembly.

Do not hide assembly in external `.S` files merely out of habit.

Assembly should be:

```text
small
localized
well-commented
tested
```

Use Rust for surrounding logic.

---

## 16. Use naked functions for actual naked-function problems

For:

```text
_start
thread startup trampolines
context/ABI shims
signal trampolines
special syscall veneers
```

prefer modern:

```rust
#[unsafe(naked)]
```

with:

```rust
naked_asm!
```

where that accurately expresses the requirement.

Do not use naked functions for ordinary optimization.

A naked function should exist because **compiler-generated prologue/epilogue is semantically invalid**, not because handwritten assembly looks appealing.

---

## 17. Prefer Rust symbols over giant `global_asm!` blobs

When a low-level routine can now be represented as an actual Rust function using:

```text
naked functions
inline asm
normal attributes
```

prefer that.

Benefits include:

```text
normal symbol ownership
generics where useful
cfg
documentation
visibility
linkage attributes
easier testing
```

Keep `global_asm!` for cases which genuinely require translation-unit-level assembly.

---

## 18. Centralize architecture-specific assembly

Linux AArch64 knowledge should live in obvious modules such as:

```text
arch/aarch64/syscall.rs
arch/aarch64/start.rs
arch/aarch64/signal.rs
arch/aarch64/tls.rs
```

Do not scatter:

```text
svc #0
register assignments
AArch64 constants
special register access
```

through generic modules.

Do not create a hypothetical multi-architecture trait hierarchy.

One concrete AArch64 implementation is enough.

---

## 19. Make syscall wrappers extremely thin

For simple syscalls, optimized output should approach:

```text
argument setup
svc #0
error handling
return
```

Avoid:

```text
allocation
trait objects
function-pointer dispatch
C ABI round trips
formatting
global registries
```

Inspect representative optimized assembly periodically.

---

## 20. Prefer const evaluation

Use `const fn` and compile-time computation when it:

```text
removes runtime work
expresses invariants
simplifies tables
```

but do not contort code purely to make everything const.

Good uses include:

```text
flag masks
layout helpers
syscall tables
small lookup tables
ABI constants
```

---

## 21. Prefer slices over pointer+length pairs internally

At an ABI boundary:

```text
ptr + len
```

is unavoidable.

Inside Rust, validate once and convert to:

```rust
&[u8]
&mut [u8]
```

when the reference invariants can honestly be guaranteed.

Otherwise retain raw pointer + length.

Do not repeatedly reconstruct and revalidate the same buffer.

---

## 22. Use checked conversions at ABI boundaries

Never casually write:

```rust
len as c_int
```

for attacker- or caller-controlled sizes.

Use:

```rust
try_into()
```

or explicit bound checks.

Pay special attention to:

```text
usize
isize
ssize_t
size_t
socklen_t
off_t
pid_t
int
u32
```

Conversions should communicate whether truncation is possible.

---

## 23. Prefer explicit overflow semantics

For address arithmetic, file offsets, sizes and layout calculations choose deliberately between:

```text
checked_*
wrapping_*
saturating_*
```

Do not rely on release-mode overflow behavior accidentally.

Loader arithmetic should usually be checked until ELF validation establishes safe ranges.

---

## 24. Keep unsafe blocks tiny

Prefer:

```rust
let value = unsafe {
    // SAFETY: precise invariant.
    ...
};
```

over:

```rust
unsafe {
    // 80 lines
}
```

Unsafe should wrap the exact operation requiring it.

Keep safe validation outside the block.

---

## 25. Every meaningful unsafe block gets a real safety comment

Explain:

```text
what invariant is required
why it holds here
who owns the memory/resource
why aliasing is valid
why lifetime is sufficient
why initialization is guaranteed
```

Do not write:

```rust
// SAFETY: safe.
```

or:

```rust
// SAFETY: caller guarantees this.
```

unless the exact caller obligation is already concretely documented.

---

## 26. Public unsafe APIs need explicit `# Safety`

Every public unsafe function must document its caller obligations precisely.

Especially:

```text
fork
signal handlers
raw mmap manipulation
mprotect
ioctl
dynamic symbols
raw pthread operations
C variadics
```

Do not hide difficult safety contracts behind safe APIs.

---

## 27. Avoid `transmute`

Treat:

```rust
mem::transmute
```

as exceptional.

Prefer:

```text
pointer casts
from_ne_bytes
transparent wrappers
MaybeUninit
explicit conversion
```

where possible.

If transmute is genuinely the clearest correct operation, document:

```text
size
alignment
validity
lifetime
representation
```

assumptions.

---

## 28. Avoid `mem::zeroed`

Use zeroed memory only when every-zero-bit-pattern is known to be valid for the type and the external ABI expects it.

Prefer:

```rust
MaybeUninit::zeroed()
```

only when justified.

Never zero Rust enums/references/non-null types.

---

## 29. Avoid `static mut`

Use:

```text
atomics
UnsafeCell
Once-like internal primitives
proper TLS
```

depending on the semantics.

If true mutable process-global state is required by libc, encapsulate it behind a type which owns the synchronization invariants.

Do not expose naked `static mut` access throughout the codebase.

---

## 30. Use atomics deliberately

Choose ordering based on the actual synchronization proof.

Do not default everything to:

```rust
SeqCst
```

just to feel safe.

Do not use `Relaxed` merely for speed.

For each nontrivial atomic protocol, document the happens-before reasoning.

Use focused tools/crates such as `atomic-wait` when they cleanly solve the primitive rather than reimplementing futex wait/wake machinery unnecessarily.

---

## 31. Do not wrap pthread internals in Rust `Mutex`

Crabc is implementing pthread/runtime primitives.

Do not accidentally depend on higher-level Rust synchronization whose implementation may itself depend on libc/pthreads.

At this layer, build on:

```text
atomics
futex
kernel primitives
small internal synchronization structures
```

as appropriate.

Avoid dependency cycles, conceptual and literal.

---

## 32. Keep panics out of libc control flow

Externally reachable libc/runtime paths must not use:

```text
unwrap
expect
panic!
unreachable!
todo!
```

as normal error handling.

Use:

```text
errno
Result
explicit process abort only where the ABI truly requires fatal failure
```

A panic crossing C ABI is not an error model.

---

## 33. Use assertions for invariants, not user errors

Internal:

```rust
debug_assert!(...)
```

is useful for impossible states already proven by validation.

Do not turn malformed caller/kernel data into assertion failures.

Return the appropriate error.

---

## 34. Treat kernel output as untrusted input

Even when the kernel is trusted for security purposes, parsing code should not rely on undocumented assumptions.

Validate:

```text
lengths
counts
offsets
alignment
NUL termination
address ranges
```

before constructing stronger Rust types.

This is especially important for:

```text
directory entries
ancillary messages
netlink-like structures
ELF data
auxv
```

---

## 35. Prefer iterators when they improve safety without hiding costs

Good:

```rust
DirEntries<'a>
AncillaryMessages<'a>
```

where an iterator naturally represents variable-length records.

Bad:

```text
an elaborate iterator framework
```

around a trivial syscall.

Keep iterator state compact and allocation-free where practical.

---

## 36. Avoid trait abstraction without multiple real implementations

Do not invent:

```rust
trait Architecture
trait SyscallBackend
trait ResolverBackend
trait LocaleProvider
```

for hypothetical futures.

Use concrete modules.

Generalize only when a second real implementation exposes meaningful duplication.

Tests may use abstraction for differential backends.

Production code should not.

---

## 37. Use cfg at compile time

Platform differences should look like:

```rust
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod darwin;
```

not runtime backend enums or function tables.

The OS and architecture are known during compilation.

Exploit that fact.

---

## 38. Keep common code actually common

Do not move platform-specific machinery into generic code merely to reduce apparent duplication.

A few duplicated lines are cheaper than a bad abstraction.

Share:

```text
types
validation
algorithms
ownership wrappers
```

when semantics align.

Keep OS mechanisms separate.

---

## 39. `crabc` should remain `no_std`

Core runtime implementation should use:

```rust
#![no_std]
```

with `alloc` only where genuinely necessary.

Do not accidentally pull `std` into libc/runtime internals.

Testing utilities may use `std`.

---

## 40. `crabc-rs` should preserve `no_std` fundamentals

Low-level interfaces such as:

```text
fds
mmap
sockets
signals
time
polling
```

should not require `std`.

Provide `std` interoperability behind a feature where valuable:

```text
std::os::fd
Path
OsStr
File
```

Do not make `std` mandatory merely for convenience.

---

## 41. Focused dependencies are encouraged

Do not hand-roll difficult, mature low-level kernels merely to claim zero dependencies.

Good candidates include:

```text
bitflags
memchr
simdutf8
atomic-wait
```

when they actually solve the problem.

Prefer:

```text
pure Rust
small
focused
no_std
fuzzed
low/no transitive graph
```

dependencies.

Do not import frameworks.

---

## 42. Use `memchr` instead of inventing byte-search SIMD

For common byte scanning:

```text
NUL
newline
delimiter
```

prefer a mature focused implementation where it fits the exact semantics.

Do not maintain custom NEON/string-search code without a concrete advantage.

---

## 43. Use `simdutf8` where UTF-8 validation is actually the problem

For large-buffer UTF-8 validation, a mature AArch64 SIMD implementation is preferable to bespoke NEON.

But do not replace POSIX byte semantics with UTF-8 semantics.

The project supports:

```text
C/POSIX byte-oriented behavior
C.UTF-8 Unicode behavior
```

as separate concepts.

SIMD optimization must not blur that distinction.

---

## 44. Scalar semantics remain the oracle

Whenever crabc owns both:

```text
scalar implementation
optimized implementation
```

maintain differential tests between them.

The optimized implementation must be replaceable without changing semantics.

This applies to:

```text
string scanning
UTF-8
memory operations
numeric kernels
```

where applicable.

---

## 45. Prefer mature algorithms in difficult domains

For:

```text
libm
resolver behavior
stdio parsing
printf/scanf
ELF lookup
POSIX regex
```

prefer proven upstream algorithms over clever redesign.

Rust should improve:

```text
safety
structure
types
testing
optimization opportunity
```

not force algorithmic novelty where decades of edge cases exist.

---

## 46. Use explicit representation attributes

Where ABI matters:

```rust
#[repr(C)]
#[repr(transparent)]
```

should be deliberate.

Do not add `repr(C)` to ordinary internal structs “just in case.”

Do not depend on Rust layout when interfacing with C/kernel ABI.

Verify:

```text
size
alignment
offset
```

through tests.

---

## 47. Keep C ABI types separate from ergonomic Rust types

It is fine to have:

```rust
#[repr(C)]
struct CTimespec { ... }
```

at the boundary and:

```rust
struct Timespec { ... }
```

for public Rust semantics if the distinction actually improves correctness.

Do not leak awkward ABI layouts throughout the entire implementation.

Likewise, avoid unnecessary conversion layers when the ABI representation is already ideal.

Use judgment.

---

## 48. Prefer transparent newtypes over aliases

Instead of:

```rust
type Pid = i32;
```

prefer:

```rust
#[repr(transparent)]
pub struct Pid(i32);
```

where type confusion is plausible.

Use aliases when distinct identity adds no value.

Do not create hundreds of ceremonial wrapper types.

---

## 49. Make invalid states difficult to construct

Examples:

```text
OwnedFd cannot contain -1
borrowed fd cannot be dropped/closed
SignalSet maintains valid storage
dynamic Symbol cannot outlive Library
prepared exec cannot reference temporary argv storage
```

Use Rust's type system where it materially strengthens invariants.

Do not make type-state machinery an end unto itself.

---

## 50. Avoid elaborate generic programming

This project should be readable by someone familiar with:

```text
Rust
POSIX
Linux ABI
ELF
AArch64
```

without requiring advanced type-level programming.

Avoid:

```text
deep trait bounds
HRTB puzzles
typestate explosion
macro-generated abstractions
generic container machinery
```

unless they solve a concrete safety problem significantly better.

At this layer, explicit code is often best.

---

## 51. Avoid proc macros

Do not introduce proc-macro infrastructure for convenience.

Prefer:

```text
functions
declarative macros
const tables
small code generation scripts where objectively useful
```

If ABI surface generation needs mechanical tooling, keep generation deterministic and inspectable.

---

## 52. Use macros only for genuine repetition

Good macro:

```text
generate a family of near-identical syscall veneers
```

Bad macro:

```text
hide normal control flow or construct a private language
```

Generated code should remain understandable.

Do not obscure safety invariants behind macros.

---

## 53. Keep functions small around unsafe/state transitions

Not every function needs to be tiny.

But the following deserve focused boundaries:

```text
FFI conversion
pointer validation
resource acquisition
resource release
syscall invocation
ELF relocation
pthread state transition
signal handling
```

Large high-level algorithms may remain coherent functions where splitting would obscure the logic.

---

## 54. Optimize for reviewable diffs

When porting a musl algorithm:

1. preserve its structure initially;
2. get differential tests green;
3. make Rust-specific simplifications separately;
4. optimize separately.

Do not combine:

```text
port
semantic rewrite
API redesign
optimization
```

in one change.

This makes regressions much easier to isolate.

---

## 55. Record provenance for translated algorithms

When code derives substantially from:

```text
musl
Rustix tests
Apple libc
other implementations
```

record:

```text
upstream revision
source file
relevant function
license/provenance
```

Do not make future maintainers reverse-engineer where subtle algorithms came from.

---

## 56. Test at the abstraction boundary

For every safe wrapper, test both:

```text
intended success semantics
unsafe/internal failure edges
```

Examples:

```text
ownership transfer
partial initialization
short reads
EINTR
fd reuse
overflow
invalid flags
partial resolver results
```

A safe API is only as good as its unhappy path.

---

## 57. Use Miri where it is actually useful

Miri is excellent for:

```text
pure pointer helpers
intrusive structures
parsers
ownership abstractions
format machinery
internal collections
```

Do not attempt to prove syscall-heavy libc wholesale under Miri.

Extract pure components and test those aggressively.

---

## 58. Fuzz parsers and variable-length formats

Particularly:

```text
ELF
DNS
printf/scanf format strings
regex
glob
tzfile
directory/ancillary record parsing where possible
UTF-8
locale/text conversion
```

Every fuzz-discovered bug becomes a regression input.

---

## 59. Keep optimized assembly observable

Maintain small representative fixtures and inspect with:

```text
llvm-objdump
llvm-nm
cargo asm or equivalent
```

for hot paths.

Examples:

```text
getpid
read
write
openat
clock_gettime
memchr-like scan
UTF-8 validation
```

Modern Rust abstractions are desirable only if they compile away appropriately in these paths.

---

## 60. Do not optimize based on folklore

Measure before introducing:

```text
unsafe
assembly
SIMD
manual unrolling
branchless tricks
custom containers
```

The project values small code and predictable optimization.

LLVM on AArch64 is already very capable.

---

## 61. Preserve whole-program LTO potential

Keep shared implementation functions visible to LLVM where practical.

Avoid artificial boundaries such as:

```text
internal extern "C"
dynamic dispatch
opaque native libraries
function-pointer routing
```

between:

```text
crabc-rs
std
crabc internals
```

unless required.

This does not mean forcing `#[inline(always)]` everywhere.

Use normal inline heuristics first.

---

## 62. Use `#[inline]` sparingly and intentionally

Good candidates:

```text
tiny conversion wrappers
error decoding
fd accessors
bit manipulation
syscall veneers
```

Avoid spraying:

```rust
#[inline(always)]
```

through large code.

Let LTO and LLVM make normal decisions unless measurements show otherwise.

---

## 63. Avoid copying buffers merely to obtain convenient ownership

Prefer:

```text
borrowing
caller-provided buffers
iterators
small stack state
```

when the OS API naturally supports them.

Allocate when ownership materially improves safety/usability.

Do not make “zero allocation” a religion for APIs that naturally return variable-sized owned data.

---

## 64. Make allocation obvious

Functions that allocate significantly should be recognizable from their API or documentation.

For performance-sensitive low-level functions, avoid hidden allocation.

Particularly:

```text
fd operations
syscalls
polling
socket send/recv
time
signals
```

must generally remain allocation-free.

---

## 65. Preserve the modern scope constraints

Coding style must reinforce the project scope:

```text
Linux >= 5.10
AArch64 first
no NSS
C/POSIX + C.UTF-8 locales
no legacy charset museum
no bundled tzdata
no crypto implementation
no custom allocator research
no async runtime
no framework growth
```

Do not add architectural complexity for unsupported legacy cases.

---

# Style summary

The desired code should feel like:

```text
modern Rust
+
direct Unix semantics
+
small unsafe kernels
+
excellent types
+
clear ABI boundaries
+
boring mature algorithms
+
LLVM-visible implementation
```

not:

```text
C code mechanically rewritten into Rust
```

and not:

```text
an abstraction-heavy Rust framework around Unix
```

The project should make aggressive use of the parts of modern Rust that now exist specifically to make low-level code honest:

```text
Strict Provenance
MaybeUninit
NonNull
addr_of!
offset_of!
CStr/core::ffi
OwnedFd/BorrowedFd
asm!
naked_asm!
naked functions
const evaluation
typed flags
RAII
Result
cfg-selected backends
```

Use these features because they let the source encode the actual machine/runtime invariants more precisely.

Do not use them merely because they are new.

The final test for every low-level implementation should be:

> **Is this the simplest modern Rust expression of the actual Unix/ABI operation, with the unsafe assumptions visible and the generated machine code unsurprising?**

If yes, keep it.

If the Rust abstraction hides the operating-system semantics, simplify it.

If C-style code obscures Rust's safety model, modernize it.

If a tiny mature pure-Rust crate solves a difficult primitive better than we reasonably can, use it.

Keep the runtime low-level, explicit, and exceptionally boring to audit.
