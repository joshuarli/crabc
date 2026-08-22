# Historical runtime delivery plan

> **Archive, not a current backlog.** This is the chronological M0–M12
> delivery record preserved for rationale and evidence provenance. It contains
> contemporaneous "next", "remaining", and incomplete measurements which are
> not current commitments. Use [`TODO.md`](../../TODO.md) for active work,
> [`SCOPE.md`](../../SCOPE.md) for governing scope, and
> [`COMPATIBILITY.md`](../../COMPATIBILITY.md) for measured status.

> **Scope reset — 2026-08-21.** [`SCOPE.md`](../../SCOPE.md) and
> [`COMPATIBILITY-PROFILE.md`](../../COMPATIBILITY-PROFILE.md) are the governing
> scope. Historical sections below retain completed evidence and provenance,
> but any future-looking item that conflicts with this reset is superseded.
> The project will not become “glibc rewritten in Rust,” nor will
> `crabc-rs` become a mechanical C-wrapper layer.

Take the existing `crabc` project from an early Rust libc/runtime
implementation to a **small, auditable, behaviorally correct modern Unix
runtime for Linux/AArch64**. Musl compatibility remains the evidence-led C ABI
target where ordinary C or Rust `std` software needs it; it is not an automatic
mandate to implement every historical subsystem.

Repository:

```text
https://github.com/mengzhuo/crabc
```

The user develops exclusively on Apple Silicon macOS.

The development model is therefore:

```text
macOS arm64
    │
  Docker
    │
Linux arm64 / Alpine
    │
   crabc
```

No Linux workstation should be required.

No x86_64 emulation belongs in the primary development loop.

---

# Core objective

The end state is:

```text
ordinary C software          ordinary Rust std software
        │                              │
        └──────── musl ABI ────────────┘
                       │
                     crabc
               ┌───────┴───────┐
             libc            ld.so
               └───────┬───────┘
                       │
               Linux AArch64
                       │
                     kernel
```

with:

* stock Rust `std`, not a fork;
* no musl implementation in the resulting runtime;
* a Rust `no_std` libc;
* a Rust dynamic linker;
* compatibility with ordinary musl-linked AArch64 software within the explicit
  profile;
* enough behavioral evidence that this is a credible modern Unix substrate
  rather than merely an ABI-shaped prototype.

The eventual optimization upside is:

```text
application
+
dependencies
+
Rust std
+
crabc
     │
 LLVM LTO
     │
Linux ELF
```

but that is **the reward for compatibility**, not the first milestone.

---

# Active platform and kernel baseline

## Linux AArch64 little-endian only

Everything must first be proven on:

```text
aarch64-unknown-linux-musl
```

or the equivalent Linux AArch64 ABI. The kernel MSRV is **Linux 5.10**. Use
clean mechanisms available there, do not add pre-5.10 fallbacks, and record an
interface needing a newer kernel before relying on it.

This includes:

* ABI/symbol accounting rather than unbounded symbol implementation;
* ABI parity;
* libc-test;
* behavioral differential tests;
* POSIX conformance;
* pthread/TLS/signals;
* resolver/networking;
* stdio/math;
* dynamic linker;
* real Alpine binaries;
* stock Rust `std`;
* LTO experiments.

There is **no active second-architecture phase**. x86_64 is deferred
indefinitely and requires an explicit user scope decision, not merely a passed
AArch64 gate. Do not write portability abstractions in anticipation of it.

## Not in scope

Do not maintain active x86_64, RISC-V, 32-bit, big-endian, or non-Linux
support. Existing harmless code may remain, but do not advertise, test, or
preserve it as a supported path.

Existing RISC-V code may remain temporarily if harmless, but:

* do not advertise it;
* do not test it;
* do not spend engineering effort preserving it;
* do not design abstractions around it.

## Scope classification and deliberate limits

Every backlog item must be classified as **core Unix runtime**, **useful
POSIX/runtime**, **C ABI compatibility machinery**, **Rust-subsumed**, or
**deliberately unsupported legacy** before implementation. This plan continues
to use vertical slices for the first two classes and honest accounting for the
last three.

The following are deliberate profile boundaries, not accidental failures:

* locales only `C`, `POSIX`, and `C.UTF-8`; UTF-8-native Rust text and only the
  documented mechanical Unicode encodings for C compatibility;
* no general locale database, NSS/plugin stack, bundled tzdata, gettext
  framework, IDNA policy, DNSSEC/DoH/DoT/mDNS framework, async runtime,
  process-management framework, security-policy framework, or portability
  facade;
* system files and zoneinfo are parsed rather than duplicated as data sets;
* POSIX regex/glob/fnmatch are compatibility facilities, not a Rust regex
  replacement;
* no hand-rolled crypto. Entropy is core OS functionality; crypto-heavy
  compatibility uses a proven focused Rust dependency or is an explicit limit.

## Allocator scope exception

`crabc` does not implement or tune its own malloc allocator. Allocator
internals are explicitly out of scope for every milestone; use mimalloc as the
allocator implementation for now. The public allocation API and observable C
contract (`malloc`, `free`, `realloc`, alignment, overflow, and failure
behavior) remain in scope and must continue to be tested at that boundary.

This is the allocator exception to native `crabc-rs` coverage. It does not
relax observable C allocation ABI behavior. Other work is governed by the
classification/profile above rather than an assumption that every musl facility
is automatically in scope.

---

# The most important sequencing rule

## Compatibility authority

musl libc is the golden compatibility example for crabc. Follow musl's public
interfaces, ABI, and behavior unless the POSIX/C specification requires a
more precise interpretation. Do not use glibc declarations, extensions, or
semantics as an implementation fallback or an oracle; a host-glibc result is
never compatibility evidence. This includes behavior inferred from glibc:
when musl and glibc differ, preserve the musl contract rather than bridging
the difference with a glibc compatibility path.

Do **not** begin with:

> implement all missing musl symbols.

Do **not** optimize for:

```text
351 / 1420
700 / 1420
1000 / 1420
1420 / 1420
```

as the primary progress metric.

That produces broad but shallow implementations and creates enormous correctness debt.

Instead, mature crabc through **vertical compatibility slices**.

The progression for a subsystem is:

```text
inventory
   ↓
surface implemented
   ↓
ABI verified
   ↓
focused tests
   ↓
libc-test green
   ↓
musl differential green
   ↓
standards/stress tests where applicable
   ↓
VERIFIED
```

Do this repeatedly.

The project should gradually expand a verified compatibility frontier rather than first creating a huge unverified surface.

---

# Compatibility states

Track every expected musl interface using three distinct states:

```text
exported
implemented
verified
```

Definitions:

## Exported

The ABI symbol/header surface exists.

This does **not** imply correct behavior.

## Implemented

The function performs its intended operation rather than being a stub.

## Verified

The implementation has sufficient evidence appropriate to the subsystem, generally including:

* ABI/layout verification where relevant;
* focused unit/integration tests;
* relevant libc-test cases;
* musl differential behavior;
* standards/stress/real-world testing where appropriate.

Only `verified` should count toward maturity.

---

# Compatibility ratchet

Compatibility must be monotonic.

CI should make regressions obvious.

Track at minimum:

```text
missing expected symbols
unimplemented exported symbols

libc-test:
    PASS
    FAIL
    BUILDERROR
    TIMEOUT

ABI mismatches

differential:
    PASS
    FAIL

POSIX-suite failures

loader failures

real-program corpus failures
```

Normal changes must not silently cause:

```text
verified → implemented
implemented → missing
PASS → FAIL
PASS → BUILDERROR
ABI match → mismatch
real program passes → fails
```

A public symbol generally should never need to disappear merely because its implementation requires rewriting.

The implementation may change substantially.

The compatibility surface should ratchet forward.

---

# Stage 0 — build the compatibility laboratory first

Before large-scale libc implementation work, establish the environment and measurement system.

This is the first real deliverable.

## Docker environment

Use a pinned ARM64 Alpine base, initially:

```text
alpine:3.24.1
```

Run natively on Apple Silicon:

```text
linux/arm64
```

Provide a small interface such as:

```sh
./scripts/dev.sh shell
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh symbols
./scripts/dev.sh libc-test
./scripts/dev.sh differential
./scripts/dev.sh compat
./scripts/dev.sh dashboard
./scripts/dev.sh loader-inventory
./scripts/dev.sh corpus
./scripts/dev.sh bench
./scripts/dev.sh mature
```

The macOS host should need essentially:

```text
git
docker
```

Everything else belongs inside Docker.

## Toolchain

Install only required packages, likely including:

```text
build-base
musl-dev
linux-headers
clang
lld
llvm
binutils
git
python3
strace
bash
file
```

Keep the image minimal.

Pin a dated Rust nightly with:

```text
profile = minimal
rust-src
```

and `llvm-tools-preview` if required later.

Record:

```text
rustc -Vv
clang --version
ld.lld --version
uname -a
```

in reports.

---

# Stage 0.1 — pin all external oracles

Primary compatibility baseline:

```text
musl 1.2.6
```

Create a machine-readable manifest such as:

```text
compat/upstreams.toml
```

containing exact revisions for:

```text
musl
libc-test
os-test
libc-bench
```

and any supplemental POSIX suite.

Do not allow ordinary builds to float against upstream `master`.

Once compatibility is mature, a non-gating tracking job against newer musl may be added separately.

---

# Stage 0.2 — generate exact AArch64 ABI inventory

Build the pinned AArch64 musl baseline.

Generate manifests mechanically using:

```text
readelf
llvm-readelf
nm
llvm-nm
```

Track separately:

```text
libc.so dynamic ABI
libc.a static-link surface
ld.so/runtime ABI
public headers
```

For dynamic symbols capture at least:

```text
name
FUNC / OBJECT / TLS
weak / strong
binding
visibility
size where relevant
```

Store this under something like:

```text
compat/abi/musl-1.2.6/aarch64/
```

This manifest, not README counts, defines symbol parity.

---

# Stage 0.3 — make libc-test machine-readable

The existing libc-test harness is valuable.

Improve it before massively expanding implementation.

For every test retain:

```text
PASS
FAIL
BUILDERROR
TIMEOUT
SKIP (only when the pinned musl oracle proves an environment limitation)
```

and machine-readable failure causes where possible.

Critically, classify BUILDERRORs caused by missing libc symbols.

Generate:

```text
missing symbol
    ↓
tests blocked by it
```

For example:

```text
getaddrinfo
    blocks 17 tests

pthread_mutex_lock
    blocks 12 tests

foo_obscure_extension
    blocks 1 test
```

This becomes the basis for implementation prioritization.

---

# Stage 0.4 — implement the differential musl runner early

Do not wait for global symbol parity.

Create:

```text
compat/differential/
```

with a runner capable of executing equivalent workloads against:

```text
REFERENCE:
    musl 1.2.6

CANDIDATE:
    crabc
```

Compare observable behavior:

```text
exit status
stdout
stderr
errno
signal termination
wait status
filesystem effects
metadata
socket behavior
environment effects
child-process behavior
```

Normalize only genuinely nondeterministic data such as:

```text
PID
ASLR addresses
temporary paths
variable timestamps
```

Do not normalize semantic differences away.

Where technically feasible, compile a C caller once against musl headers and link/run equivalent artifacts against both runtimes.

Keep separate tests for crabc-header source compatibility.

---

# Stage 1 — establish the foundational vertical slice

Before trying to unlock every libc-test case, make the core runtime unusually solid.

Prioritize foundational facilities approximately in this order:

```text
syscall/error substrate
memory/string
allocator
basic file descriptors
filesystem basics
time/clocks
environment/process basics
basic pthread
TLS / errno
basic synchronization
basic stdio
```

Exact ordering should follow actual dependencies and test-unlock analysis.

For each subsystem, complete the full vertical slice.

Do not merely implement its symbols.

---

# Vertical-slice procedure

For every subsystem:

## Step A — inventory

Determine:

```text
expected musl symbols
expected headers/declarations
public ABI-bearing types/constants
libc-test cases
other subsystems depending on it
```

## Step B — implement surface

Implement missing symbols faithfully.

Do not add empty parity stubs.

Do not count functions that simply:

```text
panic
abort
return ENOSYS
return dummy success
```

unless that is genuinely the specified behavior.

## Step C — verify ABI

Check:

```text
symbol kind
binding
visibility
sizeof
alignof
offsetof
constants
calling convention
TLS/object/function classification
```

where relevant.

## Step D — focused tests

Add small targeted tests for important boundary cases.

## Step E — libc-test

Run all relevant functional/regression/API/math tests.

## Step F — musl differential

Add differential cases for semantics not sufficiently captured by libc-test.

## Step G — subsystem-specific stress or standards tests

Examples:

```text
pthread → race/cancellation stress
signals → process-isolated signal torture
resolver → deterministic local DNS server
stdio → pipes/files/PTY/memory streams
loader → synthetic DSOs
```

## Step H — mark verified

Only now move the subsystem's interfaces into `verified`.

Then continue outward.

---

# Stage 2 — maximize test unlock, not raw symbol count

Once the foundation is solid, use BUILDERROR analysis to prioritize missing symbols.

Compute something conceptually like:

```text
priority =
    number_of_tests_unblocked
    × foundational_value
    ÷ implementation_cost
```

The exact formula need not be literal.

The engineering principle matters:

> implement symbols that unlock large amounts of correctness evidence before obscure symbols that only improve the headline count.

Continue vertical closure as soon as a subsystem becomes testable.

Do not leave a newly unlocked subsystem with known behavioral failures merely to chase more missing symbols elsewhere.

---

# First major milestone

The first milestone is **not** 100% symbol parity.

It is:

> **Eliminate broad test blindness.**

Completion criteria:

```text
100% of expected musl AArch64 symbols inventoried

compatibility ratchet operational

foundational subsystems verified

libc-test BUILDERRORs caused by missing core/foundational symbols
reduced close to zero

most libc-test categories now meaningfully executable

remaining missing symbols concentrated in advanced or isolated subsystems
rather than preventing broad behavioral testing
```

At this point, the project has enough breadth to make correctness work productive across most of libc.

---

# Stage 3 — expand the verified frontier subsystem-by-subsystem

Continue through the remaining libc surface.

Likely broad areas include:

```text
string/memory
ctype
stdlib/conversion
filesystem/stat/dirent
unistd/fcntl
time/timers
mmap/IPC

process
fork
exec
wait
spawn

signals

pthread
mutex/rwlock/condvar
barrier/semaphore
cancellation
TLS

sockets
netdb
resolver

stdio
printf
scanf

locale
wchar/wctype
iconv

regex
glob
fnmatch
wordexp

pwd/grp

math
complex math
fenv

dlfcn

misc POSIX/Linux interfaces
```

Do not treat this list as a fixed implementation order.

Let:

```text
dependency structure
test-unlock value
compatibility failures
real-program blockers
```

determine sequencing.

---

# Stage 4 — only now push to complete symbol parity

Once:

```text
most libc-test cases compile
the foundational runtime is verified
the majority of major subsystems have active correctness coverage
```

make:

> **100% implemented AArch64 musl symbol parity**

an explicit milestone.

At this point parity is valuable because each newly implemented interface can immediately be tested inside a mature harness.

Target:

```text
100% expected exports accounted for

0 fake stubs

correct ELF symbol kinds/bindings

all public headers accounted for
```

Do not confuse this milestone with full compatibility.

---

# Stage 5 — complete ABI parity

After surface parity, close every remaining ABI gap.

Generate C probes for all public ABI-bearing definitions.

Compare:

```text
sizeof
_Alignof
offsetof
constants
enums
macro values where ABI-significant
```

between pinned musl and crabc headers.

Derive coverage from public headers rather than a hand-written shortlist.

AArch64-specific areas deserve special attention:

```text
pthread types
signals/ucontext
termios
socket structures
stat
TLS
long double
fenv
complex ABI
```

No test-only ABI-changing compiler flags may remain.

---

# Stage 6 — drive libc-test fully green

Promote libc-test to a hard gate.

Target:

```text
functional:
    0 unexpected FAIL
    0 unexpected BUILDERROR
    0 unexpected TIMEOUT

regression:
    same

api:
    same

math:
    same
```

If a case genuinely does not apply, maintain a narrow allowlist containing:

```text
test
reason
spec/upstream reference
date
```

No blanket ignored directories.

No vague "known failures."

---

# Stage 7 — standards conformance

Integrate a pinned modern `os-test`.

Prioritize:

```text
include
namespace
basic
io
limits
malloc
process
pty
signal
stdio
udp/networking
```

For the `malloc` entry, test the public allocation contract against the
mimalloc-backed implementation; do not treat allocator algorithms or
performance tuning as crabc work.

Run it against both musl and crabc where useful.

Supplement with portions of Open POSIX tests only where they add meaningful coverage.

Musl remains the compatibility oracle.

POSIX/C specifications remain the correctness oracle when musl behavior is:

```text
implementation-specific
undefined
unspecified
or buggy
```

Do not blindly reproduce undefined behavior merely to match musl.

---

# Stage 8 — mature `ld.so` as its own vertical track

The dynamic linker should run in parallel once enough libc exists to support it.

Do not wait until every libc function is complete.

But do not allow loader work to derail foundational libc closure either.

Create:

```text
compat/ldso/
```

with synthetic AArch64 ELF/DSO fixtures.

Test actual AArch64 mechanisms emitted by:

```text
clang
LLVM lld
GNU tools
musl
Alpine packages
```

Use `readelf` to prove fixtures exercise intended relocations.

---

# Loader vertical slices

Work mechanism-by-mechanism:

```text
basic PIE loading
    ↓ verified

DT_NEEDED graph
    ↓ verified

symbol lookup
    ↓ verified

constructors/destructors
    ↓ verified

TLS
    ↓ verified

RPATH/RUNPATH
    ↓ verified

LD_LIBRARY_PATH
    ↓ verified

LD_PRELOAD
    ↓ verified

dlopen/dlsym/dlclose
    ↓ verified

late-loaded TLS
    ↓ verified

real Alpine DSO graph
    ↓ verified
```

Do not simply implement all relocation constants first and debug later.

---

# Loader test requirements

Cover, where applicable:

```text
DT_NEEDED
weak/strong resolution
visibility
symbol lookup order
PIE
constructors/destructors
init/fini arrays
initial TLS
dynamic TLS
RPATH
RUNPATH
LD_LIBRARY_PATH
LD_PRELOAD
dlopen
dlclose
dlsym
dlerror
dladdr
dl_iterate_phdr
hash formats
AArch64 relocation classes
RELR if encountered
RELRO
auxv
vDSO
ASLR
```

Derive requirements from actual AArch64 binaries.

Do not implement architecture-generic abstractions preemptively.

---

# Stage 9 — concurrency/TLS vertical slices

Threading must mature gradually, not as one final blob.

Example progression:

```text
pthread_create/join
    ↓ verified

thread-local errno
    ↓ verified

mutex
    ↓ verified

condition variable
    ↓ verified

rwlock
    ↓ verified

once
    ↓ verified

TLS keys/destructors
    ↓ verified

timed waits
    ↓ verified

cancellation
    ↓ verified

fork-with-threads
    ↓ verified
```

Stress every slice at high iteration counts.

---

# Cancellation deserves its own gate

Explicitly test:

```text
deferred cancellation
cancellation points
cleanup handlers
syscall cancellation
stdio cancellation
join semantics
resource cleanup
```

Do not claim pthread maturity while cancellation remains largely unverified.

---

# Stage 10 — signal/process vertical slices

Build process-isolated tests for:

```text
sigaction
signal masks
pending signals
SA_RESTART
SA_SIGINFO
alternate signal stack
nested signals
per-thread masks
pthread_kill
sigwait*
timers/signals
fork
exec
wait
pthread_atfork
```

Then test:

```text
multithreaded process
    ↓
atfork handlers
    ↓
fork
    ↓
child-safe operation
    ↓
exec
```

Exercise interactions with:

```text
allocator
stdio
locks
TLS
signal state
```

---

# Stage 11 — resolver/networking vertical slices

Never rely on public Internet or public DNS.

Build a deterministic local DNS fixture supporting:

```text
A
AAAA
CNAME
NXDOMAIN
NODATA
UDP truncation
TCP fallback
multiple servers
timeouts
search domains
```

Then verify:

```text
/etc/hosts
    ↓
getaddrinfo basics
    ↓
IPv4/IPv6
    ↓
CNAME
    ↓
search domains
    ↓
fallback/failure behavior
    ↓
other netdb APIs
```

Compare against musl.

---

# Loopback networking

Test locally:

```text
TCP
UDP
IPv4
IPv6
socketpair
sendmsg/recvmsg
ancillary data
poll/select
epoll
shutdown
nonblocking behavior
partial I/O
timeouts
EINTR
```

No host-network dependency.

---

# Stage 12 — stdio/text/math vertical slices

## stdio

Progress through:

```text
basic FILE
buffering
flush
seek/tell
EOF/error
ungetc
pipes
memory streams
locking
concurrency
printf
scanf
wide streams
```

## text/locale

Progress through:

```text
UTF-8 basics
multibyte state
wchar
wctype
locale_t
setlocale
iconv
musl-supported collation semantics
```

## math

Use libc-test heavily.

Pay special attention to:

```text
NaN
infinity
signed zero
subnormals
rounding
exceptions
AArch64 long double
complex math
```

Prefer faithful musl translations over speculative rewrites.

---

# Stage 13 — fuzz high-value parsers/state machines

Fuzz:

```text
ELF loader
printf
scanf
strtod
regex
fnmatch
glob
DNS parser
locale/text conversion
```

For valid structured inputs:

```text
compare crabc with musl
```

For malformed/undefined inputs require:

```text
no memory corruption
no UB
no infinite loop
no runaway allocation
no uncontrolled panic across FFI
predictable failure
```

Run malformed ELF cases in isolated processes with resource limits.

Retain every discovered crash as a regression case.

---

# Stage 14 — real unmodified Alpine binaries

Once major libc/loader slices are verified, begin end-to-end compatibility.

Use ordinary AArch64 Alpine package binaries.

Do not rebuild them against crabc.

Run:

```text
same application binary
same non-libc DSOs
same Linux kernel
```

under:

```text
Alpine musl loader/libc
vs
crabc loader/libc
```

Do not overwrite the container's real system loader.

Use an isolated rootfs or explicit candidate loader invocation.

---

# Alpine corpus progression

## Tier A

```text
true
echo
cat
mkdir
cp
mv
rm
printf
env
sleep
```

## Tier B

Representative utilities such as:

```text
grep
sed
file
tar
gzip
zstd
sqlite3
```

## Tier C

Networking/crypto:

```text
curl
openssl
ssh -V
```

using local fixtures only.

## Tier D

Complex runtimes/applications:

```text
git
python3
```

or similarly demanding programs.

These serve as integration tests for:

```text
loader
threads
signals
stdio
filesystem
resolver
dlopen
TLS modules
large DSO graphs
```

---

# Stage 15 — stock Rust `std`

Do not fork Rust `std`.

The target is:

```text
normal Rust source
     ↓
stock std
     ↓
musl ABI
     ↓
crabc
```

Use nightly and `-Z build-std` where needed to control linkage.

Test normal Rust applications exercising:

```text
allocation
Vec/String
filesystem
directories
environment
time
TCP
UDP
DNS
threads
Mutex
Condvar
process spawn
pipes
stdio
```

Then build at least one nontrivial pure-Rust application with no crabc-specific source changes.

A failure here is a crabc compatibility problem unless proven otherwise.

---

# Stage 16 — LTO experiment

Only after compatibility is strong, investigate the distinctive opportunity:

```text
application
+
dependencies
+
stock Rust std
+
crabc
        │
     LLVM
        │
     fat LTO
```

Compare:

```text
A. musl static

B. crabc static

C. crabc + build-std

D. crabc + build-std + fat/linker-plugin LTO
```

Use an appropriate configuration around:

```text
opt-level = 3
lto = fat
codegen-units = 1
panic = abort
```

plus whatever bitcode/linker-plugin configuration is actually required.

Do not assume static linking alone creates whole-program LTO.

---

# LTO evidence

Construct controlled paths:

```text
Rust application
→ std
→ libc wrapper
→ crabc implementation
→ syscall
```

Inspect using:

```text
llvm-nm
llvm-readelf
llvm-objdump
```

Look for actual evidence that:

```text
wrapper calls disappear
helpers inline
compatibility branches disappear
constants propagate
unused libc code is removed
```

Measure:

```text
.text
stripped ELF size
retained symbols
startup
RSS
instruction/cycle counts where practical
syscalls
```

A modest result is acceptable.

An unmeasured claim is not.

---

# Implementation prioritization algorithm

At every point, choose the next work item based on:

```text
1. foundation dependency importance
2. number of blocked tests unlocked
3. number of real programs blocked
4. correctness/security risk
5. implementation cost
```

Do not prioritize:

```text
alphabetical order
easy symbol-count inflation
README percentage
```

Examples:

A missing string primitive blocking 30 libc-test cases should usually precede an obscure function blocking none.

A TLS bug blocking all threading correctness should precede another easy batch of unrelated functions.

A loader bug blocking every real Alpine binary should receive high priority even if symbol parity is incomplete elsewhere.

---

# Explicit subsystem completeness rule

Once a subsystem has sufficient surface for meaningful testing:

> stop increasing its breadth until known correctness failures in that subsystem are closed.

Example:

Bad:

```text
pthread:
    40 symbols exported
    17 known failures

agent:
    adds 30 more pthread symbols
```

Good:

```text
pthread:
    enough surface to exercise mutex/condvar tests
    ↓
fix those semantics
    ↓
mark them verified
    ↓
expand to rwlock/barrier/cancellation
```

Keep exported, implemented, and verified frontiers reasonably close.

---

# Dynamic linker parallelism rule

`ld.so` can progress in parallel with libc, but only as independent vertical slices.

Do not attempt complete loader parity in one burst.

Do not allow loader work to block basic libc correctness.

Do prioritize loader work once it becomes the bottleneck for real-program testing.

---

# Test harness as product

When implementation semantics are unclear, improve the harness before guessing.

Examples:

```text
unclear resolver behavior
→ build deterministic DNS oracle

unclear symbol precedence
→ build synthetic DSO graph

unclear cancellation behavior
→ build cancellation stress fixture

unclear struct ABI
→ generate C layout probe

unclear real-world requirement
→ inspect Alpine binary / run differential case
```

The compatibility laboratory is a first-class project deliverable.

---

# Reproducibility rules

All tests execute inside Docker.

No public Internet during actual compatibility tests.

No public DNS.

No dependence on macOS filesystem or process semantics.

After upstream sources/images are fetched, ordinary correctness tests should be capable of running offline.

Every report records:

```text
crabc git SHA
musl revision
libc-test revision
os-test revision
Alpine image/version
Rust nightly
clang/lld versions
Linux kernel
target = aarch64
```

---

# Unsafe-code discipline

A libc necessarily contains unsafe Rust.

Create:

```text
SAFETY.md
```

Document major invariants around:

```text
raw pointers
C strings
allocator
threads
TLS
signals
ELF relocation
FILE internals
startup/auxv
syscalls
```

Every substantial unsafe block needs a meaningful safety comment.

Use Miri selectively for internal pure-ish components:

```text
parsers
lookup structures
containers
relocation calculations
format parsers
```

Do not pretend syscall-heavy libc can simply be validated wholesale under Miri.

---

# Error-handling discipline

Exported libc functions must not use Rust panics as normal error handling.

Audit for:

```text
unwrap
expect
panic
unreachable
```

in externally reachable paths.

Use proper libc semantics:

```text
errno
error return values
defined failure behavior
```

where applicable.

Test resource exhaustion:

```text
EMFILE
EAGAIN
partial I/O
EINTR
thread creation failure
pipe/socket exhaustion
small buffers
allocation failure where practical
```

---

# Production dependency discipline

Keep libc/ldso:

```text
#![no_std]
```

Prefer:

```text
core
alloc only where required
direct syscalls
small internal modules
```

Do not add large Rust dependencies to solve libc functionality.

Every production dependency needs explicit justification.

Testing infrastructure may use normal tooling freely.

---

# AArch64-first architecture discipline

Centralize real AArch64-specific knowledge:

```text
syscall ABI
ELF relocations
TLS ABI
signal context
startup stack
auxv
floating-point ABI
futex/atomic details
```

Do not scatter magic constants.

Do **not** create a generic `Architecture` abstraction for hypothetical
ports. Linux/AArch64 is the whole active target. If a later explicit scope
decision opens another architecture, begin with the existing evidence harness
and only generalize duplication proven by that work.

---

# Machine-readable compatibility dashboard

Maintain:

```text
COMPATIBILITY.md
```

generated from structured reports where possible.

It should show:

```text
baseline:
    musl 1.2.6

architecture:
    AArch64

symbols:
    expected
    exported
    implemented
    verified

ABI:
    matches
    mismatches

libc-test:
    PASS
    FAIL
    BUILDERROR
    TIMEOUT
    SKIP

differential:
    pass
    fail

POSIX:
    pass
    fail

loader:
    verified feature slices
    failures

stress:
    pthread
    TLS
    cancellation
    signals
    fork/process

Alpine corpus:
    pass / total

Rust std:
    pass / total
```

Never use a hand-written “90% complete” number when an actual measurement can be generated.

---

# Fast development commands

The full maturity suite will eventually be expensive.

Support focused loops such as:

```sh
./scripts/dev.sh test string
./scripts/dev.sh test malloc
./scripts/dev.sh test pthread
./scripts/dev.sh test resolver
./scripts/dev.sh test stdio
./scripts/dev.sh test math
./scripts/dev.sh test ldso
```

And one broad gate:

```sh
./scripts/dev.sh mature
```

which should eventually orchestrate:

```text
build
ABI/symbol ratchet
focused tests
libc-test
differential
POSIX
loader
thread/TLS/signal/process stress
Alpine corpus
Rust std smoke suite
```

Keep:

```text
fuzz
bench
```

separate.

---

# Recommended project sequence

## Milestone 0 — Compatibility laboratory

Complete:

```text
Docker ARM64 environment
pinned toolchain/upstreams
exact musl ABI manifest
libc-test structured reports
BUILDERROR → missing-symbol graph
musl differential runner
compatibility ratchet
```

Do not undertake mass symbol work before this exists.

### Progress — 2026-08-20 UTC

The core laboratory is operational on native Docker `linux/arm64` and is
intentionally Python-based where a harness needs control flow or structured
reporting. The reproducible environment is pinned to Alpine 3.24.1, Rust
`nightly-2026-07-24`, and musl 1.2.6; exact source revisions are in
[`compat/upstreams.toml`](../../compat/upstreams.toml).

Completed evidence:

- `./scripts/dev.sh image`, `build`, `test`, `symbols`, `compat`,
  `libc-test`, `differential`, `loader-inventory`, and `dashboard` run in the
  native ARM64 image.
  The full workspace test currently reaches, but does not satisfy, the legacy
  Wave 5 expectation of 73 functional passes and zero failures.
- The musl ABI inventory is mechanically reproducible: 1,647 public dynamic
  `libc.so` records, 2,004 `libc.a` records (1,939 unique names), and 217
  installed headers (183 public plus 34 architecture-internal).
- The musl loader/runtime shape and crabc loader feature surface are separately
  reproducible. The candidate report inventories 20 feature slices without
  claiming runtime verification; eight have a focused test target.
- The public dynamic-symbol ratchet is active. Its current baseline measures
  683 crabc exports, 590 exact kind/binding/visibility matches, 985 missing
  musl names, 72 metadata mismatches, and 21 unexpected names. A ratchet run
  reports zero regressions; this is not a claim of implementation parity.
- The libc-test execution loop and structured report parser are Python
  standard-library code. They retain per-test results and build a
  `missing symbol -> blocked tests` graph. Oracle-proven Docker constraints
  are explicit `SKIP` events, never candidate passes.
- The foundational differential workload compares exit status, stdout, raw
  stderr, and errno against musl. It currently passes with zero normalization.
  Successful crabc loader startup is covered by a focused regression requiring
  empty application stderr.
- [`COMPATIBILITY.md`](../../COMPATIBILITY.md) is generated from the structured
  reports and distinguishes exported, implemented, and verified states.

Current measurements are recorded in `COMPATIBILITY.md` rather than duplicated
as a moving headline here. At this checkpoint the latest results are:

```text
libc-test functional: 69 PASS, 4 FAIL, 1 BUILDERROR
libc-test API:        20 PASS, 0 FAIL, 59 BUILDERROR (strict crabc-header mode)
libc-test regression: 66 PASS, 1 FAIL, 0 BUILDERROR, 1 oracle-environment SKIP
differential:         foundational PASS
```

The first implementation work should use this evidence, not symbol count
alone. The immediate real blockers are `wordexp`/`wordfree`; current functional
behavior failures are `strtold` and TLS/dlopen paths. `regression/sigaltstack`
also remains a real failure. A previous functional rerun exposed an
`ipc_shm` timestamp discrepancy, so that case should be treated as a possible
flake until reproduced and explained.

Milestone 0 is **complete**. Its inventories deliberately stop short of
claiming header declaration/layout parity or loader runtime behavior; those
are verification work for later vertical slices. The dashboard correctly
reports POSIX, real-Alpine corpus, stock Rust `std`, static candidate ABI
coverage, and loader runtime-slice results as unmeasured.

## Milestone 1 — Foundation verified

Vertically verify the runtime foundation:

```text
syscalls/errors
memory/string
allocator
basic files/fds
filesystem basics
time
environment/process basics
basic pthread/TLS
basic synchronization
basic stdio
```

### Progress — 2026-08-20 UTC

Milestone 1 is **complete**. The verified foundation is intentionally a
bounded AArch64 runtime slice, not a claim that the remaining libc surface is
complete.

Implemented and verified in this slice:

- Syscall failures now use one errno translation path, and `errno` is TLS.
  Focused coverage checks invalid descriptor, clock, path, and stat calls in
  both the initial and a pthread-created thread.
- String and memory behavior has focused boundary coverage plus a pinned-musl
  differential workload for overlapping `memmove`, bounded searches,
  `strncpy` padding, zero-length concatenation, `strlcpy`/`strlcat`, and
  overlapping substring searches.
- The allocator records allocation metadata independently of page alignment.
  It now has checked size arithmetic, correct `realloc` preservation semantics,
  aligned allocation, `posix_memalign`, and musl-compatible non-multiple sizes
  for `aligned_alloc`.
- Basic FD/filesystem work includes `openat`, `pread`, `pwrite`, `lstat`, and
  `fstatat`, with correct syscall errno conversion and an AArch64 `struct stat`
  layout. The public `fstatat` symbol is weak, matching musl metadata.
- The AArch64 public ABI probe compares `FILE`, pthread opaque types,
  `sigset_t`, signal-stack constants, and `struct stat` layouts directly with
  pinned musl headers.
- TLS initialization, 4 KiB TLS alignment, and `dlopen` TLS now work for the
  loading thread and for a thread that predated the DSO. Dynamic TLS images are
  relocated before they are copied, and dynamic AArch64 TLS descriptors expand
  an older thread before calculating their TP-relative result.
- Basic pthread synchronization retains the existing focused coverage and now
  has a 10-thread mutex-contention regression. A mutex waiter can no longer
  transform an unlocked mutex into an ownerless wait state. The upstream
  `pthread_cond-smasher` was re-executed 1,000 times natively after this fix.
- Existing process, clock, environment, pthread, and stdio integration tests
  remain green; the libc-test functional suite independently exercises their
  ordinary C call paths.

The Python differential runner now disables compiler builtins and supports
four exact, unnormalized workloads: `foundational`, `string-memory`,
`allocator`, and `fd-filesystem`. All four pass against pinned musl 1.2.6.
The `libc-test` development command now builds the workspace before invoking
the Python runner, ensuring a report cannot accidentally describe stale
artifacts.

Final validation for this milestone:

```text
focused foundation integration tests: PASS
pthread_cond-smasher native stress (1,000 executions): PASS
musl differential (4 workloads): PASS
symbol compatibility ratchet: PASS (690 candidate exports; no regression)
libc-test functional: 72 PASS, 1 FAIL, 1 BUILDERROR
libc-test regression: 66 PASS, 1 FAIL, 0 BUILDERROR, 1 oracle-environment SKIP
libc-test API:        20 PASS, 0 FAIL, 59 BUILDERROR (strict crabc-header mode)
```

The remaining functional `strtold` failure and `wordexp` build error are math
and shell-expansion work for later slices. `regression/sigaltstack` is a real
signal-stack failure and remains outside this foundation milestone. The API
BUILDERRORs are concentrated in unimplemented headers/interfaces; they are
the intended input to Milestone 2's test-unlock work.

## Milestone 2 — Eliminate test blindness

Use test-unlock analysis to expand surface until:

```text
almost all libc-test cases can compile
```

while closing each newly testable subsystem vertically.

This milestone does **not** require 100% symbol parity.

### M2 completion evidence — 2026-08-20

The strict public-header surface is now fully reachable: the pinned
`libc-test` API suite passes all 79 source-compilation checks in strict
crabc-header mode (`gcc -nostdinc` with crabc's headers and GCC builtin
headers). This removes the prior 59 API BUILDERRORs and makes missing or
incompatible declarations visible without silently borrowing host musl
headers.

This is deliberately **source-interface evidence**, not a claim that every
declared function is exported or behaviorally complete. For example,
`wordexp.h` now has its public contract so API clients compile, while
`wordexp` remains an explicit link-time gap; a partial shell-wrapper
implementation was rejected because upstream grammar coverage exposed an
unsafe success path. Likewise, the math header now compiles its consumers,
but the unimplemented math symbols remain Milestone 3 behavioral work.

The newly exercised runtime boundaries that were brought into this milestone
are closed vertically:

- `sigaltstack` uses the Linux AArch64 ABI values (`MINSIGSTKSZ` 6144 and
  `SIGSTKSZ` 12288), and focused coverage verifies that the kernel rejects a
  one-byte-too-small alternate stack with `ENOMEM`.
- The loader identifies DSOs by `(st_dev, st_ino)` before loading them. This
  prevents the harness's `libpthread.so`, `libm.so`, `librt.so`, and related
  symlink aliases of `libc.so` from being mapped as separate libc instances.
  The focused alias fixture forces seven DT_NEEDED aliases and checks the
  process mapping result.

Final validation for this milestone:

```text
libc-test API (strict crabc headers): 79 PASS, 0 FAIL, 0 BUILDERROR
focused signal integration test:      PASS
focused loader-alias integration test: PASS
libc-test regression:                 67 PASS, 0 FAIL, 0 BUILDERROR, 1 pinned-musl overlay SKIP
libc-test functional:                 72 PASS, 1 FAIL, 1 BUILDERROR
```

The remaining functional failure is `strtold`; the remaining functional
BUILDERROR is `wordexp`. Both are intentionally retained as named M3 runtime
work rather than obscured by declarations or fake exports. The M2 header
completion therefore separates compile visibility from the M3/M4 obligation
to provide the corresponding behavior and symbols.

## Milestone 3 — Complete major behavioral slices

Drive:

```text
process/signals
network/resolver
pthread/cancellation
stdio/text
math
```

toward verified status.

Advance loader slices alongside them.

This behavioral-slice milestone is complete. It closes the named M2 runtime
gaps and gives each major slice focused, executable evidence; it does **not**
claim the later Gate D requirement that every libc-test workload is green.

- Process, signal, and socket wrappers now translate kernel errors through
  the POSIX `errno` boundary. `fork`, `execve`, `wait`/`waitpid`, `kill`,
  `sigprocmask`, socket-option calls, and the pthread signal APIs retain their
  respective raw-kernel or POSIX-return contracts. Focused fixtures cover
  `ECHILD`, failed `execve`, bad socket descriptors, and the pthread return
  convention. `pclose` now retries a POSIX `waitpid` interrupted by a signal;
  the stdio fixture forces that path with `SIGALRM`.
- The existing pthread, cancellation, locale, iconv, stdio, resolver/network,
  and loader slices remain green under the dockerized AArch64 test environment.
  The focused loader suite covers an interpreter, a real PIE, dependencies,
  startup argv/environment, static and dynamic TLS, TLS alignment, and
  DT_NEEDED symlink-alias deduplication.
- `strtold` now parses AArch64/riscv64 binary128 input directly rather than
  extending a binary64 `strtod` result. The public `float.h` long-double
  constants match that ABI, and a focused fixture verifies preserved precision.
- The math surface now has explicit C99/POSIX exports for the remaining
  unported algorithms, ABI-correct long-double entry points, musl-derived
  `acosh`/`asinh`, and targeted IEEE exception behavior for `expm1`,
  `nearbyint`, `scalb`, `sinh`, and related helpers. This replaces 132 math
  link failures with behavioral results.
- `wordexp`/`wordfree` are now exported and have a focused integration test
  for empty positional parameters, expansion, append/offset layout,
  `WRDE_NOCMD`, and `WRDE_UNDEF`. The shell wrapper clears transport positional
  parameters before evaluation and preserves shell stderr only for
  `WRDE_SHOWERR`.

Final validation for this milestone:

```text
focused process/signal/network/pthread/stdio/locale/iconv/strtold/wordexp: PASS
focused loader slice suite:                                             PASS
libc-test API:       79 PASS, 0 FAIL, 0 BUILDERROR
libc-test functional: 73 PASS, 1 FAIL, 0 BUILDERROR
libc-test regression: 67 PASS, 0 FAIL, 0 BUILDERROR, 1 pinned-overlay SKIP
libc-test math:      185 PASS, 14 FAIL, 0 BUILDERROR
symbol ratchet:      824 candidate exports; 844 names still missing
```

The sole functional failure is the deliberately bounded `wordexp` grammar
scanner; it avoids unsafe success for command-substitution forms but still
needs musl-equivalent parsing for rare nested quoting and parameter-expansion
cases. The 14 math failures are numerical-accuracy work in `acosh`, `asinh`,
the Bessel family, gamma functions, and one `sinh` case. Those are explicit
remaining behavior tasks for the later Gate D closure, not hidden build or
link failures. Milestone 4 begins the still-large isolated/advanced symbol
surface without representing those functions as complete.

## Milestone 4 — 100% implemented symbol parity

Now close remaining isolated/advanced API surface.

No fake stubs.

### Progress — 2026-08-20 UTC

M4 is complete. Every expected AArch64 public dynamic symbol now has the
required name, kind, binding, and visibility, and the additions remain backed
by focused runtime fixtures rather than link-only declarations. The final
dynamic-symbol inventory is:

```text
expected public exports: 1,647
crabc exports:           1,669
missing:                     0
unexpected (baselined):     22
ELF metadata mismatches:     0
```

The completed first tranche covers locale/locale-aware ctype and wide-string
entry points, existing math ABI helpers, `*at` filesystem/process calls,
vector/file/pipe I/O, filesystem path operations, unlocked and ISO99 stdio
entry points, C11 threads, wide-character operations, string/memory
compatibility operations, scalar bit/math helpers, historical `__xstat` and
`__strto*` entry points, terminal control, VM operations, polling/event
descriptors, select-family calls, integer/NaN utilities, C11 UTF-16/UTF-32
state conversions, GNU stdio extensions, and legacy priority/signal helpers.
The second tranche adds kernel random sources, timer/signal descriptors,
`timespec_get`, scheduling and CPU-affinity calls, Linux extended attributes,
and directory streams. The additions use the existing implementation or raw
Linux syscall path where appropriate, preserve the C errno versus direct-error
boundary, and have C fixtures run through `libldso.so`. The polling fixture
also locks in AArch64's naturally aligned `epoll_event` ABI, distinct from
x86_64's packed layout; the directory fixture caught and corrected the public
AArch64 `O_DIRECTORY` constant before it could mask that slice.

The current tranche also closes POSIX spawn attribute/action accessors and
administrative kernel interfaces. Spawn file actions are heap-backed and are
applied in their declared order by the child path; their C fixture verifies
the direct-error accessor contract. Administrative wrappers retain kernel
authorization errors rather than manufacturing privileged success.

Advanced socket messaging is now covered by accept/peer/socket-option calls,
scatter-gather and batched messages, SCM_RIGHTS control data, and `sockatmark`.
The fixture treats the kernel's urgent-mark position as intentionally
non-deterministic for an OOB-only stream (confirmed against musl), while still
requiring a successful ioctl and a received urgent byte.

The newest verified cohort implements C99's basic complex primitives (with
binary128 long-double handling), host/process identity and resource calls,
filesystem timestamp/statfs operations, signal-set and signal-disposition
helpers, Linux system-memory/load/CPU information, and program utilities such
as secure environment lookup, path/temporary-file helpers, allocation
compatibility, byte/word stream helpers, and tty password input. Every added
boundary has a Docker AArch64 fixture; the symbol report again has zero metadata
mismatches.

`getopt` now supplies its musl-facing parser state, reset spellings, weak
POSIX entry point, and startup-derived program-name globals; its fixture covers
clustered and required arguments, reset semantics, error reporting state, and
the executable-name contract. A separate ownership/identity slice adds real
`chown`/`fchown`/`fchownat`/`lchown`, `chroot`, and filesystem UID/GID wrappers,
testing both kernel error propagation and safe non-mutating identity queries.

Complex transcendentals now cover the C99 double, float, and ABI-correct
long-double entry points, including branch-sensitive square root, logarithm,
trigonometric, hyperbolic, and inverse forms. POSIX message queues use the
native Linux queue syscalls with POSIX-name translation, attributes, timed
operations, notification, and safe cleanup coverage. Process-control work now
covers process groups, `waitid` state transitions, scheduler queries and
authorization errors, and pthread CPU-clock IDs. Resolver compatibility
globals (`in6addr_*`, `h_errno`) and their error strings, plus C11 quick-exit
handlers, have their own runtime fixtures. That checkpoint measured 1,378
candidate exports, 290 missing expected symbols, and zero metadata mismatches.

The next integrated tranche adds actual filesystem-aware `pathconf` and
`fpathconf`, POSIX `confstr` truncation semantics, historical `ulimit`, raw
program-break operations, bounded multibyte/wide-character conversions and
wide tokenization, plus advanced vectored and directory I/O (`preadv2`,
`pwritev2`, `getdents`, and the POSIX direct-error wrappers). Its fixtures
cover both resumption/error behavior and real filesystem state. The current
ratchet measures 1,397 candidate exports, 271 missing expected symbols, and
zero metadata mismatches.

The latest tranche extends the terminal boundary with window-size, speed, and
real pseudo-terminal allocation/session helpers; supplies GNU long-option
parsing; and closes musl-compatible legacy ctype/assertion entry points, legacy diagnostics,
effective-ID filesystem checks, ISO99 scanner aliases, directory comparators,
and Linux's musl-compatible gettext fallback. These paths have focused C
fixtures through `libldso.so`, including child-process exit/error output,
terminal I/O, parser ambiguity and permutation, assertion diagnostics, and
gettext binding/query state. The current AArch64 ratchet is 1,442 candidate
exports, 226 missing expected symbols, and zero ELF metadata mismatches.

The newest additions cover DNS packet wire-format parsing and compression
validation, Linux resource/capability syscalls, generic `ioctl`, supplementary
group validation, legacy line/wide-stdio helpers, and POSIX process timers.
Their fixtures run against `libldso.so` and exercise malformed DNS messages,
capability version errors, resource-copy semantics, `ioctl` requests, and
timer lifecycle/error boundaries. The current AArch64 ratchet is 1,471
candidate exports, 197 missing expected symbols, and zero ELF metadata
mismatches.

The newest cohort adds full exec-family PATH and shell-fallback behavior,
syslog transport and mask state, the protected stdio refill entry point, and
wide standard-output wrappers. The loader fixtures execute child replacement
processes, verify errno selection and `fexecve`, check syslog's musl-formatted
`LOG_PERROR` output, and cover wide/byte stream boundaries. The current
AArch64 ratchet is 1,485 candidate exports, 183 missing expected symbols, and
zero ELF metadata mismatches.

The current checkpoint also supplies the weak locale-aware `strftime_l` ABI
entry point. crabc presently implements the C/POSIX time locale, so the entry
point intentionally delegates to the already-tested bounded `strftime`
implementation while preserving its format, calendar, and output-size
contract. Its loader fixture exercises the public spelling directly. The
current AArch64 ratchet is 1,486 candidate exports, 182 missing expected
symbols, and zero ELF metadata mismatches.

The latest network and terminal tranche adds netlink-backed interface-name
enumeration and ioctl point lookups, strict Ethernet text conversion plus real
`/etc/ethers` lookup behavior, and musl-style pseudo-terminal name resolution
that verifies the procfs target's device identity. Each boundary has a loader
fixture covering a real success path, lifecycle/ownership where applicable,
and a deterministic invalid-input or kernel-error path. The current AArch64
ratchet is 1,498 candidate exports, 170 missing expected symbols, and zero ELF
metadata mismatches.

The current database-cursor slice adds `getusershell`, `setusershell`, and
`endusershell` with the real `/etc/shells` source, including rewind and
close/reopen behavior. The loader fixture verifies the same first entry across
those state transitions. The current AArch64 ratchet is 1,501 candidate
exports, 167 missing expected symbols, and zero ELF metadata mismatches.

The latest real-state utilities add `tempnam` via an exclusive-create/unlink
name reservation and `getifaddrs`/`freeifaddrs` via two-pass rtnetlink dumps.
The latter provides owned AF_PACKET, IPv4, and IPv6 records with address,
netmask, broadcast/destination, flag, and interface-name fields. Loader tests
cover temporary-name ownership, link-list traversal, kernel-family layouts,
and the null-argument error contract. The current AArch64 ratchet is 1,504
candidate exports, 164 missing expected symbols, and zero ELF metadata
mismatches.

The latest behavioral cohort completes callback-backed and stateful interfaces
without hiding their real effects. `fopencookie` now preserves musl's callback
buffering, read-ahead, seek, close, and error contract; `open_wmemstream`
publishes an owned, NUL-terminated wide-character buffer after flush/close;
and `cuserid` derives its bounded result from the effective UID's passwd
record. Filesystem traversal now implements `GLOB_TILDE`/`GLOB_TILDE_CHECK`
against HOME and the passwd database, along with `FTW_CHDIR` restoration even
when callbacks change directories or abort. The passwd and group databases
now provide real lookup, reentrant, enumeration, stream, and membership APIs
from `/etc/passwd` and `/etc/group`; `initgroups` is exercised only in a child
so the harness credentials remain intact. Finally, the Linux administrative
cohort provides raw, errno-preserving wrappers for accounting, module, log,
mount, quota, reboot, swap, and terminal-hangup syscalls, using safe invalid
probes and an isolated child where required. Focused Docker loader fixtures
pass together, and the current AArch64 ratchet is 1,546 candidate exports,
122 missing expected symbols, and zero ELF metadata mismatches.

The next stateful cohort adds real shadow and utmp/utmpx database behavior,
effective-login lookup, password-database advisory locking, native file-handle
and ptrace boundaries, and the nonportable pthread attribute/name/join APIs.
It also completes the legacy file-backed hosts, networks, protocols, and
services interfaces (including their reentrant forms), the Linux clock
administration syscalls, timed SysV semaphore operation, and POSIX AIO. AIO
uses immediate completion backed by the actual positional/current-offset I/O
syscalls, so each `aiocb` still exposes a real completion/error/return
lifecycle rather than fabricated success. The focused loader suite verifies
database cursor/ownership behavior, lock visibility across a child process,
kernel error order under missing clock privileges, AIO operation failures and
list semantics, and the required weak compatibility aliases. At this
checkpoint the AArch64 inventory is 1,643 candidate exports, 25 missing
expected symbols, and zero ELF metadata mismatches.

Resolver closure now supplies the process resolver state, `/etc/resolv.conf`
nameserver discovery, bounded DNS query encoding/UDP transport/response
handling, `getaddrinfo`/`getnameinfo`, and DNS name compression. Numeric and
file-backed hosts/services cases have Docker loader evidence without relying
on external network reachability. The historical `ecvt`, `fcvt`, and `gcvt`
interfaces share their required static-result ownership and preserve musl's
precision limits, rounding, sign, decimal-point, and special-value behavior.

M4 closure adds the remaining formatting/date, clone, startup, debugger
rendezvous, public TLS, and init/fini ABI surfaces. `__dls2b` and `__dls3`
install only the bounded libc process state they own; ELF mapping, relocation,
TLS allocation, constructors, and the final entry transfer remain ldso's
responsibility. The debugger view is ldso's real `r_debug`/link-map state,
published at initial and runtime rendezvous transitions. The public
`__tls_get_addr` follows the one-based ELF module-ID ABI and delegates to the
loader-owned TLS layout. `_dlstart` is an AArch64 raw-stack trampoline rather
than a callable C stub, while `_init` and `_fini` retain musl's weak dummy
ABI without CRT-generated strong replacements.

The final Docker report is 1,647 expected symbols, 1,669 candidate symbols,
zero missing names, and zero metadata mismatches. Its 22 unexpected names are
the pre-existing ratchet baseline; `./scripts/dev.sh compat` reports no new
unexpected exports or ABI regressions. Focused Docker coverage passes for
`getdate`, legacy formatting, clone, setjmp aliases, loader startup/debugger
state, loader introspection, public TLS resolution, weak init/fini, and real
loader startup. This completes M4's symbol-surface gate without representing
unimplemented behavior as a successful call.

## Milestone 5 — ABI + libc-test closure

Require:

```text
ABI parity
headers parity
libc-test green
```

Completed on 2026-08-20. The Docker AArch64 ABI probe compares the nine
selected public layout/value surfaces (`stat`, `termios`, `socket`, `fenv`,
`complex`, `pthread`, signals/ucontext, TLS, and native `long double`) against
pinned musl 1.2.6; all match. Its header inventory reports all 183 pinned
public headers as `compile_ok`, with that compile-only evidence explicitly
separated from the layout comparisons. The expanded candidate header tree
includes the previously absent network, Linux UAPI, SCSI, ucontext, compiler,
and system surfaces; focused candidate-vs-pinned tests cover their public
constants, ioctl encodings, AArch64 layouts, and dependent types.

`./scripts/dev.sh libc-test all` is green: 420 total, 406 PASS, and zero FAIL,
BUILDERROR, or TIMEOUT. Fourteen exceptions remain individually evidenced:
Docker overlay `regression/statvfs`, plus thirteen native-AArch64 math
identities where pinned musl produces the same raw IEEE-754 results. The
Python runner regenerates and executes exact-bit verifiers for every math
exception on every run, so a current candidate regression becomes a failure
instead of a skip. The full Docker workspace suite, ABI/header fixtures,
Python harness tests, static `libc.a` linkage, and the M4 symbol ratchet all
pass. The ratchet remains 1,647 expected dynamic symbols, 1,669 candidate
symbols, zero missing names, zero metadata mismatches, and 22 baselined
unexpected exports.

## Milestone 6 — standards + stress closure

Require:

```text
POSIX confidence
pthread/TLS stress
signal/process stress
resolver/network correctness
```

Completed 2026-08-20. M6 remains musl-first: all implementation and runtime
comparison evidence uses pinned musl 1.2.6. The only narrower source contract
is the selected current POSIX namespace test, used to remove legacy names that
current XSI no longer requires; it is not a glibc oracle or compatibility path.
Allocator internals remain deliberately mimalloc-backed under the allocator
scope exception, while the observable C allocation contract is tested.

`./scripts/dev.sh os-test` passes all ten selected suites (`include`,
`namespace`, `basic`, `io`, `limits`, `malloc`, `process`, `pty`, `signal`,
and `stdio`). The bounded musl differential pthread/TLS stress run passes
10/10 iterations, the isolated signal/process comparison passes 12/12
subcases, and the deterministic loopback resolver/network comparison passes
all 22 contract items.

Fork child-state repair preserves the live calling worker slot while clearing
stale sibling slots. The upstream `pthread_exit-dtor` and `raise-race`
regressions now pass. Final `./scripts/dev.sh libc-test all` evidence is 420
total cases: 406 PASS, zero FAIL/BUILDERROR/TIMEOUT, and 14 individually
evidenced exceptions; the strict API subset is 79/79. The workspace suite,
Python harness tests, AArch64 ABI probe, and symbol ratchet all pass. The
ratchet records 1,647 reference exports, 1,669 candidate exports, no missing
or metadata-mismatched symbols, and 22 baselined candidate-only exports.

## Milestone 7 — dynamic loader maturity

Require synthetic DSO/relocation/TLS/dlopen suite green.

**Complete (2026-08-20).** `compat/ldso/run.py` now runs 20 bounded native
AArch64 pinned-musl differential cases. The suite covers recursive
`DT_NEEDED` graphs, constructor dependency ordering and fini-array lifecycle,
initial and late TLS, main/DSO `RPATH`/`RUNPATH` plus `$ORIGIN`,
`LD_LIBRARY_PATH`, `LD_PRELOAD`, `dlopen`/`dlsym`/`dlclose`/`dlerror`,
local/global and visibility lookup boundaries, GNU/SysV hash tables, the
exercised AArch64 relocation classes, GNU_RELRO protection, auxv/vDSO handoff,
and PIE/DSO ASLR. Fixtures prove their ELF shape with `readelf` and compare
raw process outcomes only with pinned musl.

The suite is run by `./scripts/dev.sh ldso` and records atomic evidence at
`compat/reports/ldso/latest.json`; the dashboard displays that report without
turning it into a claim about arbitrary real-world DSO graphs. The loader
feature inventory is regenerated by `./scripts/dev.sh loader-inventory`.

Final closure evidence:

```text
./scripts/dev.sh ldso                         20/20 PASS
python3 compat/ldso/tests/test_runner.py      3/3 PASS
./scripts/dev.sh test                         workspace PASS
./scripts/dev.sh libc-test all                406 PASS, 0 FAIL/BUILDERROR/TIMEOUT, 14 evidenced skips
./scripts/dev.sh loader-inventory             reproducible PASS
```

## Milestone 8 — real Alpine compatibility

Drive unmodified AArch64 Alpine corpus through increasingly complex tiers.

### Progress — 2026-08-20 UTC

Milestone 8 is **complete**. The Python standard-library corpus harness in
`compat/corpus/run.py` measures pinned Alpine 3.24.1 AArch64 packages from
archive URLs, versions, and SHA-256 digests recorded in
`compat/corpus/manifest.toml`. It exercises 22 cases across the planned A–D
progression: core utilities; `grep`, `sed`, `file`, archive/compression, and
SQLite tools; `curl`, OpenSSL, and SSH version paths; then Git and Python.
Network-facing commands use only their local, non-network invocation paths.

The package programs are not rebuilt. Docker cannot safely mount an isolated
root in this environment, so the runner makes a disposable byte-copy of each
package executable and changes only its `PT_INTERP` string. The kernel still
executes the package binary directly, with its original `argv[0]` and
`/proc/self/exe`; reference musl and candidate crabc runs share the same
kernel, image files, non-libc DSOs, and identical `LD_LIBRARY_PATH` text.
Only the staged loader/libc alias bytes differ. Raw exit status, stdout, and
stderr must match exactly, and each report retains input and runtime digests.

The first real coreutils programs exposed AArch64 `DT_RELR`, which is now
relocated by `ldso` and retained as a real-corpus requirement. The full corpus
also found and fixed the musl `printf` `%lc` contract and Linux/musl
`sysconf(_SC_CLK_TCK) == 100` required by Python initialization. Both have
focused integration regressions.

Final closure evidence:

```text
python3 compat/corpus/tests/test_runner.py          10/10 PASS
./scripts/dev.sh corpus --tier all --offline        22/22 PASS
./scripts/dev.sh test --test stdio_wide_char_printf --test sysconf
                                                    2/2 PASS
./scripts/dev.sh ldso                               20/20 PASS
./scripts/dev.sh test                               workspace PASS
./scripts/dev.sh libc-test all                      406 PASS, 0 FAIL/BUILDERROR/TIMEOUT, 14 evidenced SKIP
./scripts/dev.sh loader-inventory                   reproducible PASS
```

## Milestone 9 — stock Rust std

Prove normal Rust software can use crabc without a std fork.

### Progress — 2026-08-20 UTC

Milestone 9 is **complete**. `compat/rust-std/run.py` builds the ordinary,
dependency-free crate in `compat/rust-std/fixtures/` with the pinned
`nightly-2026-07-24` Rust source tree and stock
`-Z build-std=std,panic_abort`. The build is an isolated temporary Cargo
project, uses the pinned musl-gcc specs, disables musl's default `crt-static`,
and produces one dynamic AArch64 PIE. No Rust `std` fork and no crabc-specific
application source are involved.

That identical compiled program is entered by the kernel twice after only its
disposable `PT_INTERP` copy is changed: once through pinned musl and once
through crabc. Both runs share one explicit environment, kernel, and staged
Alpine `libgcc_s`; the `libc.musl-aarch64.so.1` loader-search filename is
populated by the corresponding pinned-musl or crabc libc bytes. This is the
canonical `DT_NEEDED` name requested by both the Rust executable and
`libgcc_s`, not an `LD_PRELOAD` workaround. Status, stdout, and stderr are
compared byte-for-byte and artifact/toolchain/digest evidence is retained at
`compat/reports/rust-std/latest.json`.

The normal Rust workload verifies allocation plus `Vec`/`String`, files and
directories, environment and time, local TCP/UDP/DNS, threads with
`Mutex`/`Condvar`, process spawn with a captured child pipe, and stdio. It is
one meaningful vertical slice, not a claim that all Rust software or all
Rust/FFI interfaces are covered.

Final closure evidence:

```text
python3 compat/rust-std/tests/test_runner.py        7/7 PASS
./scripts/dev.sh rust-std                           1/1 PASS, exact raw comparison
./scripts/dev.sh test                               workspace PASS
```

## Milestone 10 — LTO research

Measure the whole-program Rust/LLVM optimization opportunity.

### Progress — 2026-08-20 UTC

Milestone 10 is **complete as an evidence milestone**. The new dependency-free
Python runner, `compat/lto/run.py`, executes the four Stage 16 configurations
inside the pinned native Linux/AArch64 image and writes a structured report at
`compat/reports/lto/latest.json`. `./scripts/dev.sh lto` is the reproducible
entry point and refreshes the compatibility dashboard.

The matrix deliberately separates two controlled static C lanes from the
normal Rust/build-std lanes. A links `fixtures/static.c` through pinned musl;
B links the same object with explicit musl CRT/GCC support files and crabc's
`libc.a`, then requires a bounded linker-map anchor for that exact candidate
archive and absence of a selected musl `libc.a`. Both built a static AArch64
ELF and exited zero. B's artifact is distinct from A (8,613,712 bytes versus
71,688 bytes before stripping), has 885,064 bytes of `.text`, 1,465,168 bytes
after stripping, and retains 1,627 defined global symbols. This proves the
explicit archive-selection setup; it is not a claim that a minimal C probe
measures all static Rust behavior.

C builds the ordinary dependency-free Rust fixture with the pinned stock
`-Z build-std=std,panic_abort` path, `opt-level=3`, one codegen unit, and the
dynamic crabc loader/libc boundary. It built and exited zero; the inspected
dynamic ELF has 253,892 bytes of `.text`, is 397,744 bytes after stripping,
and retains 348 defined global symbols. Its `llvm-readelf` inspection records
only that crabc is external/opaque to this Rust graph—no cross-boundary LTO
claim follows from a dynamic link. Its inspected disassembly/symbol evidence
still mentions the direct `getpid`, `write`, `malloc`, and `free` boundaries,
so it supplies no wrapper-elimination claim.

D requests static `build-std`, fat LTO, embedded bitcode, linker-plugin LTO,
and clang/lld. The isolated crabc archive rebuild succeeded and contained 267
`.llvmbc` markers. Its Rust artifact also built as a static ELF and exited
zero, with Rust rlib bitcode observed. Crucially, the recorded LLD map selected
Rust's self-contained musl `libc.a` and contained neither the rebuilt crabc
archive path nor an `llvm-nm`-derived crabc archive-member anchor. D is
therefore recorded as **invalid**, not as cross-boundary LTO: this topology
does not establish that crabc participated, so
`whole_program_lto_proven` remains false. The next optimization experiment
must explicitly remove or replace Rust's self-contained musl archive before
making that claim.

For every produced artifact the runner retains `llvm-nm`, `llvm-readelf`, and
`llvm-objdump` evidence, `.text`, stripped/full ELF size, retained-symbol
count, exact linker/build input records, raw run timing, and `strace -f -c`
syscall counts when available. It separately records whether the fixture's
named helpers remain in inspected symbol/disassembly text; absence is bounded
inlining/internalization evidence, not a cross-boundary claim. The RSS field
is intentionally labeled a raw cumulative `RUSAGE_CHILDREN` delta, not an
isolated process-peak benchmark.
The harness does not normalize outputs or substitute glibc at any point.

Final closure evidence:

```text
python3 compat/lto/tests/test_runner.py            11/11 PASS
./scripts/dev.sh lto                               PARTIAL: A/B/C built and ran; D invalid by link-map evidence
./scripts/dev.sh test                              workspace PASS
```

## Milestone 10.5 — AArch64 maturity refinement

Close the evidence and correctness gaps discovered by the post-M10 AArch64
audit before considering a second architecture. This milestone blocks M11.

### Contract

1. **Repair the judge before trusting green.** `compat/os-test/run.py` must
   require the source contract for a suite to pass. Retain only individually
   named pinned-musl exceptions, expose every source-contract failure in the
   dashboard, and add a regression test for the former false-green condition.
2. **Harden the dynamic linker at its real process boundary.** Add isolated
   musl-oracle tests and fixes for `AT_SECURE` environment sanitization,
   dependency search (never search the working directory for a bare
   `DT_NEEDED` name), error handling for dependency/capacity overflow, and
   failed-load mapping cleanup. Replace the bounded/truncating replacement
   stack with a representation that preserves the actual argc/envp/auxv
   contract, including the normal kernel auxv entries. `dlopen`/`dlsym`/
   `dlclose` and `dlerror` must have a documented synchronization/per-thread
   contract under application threads. Re-test late TLS growth and thread exit
   against the correct allocation layout.
3. **Make static and ABI evidence generated rather than sampled.** Generate
   public-header declaration/layout/constant probes from the pinned musl
   header surface, compare candidate and reference static archives, and add
   static pthread/TLS lifecycle tests. Malloc internals remain out of scope;
   mimalloc remains the allocator implementation.
4. **Exercise state, not version banners.** Extend every Tier B–D Alpine
   corpus package with at least one deterministic stateful operation. Add a
   dependency-bearing, unmodified stock Rust application with filesystem,
   async/networking, synchronization, subprocess, and error-path behavior;
   compare raw musl/crabc outcomes.
5. **Make the gate durable.** Re-run all closure evidence from the current
   commit with recorded environment/artifact provenance. M11 remains deferred
   until the dashboard no longer relies on a false-green source contract and
   the remaining boundaries are explicitly measured.

### Completion evidence

```text
os-test source contracts are green or individually justified
loader security/concurrency/stack/TLS regressions pass against musl
generated static ABI/header report has no unexplained difference
static pthread/TLS lifecycle test passes
stateful Tier B–D corpus cases have exact raw musl/crabc outcomes
dependency-bearing stock Rust application has exact raw musl/crabc outcomes
full current-commit AArch64 closure is retained in structured reports
```

### Progress — 2026-08-20 UTC

Milestone 10.5 is **complete**. M11 remains deliberately deferred: this
milestone closes the identified AArch64 evidence and correctness gaps, rather
than claiming that every unmeasured musl interface is complete.

`compat/os-test/run.py` now makes the `basic` source contract a hard gate; its
unit regression preserves the former shared-diagnostic false-green case. The
current all-profile report passes all ten selected suites. `basic` has
`source_contract_passed=true`, zero candidate source failures, and zero
unaccepted differences; the remaining 50 source differences are individually
recorded source improvements rather than substituted host-libc behavior.

`ldso` now sanitizes unsafe loader environment inputs under `AT_SECURE`, never
opens a bare `DT_NEEDED` name from the working directory, rejects bounded
graph/name/dynamic-table failures without truncation, rolls back failed DSO
mappings, and preserves full argc/envp/auxv startup vectors. Runtime loader
operations are serialized with a recursive loader lock; `dlerror` uses
per-thread identity storage, and TLS allocation metadata follows the actual
thread block through late module growth. Focused startup-vector, cwd-search,
and multithreaded `dlerror` regressions accompany the existing dynamic TLS
coverage. `./scripts/dev.sh ldso` passes all 20 synthetic pinned-musl cases.

The ABI runner now writes durable generated evidence: 183/183 pinned public
header declaration probes compile, all nine named layout/constant probes match,
and a complete `nm -A` static-archive name/class comparison retains every
difference as explicit informational triage. Static archives are not falsely
claimed equal: musl internals and Rust/mimalloc implementation members remain
visible in that report, with malloc internals still out of scope. The separate
conventional `libc.a` pthread/TLS lifecycle fixture links with pinned musl CRT
objects and passes under both reference and candidate.

The Alpine corpus contains 34 exact raw comparisons: 10 Tier A, 14 Tier B, 6
Tier C, and 4 Tier D. All Tier B–D packages have a required deterministic
stateful case (12 total). The locked, dependency-bearing stock Rust fixture
uses `async-net`, `futures-lite`, and `smol` for filesystem, async local TCP,
synchronization, subprocess, and error-path behavior; its status, stdout, and
stderr match pinned musl exactly.

Final current-workspace closure:

```text
./scripts/dev.sh test                              workspace PASS
./scripts/dev.sh libc-test all                     406 PASS, 0 FAIL/BUILDERROR/TIMEOUT, 14 evidenced SKIP
./scripts/dev.sh os-test                           10/10 selected profiles PASS; basic source gate green
./scripts/dev.sh ldso                              20/20 PASS
./scripts/dev.sh static-pthread-tls                PASS
./scripts/dev.sh abi-probe                         183 header probes + 9 runtime probes PASS; static triage retained
./scripts/dev.sh corpus --tier all --offline       34/34 exact raw PASS; 12 stateful B–D cases
./scripts/dev.sh rust-std-dependent                exact raw PASS
./scripts/dev.sh rust-std                          exact raw PASS
./scripts/dev.sh pthread-stress                    10/10 PASS
./scripts/dev.sh signal-process                    12/12 PASS
./scripts/dev.sh resolver-network                  22 contract items PASS
./scripts/dev.sh differential                      foundational PASS
./scripts/dev.sh compat                            ratchet PASS; 1,647 reference, 1,669 candidate, 0 missing/mismatched
./scripts/dev.sh loader-inventory                  reproducible PASS
./scripts/dev.sh lto                               PARTIAL by design: A/B/C built and ran; D remains invalid by link-map evidence
python3 compat/abi/tests/test_probe.py             11/11 PASS
python3 compat/os-test/tests/test_runner.py        19/19 PASS
python3 compat/corpus/tests/test_runner.py         12/12 PASS
python3 compat/rust-std/tests/test_runner.py       9/9 PASS
python3 compat/ldso/tests/test_runner.py           3/3 PASS
python3 compat/lto/tests/test_runner.py            11/11 PASS
```

## Milestone 11 — scope-aligned core-runtime refinement (complete)

The former x86_64 milestone is deliberately inactive. M11 now means the next
Linux/AArch64 refinement work selected from the post-M10 ledger; it does **not**
activate another architecture. Any future architecture proposal needs a
separate user decision and a new scope/profile review.

This selection preserves the profile in `SCOPE.md` and
`COMPATIBILITY-PROFILE.md`:

| Priority | Post-M10 groups | Scope boundary |
| --- | --- | --- |
| Core Unix runtime | calendar/timezone, process control/credentials/environment/signals, pthread/C11, `dlopen` runtime, filesystem extensions | Direct Linux/AArch64 behavior with normal POSIX failure semantics; timezone data comes from the system. |
| Core network profile | resolver and netdb | `/etc/hosts`, `/etc/resolv.conf`, A/AAAA/CNAME, search, UDP/TCP fallback, retries, and conventional text databases only; no NSS, DNSSEC, DoH/DoT, mDNS, or IDNA framework. |
| Useful POSIX | regex/glob, IPC, PTY/session, user databases, narrowly scoped kernel administration | Compatibility-focused implementations without a Rust regex, process-framework, or security-policy substitute. |
| C ABI/profile machinery | stdio, locale, wide text, long-double and other C-only families | Account and test the C contract where it belongs; do not manufacture a broad Rust wrapper. |

### Completion — 2026-08-21 UTC

M11 is complete for its three deliberately selected Linux/AArch64 seams. This
is not a claim that their larger legacy C families are complete:

- `timezone::TimeZone` owns caller-supplied POSIX TZ or TZif v1/v2/v3 bytes
  and provides immutable UTC-offset lookup. It validates trailing POSIX
  continuations and does not bundle tzdata, read `TZ`, change global timezone
  state, format local time, or control clocks.
- The configured resolver transport now uses nonblocking UDP with one
  monotonic deadline per server, discards malformed/wrong-ID datagrams, falls
  back to framed TCP on `TC`, handles partial TCP I/O, and fails over in
  configured order. It remains an explicit caller-owned configuration: system
  discovery, hosts/search policy, CNAME completion, and netdb are not claimed
  by this transport slice.
- `dl::Library` now covers owned basic open/symbol/close and copied
  diagnostics/address metadata through the private versioned runtime table.
  Its synthetic DSO fixture proves constructor/destructor and reference-count
  lifetimes; `dlinfo` and `dl_iterate_phdr` remain deferred introspection
  work.

The ledger records these as two native implementation capabilities and a
verified five-symbol basic dlfcn group, while retaining the sixteen larger
semantic deferrals. The 43 `documented` groups are not hidden M11 work unless
a new profile decision promotes one.

Completion evidence:

```text
./scripts/dev.sh test -p crabc-rs --test m11_timezone_rules  6/6 PASS
./scripts/dev.sh test -p crabc-rs --test m11_resolver_transport  4/4 PASS
./scripts/dev.sh test -p crabc --test m11_loader_dlfcn_basic  PASS
./scripts/dev.sh crabc-rs  PASS
```

## Milestone 12 — native `crabc-rs` LTO proof (complete)

M12 completes the bounded Linux/AArch64 optimization evidence requested by
`crabc-rs` delivery record; it is separate from the older M10 C-runtime LTO matrix. The
checked-in native fixture uses only `crabc-rs` direct operations for its
inspected route, while a second fixture adds stock `std` for a dynamic-runtime
compatibility comparison. Both path-pin the repository crates and carry their
own lockfiles.

The reproducible command builds the normal dynamically linked application in
O3-without-LTO and fat-LTO lanes, plus the stock-`std` fat-LTO lane:

```text
./scripts/dev.sh lto-m12  COMPLETE
python3 -m unittest discover -s compat/lto/tests -p 'test_*.py'  16/16 PASS
```

The fat native witness contains direct AArch64 `getpid` syscall 172 plus
`svc #0`, retains direct `write` syscall 64 evidence for the fixture, and has
no observed public-C/TLS-errno or internal facade-call branch in its named
function. It retains `.llvmbc` provenance for both `crabc-rs` and
`crabc-core`, then compares raw status/stdout/stderr under pinned musl and the
staged crabc loader/libc. The `stock-std-fat` lane also raw-compares cleanly.

This is deliberately not an assertion that a dynamic `libc.so` was LTOed,
that LLVM performed unique cross-crate inlining, that the complete program is
whole-program optimized, or that assembly bytes are stable. The report records
each of those non-claims explicitly.

### Prerequisite progress — 2026-08-20 UTC

`crabc-rs` M5 is complete for its declared direct descriptor, readiness,
timer, and mapping slice. The pinned Rustix correspondence ledger is now
fully classified and its documented direct-boundary/source-comparison gate is
green. The remaining `crabc-rs` milestones and their explicit deferred
Linux/AArch64 surfaces are capability-accounting work; they do not activate
another architecture.

Reuse the same compatibility laboratory first.

No RISC-V.

### Prerequisite progress — crabc-rs M6 — 2026-08-20 UTC

`crabc-rs` M6 is complete for Linux/AArch64 little-endian: native typed
signal disposition/masks/waits/queueing/alternate stacks/`signalfd`, raw and
atfork fork, prepared fork/exec spawn, typed waits/`waitid`, and isolated
process-group/session controls all use the shared direct `crabc-core` syscall
seam. The native atfork registry is explicitly separate from C
`pthread_atfork`; no mixed-registry semantics are claimed.

Musl 1.2.6 remains the only libc semantic oracle. In particular, signals
32–34 are reserved, `SIGRTMIN` is 35, and safe native realtime signals span
35–64. The overlapping C facade has regression coverage for those rules and
for `signal`'s `SA_RESTART` behavior. POSIX timer-generated notification is
recorded as a later native time/runtime capability rather than being hidden
behind the completed signal claim.

The M6 native gate adds isolated realtime queue/wait and timeout, signalfd,
handler/alternate-stack, atfork-order, failure-reporting spawn, wait/waitid,
and process-session cases; it source-compares the Rustix-compatible wait
shape and statically proves direct AArch64 syscalls with no public C ABI or
TLS-errno transition. This remains Linux/AArch64 evidence only.

Linux arm64 big-endian is not a project target. Its upstream deprecation
confirms the existing `aarch64-unknown-linux-musl` little-endian-only scope;
do not introduce endian-parametric abstractions or `aarch64_be` tests.

### Prerequisite progress — crabc-rs M7 native runtime slice — 2026-08-20 UTC

The first Linux/AArch64 little-endian `crabc-rs` runtime vertical slice is
implemented and verified. Rust-owned, process-private direct-futex primitives
now cover non-poisoning mutex/condition/once/semaphore, writer-preferring
rwlock, and reusable barrier semantics. Their broadcast count is the largest
positive Linux futex value, avoiding the unsigned wake-all deadlock that the
multi-generation barrier regression exposed.

Resolver/netdb calls are caller-owned direct DNS and text-database operations;
they do not cross the C resolver ABI or C TLS errno. Native dynamic loading and
thread/TLS/cancellation access use the one private, versioned
`__crabc_runtime_v1` singleton table in `libc.so`, so `libldso` and libc remain
the sole owners of their process state. Static-archive ELF checks reject public
`dl*`, `pthread_*`, resolver, and TLS-errno dependencies; C fixtures run the
loader and thread/TLS probes under crabc's `libldso.so`.

This records a bounded native Rust slice, not a blanket claim over C pthread
extensions. Robust/process-shared/recursive/error-checking forms, C cleanup
macro scopes, and a shared C `pthread_atfork` registry remain explicit
Linux/AArch64 capability-accounting work; there is no M11 architecture gate.

### Prerequisite progress — crabc-rs M8 semantic facilities — 2026-08-20 UTC

`crabc-rs` M8 is complete for its explicit implement-or-classify scope. The
native surface adds allocation-free byte-oriented `fnmatch` over `CStr` and
typed flags, direct calling-thread AArch64 FPCR/FPSR control with an RAII
restore guard, and a close-on-drop `CFile<'buffer>` memory-stream facade. The
first two share pure `crabc-core` implementations with the C facade; CFile is
an opt-in `runtime-stdio` facility that reaches only the append-only private
`__crabc_runtime_v1` table and provides `std::io::{Read, Write, Seek}` adapters
without a public C stdio or TLS-errno hop.

The C runtime repair made by this slice also reclaims dynamic `FILE`, cookie,
and `fgetln` allocations while protecting static standard streams with
`F_PERM`. A regression proves both `freopen` of an `fmemopen` stream and
`freopen(stdout)` followed by `fclose(stdout)`, preventing stale callback
state and static-storage free. The expanded Docker gate covers the native
tests, no-std AArch64 archives, Python ELF verifiers, loader-backed CFile
fixture, C fenv/fnmatch tests, and the relevant stdio/memory-stream
regressions.

M8 deliberately classifies—not silently claims—the remaining locale, wide
character, iconv, regex, glob, wordexp, passwd/group, special math, and
complex facilities. They remain explicit M9/M10 capability work; this
milestone does not enable another architecture.

### Prerequisite progress — crabc-rs M9 capability accounting — 2026-08-20 UTC

`crabc-rs` M9 is complete for the measured Linux/AArch64 little-endian dynamic
surface. The v2 `compat/crabc-rs/coverage.toml` ledger assigns every one of
the 1,669 candidate exports to exactly one semantic capability group, pins the
1,647-symbol musl baseline and both source TSV SHA-256 digests, and gives all
22 candidate-only exports an independently checked owning group and rationale.
The generated Python report is green with zero unclassified public symbols and
zero unclassified capability groups.

The ledger continues to make the boundary honest: 204 capability groups now
record 145 verified native seams, 39 meaningful deferred groups with an
intended M10 API and reason, and 20 documented Rust-subsumed, strictly ABI-only,
or internal-runtime groups. Existing M0–M8 slices remain evidence for their
named operations; a mixed C semantic group is not called verified until its
whole native contract is complete. The ledger records
the public malloc family as the versioned `scope-exception`
`allocator-mimalloc-libc-boundary` v1, out of scope for crabc-rs under the
mimalloc strategy; it does not treat that,
`fopen64`, private crypt/atfork helpers, or loader ABI plumbing as hidden
native coverage. The M9 mutation suite rejects missing, duplicated, or extra
exports; unowned candidate-only entries; unclassified groups; C-ABI/errno
hops in verified native entries; and unsupported ABI-only classifications.

This completes accounting, not native capability completion. M10 turns each
meaningful deferred group into an idiomatic Rust API or a rigorously documented
Rust-native equivalent where it belongs in the supported Linux/AArch64 profile.

### Milestone 10 completion — crabc-rs semantic capability closure — 2026-08-21 UTC

M10 is **complete**. The 1,669-export inventory is exact and green; its 215
semantic groups record 156 verified native seams, 16 explicitly deferred
post-M10 capability groups, and 43 documented Rust-subsumed, C-ABI, or
private-runtime groups. This is the project’s semantic-accounting definition
of completion, not a promise to create a Rust wrapper for every historical C
symbol. The full malloc family, including `malloc_usable_size`, remains the
sole versioned `allocator-mimalloc-libc-boundary` scope exception: it belongs
to the mimalloc-backed C libc boundary, not crabc-rs.

All hand-rolled cryptographic implementations have been removed. The bounded
C `crypt` profile delegates complete SHA-256-crypt (`$5$`) and SHA-512-crypt
MCF construction to pure RustCrypto `sha-crypt`; it accepts only canonical,
non-empty `Base64ShaCrypt` salts and preserves the dependency's explicit
default-rounds spelling. Arbitrary legacy salt text, DES, MD5-crypt, and
bcrypt remain documented compatibility limits. There is no AWS-LC, OpenSSL,
BoringSSL, or other C-backed crypto provider. The dependency and ABI adapter
review lives in `compat/crabc-rs/crypt-profile.md`.

The terminal-control seam now verifies typed `tcgetattr`, `tcsetattr`,
`tcgetpgrp`, `tcsetpgrp`, and `tcgetsid` using direct AArch64 ioctls and a
private kernel record. It does not overclaim PTY or terminal-session creation.

The final M10 verified slices remain deliberately narrow: checked
descriptor-to-descriptor range copying, explicit file-range writeback/wait,
connected vectored message I/O, current-directory retrieval, millisecond
realtime observation, typed eventfd counter I/O, process-accounting ticks,
access checks, pathname truncation,
process identity, group/session observation, process CWD mutation, global
writeback, FIFO-special-node creation, ownership mutation, kernel thread
identity, transient CPU observation, bounded kernel entropy, typed
create-or-truncate file creation, owned system-name observation, shared
open-file-description status flags, typed priority mutation, descriptor-only
microsecond timestamp updates, fixed-window load-average observation,
no-follow, directory-relative-follow, cwd-follow, and second-resolution
timestamp updates,
targeted read-only resource-limit observation, process CPU-time observation,
direct extended metadata, scheduler-priority-bound observation, round-robin
scheduler-interval observation, directory-relative access checks, CPU-affinity
snapshots, typed affinity-mask reapplication, Linux process-descriptor opening,
Rustix-shaped socket-type/protocol/cookie/domain/listening-state querying and
per-socket urgent-data-inline/broadcast-flag mutation, non-consuming pipe
duplication, read-only pipe-capacity and inode-seal observation/mutation, a
process-associated record-lock conflict query, and the complete four-symbol
descriptor group: owned Linux close, checked current-position range locks,
Rustix-shaped splice, and explicitly unsafe raw-memory vmsplice. The close
owner is consumed before the syscall and treats Linux `EINTR` as success, so
the released descriptor is never retried. They do not turn other broad
I/O, timer mutation, arbitrary socket options, addresses, ancillary data, or
multi-message APIs into implied coverage.

`process::{set_fs_uid, set_fs_gid}` is a deliberately unsafe Linux extension,
not an ordinary POSIX credential facade. `None` alone represents the
all-ones query word; an explicit all-ones typed ID is rejected. The kernel
returns the previous filesystem identity even for a denied requested change,
so its calling-task-only authority transition cannot be mistaken for musl's
process-wide `__synccall` credential semantics, which remain deferred.

`termios::{tcdrain, tcflush, tcflow, tcsendbreak}` is now the separate safe,
Rustix-compatible queue-control slice. Closed action and queue selector types
reach only the direct terminal ioctl boundary over a borrowed descriptor. The
private 44-byte termios record, foreground process/session control, and PTY
creation/session lifetime contracts remain deferred rather than being implied
by this quartet.

`fs::posix_fallocate` is the mode-zero, borrowed-descriptor allocation range
operation. It reuses the direct Linux `fallocate` seam and pre-syscall signed
`loff_t` range validation, but returns ordinary Rust `Errno` values rather
than C's integer error convention. File position is unchanged; temporary-file
race policy and open-by-handle ownership remain deferred.

`process::{get_current_dir_name, get_current_dir_name_alloc}` preserves a
logical CWD spelling only from a caller-owned optional `PWD` snapshot. A
nonempty absolute snapshot must match `.` by direct `(st_dev, st_ino)` checks;
its exact symlink and non-UTF-8 bytes are then returned, otherwise direct
`getcwd` supplies the physical spelling. The `lchmod` export is instead
documented ABI-only: Linux has no symlink-mode mutation, and musl's constant
`ENOTSUP` does not warrant an invented native operation.

`time::timespec_get` represents only C11's `TIME_UTC` case: a direct,
read-only realtime `clock_gettime` result with canonical nanoseconds and a
Rust `Result` rather than a C base-or-zero sentinel. Timezone ownership,
calendar parsing/formatting, and clock adjustment remain deferred.

`time::{RealtimeMillis, realtime_millis}` is the native replacement for musl's
`ftime`: it reads `CLOCK_REALTIME` through direct Linux/AArch64 syscall 113,
retains signed Unix seconds, and truncates a validated nanosecond remainder to
milliseconds. It does not expose C `struct timeb`, timezone state, allocation,
vDSO dispatch, or TLS `errno`; the remaining local-time, formatting, parsing,
and clock-control symbols stay deferred in `time.clock-calendar`.

`net::parse_ipv4_legacy` preserves musl's historical one-to-four component,
base-zero IPv4 grammar over a complete byte slice. Its typed `Ipv4Addr` result
accepts the valid all-ones address without `inet_addr`'s ambiguous sentinel,
and normal Rust formatting replaces `inet_ntoa` static storage. Strict modern
IP parsing and interface address families remain separate work; Ethernet text
codecs are covered by the dedicated native slice below.

The adjacent `net::{parse_ipv4_network_number, make_ipv4_address,
ipv4_local_number, ipv4_network_number}` capability covers musl's four
classful IPv4 helpers: parsing a legacy network number, constructing an
address from network and host portions, and extracting those portions from an
address. Its contract names `Ipv4Addr`'s logical network-order octets and
host-order `u32` numbers explicitly; musl's `htonl`/`ntohl` conversions make
the result independent of AArch64 object representation. It returns owned Rust
values and has no C sentinel, process-global static storage, allocator call, or
TLS `errno` state. This is only the classful IPv4 arithmetic slice: strict
modern presentation parsing remains separate from the owned interface-address
and ethers-database contracts below.

The adjacent Ethernet codec slice now verifies all four musl address codecs as
one native capability. `crabc_rs::net::EthernetAddress` owns six wire-order
octets; `parse` requires a complete byte slice with exactly six colon-separated
components, preserves musl's `strtoul(..., 16)` extensions (leading C
whitespace per component, optional sign, and optional `0x`/`0X` prefix), and
rejects no-conversion/empty components, out-of-range values, and trailing
bytes. `to_ascii_bytes` and `write_to` emit the exact musl canonical spelling:
two uppercase hexadecimal digits per byte separated by colons (`%.2X`,
`:%.2X`), without a NUL terminator or static storage. The release AArch64
static archive probe covers successful/noncanonical parsing, round-trip bytes,
uppercase formatting, short output, and malformed/trailing input; the Python
verifier rejects C Ethernet/address helpers, allocator symbols, and TLS errno.

The remaining former `network.address` group is now deliberately split by
contract rather than marked with one misleading parity status.
`net::ethers::{parse_line, EthernetLine, EthernetRecord, EthernetDatabase}`
is a verified crabc-specific extension: musl 1.2.6's `ether_line`,
`ether_hostton`, and `ether_ntohost` are failure stubs, while mature crabc
intentionally offers real ethers records. The native layer performs no
implicit `/etc/ethers` I/O; a caller supplies bounded bytes, valid source
records retain raw hostname bytes and order, database growth is fallible, and
first lookup is ASCII case-insensitive. `IN6ADDR_ANY`, `IN6ADDR_LOOPBACK`, and
`Ipv6Constants` are documented aliases for `core::net::Ipv6Addr`'s complete
all-zero and loopback values, not C global-object identity claims.

`net::netdevice::InterfaceAddresses` is the verified Linux-native replacement
for `getifaddrs`/`freeifaddrs`. It owns a direct
`RTM_GETLINK(AF_UNSPEC)` followed by `RTM_GETADDR(AF_UNSPEC)` snapshot with
raw bounded names, link-layer payloads (up to the musl 24-byte extension),
flags, opaque stats bytes, typed IPv4/IPv6 addresses/netmasks, optional
broadcast/destination, and exactly musl's link-local IPv6 scope rule. Drop
releases Rust-owned records; there is no C pointer-list or manual-free API.
Malformed netlink framing returns `BADMSG`, absent links/unknown families are
skipped, and allocation failure is `NOBUFS`. Loopback-only runtime tests,
synthetic parser tests, and the alloc-gated AArch64 archive prove direct
`socket`/`sendto`/`recvfrom`/`close` use with C enumeration/address helpers
and TLS errno forbidden.

Focused behavioral tests, release static-boundary probes, the Python metadata
harness, and the complete pinned Linux/AArch64 `./scripts/dev.sh crabc-rs`
gate pass as final evidence. Rustix source comparison remains applicable
only where Rustix has a matching surface. The ledger check confirms the
215-group inventory (156 verified, 16 deferred, 43 documented). The deferred
groups are the scope-aligned M11 backlog described above, rather than an
unacknowledged gap in the M10 completion claim.

`memory::ByteOps` closes the four non-basic byte primitives with borrowed
typed slices: volatile, compiler-fenced `explicit_bzero`; delimiter-aware
`memccpy`; suffix-returning `mempcpy`; and pairwise `swab` with its odd tail
left untouched. The allocation-free AArch64 probe rejects the specialized C
symbols, allocator calls, and TLS errno rather than mistaking compiler-lowered
ordinary copies for a C ABI hop.

`text::{CStrBuilder, CStrWrite, PaddedCopy}` holds a C-string invariant while
making exact, truncating, padded, and append-prefix writes explicit. Its
alloc-gated `CString` duplication keeps non-UTF-8 bytes intact. Native ASCII
case folding, musl-compatible version comparison, empty-preserving splitting,
and independent token cursor state replace the corresponding process-global
or raw-pointer C interfaces. `path::{PathPart, basename, dirname}` accepts
NUL-free C strings or checked byte slices, preserving musl's lexical path
rules without creating an invalid interior-NUL string.

`numeric::{EncodedLong, DecodedLong, DecodeStatus}` gives the historical
`a64l`/`l64a` payload an owned six-byte representation: it retains musl's
low-32-bit, least-significant-digit radix-64 encoding and makes termination,
invalid input, and the six-digit limit typed outcomes. `collections::{Search,
CallbackSort}` replaces raw comparator pointers with ordered typed slices,
alloc-gated `Vec` insertion, and an explicit mutable sorting context. The
native probe and the expanded C fixture cover search, append capacity, and
context-directed unstable order without relying on C callbacks in Rust.

`process::kernel_brk` makes the allocator-uncoordinated kernel-break query
explicitly unsafe; it is not a second allocation strategy. The accompanying
VM vocabulary distinguishes musl's successful POSIX `DONTNEED` no-op from
Linux page discard, makes global memory-lock policy visible, and fixes the
legacy remap compatibility words to zero. The C `brk`/`sbrk` and
`posix_madvise` adapters now follow those musl rules as well.

`net::{MMsgHdr, sendmmsg, recvmmsg}` uses private Linux message records to
retain every payload borrow and report partial batch completion, per-message
lengths, flags, and timeout mutation without exposing uninitialized receive
storage. `sockatmark` is deliberately separate: it is one fixed ioctl with a
typed boolean result, not a generic pointer-bearing ioctl surface.

`time::{setitimer, alarm, ualarm}` uses validated microsecond process-timer
settings and returns the complete prior state. `PosixTimer` owns a private
kernel timer ID, typed nanosecond settings, and non-callback signal modes;
explicit deletion is retryable and `Drop` is best effort. `SIGEV_THREAD`
remains a separate deferred runtime contract. `sleep` and `usleep` are
documented as subsumed by `nanosleep(Duration)` with explicit interruption.

`time::{CalendarTime, time, difftime, gmtime, timegm}` adds a strict,
musl-derived UTC Gregorian value without C `tm` storage, static buffers, or
timezone state. It rejects invalid civil fields and C `timegm` normalization
instead of creating an invalid typed value; local time, format/parse, and
clock-discipline APIs remain separate contracts. `process::chroot` follows
the Rustix path shape but documents its process-wide root effect; its
regression uses only a nonexistent path. `process::{umask, setrlimit}` make
their process-global mutations explicit, validate resource-limit ordering,
and restore the test state. The direct proofs require only AArch64 syscalls
51, 113, 166, and 261. Finally, the C `remove` adapter now follows musl's
`EISDIR` retry with `AT_REMOVEDIR`; native Rust continues to represent file
unlinking and directory removal as separate typed operations.

`fs::{canonicalize_into, canonicalize}` provides a physical, byte-preserving
`realpath`-equivalent with caller-buffered and alloc-gated owned forms. It
resolves `.`/`..` and absolute or relative symlinks through stable directory
descriptors, enforces `PATH_MAX` and the forty-link bound, and exposes output
capacity failure instead of a C result pointer or implicit allocation.

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

`thread::futex::{Flags, Timespec, wait, wake}` adds the bounded Rustix-shaped
Linux futex primitive. A borrowed `AtomicU32` makes the word alignment and
lifetime contract explicit, while the optional borrowed timeout keeps the
kernel's relative `FUTEX_WAIT` form. `PRIVATE`, `CLOCK_REALTIME`, and future
flag bits go directly to Linux for operation-specific validation; direct
`EAGAIN`, `EINTR`, timeout, and wake-count outcomes are not rewritten. This
does not claim priority-inheritance, requeue, bitset, futex-fd, or waitv
coverage, nor a C pthread ABI.

`thread::{Uid, Gid, set_thread_res_uid, set_thread_res_gid}` exposes Rustix's
Linux `setres*` shape with the actual calling-task-only effect. `None`
is the kernel all-ones no-change sentinel, while an explicit all-ones typed ID
is rejected so it cannot silently change meaning. This is not musl's
process-wide synchronized C credential contract, which remains deferred.

`fs::{create_temp_dir_into, create_temp_dir, create_temp_dir_at_into,
create_temp_dir_at}` replaces `mkdtemp`'s mutable `XXXXXX` template with an
explicit parent, prefix, caller buffer or alloc-gated result, 96-bit kernel
random suffix, and atomic `mkdirat(..., 0700)` retry loop. The returned path
is not a retained directory capability; callers that coordinate CWD changes
retain a parent descriptor and use the `_at` forms.

The first M10 implementation capability is an allocation-free native text
converter, `text::{TextEncoding, TextConverter}`, built on
`crabc_core::iconv`. It supports strict UTF-8, ASCII, UTF-16LE/BE,
UTF-32LE/BE, Linux/AArch64 little-endian `WChar`, and ISO-8859-2 through -16
over borrowed input/output slices. It reports typed resumable progress and
conversion errors, and has an AArch64 static probe that rejects C `iconv`, C
allocator, and TLS-errno references. Undefined ISO table slots retain their
extracted table scalar in this native contract. The public C `iconv*` symbols
and their broader legacy codec/alias behavior remain deferred until the
compatibility adapter can use the same complete typed core; this initial slice
must not be read as C iconv parity.

`text::AsciiClass` now also completes the fixed C/POSIX byte ctype family with
typed `u8` predicates and ASCII conversions. It explicitly treats high bytes
as unclassified rather than invalid, and makes C EOF/negative integers,
locale handles, and wide-character behavior unrepresentable at this boundary.

`stdio::{BoundedFormatter, FormatResult, format_to}` now provides the native
bounded-output seam for the useful `snprintf`/`vsnprintf` shape: typed
`core::fmt::Arguments`, caller-owned byte storage, exact required UTF-8 byte
counts, and valid-prefix truncation without allocation, C varargs, a trailing
NUL, locale state, or errno. The M10 static probe rejects C formatted-output,
allocator, and errno references.

The public C `iconv` adapter has a musl-grounded error-progress fixture for
incomplete UTF-8, surrogate rejection, and committed progress before
`EILSEQ`/`E2BIG`; those cases now pass. ISO-8859-2 through -16 repertoire data
has one allocation-free source in `crabc_core::iconv`, used by the legacy C
adapter. This is a staged data migration, not a claim that legacy C iconv
aliases or all codec behavior are yet complete.

`text::{NumberParser, NumberParseError}` now supplies allocation-free, full
slice ASCII integer parsing for explicit radices 2 through 36 and signed or
unsigned 64-bit bounds. It intentionally does not skip whitespace, infer a
base prefix, consult locale, return an end pointer, or use errno. Floating,
wide-character, locale-sensitive, and legacy conversion formatting remain
separate M10 work.

`rand::{RandomState, random_u32, getrandom, GetRandomFlags}` now covers owned
deterministic random state plus fallible direct Linux kernel entropy. It does
not borrow C's mutable process-global rand families and does not claim that
the deterministic SplitMix64 sequence is cryptographic after seeding.

`fs::{StatFs, StatVfs, statfs, fstatfs, statvfs, fstatvfs}` now exposes typed
filesystem-capacity observations. The direct Linux/AArch64 `statfs` and
`fstatfs` syscalls retain their kernel layout privately, while the documented
`StatVfs` mapping follows Rustix's conservative Linux conversion. This does
not claim the remaining C path/metadata aliases.

`fs::{fallocate, FallocateFlags}` now allocates, keeps, zeros, or punches a
checked byte range through the direct Linux/AArch64 syscall. It borrows the
descriptor, preserves its offset, accepts only a closed set of supported mode
combinations, and rejects invalid signed `loff_t` ranges—including sum
overflow—before a syscall. POSIX allocation aliases and temporary-path policy
remain separate work.

`fs::syncfs` flushes the mounted filesystem associated with a borrowed
descriptor through its direct Linux/AArch64 syscall. It is distinct from
per-file durability and does not cross a C ABI or TLS errno boundary.

`fs::sync` initiates global filesystem writeback through its direct
zero-argument Linux/AArch64 syscall. Linux waits for kernel/filesystem
writeback completion, whereas POSIX permits scheduling-only behavior; neither
contract proves that a device volatile cache has reached nonvolatile media.

`fs::{Advice, fadvise}` models the six POSIX file-access hints as a closed
native type. Its range is either an explicit nonzero length or the kernel's
zero-length-to-end-of-file convention; checked signed ABI bounds reach the
direct `fadvise64` syscall without reproducing C's direct-error interface.

`fs::readahead` initiates an advisory file-cache read on a borrowed descriptor
without changing its current position. Its unsigned offset and length form a
checked half-open range; values or range ends outside Linux's signed `loff_t`
domain return `EINVAL` before the direct syscall rather than being truncated.

`fs::copy_file_range` copies a requested range from one borrowed descriptor to
another through the direct Linux/AArch64 syscall. `Some(&mut offset)` retains
the independent explicit offset without moving the descriptor, while `None`
retains Linux's shared-position mode. All offsets and range ends are checked
for signed `loff_t` representation, short copies remain visible, and explicit
caller offsets commit only after a successful kernel return.

`process::{getcwd, getcwd_alloc}` reads the current directory through the
direct Linux/AArch64 syscall. The allocation-free `Buffer<u8>` form exposes
only the initialized NUL-terminated prefix of caller storage; the alloc-gated
convenience reuses caller capacity and grows only after `ERANGE`. Neither form
adopts C's allocation ownership rule or raw pointer/length interface.

`process::{chdir, fchdir}` changes that process-global directory through direct
Linux/AArch64 syscalls. The safe Rustix/std-shaped API has no per-thread
isolation: callers must coordinate concurrent pathname work. Its regression
restores the original directory through an owned descriptor even on an error
path.

`fs::{access, Access}` checks a pathname from the process current directory
with a closed read/write/execute/existence mode set. It retains Linux's
real-ID `access()` semantics through the direct three-argument `faccessat`
syscall, but deliberately does not claim directory-relative, effective-ID, or
newer `faccessat2` flag behavior.

`fs::sendfile` transfers between borrowed descriptors without changing
ownership. `Some(&mut offset)` advances only that explicit offset, while
`None` advances the input descriptor's current position; short transfers stay
visible and offsets outside signed `off_t` fail before the direct syscall.

`fs::truncate` applies the same checked unsigned-byte-count boundary to a
pathname-selected file. A length outside signed `loff_t` is rejected as
`EINVAL` before path conversion or the direct syscall, so it cannot mutate the
selected file.

`fs::ftruncate` now rejects any `u64` length outside Linux's signed `loff_t`
range before descriptor borrowing or the direct syscall. Its focused regression
proves the error is `EINVAL` and leaves the existing file size untouched,
eliminating the prior unsigned-to-signed cast-wraparound path.

`fs::{Dev, FIFO_DEVICE, mknodat, mkfifo, mkfifoat}` creates Linux filesystem
nodes through direct `mknodat`. The caller supplies an explicit node type,
permissions, and exact `dev_t`; metadata-only `FileType::Unknown` and any
caller-supplied type bits in `Mode` fail as `EINVAL` before the syscall. FIFO
helpers supply their required zero device value, and the regression uses only
FIFOs, avoiding privileged device-node assumptions.

`fs::{ChownFlags, chown, lchown, fchown, chownat}` changes ownership through
direct `fchownat`/`fchown` on Linux/AArch64. `None` is the only spelling for
the kernel's all-ones no-change field; a raw all-ones `Uid` or `Gid` is
rejected rather than silently reinterpreted. The ownership-specific flag type
admits only final-symlink no-follow, so unrelated `AT_*` meanings cannot cross
this API boundary.

`thread::sched_getcpu` returns the calling thread's transient current CPU via
direct `getcpu` into private valid stack storage. It matches Rustix's
infallible observation shape without implying affinity, pinning, or a stable
thread property.

`rand::{getentropy, GETENTROPY_MAX_LENGTH}` fills caller-owned storage from
direct Linux/AArch64 `getrandom` with the exact musl 256-byte request ceiling.
Oversize inputs are rejected as `EIO` before the kernel boundary; interrupted
requests retry, and a result is exposed only after every output byte is
initialized. This avoids C's process/error state while retaining the useful
full-or-error entropy contract.

`fs::create` provides the deliberately narrow `creat` equivalent through
`openat`: write-only, create, and truncate, with no implicit close-on-exec.
It returns an owned descriptor, so broader creation policy remains explicit in
`fs::open` rather than being hidden behind legacy C naming or flags.

`system::{Uname, uname}` exposes owned kernel name observations; callers use
`Uname::{nodename, domainname}` rather than C buffer sizing, truncation, or
errno conventions. This follows Rustix's `uname`-backed hostname direction and
keeps the Linux/AArch64 UTS layout private.

`fs::{fcntl_getfl, fcntl_setfl}` handles only the Rustix-shaped status-flag
forms of `fcntl`. It retains unknown observed `OFlags` bits and keeps the
shared-open-file-description effect explicit: duplicate descriptors see a
status change. Descriptor-local `FD_CLOEXEC` remains a separate typed
operation, and kernel policy/permission outcomes remain direct errors.

`process::{setpriority_process, setpriority_process_group,
setpriority_user}` adds typed Linux/AArch64 priority mutation. The closed
`Priority` range is validated before the direct syscall, while the target
vocabulary makes process-wide process-group/user effects explicit. The
isolated regression never changes the test runner's own scheduling state;
legacy C `nice` increment and errno-translation behavior remains deferred.

`fs::{futimes, Timeval}` supplies the descriptor-only microsecond timestamp
operation over the existing direct `utimensat` futimens form. `None` is the
typed current-time request; supplied signed seconds remain exact while invalid
microseconds are rejected before conversion to nanoseconds and before the
syscall. Path-based timeval aliases retain their separate symlink/path policy
work.

`system::{LoadAverages, load_average}` turns Linux `sysinfo`'s three 16.16
fixed-point load words into an owned one/five/fifteen-minute observation. It
does not reproduce C `getloadavg`'s partial caller buffer or sentinel protocol
and adds no new kernel or runtime boundary.

`fs::{lutimes, Timeval}` applies the same checked microsecond conversion to a
pathname while passing Linux's final-symlink no-follow flag. The test proves
that the symlink receives the update while the target metadata is unchanged;
follow-path and directory-relative timeval aliases stay separate.

`process::getrlimit_for` adds a selected-process, read-only `prlimit64`
observation. `None` selects the caller and `Some(Pid)` preserves Linux's
permission, exit, and PID-reuse behavior; the new-limit pointer is always
null, so limit mutation remains explicitly deferred.

`fs::{futimesat, Timeval}` provides the directory-relative, final-symlink-
following timeval form. It takes an owned descriptor borrow and a non-null
typed path, uses zero `utimensat` flags, and retains the checked microsecond
conversion and typed current-time request; cwd-only, no-follow, and C
null-path forms remain separate contracts.

`time::process_cpu_time` samples Linux's known process CPU-time clock as a
canonical `Duration`. It reuses the direct clock seam but deliberately does
not expose C `clock_t` microseconds, its overflow sentinel, or calendar-time
semantics.

`time::{DynamicClockId, clock_gettime_dynamic}` now covers the Rustix-shaped
fallible dynamic-clock observation. `Known` clocks and borrowed Linux
clock-device descriptors use direct AArch64 syscall 113 with caller-owned
timespec storage; descriptor lifetimes are retained and kernel failures such
as `EINVAL` are preserved. The proof rejects libc, vDSO, and TLS errno
references; clock mutation remains deferred.

`fs::{utimes, Timeval}` is the AT_FDCWD, final-symlink-following timeval
form. It shares the checked conversion and typed current-time request, while
keeping cwd selection explicit and leaving C's nullable-pointer form outside
the native contract.

`fs::{utime, Utimbuf}` adds the corresponding whole-second path timestamp
operation. Its two signed seconds are privately converted into zero-nanosecond
records for direct `utimensat`; `None` selects Linux current time, and the
AT_FDCWD/zero-flag path resolves a final symlink to its target. The native
value makes no public C-layout or nullable-pointer promise.

`fs::statx` exposes Linux extended metadata through a typed 256-byte private
wire record and an authoritative returned field mask. It rejects the reserved
request bit before syscall entry and preserves direct kernel errors—including
`ENOSYS`—rather than adding musl's `fstatat` fallback or a process-global
availability cache.

`process::scheduler_priority_bounds` observes the fixed priority ranges of
the closed `SCHED_OTHER`, `SCHED_FIFO`, and `SCHED_RR` policy vocabulary. It
uses the two direct scalar syscalls, preserves kernel errors, and rejects an
inverted result; scheduler-policy selection and parameter mutation stay
deferred.

`thread::sched_rr_get_interval` observes one Linux task's round-robin quantum
through direct syscall 127. `None` retains PID-zero current-task selection,
while `Some(Pid)` preserves task lookup and permission errors; the private
timespec becomes a checked `Duration` and the operation does not select or
mutate a scheduling policy.

`fs::accessat` follows Rustix's `Access`/`AtFlags` source shape while keeping a
direct Linux/AArch64 boundary: empty flags use `faccessat`, while the closed
`EACCESS`/`SYMLINK_NOFOLLOW` subset uses `faccessat2`. Other distinguishable
at-family bits are rejected before the syscall; Linux's shared
`REMOVEDIR`/`EACCESS` bit is necessarily interpreted as `EACCESS`. There is
no musl/Rustix fallback, credential emulation, or availability cache, so an
older kernel's `ENOSYS` remains observable.

`thread::{CpuSet, sched_getaffinity}` exposes the Rustix-shaped fixed 1024-bit
read-only CPU mask through direct syscall 123. A kernel `EINVAL` for an
insufficient mask capacity remains visible without allocation, retry, or
truncation; successful short writes have their private tail zeroed. `CpuSet`'s
local construction and bit methods mutate only the value, not task affinity.
Each call is a transient affinity snapshot, not a kernel-mutation API or a
stability promise across calls.

`thread::sched_setaffinity` supplies the paired direct syscall 122 mutation
over that same fixed `CpuSet`. `None` selects the calling task, and `Some(Pid)`
preserves task lookup and permission errors. Linux retains authority to
intersect a requested mask with online and cpuset-permitted CPUs; an empty
effective mask remains `EINVAL`. The regression reapplies the observed mask,
exercising the mutation without intentionally changing the task's eligibility.

`io::{pread, pwrite}` now provides direct Linux/AArch64 positioned I/O over a
borrowed descriptor, caller-owned `Buffer`, and explicit non-negative `u64`
offset. It preserves descriptor position and supports `MaybeUninit` reads;
flag-bearing, splice, and remaining descriptor extensions stay deferred.

`io::{IoSlice, IoSliceMut, readv, writev}` now covers the ordinary initialized
vectored-I/O pair. The wrappers retain source or exclusive destination slice
lifetimes and pointer provenance through the direct Linux/AArch64 syscalls;
short operations remain visible to callers, which can explicitly advance a
segment before retrying. Empty segments and vectors are valid. This does not
claim positioned/flag-bearing vector I/O, splice, or the rest of the descriptor
extension family.

`io::{preadv, pwritev}` extends those same initialized segment contracts to
explicit `u64` offsets without changing the descriptor position. The
Linux/AArch64 ABI is recorded directly as low and high 32-bit offset words,
including rejection of offsets outside signed `off_t`; short reads leave the
remaining initialized destination bytes untouched. Flag-bearing vector I/O and
splice remain separate work.

`io::{preadv2, pwritev2, ReadWriteFlags}` adds the documented Linux RWF flags
to that exact vectored contract. Unknown flag bits are rejected before the
direct syscall; ordinary offsets use the same explicit words while `u64::MAX`
preserves Linux's current-offset sentinel semantics.

`io::{sync_file_range, SyncFileRangeFlags}` submits the closed Linux
writeback/wait flag set for one checked descriptor range. It validates signed
`loff_t` bounds before the direct Linux/AArch64 ABI call and retains
zero-length's through-end-of-file meaning; this is not a claim of process-wide
`sync` or C errno semantics.

`event::{ppoll, PollFd, PollFlags}` adds the mask-aware readiness form over
borrowed descriptor records. An optional borrowed `SignalSet` is installed
atomically only for the direct Linux/AArch64 syscall and uses the exact
eight-byte kernel mask; the immutable timeout is copied because Linux may
write the ABI record. The existing `poll` convenience API is its explicit
unmasked form. `event::{epoll::create_legacy, epoll::wait_with_mask}` adds the
legacy positive-size epoll alias and mask-aware wait over the existing typed
event buffer. `event::{FdSetElement, FdSetIter, fd_set_*, select, pselect}`
provides the Rustix-shaped Linux descriptor bit-vector contract: readiness
rewrites the sets, raw descriptor liveness is unsafe, and `pselect6` receives
the exact eight-byte kernel signal-set width. The C select adapter validates
negative timeval components, checked-normalizes large microsecond fields, and
keeps caller timeouts immutable.

`event::{eventfd_read, eventfd_write}` borrows an event descriptor and keeps
its exact eight-byte counter record private as a typed `u64`. The direct
read/write syscalls retain normal counter-reset and semaphore behavior,
all-ones write rejection, and nonblocking `EAGAIN`; no raw partial buffer or C
eventfd wrapper crosses this boundary. The select-family and legacy epoll
aliases are now separately verified; pause and unrelated readiness extensions
remain distinct contracts.

`unsafe mm::{madvise, Advice}` gives Linux an explicitly bounded set of
access-pattern or discard hints for a caller-proven mapping. Page alignment,
range, pointer provenance, and potential content invalidation are all unsafe
caller obligations; no C advisory ABI or errno state crosses this boundary.
Locking, remapping, residency, and the remaining VM policies stay deferred.

`unsafe mm::{msync, MsyncFlags}` synchronizes a caller-proven mapping through
the direct Linux/AArch64 syscall. Page alignment, lifetime, provenance, and
the cache/invalidation effects remain explicit unsafe obligations; the
Rustix-compatible Linux flags cross no C sentinel or errno boundary.

`unsafe mm::{mincore, MINCORE_PAGE_SIZE}` snapshots mapping residency into an
exclusive caller-owned vector. Capacity is checked with the 4 KiB AArch64
minimum page size, safely over-provisioning larger configured pages; mapping
alignment, lifetime, provenance, and output disjointness remain unsafe caller
obligations.

`unsafe mm::{mlock, mlock_with, munlock, MlockFlags}` locks or unlocks one
caller-proven mapped range through direct Linux/AArch64 `mlock`, `mlock2`, and
`munlock` syscalls. `ONFAULT` is explicit, while mapping lifetime,
rounded-range validity, pointer provenance, and memlock-budget effects remain
unsafe caller obligations. Process-wide `mlockall`/`munlockall` remain
separate work.

`unsafe mm::{mremap, mremap_fixed, MremapFlags}` resizes or moves a
caller-owned mapping and returns its successor address. The old range is
consumed on success; fixed relocation also invalidates the replaced destination
mapping. The only public flag is `MAYMOVE`; fixed destination selection has a
separate API, and `DONTUNMAP` remains deferred because it changes ownership.

`fs::{Dir, DirEntry}` now supplies a descriptor-owning, caller-buffered native
directory stream. Its entries borrow the stream and expose byte names rather
than assuming UTF-8; EOF and the first error are terminal states. Controlled
`O_RDONLY | O_DIRECTORY | O_CLOEXEC` opening, drop-based closure, and both
crabc-rs and standard Rust FD borrowing are part of the contract.

`Dir::{rewind, seek}` and the underlying `RawDir` add directory cursor
positioning without adopting mutable C `DIR` state. Cookies are opaque Linux
`d_off` values, never byte positions, and each operation discards buffered
records. Rewind defers direct `lseek(fd, 0, SEEK_SET)` until the next read;
seek reports the direct failure immediately. Both retry `EINTR`. Sorting,
walking, reentrant C records, and a tell-position operation remain distinct
work.

`time::{UnixTime, wall_clock}` provides a fallible UTC Unix-epoch reading from
the direct Linux/AArch64 `gettimeofday` syscall. It carries signed seconds and
normalized nanoseconds, requests no legacy timezone output, and does not use
C `timeval`, vDSO/libc routing, allocation, or TLS errno. Calendar conversion,
formatting, clock mutation, and the other global-time semantics remain separate
native work.

`time::{getitimer, IntervalTimerKind, IntervalTimerValue, GetitimerError}`
reads but never mutates the three Linux process interval timers. The closed
selector vocabulary and private validated `Duration` pair keep arbitrary C
selectors and malformed signed `timeval` fields out of the public API; timer
arming and signal-delivery semantics remain separate work.

`process::{times, ClockTicks, ProcessTimes}` reads Linux process accounting as
opaque clock ticks. The private validated four-word `tms` record and the
syscall's separate elapsed-tick return remain distinct observations; the API
does not invent a `CLK_TCK` conversion, expose C output storage, or claim
calendar-time semantics.

`time::{nanosleep, SleepOutcome, SleepError}` now takes `core::time::Duration`
and makes Linux interruption observable: completion and an `EINTR` result with
the kernel's remaining duration are distinct outcomes, and it never silently
retries. C seconds/microseconds sleep aliases, process-global timers, and timer
callback lifetime are intentionally still separate native contracts.

`time::{clock_nanosleep_relative, clock_nanosleep_absolute}` adds clock-based
sleeping without collapsing its two semantic modes. Relative sleeps preserve
the kernel remaining duration on `EINTR`; absolute sleeps return `EINTR` as an
error without fabricating a remainder, and reject non-canonical nanoseconds
before the syscall. Calendar/timezone behavior and global clock mutation remain
separate native work.

`process::{getuid, geteuid, getgid, getegid, Uid, Gid}` now reads the calling
task's real and effective identities through direct zero-argument Linux
syscalls. The opaque value types retain exact raw `uid_t`/`gid_t` words while
preventing accidental interchange with unrelated integers; all
authority-changing credential and limits semantics remain distinct work.

`process::{getresuid, getresgid, UidTriple, GidTriple}` adds real, effective,
and saved-set identity observations through direct Linux/AArch64 syscalls into
private caller-owned words. Triple fields retain opaque UID/GID types, while
all credential mutation remains separate work.

`process::{Resource, Rlimit, getrlimit}` now exposes read-only resource-limit
observations via `prlimit64` with PID zero and a null new-limit. The closed
Linux resource vocabulary maps infinity to `None`; no process-wide limit
mutation is claimed by this slice.

`process::{PidfdFlags, pidfd_open}` adds the Linux process-descriptor creation
extension through direct syscall 434. It transfers a fresh descriptor into
`OwnedFd`, keeps `NONBLOCK` plus future flag bits for kernel validation, and
does not cache or emulate unsupported kernels: `ENOSYS`, target-lifetime,
permission, descriptor-limit, and flag errors remain direct. This is native
Rustix compatibility, not a claim for a musl C export.

`process::{ResourceUsageTarget, ResourceUsageTime, ResourceUsage, getrusage}`
adds direct read-only resource accounting for the pinned self, children, and
thread targets. It preserves canonical microsecond times and fourteen
initialized counters while deliberately omitting musl's uninitialized reserved
compatibility tail.

`process::{getgroups_count, getgroups, Gid}` exposes the read-only Linux
supplementary-group query/fill protocol through typed caller-owned storage. It
preserves the separate supplementary list rather than adding the effective
group ID, and documents `EINVAL` retry behavior when credentials change
between sizing and fill; no credential mutation is included.

`process::{Priority, PriorityTarget, getpriority}` now reads process,
process-group, or user nice values without C's ambiguous `-1`/errno shape. It
translates Linux's non-negative `[40, 1]` kernel success representation into
the closed `[-20, 19]` typed range; priority mutation remains separate work.

`process::{getpid, getppid, Pid}` is independently verified as a direct,
read-only kernel identity query. The caller PID is positive and typed; Linux's
zero-parent namespace-init/no-visible-parent sentinel becomes `None`. Process
creation, execution, waiting, and mutation remain separate contracts.

`process::{getpgid, getpgrp, getsid}` exposes read-only group/session
observations for the current process or an explicit typed `Pid`. `getpgrp` is
the independently tested current-group shorthand over that same direct
`getpgid` kernel contract; group/session creation or mutation, spawning, and C
aliases remain separate contracts.

`thread::gettid` is independently verified as a positive, stable kernel task
identity, including distinct concurrent kernel threads. It does not stand in
for a pthread handle, cancellation, or TLS contract, which remain deferred.

`fs::{memfd_create, MemfdFlags}` creates an anonymous Linux memory file with a
byte-oriented `Arg` name and transfers its successful descriptor to `OwnedFd`.
The closed flag set contains only stable `CLOEXEC`, sealing, and default-huge
page choices; huge-page size encodings and newer exec-policy flags remain
explicit future work rather than silently forwarded kernel bits.

`fs::{SealFlags, fcntl_get_seals}` adds the bounded read-only seal companion:
direct `fcntl(F_GET_SEALS)` syscall 25 reports all observed Linux seal bits,
including future bits. An allow-sealing memfd begins unsealed, whereas a plain
memfd carries `F_SEAL_SEAL`; ineligible descriptors retain direct `EINVAL`.

`fs::fcntl_add_seals` is the matching bounded mutator over direct
`fcntl(F_ADD_SEALS)`. It supplies seal bits as the kernel's immediate integer
argument, retains `EPERM` for unsealable or already-finally-sealed memfds, and
leaves the public C `fcntl` ABI in its separate status-flag capability.

`process::{Flock, FlockType, FlockOffsetType, fcntl_getlk}` adds the
read-only `fcntl(F_GETLK)` conflict query. A validated private AArch64 flock
record becomes `None` for `F_UNLCK` or a typed first conflicting lock. Fcntl
locks are process-associated, so the regression uses a forked child to observe
the parent's lock; lock mutation remains separate work.

`net::{NetworkU16, NetworkU32}` makes network byte order explicit as owned
big-endian bytes, covering the value-only `htonl`/`htons`/`ntohl`/`ntohs`
capability without C static storage or ABI calls. Interface address-list enumeration,
address helpers, and hostname state remain separate native work.

`net::{socket, Shutdown}` now provides typed socket construction and directional
shutdown via direct Linux/AArch64 syscalls. Creation flags are a closed set,
and non-default protocols retain Rustix's nonzero raw word before a bit-for-bit
Linux C-`int` syscall conversion. Success transfers unique ownership to `OwnedFd`.
Address encoding,
connect, options, ancillary data, and multi-message operations remain explicit
later slices.

`net::{set_socket_reuseaddr, socket_reuseaddr}` adds the one bounded basic
socket-option seam: Linux `SOL_SOCKET/SO_REUSEADDR` is a Rust `bool` over
private four-byte kernel storage. It validates the returned length and retains
kernel errors, while exposing no arbitrary C level/name/pointer/length
interface; broad socket options remain separate work.

`net::sockopt::socket_type` adds Rustix's exact typed `SOL_SOCKET/SO_TYPE`
query. Its private four-byte result becomes the existing raw-preserving
`SocketType`, preserving an unknown future type and a non-socket descriptor's
direct `ENOTSOCK`; arbitrary socket options remain separate work.

`net::sockopt::socket_protocol` adds the companion Rustix-shaped
`SOL_SOCKET/SO_PROTOCOL` query. The direct four-byte result maps zero to
`None` and otherwise preserves the exact raw `Protocol` word; fixed option
storage retains direct `ENOTSOCK` without expanding to arbitrary options.

`net::sockopt::socket_cookie` adds the fixed-width Rustix-shaped
`SOL_SOCKET/SO_COOKIE` observation. It returns the kernel's opaque `u64`
unchanged through private eight-byte storage; repeated reads on a live socket
are stable, but the facade makes no broader lifetime or global-uniqueness
claim. Non-socket descriptors retain direct `ENOTSOCK`.

`net::sockopt::socket_domain` adds Rustix's typed `SOL_SOCKET/SO_DOMAIN`
query through fixed private storage. Its signed kernel result is checked before
conversion to the closed `AddressFamily` type; unrepresentable values become
`OPNOTSUPP`, while non-socket descriptors retain `ENOTSOCK`.

`net::sockopt::socket_acceptconn` adds Rustix's fixed
`SOL_SOCKET/SO_ACCEPTCONN` observation. It returns a Rust `bool` from private
four-byte kernel storage; a stream socket reports `false` before `listen` and
`true` afterward, while non-socket descriptors retain `ENOTSOCK`.

`net::sockopt::{set_socket_oobinline, socket_oobinline}` adds Rustix's fixed
`SOL_SOCKET/SO_OOBINLINE` boolean option. Private four-byte Linux storage maps
to Rust `bool`; the bounded contract covers only querying/mutating the
per-socket flag, not urgent-data I/O, and preserves `ENOTSOCK` on a non-socket
descriptor.

`net::sockopt::{set_socket_broadcast, socket_broadcast}` adds Rustix's fixed
`SOL_SOCKET/SO_BROADCAST` boolean option. Private four-byte Linux storage maps
to Rust `bool`; it covers only the per-socket flag and preserves `ENOTSOCK`,
not broadcast packet transmission or interface behavior.

`pipe::{SpliceFlags, tee}` duplicates up to a requested count from one pipe to
another through direct syscall 77 without consuming the source. The copied
count can be short, and all `SPLICE_F_*` bits are preserved for kernel
validation; offset-bearing `splice` and raw-memory `vmsplice` remain distinct
contracts.

`pipe::fcntl_getpipe_size` is the companion read-only pipe observation through
direct `fcntl(F_GETPIPE_SZ)` syscall 25. It returns the current shared kernel
capacity as a `usize` and preserves non-pipe errors; callers must not treat the
value as stable if another actor resizes the pipe. `F_SETPIPE_SZ` remains a
separate mutating contract.

`net::{sendmsg, recvmsg, MsgIoSliceMut, RecvMsg}` adds connected vectored
message I/O through private Linux `msghdr` records. The public contract has no
destination/name record, ancillary control data, public raw header, or
multi-message operation. `RecvMsg` carries the complete `MSG_TRUNC` byte count
and message flags while yielding only initialized prefixes of caller-owned
`MaybeUninit` segments.

`net::{IpAddress, SocketAddress, connect}` now makes one allocation-free
IPv4/IPv6 endpoint type available to no-std socket code while preserving the
existing `resolver::{IpAddress, SocketAddress}` spelling through re-exports.
The direct connection seam writes exact Linux address records, rejects nonzero
IPv4 scope rather than silently discarding it, and forwards IPv6 scope IDs;
binding, listening, received-address, and option operations remain separate.

`net::{bind, getsockname}` extends the shared endpoint encoding through direct
Linux/AArch64 local-address syscalls. Returned sockaddr lengths are validated
before decoding; unrepresented address families return `AFNOSUPPORT` rather
than a partial opaque buffer. Listening, peers, options, ancillary data, and
message-address APIs remain separate work.

`net::getpeername` reuses the same strict endpoint decoder for connected peer
addresses. It preserves Linux `NOTCONN` and returns `AFNOSUPPORT` for families
outside `SocketAddress`, rather than exposing an opaque sockaddr record.

`net::{listen, accept, accept_with, accept4, acceptfrom, acceptfrom_with}`
adds the borrowed-listener server-socket lifecycle. Accepted descriptors move
into `OwnedFd`; `accept4` has a closed atomic `CLOEXEC`/`NONBLOCK` flag set;
and peer-returning forms strictly decode IPv4/IPv6 before returning, dropping a
just-created descriptor if another family becomes `AFNOSUPPORT`. Socket
options, message addresses, ancillary data, and multi-message operations stay
separate work.

`net::{sendto, recvfrom}` adds addressed IPv4/IPv6 datagrams on the same
borrowed-descriptor boundary. Send preserves strict endpoint encoding; receive
strictly decodes the source, retains Buffer initialization and `MSG_TRUNC` full
length semantics, and returns `AFNOSUPPORT` rather than exposing an opaque
sockaddr for another family.

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

`net::netdevice::InterfaceAddresses` separately owns musl-shaped interface
address observation through direct link and address netlink dumps. Raw
kernel names, packet addresses, flags, stats bytes, IPv4/IPv6 addresses,
prefix-derived masks, broadcast/destination distinction, and link-local IPv6
scope are all contained in typed Rust records; the C pointer-list and
`freeifaddrs` lifetime are not exposed. `net::ethers` is instead the explicit
caller-supplied crabc extension for real ethers records, and the two IPv6
global values are standard Rust `Ipv6Addr` values. They are separate contracts
and are not presented as musl's stub host-lookup behavior.

---

# AArch64 maturity gates

These gates measure quality and evidence for the sole active platform. Passing
them does not activate another architecture.

## Gate A — foundation

Core libc substrate is verified rather than merely present.

## Gate B — surface

```text
100% expected musl AArch64 API/symbol surface accounted for
no fake stubs
```

## Gate C — ABI

```text
symbol kinds/bindings correct
public type layouts correct
constants correct
native AArch64 floating-point ABI correct
headers correct
```

## Gate D — libc-test

```text
functional green
regression green
API green
math green
```

with only individually justified exceptions.

## Gate E — differential

Musl-vs-crabc differential suite is substantially green with intentional differences documented.

## Gate F — standards

Modern POSIX-oriented test coverage is at least comparable to the pinned musl baseline.

## Gate G — concurrency/process

```text
pthread
TLS
cancellation
signals
fork/exec
```

stress suites are green.

## Gate H — loader

```text
relocation
symbol resolution
TLS
dlopen
constructors/destructors
ASLR
```

tests are green.

## Gate I — real software

A broad AArch64 Alpine binary corpus runs unchanged.

## Gate J — Rust ecosystem

Stock Rust `std` programs and at least one nontrivial Rust application work against crabc.

After Gates A–J, continue evidence-led Linux/AArch64 refinement. A new
architecture remains out of scope until separately approved.

---

# Working rules for the coding agent

1. **Do not spend the whole run planning.** Establish instrumentation, then implement.
2. **Use evidence-generated backlog.** Missing symbols, blocked tests, differential failures, ABI mismatches and corpus failures drive work.
3. **Work in vertical slices.**
4. **Do not mass-generate stubs.**
5. **Do not chase symbol count while known subsystem failures remain.**
6. **Prefer faithful musl translations in subtle areas.**
7. **Keep commits subsystem-coherent and reviewable.**
8. **Every discovered bug should become a regression test.**
9. **Do not weaken tests to manufacture green results.**
10. **When uncertain, improve the oracle before guessing.**
11. **No Rust `std` fork.**
12. **No x86_64, RISC-V, 32-bit, big-endian, or non-Linux work without an explicit scope decision.**
13. **No premature cross-architecture abstraction framework.**
14. **Use musl, never glibc, as the libc compatibility authority.**

---

# Final engineering principle

The project should not grow like this:

```text
350 exported
↓
700 exported
↓
1000 exported
↓
1420 exported
↓
begin discovering correctness
```

It should grow like this:

```text
compatibility laboratory
        ↓
foundation
    VERIFIED
        ↓
more surface unlocked
        ↓
filesystem
    VERIFIED
        ↓
time/process
    VERIFIED
        ↓
pthread/TLS
    VERIFIED
        ↓
network/resolver
    VERIFIED
        ↓
stdio/text/math
    VERIFIED
        ↓
remaining surface
        ↓
100% implemented
        ↓
whole libc + ld.so
    VERIFIED
```

The key metric is not:

> How many musl symbols exist in crabc?

It is:

> **How much of the musl compatibility boundary is backed by strong evidence?**

Use symbol coverage aggressively to unlock testing.

Use vertical slices aggressively to prevent correctness debt.

Keep the distance between:

```text
exported
implemented
verified
```

as small as practical.

That is the path from an exciting prototype to a libc that can credibly sit underneath real software.
