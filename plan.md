# Mature `crabc` on Linux ARM64 through vertical compatibility slices

Take the existing `crabc` project from an early Rust libc/runtime implementation to a **credible musl-compatible libc and dynamic linker for Linux AArch64**.

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
* compatibility with ordinary musl-linked AArch64 software;
* enough behavioral evidence that this is a credible musl replacement rather than merely an ABI-shaped prototype.

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

# Architecture scope

## Phase 1: Linux AArch64 only

Everything must first be proven on:

```text
aarch64-unknown-linux-musl
```

or the equivalent Linux AArch64 ABI.

This includes:

* symbol/API parity;
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

## Phase 2: x86_64

x86_64 begins **only after the AArch64 implementation is mature**.

Do not work on x86_64 opportunistically while ARM64 compatibility remains incomplete.

When x86_64 starts, first reuse the proven compatibility harness and only then generalize architecture-specific code.

## Not in scope

Do not maintain active RISC-V support.

Existing RISC-V code may remain temporarily if harmless, but:

* do not advertise it;
* do not test it;
* do not spend engineering effort preserving it;
* do not design abstractions around it.

## Allocator scope exception

`crabc` does not implement or tune its own malloc allocator. Allocator
internals are explicitly out of scope for every milestone; use mimalloc as the
allocator implementation for now. The public allocation API and observable C
contract (`malloc`, `free`, `realloc`, alignment, overflow, and failure
behavior) remain in scope and must continue to be tested at that boundary.

This is the sole subsystem exception. All other interfaces and behavioral
requirements in this plan remain in scope.

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

But do **not** create a generic `Architecture` abstraction solely because x86_64 will eventually exist.

When x86_64 arrives:

```text
run proven harness
    ↓
identify actual differences
    ↓
add x86 implementation
    ↓
generalize duplicated code only then
```

Tests generalize first.

Implementation abstractions generalize second.

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
[`compat/upstreams.toml`](compat/upstreams.toml).

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
- [`COMPATIBILITY.md`](COMPATIBILITY.md) is generated from the structured
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
crabc exports:           1,668
missing:                     0
unexpected (baselined):     21
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

The final Docker report is 1,647 expected symbols, 1,668 candidate symbols,
zero missing names, and zero metadata mismatches. Its 21 unexpected names are
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
pass. The ratchet remains 1,647 expected dynamic symbols, 1,668 candidate
symbols, zero missing names, zero metadata mismatches, and 21 baselined
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
ratchet records 1,647 reference exports, 1,668 candidate exports, no missing
or metadata-mismatched symbols, and 21 baselined candidate-only exports.

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

## Milestone 9 — stock Rust std

Prove normal Rust software can use crabc without a std fork.

## Milestone 10 — LTO research

Measure the whole-program Rust/LLVM optimization opportunity.

## Milestone 11 — only then begin x86_64

Reuse the same compatibility laboratory first.

No RISC-V.

---

# AArch64 maturity gates

The implementation is ready for x86_64 work only after these are effectively satisfied.

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

Only after Gates A–J should x86_64 become active implementation scope.

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
12. **No x86_64 work until ARM64 maturity.**
13. **No RISC-V work.**
14. **No premature cross-architecture abstraction framework.**
15. **Use musl, never glibc, as the libc compatibility authority.**

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
