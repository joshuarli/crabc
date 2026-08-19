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

---

# The most important sequencing rule

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

## Milestone 2 — Eliminate test blindness

Use test-unlock analysis to expand surface until:

```text
almost all libc-test cases can compile
```

while closing each newly testable subsystem vertically.

This milestone does **not** require 100% symbol parity.

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

## Milestone 4 — 100% implemented symbol parity

Now close remaining isolated/advanced API surface.

No fake stubs.

## Milestone 5 — ABI + libc-test closure

Require:

```text
ABI parity
headers parity
libc-test green
```

## Milestone 6 — standards + stress closure

Require:

```text
POSIX confidence
pthread/TLS stress
signal/process stress
resolver/network correctness
```

## Milestone 7 — dynamic loader maturity

Require synthetic DSO/relocation/TLS/dlopen suite green.

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
