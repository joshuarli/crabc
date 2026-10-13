# Paused AArch64 allocator route

AArch64 allocator implementation and qualification are paused; these are the preserved reproduction commands for the frozen baseline, not the active work queue. The active route is the native x86-64 harness in [`README.md`](README.md). Everything below runs through the AArch64 `scripts/dev.sh` dispatcher in the pinned Linux/AArch64 development image.

```sh
./scripts/dev.sh allocator --quick
./scripts/dev.sh allocator-m1
./scripts/dev.sh allocator --full
./scripts/dev.sh allocator --churn
./scripts/dev.sh allocator-tls
./scripts/dev.sh sysroot
./scripts/dev.sh static-pthread-tls
./scripts/dev.sh test -p crabc-libc --test pthread_create_join_tls_regression
./scripts/dev.sh pthread-stress --iterations 1 --timeout 15
./scripts/dev.sh allocator-perf --smoke
./scripts/dev.sh allocator-perf --full
./scripts/dev.sh test -p crabc-mimalloc --lib --features loom remote_free::loom_tests -- --test-threads=1
```

Runner-owned mutable state stays below `CRABC_WORK_DIR`, or the checkout's
`.work/` directory when that variable is unset. The pinned archive and tag
attestation use `.work/allocator-cache/`; compiled C-oracle, adapter, fixture,
and isolated Cargo outputs use `.work/target/compat/allocator/`; reports use
`.work/reports/allocator/`; and disposable extracted sources and probe files
use `.work/tmp/allocator/`. The selected native-shadow runtime remains the
logical `target/debug` location: the canonical dispatcher maps that repository
path to the repository-local target volume rather than changing the runtime
selection contract.

`allocator --quick` is the former ordinary development gate, retained to
reproduce evidence. It verifies the
annotated tag and archive identities, regenerates the checked-in contracts in
memory, checks them and the source-map ratchet, and builds all five exact C
oracle profiles. Its ignored report is
`.work/reports/allocator/latest.json`; profile artifacts and layout probes
are under `.work/target/compat/allocator/oracle/`. The gate runs the complete
`crabc-mimalloc` library unit suite with a marked Rust machine record and
rejects any mismatch in the currently ported configuration constants,
page/memory-ID layout, queue block-size table, or bin-selection boundary
vectors. The release profile additionally runs independent C and Rust small-
allocation traces and requires the exact same 378-key logical record: every
one of 62 good-size transition requests, usable size, pointer-distinctness and
alignment observation, payload preservation, zeroing, and a 96-block repeated
fill/free permutation. Raw addresses are deliberately excluded. The gate also
records a separate 51-key exact-C baseline for page-kind, calloc, realloc,
aligned/offset-aligned, usable-size, preservation, and invalid-size OOM
behavior. The same library run emits an independent 51-key Rust record and
requires exact equality with that pinned C baseline. The native x86-64 lane
below extends its own trace to 75 fields with no-padding `mi_expand` and
checked `mi_recalloc`; native AArch64 revalidation of that extension remains
pending. This proves the bounded
single-thread engine's fundamental operation slice; it is not a production C
adapter, process lifecycle, or whole-allocator parity claim. A
default-off `test-adapter` feature now owns one allocation-backed, creating-
thread-only context with root-last initialization, exact outstanding-block
accounting, and explicit retryable page-map/arena teardown. It exists only to
support the standalone prefixed C evidence adapter and is not a production
allocator API. The gate also
traverses Cargo metadata for the
fixed `aarch64-unknown-linux-musl` target and rejects any selected allocator
dependency package, version, source, edge, build script, or proc macro outside
the audited `chacha20`/`zeroize` graph. Target-conditional packages retained
only in `Cargo.lock` do not satisfy or fail that selected-graph judge. It then
runs the test-only Loom page-protocol schedules over the shared production
remote-head publication/detach and abandoned owner-claim/unown loops and
records their exact pass count separately from the
ordinary unit suite. That test command explicitly clears
`CARGO_ENCODED_RUSTFLAGS`: the model does not access a compiler-TLS root, and
the pinned nightly cannot link its `std`/Loom test binary with the production
initial-exec TLS setting. The dedicated TLS-codegen judge below remains the
sole evidence for that production setting.

The quick gate also invokes the dedicated allocator compiler-TLS judge. It
builds one default-off probe codegen unit with
`-Ztls-model=initial-exec`, requires all five roots to be hidden `STT_TLS`
objects in the appropriate initialized/uninitialized TLS sections, and rejects
resolver-based or dynamic TLS relocation forms. Its negative-control build
explicitly clears the production target rustflags and must show that the
pinned compiler default emits TLSDESC, keeping the production model requirement
explicit. `allocator-tls` runs this judge alone and writes
`.work/reports/allocator/tls-codegen.json`.

`allocator-m1` writes the current-commit
`.work/reports/allocator/m1-foundations-latest.json` record from the checked-in
[`m1-foundations-v3.5.0.json`](m1-foundations-v3.5.0.json) contract. It reruns
the source/ratchet/C-release-layout producers and only the named focused Rust
checks, binds the result to an unchanged clean Git commit, and classifies each
component plus its explicit exclusions. It exits 0 only when the checked
contract is complete; exit 3 remains the intentional result for a partial M1
contract. A passing focused check or shared M0/M3/M4 producer does not close a
whole source unit or promote any allocator backend.
The complete atomics/locks/once/bootstrap component compares a 148-key, address-independent
release C/Rust vector for every represented field of the pinned immutable
`mi_page_empty`, direct-page table, all 75 queues, pre-process-init
`mi_tld_detached` source image, and `_mi_theap_empty` prefix through `memid`.
The C reader alone defines `MI_PRIM_HAS_PROCESS_ATTACH=1`, so `prim.c` cannot
run its automatic constructor and mutate that TLD before the comparison; the
normal C oracle artifact retains automatic attach. Pointer fields are null/sentinel
relationships, and the detached lock is try-locked then released rather than
being treated as a pthread byte-layout match. The contract also records an
explicit disposition for every 12 pinned direct `mi_atomic_do_once` call
sites. This remains evidence for those source-initializer images only: it excludes
stats, guarded/page-tail variants, mutable process storage, publication and
teardown. Its source-shaped Rust once witnesses also prove the bounded
identity-capable `ProcessMainInitializationStorage` route: an active foreign
racer waits through release, same-owner recursion refuses without blocking,
READY cannot bypass a retained once lock, retained failure wakes its waiter,
and a pre-body Rust-only cancellation is retryable. This is unit evidence for
the named bounded envelope, not a C/Rust dynamic differential or a claim to
complete `mi_process_init_once`, `mi_process_done`, automatic lifecycle, or
process destruction; those remain M5 work.
The complete raw-primitive component adds one native, pinned-C/Rust 47-field
record: the C probe directly includes pinned `src/os.c`, then compares the
immutable configuration, good-size and large-page predicates, one
no-hint/non-large map transition sequence, NUMA/current-node relation,
monotonic-yield observation, successful zero/16-byte entropy calls, and the
constant-false threadpool observation. It deliberately excludes addresses,
random bytes, timestamps, error/fallback branches, hints, and huge/THP policy.
The compiler-TLS component retains one 32-field direct pinned-C/Rust record:
a constructor-suppressed initial five-root image and TPIDR identity, the
count-zero image plus positive regular-slot reset, and the local cached-Theap
`1 -> 2 -> 1` reference pair. A distinct 40-field normal-artifact C/Rust
record direct-includes pinned `src/init.c` and invokes file-static
`mi_thread_theaps_done` on one page-free same-TLD static-default `D` plus
Malloc cached `A` fixture. It records C's A→D collector calls and Rust's A→D
generic queue-half empty branch with ordered empty-prepass witnesses, then
default/cached reset, heap detach, TLD final-loop order, and logical final
release. C bounds
main-Heap membership as metadata+D then metadata-only while the selected Rust
image is D then empty, so only common D membership/absence relations compare.
Together these records close the bounded M1 compiler-TLS component. They do
not claim outer `_mi_thread_done`, regular-backing/fast teardown, statistics,
TLD free, process hooks, page-bearing collection, production deferred/retired
prepasses, public Heap lifecycle, or M5 process/thread integration.
The complete finite configuration-and-arithmetic component compares
every frozen `config.*` C/Rust record and a compact representable scalar
vector, including `_mi_is_power_of_two(0)`, generic non-power-of-two
`_mi_align_up`/`_mi_align_down`, division, word rounding, and slice conversion.
Its geometry entries read `MI_ARENA_SLICE_SHIFT` and `MI_BCHUNK_BITS_SHIFT`
themselves, so a source selector change cannot hide behind duplicated probe
formulas. It makes no claim about C unsigned-overflow behavior, whole
`types.h`/`bits.h`/`internal.h` completion, or unselected CMake modes.

`allocator --full` extends that gate by building and auditing the standalone
static and shared test adapter, including its exact 16-symbol export boundary,
native link tail, and dynamic dependencies. It applies the reviewed patch to
the hash-pinned upstream `test/test-api.c` without checking in a source fork,
then runs both the existing crabc allocator fixture and 33 selected upstream
API checks. In that full-only lane it also applies the separately reviewed
creating-thread `test/test-stress.c` patch, compiles it with `NTHREADS=1`, and invokes
the exact source program as `1 1 2`. That preserves the source allocation
distribution, zero/cookie checks, reallocating data table, retained objects,
atomic transfer buffer, and final cleanup across two iterations. The patched
scheduler instead runs its sole worker on the creating thread, so it creates
no pthread; heaps, subprocesses, large-object mode, and the libc allocator
path hard-fail at compile time. It is therefore recorded as preliminary
source-derived stress evidence, not a cross-thread, remote-free, or
thread-recreation acceptance claim. `allocator --churn` and `--soak` do not
silently run that distinct full-lane witness. `allocator --full` also executes
the reviewed
[`native-owner-exit-lifecycle-v3.5.0.json`](native-owner-exit-lifecycle-v3.5.0.json)
suite: fifteen focused direct `crabc-mimalloc` checks spanning the mixed runtime
route, pointer-first publication before and after exit, source-selected live
medium abandonment, same-page PageMap-claim lifetime, aggregate final-member
reclamation, failed OS terminal release, terminal finish ordering, and source
traversal filters. It records
Gate 5C as passed only when that complete checked
record is present; the suite is direct-engine lifecycle evidence, not a
shadow-ABI or general concurrent-routing claim. It then runs the same 128-cycle,
30-second, seed
`0xd1b54a32d192ed03` ticket-zero lifecycle schedule as `allocator --churn`
and writes a versioned [`m5-gate-v3.5.0.json`](m5-gate-v3.5.0.json) result to
`.work/reports/allocator/latest.json`. The report records the bounded base,
persistent-worker, live-owner remote-free, and owner-exit evidence as passed
only when their executed checks pass. It records Gate 5D (soak, stability, and
upstream stress) and Gate 5E (selected native-shadow acceptance) as explicit
blockers until their documented acceptance criteria are met. Consequently
`allocator --full` still exits 3 today, but its failure is
the named reviewed gate state rather than a synthetic post-run placeholder.

Before rendering that M5 record, `allocator --full` reads only the fixed
`.work/reports/allocator/upstream-stress/latest.json` canonical report; it does
not invoke `upstream-stress/run.py` itself. The consumer accepts a report only
when its format, pin, ordered 12-case source matrix, failure-closed
capability, selected native-shadow backend/build record, live named artifacts,
and current-head companion all still bind to the current clean Git source. The
sole execution-scoped artifact is the producer-container's staged
`/lib/ld-crabc-aarch64.so.1` record: its fixed path and bytes bind to the live
selected loader, but the later consumer does not require that transient file.
Its Git reads set `GIT_OPTIONAL_LOCKS=0`. The durable
`canonical_upstream_stress` field is `verified`, `unavailable`, or `rejected`.
Only a `verified` record is surfaced as observed Gate 5D evidence. Its first
eight rows retain the 1/2/4/8-worker low-scale schedules; four appended
1/2/4/8-worker `SCALE=101`, `ITER=1` rows exercise the unmodified source's
strict `SCALE > 100` CLI branch and exact ` (allow large objects)` stdout
suffix. The record remains a nondefault `shadow_subset` with
`large_object_mode: source-cli-enabled`: it attests source-mode activation and
completed bounded workload execution, not that every probabilistic large
allocation succeeded. It does not promote Gate 5D or Gate 5E. The separate
opt-in 1024-cycle soak and metadata high-water acceptance remain required.

`allocator --churn` uses that same prefixed evidence adapter but succeeds only
when one fresh process completes 128 bounded C cycles within its 30-second
watchdog. Each cycle runs exactly the two pointer-private workers,
mixed-local and live-owner remote-free, once in a deterministic
Fisher-Yates order from recorded unsigned-64-bit seed
`0xd1b54a32d192ed03`. The fixture accepts no arguments for its three-cycle
default, or at most one each of `--worker-cycles N` for decimal `N` in
1..1024 and `--stress-seed SEED` for a base-0 unsigned-64-bit seed, in either
order; it exports no additional symbol. The separately focused mixed post-exit
owner-exit and alternating mapped-regular reclamation regressions are not
additional C fixture schedule routes. They first suspend A's exact page engine
into the private runtime TLS slot and invoke ordinary post-destructor finish.
That dispatcher resumes the matching engine, runs the existing aggregate source
traversal for the mixed and sole-medium cases or the direct-cache-validating
small-or-medium drain for direct small, and retains A's admission until the
resulting typed B-side route terminally releases; A cannot fall through the
no-page finalizer after its Theap/TLD has detached. The mixed opaque owner-exit
route carries two full medium pages (one mapped by a joined pre-exit remote
free and one source-unmapped), a distinct one-client large page whose joined
remote free releases it during source collection, one live arena singleton,
and one live OS-aligned singleton; B receives no client address and must
terminally release the arena singleton's PageMap-only tail and the OS
singleton's private-list/clipped-mapping tail before A becomes fork-quiescent.
On B's first direct free of either an existing direct-small client or one of
three remaining clients on the pre-exit-normalized mapped, non-full medium
page, joined C and D each receive the matching nominal scoped same-page
producer after B claims the source low owner bit; C and D atomically append
distinct private clients in separate joined turns and B's ordinary collector
consumes the resulting two-node remote chain before the route continues. The
direct runtime regressions pause after this opaque route transfers and prove
ticket zero remains unavailable until B returns the final PageMap-release
proof; a missing or mismatched publisher retains the route instead of invoking
B's ordinary no-page finalizer. The alternating sole-medium
and direct-small reclamation sides give B no client identity or PageMap handle;
B attaches, adopts/uses the exact page, drains it, and finishes its attachment
before returning the only proof that releases A's admission. The direct-small
side first validates and clears its rounded direct-cache image and immediate
head; it does not make direct small an aggregate traversal result. This is Gate 5D
preliminary stability evidence alongside deterministic eight-cycle Rust state
audits, which also check static-main abandoned counts and the private
OS-abandoned-list baseline. The runtime integration additionally shuffles
eight core pointer-private routes, including the all-free parked TLS session
finish, ordinary parked TLS session owner exit, and the parked session's
scoped B/C/D post-exit publication group, for eight epochs from seed
`0x9e3779b97f4a7c15` and proves ticket-zero reactivation after every route.
It does not close general abandonment/reclamation or promote a libc backend.
`allocator --soak` runs the same two-worker C fixture schedule for 1,024
cycles from seed `0x94d049bb133111eb` under a separate 180-second watchdog:
two routes per cycle, for exactly 2,048 route invocations. On success it
atomically replaces only
`.work/reports/allocator/runtime-ticket-zero-soak-1024.json`; it never writes
the shared `.work/reports/allocator/latest.json` slot. The durable report is
`crabc-mimalloc-runtime-ticket-zero-soak-report` format 1 and binds the live
ticket-zero contract digest, pinned archive, adapter archive/shared library,
fixture binary, C-oracle identity, target, commands, schedule, and all
13 scalar audit fields. Each artifact is re-attested at its fixed raw
producer path before recording, rejecting final-component and parent-directory
symlinks; the fixture's executable and `-o` output must name that fixture,
and its build record must name the checked-in C fixture and attested adapter
archive. The pinned annotated-tag attestation must also be live and exactly
match the loaded pin. Its Git source attestation reads with
`GIT_OPTIONAL_LOCKS=0` and requires byte-identical clean source states before
its pin, contract, and header reads and immediately before publication, so a
failed, dirty, changed, or artifact-drifting run preserves a prior good stable
record. After its first
complete two-worker cycle, the original fixture thread records the scalar-only
quiescent baseline: process and ticket-zero readiness, PageMap
registration/submap counts, arena registry, live TLDs, metadata
live/high-water capabilities, shared Theaps, regular abandoned pages, and
whether the private OS-abandoned list is empty. Every later cycle and the
final ticket-zero allocation/free must match it; the report records the
baseline and audit-snapshot count. This direct adapter does not install a
post-exit registry; its C worker paths start from their supplied pointer or
their own live engine. It remains opt-in bounded stability evidence:
`allocator --full` only validates and renders its one fixed report through the
top-level non-executing `runtime_ticket_zero_soak` consumer. Its result is
`verified`, `unavailable`, or `rejected`, but it satisfies, advances, and
unblocks no M5 gate; it does not establish a selected/default libc backend,
general cross-thread/post-exit acceptance, upstream pthread acceptance, or
large-object coverage.
`allocator --churn` remains the 128-cycle, 30-second development gate.

The prefixed mixed-local and live-owner remote-free workers now enter through
the typed runtime A-side operation and prove their ordinary
`PAGE_OWNER_READY -> BUSY -> READY` finish without widening the C ABI. A
separate lower persistent-engine regression represents a counted `PARKED(n)`
set of independently suspended normal engines. Each normal suspend increments
that count, each exact token finish decrements it, and ticket zero remains
unavailable until the count reaches zero; one active mutation still owns the
serial `BUSY` transition and PageMap lease. A non-parkable interleaving
operation preserves the observed count. Neither token exposes a client address,
PageMap handle, or post-exit finalizer; abandoning either retains the process
owner. This is not a public worker API, a general concurrent allocator, or
libc allocation routing.

Loom 0.7.2 is an exact, defaults-disabled optional test-model dependency. The
`loom = ["dep:loom"]` feature selects its allocation-backed `std` scheduler,
`generator` build script, and tracing support stack only for the
`cfg(all(test, feature = "loom"))` library model; ordinary selected native
integration tests do not resolve that graph. The generator's external assembly
path is not selected on AArch64, and Cargo's production-graph judge excludes
the entire Loom graph. Both performance modes likewise remain explicitly
unavailable; these status-3 results are not skips and must not become
successful placeholders.

