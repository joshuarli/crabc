# Paused AArch64 native-mimalloc handoff

Preserved from `native-mimalloc.md` at `50fcb75d` during the 2026-09-04
live-document cleanup. All milestone and evidence claims below retain their
original architecture and revision. Older "current", "active", "next", and
continuation instructions are historical, not authorization to resume AArch64
work or a source of x86 milestone passes. Do not append new work here.

The live x86 queue and acceptance contract are in
[`native-mimalloc.md`](../../native-mimalloc.md); the combined goal is
[`plan.md`](../../plan.md). Paths in backticks are repository-relative.

---

## Paused AArch64 handoff — 2026-09-03

Resume this AArch64 queue only after explicit future user direction. The
following is its preserved state at suspension. It supersedes older
"current" wording in the historical chronologies below; those records remain
provenance, not a live work queue. `STATUS.md` is not the native allocator
status record.

**Last integrated implementation.** `8db445ea3cbc75da59b283fc2f40905b9f0131a5`
adds a sealed `NormalOsBaseAllocation` handoff for one selected
`src/arena.c:1885-1912` `mi_reserve_os_memory_ex2` caller. Only the normal
zero-offset/base-equals-client aligned route can move its exact `Mapping` and
original `MemoryId` into `ProcessSharedArenaStorage`; an offset allocation
cannot become arena backing. `manage_os_in_place` refuses wrong-kind, pinned,
or mismatched base/extent provenance before metadata mutation. This is one
source-shaped VM ownership slice, not VM-component or allocator completion.

**Current native evidence.** A clean detached Linux/AArch64 checkout at that
exact revision ran `./scripts/dev.sh allocator --quick` with exit 0 and
`./scripts/dev.sh allocator-m1` with exit 0. The M1 report attests a clean,
unchanged source tree and all six bounded components complete with no unmet
IDs. `./scripts/dev.sh allocator-m2` ran all 67 selected checks and exited 3,
which is the contract's required partial result; its report attests the same
clean, unchanged source tree. Its counts are fifteen VM-primitives, twelve
metadata, nine bitmap, ten PageMap, five arena, ten initialization, two
fault-injection, and four allocator-recursion checks.

**Actual milestone state.** M0 is genuinely complete as an inventory/skeleton
contract and M1 is genuinely complete as its six bounded foundations; neither
claim means allocator-engine or lifecycle parity. At suspension, M2 was the active closure
gate. `page-map` is its sole complete component. The seven still-partial
components are `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. M3 and every
later milestone remain blocked behind a fully complete M2.

**What is next.** Do not treat another selected witness, a source-map entry,
or a larger check count as milestone progress. The next implementation wave
must be a component-scale M2 closure wave, starting with
`vm-primitives`: turn its remaining condition in
`compat/allocator/m2-memory-substrate-v3.5.0.json` into a finite pinned-source
function/ownership/failure matrix, then implement and test the remaining
reserve, commit/decommit, purge/protect, unmap/reuse, aligned-map, and
hint/huge/NUMA policy paths together with their fault and recursion boundaries.
Clear that component only when its remaining condition is empty and a clean
native gate proves it. Apply the same rule to the remaining M2 components;
keep fault injection and recursion as cross-cutting closure requirements, not
late checklist items.

### Paused AArch64 continuation prompt

> Fully complete the Linux/AArch64 native mimalloc v3.5.0 port through every
> applicable milestone M0–M11 in `native-mimalloc.md`, in order. Treat the
> milestone definitions, the machine-readable contracts, the pinned upstream
> source map, and clean native Linux/AArch64 evidence as the acceptance
> contract. Preserve M0 and M1 as their already-complete *bounded* contracts,
> but do not mistake them for allocator-engine completion. Do not advance past
> any milestone while it has an incomplete component, a nonempty
> `remaining_conditions` entry, unclassified applicable source behavior, or
> missing current-commit native evidence. In particular, do not begin or claim
> M3 until all eight M2 components are complete and the M2 gate has a complete
> current-commit result; a partial-gate exit, a direct trace, a unit-test count
> increase, or a documentation update never constitutes closure. Port pinned
> mimalloc semantics rather than inventing allocator behavior; use focused
> regressions, C/Rust differentials where applicable, fault/recursion evidence,
> and source-map/ratchet updates for each vertical slice. After every
> integrated wave, update this handoff with the exact state, remaining closure
> conditions, next component-scale work, commit, and clean native validation.
> Keep `native-mimalloc.md` as the native allocator status authority and do not
> use `STATUS.md` to advance it.

## Preserved AArch64 milestone closure

| Milestone | Status | Evidence and remaining closure condition |
| --- | --- | --- |
| M0 — pin, scope, inventory, skeleton | complete (inventory/skeleton; revalidated) | `crabc-mimalloc/UPSTREAM.md` fixes v3.5.0, its revision, archive hash, and MIT provenance; `crabc-mimalloc` is `#![no_std]`; `compat/allocator/api-v3.5.0.json`, `compat/allocator/port-map.toml`, and `compat/allocator/run.py` provide the inventory, source map, C oracle, layout baseline, and canonical harness. At `8db445ea3cbc75da59b283fc2f40905b9f0131a5`, a clean detached native `./scripts/dev.sh allocator --quick` revalidation exited 0. This is inventory/skeleton completion only, not engine parity. |
| M1 — pure foundations | complete (6/6 bounded components; revalidated) | `configuration-and-arithmetic`, `atomics-locks-once-and-bootstrap`, `provenance-and-represented-layouts`, `random-image`, `linux-raw-primitives`, and `compiler-tls-roots` have no remaining condition in `compat/allocator/m1-foundations-v3.5.0.json`. At `8db445ea3cbc75da59b283fc2f40905b9f0131a5`, a clean detached native `./scripts/dev.sh allocator-m1` revalidation exited 0; its report attests a clean source before and after execution, unchanged during it, with all six components complete and no unmet IDs. The compiler-TLS evidence is its selected 32-field image and the 40-field normal-artifact C/Rust same-TLD `D`/`A` terminal trace. These are bounded component claims, not whole-`src/init.c`, `types.h`, `prim.h`, `prim-tls.h`, or `internal.h` completion, and not outer `_mi_thread_done`, page-bearing lifecycle, production deferred/retired prepasses, or allocator integration. |
| M2 — memory substrate | partial (current 67-check executable gate; revalidated) | `compat/allocator/m2-memory-substrate-v3.5.0.json` fixes eight categories. At `8db445ea3cbc75da59b283fc2f40905b9f0131a5`, a clean detached native sequence ran `allocator --quick` (exit 0), `allocator-m1` (exit 0), and `allocator-m2` (exit 3 as its partial contract requires). The M2 report attests a clean, unchanged exact revision and all 67 selected checks passing: fifteen VM-primitives, twelve metadata, nine bitmap, ten PageMap, five arena, ten initialization, two fault-injection, and four allocator-recursion checks. The added VM record proves only one normal-aligned, base-only `src/arena.c:1885-1912` regular-OS reservation caller carrying its exact mapping/provenance into one arena; it does not close VM primitives. The earlier detached and normal-helper records remain bounded helpers, not a general `mi_tld_create` lifecycle. PageMap remains the sole complete M2 component; its exact unmet IDs remain `vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. |
| M3 — single-thread allocation | not active (historical partial evidence only) | The direct-engine allocator covers selected queues, page classes, retirement, and traces, but Heap/Theap, page, and queue units remain partial. The pinned image has no Miri. A forced `cfg(miri)` smoke is currently unavailable because `os_host_model.rs` lacks the existing NUMA/identity/entropy and `Mapping::page_size` APIs its callers require; the same ten compile errors existed at `265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`. This is not M2 evidence or a reason to advance past the still-partial M2 gate. |
| M4 — fundamental operations | bounded direct-engine evidence | A reviewed private M4 C adapter selects 33 tests and explicitly omits 21, but no clean-current-commit native adapter report exists; it runs only in the `allocator --full`/`--churn` lanes. It is a one-thread private adapter over the still-partial M1–M3 substrate, not a closed production/general milestone. |
| M5 — concurrency and lifecycle | open | `m5.base`, `m5.5a`, `m5.5b`, and `m5.5c` are bounded/direct evidence only. `m5.5d` and `m5.5e` are blocked; all Phase A–G acceptance conditions remain required. |
| M6–M7 | not started | Blocked behind the allocator foundations and M5. |
| M8 | partial, nondefault shadow only | The selected Rust shadow exists; it is not full libc integration. |
| M9 | not started | No qualified AArch64 performance closure. |
| M10 | blocked | C mimalloc remains the default production backend. |
| M11 | not started | Follows promotion. |

A checked-in contract records the current boundary; only its clean-current-commit
report is current runtime evidence. Evidence from an ancestor is historical
supporting evidence, not a pass for a later checkpoint, though it remains the
closure record for the exact contract and revision it attests.

For M2 specifically, the table's `b09b1fd9` 42-check report is historical.
At `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, a clean detached checkout
attested the then-current 47-check M2 contract: `allocator --quick` exited 0,
`allocator-m1` exited 0 with all six components complete, and `allocator-m2`
exited 3 as its partial contract requires. Its source was clean before and
after, and unchanged during, execution; it recorded exactly twelve
VM-primitives, eleven metadata, four bitmap, ten PageMap, three arena, three
initialization, one fault-injection, and three allocator-recursion checks, and
exactly the seven unmet IDs named in the table. That is current runtime
evidence for `bdbcfc71` only, not for later code. The later `f379f03e`
contract contained 56 selected checks: fourteen VM-primitives, eleven metadata, eight
bitmap checks, ten PageMap, five arenas, four initialization, one
fault-injection, and three allocator-recursion checks. Relative to the
historical 54-check contract, the two additions are the fixed no-option NUMA
cache/current-node-normalization record and the custom external-arena purge
`needs_recommit` record. At `4c2a8bfe2f9b2d1a2125b822a888c74b58971bde`, a
clean detached native revalidation executed the prior 54-check shape:
`allocator --quick` and `allocator-m1` exited 0, and `allocator-m2` exited 3
as its partial gate requires. Its M1/M2 reports attest clean source before and
after execution and no change during it. That is historical evidence for that
exact prior code/contract revision. At
`f379f03e9f562fc85111d541c2a17ebe1def0115`, a clean detached native rerun
attested the then-current 56-check revision: `allocator --quick` and `allocator-m1`
exited 0, while `allocator-m2` executed all 56 selected checks and exited 3 as
its partial contract requires. The M1/M2 reports attest source cleanliness
before and after execution and no change during it. M1 records all six bounded
components complete with no unmet IDs; M2 records fourteen VM-primitives,
eleven metadata, eight bitmap, ten PageMap, five arena, four initialization,
one fault-injection, and three allocator-recursion checks, with exactly the
seven unmet IDs named in the table. This is runtime evidence for the exact
`f379f03e` source/contract revision only; it does not make M2 complete.
The subsequent `a0f63f15fff16fcab894bb4a832008b1a1a0b755` static-TLD NUMA
caller supplies the fifth initialization record. At
`685e9da10096feb44819dd5c470bb21fb52f70f3`, a clean detached native rerun
attested the then-current 57-check source/contract revision: `allocator --quick`
and `allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest source cleanliness before and
after execution and no change during it; that evidence is historical now that
the then-current 59-check M2 contract had its own clean native revalidation.
M1 remains six-of-six complete and
M2 records all 57 selected checks passing while retaining exactly the seven
unmet IDs named in the table.

At `448b4cf4e8833394df1f96594e9e15ee6640bed7`, a clean detached native rerun
attested the then-current 59-check source/contract revision: `allocator --quick`
and `allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest the same revision was clean before
and after execution and unchanged during it. M1 remains six-of-six complete;
M2 records all 59 selected checks passing—fourteen VM-primitives, twelve
metadata, eight bitmap, ten PageMap, five arena, five initialization, one
fault-injection, and four allocator-recursion—while retaining exactly the
seven unmet IDs named in the table. This is historical evidence after the
60-check revalidation below.

At `22732b90eb379e2e654d99e966c62067c22f601b`, a clean detached native rerun
attested the then-current 60-check source/contract revision: `allocator --quick`
and `allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest the same revision was clean before
and after execution and unchanged during it. M1 remains six-of-six complete;
M2 records all 60 selected checks passing—fourteen VM-primitives, twelve
metadata, eight bitmap, ten PageMap, five arena, five initialization, two
fault-injection, and four allocator-recursion—while retaining exactly the
seven unmet IDs named in the table. This is historical evidence after the
61-check revalidation below.

At `f304bfb36a718e97a427c10bd6b628eee6904e3a`, a clean detached native rerun
attested the then-current 61-check source/contract revision: `allocator --quick`
and `allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest the same revision was clean before
and after execution and unchanged during it. M1 remains six-of-six complete;
M2 records all 61 selected checks passing—fourteen VM-primitives, twelve
metadata, nine bitmap, ten PageMap, five arena, five initialization, two
fault-injection, and four allocator-recursion—while retaining exactly the
seven unmet IDs named in the table. This is historical evidence after the
63-check revalidation below.

At `3012d983daaf02417496097abbf5dc2283e239a9`, a clean detached native rerun
attested the then-current 63-check source/contract revision: `allocator --quick`
and `allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest the same revision was clean before
and after execution and unchanged during it. M1 remains six-of-six complete;
M2 records all 63 selected checks passing—fourteen VM-primitives, twelve
metadata, nine bitmap, ten PageMap, five arena, seven initialization, two
fault-injection, and four allocator-recursion—with exactly the same seven
unmet IDs named in the table. This is historical evidence after the later
65- and 66-check revalidations below.

At `46d179f7f2ca3830700be8cbd11b1185fe65f2d3`, two clean detached native
reruns attested the then-current 65-check source/contract revision: each ran
`allocator --quick` and `allocator-m1` with exit 0, then `allocator-m2` with
its expected partial-gate exit 3. The M1/M2 reports attest the same revision
was clean before and after execution and unchanged during it. M1 remains
six-of-six complete with no unmet IDs; M2 records all 65 selected checks
passing—fourteen VM-primitives, twelve metadata, nine bitmap, ten PageMap,
five arena, nine initialization, two fault-injection, and four
allocator-recursion—with exactly the same seven unmet IDs. The two additions
are the direct normal `mi_tld_init` C/Rust trace and its Rust busy-lock safety
regression; PageMap remains the sole complete M2 component. This is historical
evidence after the 66-check revalidation below.

At `0e15fcbbb3775b6ff5a4f991f2751626c3d67f64`, two clean detached native
reruns attest the then-current 66-check source/contract revision: each ran
`allocator --quick` and `allocator-m1` with exit 0, then `allocator-m2` with
its expected partial-gate exit 3. The M1/M2 reports attest the exact revision
was clean before and after execution and unchanged during it. M1 remains
six-of-six complete with no unmet IDs; M2 records all 66 selected checks
passing—fourteen VM-primitives, twelve metadata, nine bitmap, ten PageMap,
five arena, ten initialization, two fault-injection, and four
allocator-recursion—with exactly the same seven unmet IDs. The added direct
static-first record is limited to the selected `src/init.c:253-272`
`mi_tld_create` success arm; it matches 36 address-independent semantic
relations and does not establish general TLD lifecycle or allocator
integration. PageMap remains the sole complete M2 component. This is
historical evidence; the current 67-check revalidation is recorded in the
Current handoff above.

## M1 closure evidence

`compat/allocator/m1-foundations-v3.5.0.json` records M1 as `complete`: each
of its six named components is complete with no remaining condition, and the
compiler-TLS component requires both independent C/Rust records. The existing
32-field record covers the constructor-suppressed root image, positive
regular-slot reset, and local cached-reference pair. The distinct 40-field
record direct-includes the pinned `src/init.c` into a normal C artifact and
compares the file-static `mi_thread_theaps_done` body with the test-only Rust
same-TLD composite. Its C setup and `_Exit` deliberately exclude outer
`_mi_thread_done`, regular-backing/fast cleanup, statistics, TLD free, process
hooks, page-bearing collection, and public Heap lifecycle; Rust performs its
metadata/key/backing cleanup only after the compared trace. Its page-free
queue-half witness checks the generic coordinator's empty branch and only the
deferred-free → retired-page prepass order; it does not execute those
production prepass algorithms.

M1 closed at `38d0a51fda55f61e4a5985eee0afc90a9211b49f` with a clean native
`./scripts/dev.sh allocator-m1` exit 0 and that revision's
`m1-foundations-latest.json` report. A partial contract or a dirty source makes
exit 3 or a hard failure, respectively; neither is closure. That report is
historical support at a later revision and must be rerun from a clean target
checkout before it can be called current runtime evidence there. The
`fec84761e9fbdb29c32d8f492ca6c9cfa08a015b` report remains historical support
for its older partial contract only. Deferred lifecycle and whole-unit
exclusions remain nonclaims, not implicit M1 coverage.

The M1 gate was rerun from a clean detached native checkout at
`33e9fc801935c02ac30bc50c82674ece93ebca95`: it exited 0 and produced that
checkout's `m1-foundations-latest.json` with all six components complete and
no unmet component IDs. Thus M1 was current evidence for the allocator source
revision that introduced the M2 cold-init record; it remains only the bounded
six-component milestone described above.

The M1 gate was rerun again from a clean detached native checkout at
`265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`: it exited 0 and produced that
checkout's `m1-foundations-latest.json` with all six components complete and
no unmet component IDs. That report is an earlier recorded M1 revalidation;
M1 remains only the bounded six-component milestone described
above.

The M1 gate was rerun once more from a clean detached native checkout at
`2b289b1f8ae10543dfc57ddda0b49b08789be400`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, with all six bounded components complete and no unmet component
IDs. This was the recorded revalidation after the detached first-head
random/cookie M2 slice; it does not broaden M1 beyond its six-component
contract.

The M1 gate was rerun again from a clean detached native checkout at
`ffaea4a9a2a3304dad0ff57ed081cc96e3b29978`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, with all six bounded components complete and no unmet component
IDs. This makes M1 current evidence for the detached-Theap identity-admission
M2 slice, without broadening M1 beyond its six-component contract.

The M1 gate was rerun again from a clean detached native checkout at
`d965a6699bd65f92f98d96a665eac9ecf60e60f0`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, unchanged during the run, with all six bounded components complete
and no unmet component IDs. A separate clean detached
`./scripts/dev.sh allocator --quick` run at that same revision also exited 0.
Those are revalidations of the bounded M0/M1 contracts at that revision only;
they do not broaden either milestone into allocator-engine or lifecycle
completion.

The M1 gate was rerun again from a clean detached native checkout at
`9136162edf724287b64b381125ae4b01671e52bb`: it exited 0 and its
`m1-foundations-latest.json` attests the source was clean before and after
execution, unchanged during the run, with all six bounded components complete
and no unmet component IDs. A separate clean detached
`./scripts/dev.sh allocator --quick` run at that same revision also exited 0.
Those were then-current revalidations of the bounded M0/M1 contracts only; they
do not broaden either milestone into allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`04e6f49c233c8d3d14d45a5299c54e255ad28917`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. A
separate clean detached `./scripts/dev.sh allocator --quick` run at that same
revision also exited 0. Those were then-current historical revalidations of the bounded
M0/M1 contracts only; they do not broaden either milestone into
allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`03264676bddff8fdf94cd2ba3d9103124c9c200c`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. Its
report attests the source was clean before and after execution and unchanged
during the run. A separate clean detached `./scripts/dev.sh allocator --quick`
run at that same revision also exited 0. Those were then-current historical
revalidations of the bounded M0/M1 contracts only; they do not broaden either
milestone into allocator-engine or lifecycle completion.

The M1 gate was rerun again from a clean detached native checkout at
`5a2708d5c1e6b463c5eade8f60afa75d6131818a`: it exited 0 with all six bounded
components complete, no unmet component IDs, and 45 executed records. Its
report attests the source was clean before and after execution and unchanged
during the run. A separate clean detached `./scripts/dev.sh allocator --quick`
run at that same revision also exited 0. These are then-current historical revalidations of
the bounded M0/M1 contracts only; they do not broaden either milestone into
allocator-engine or lifecycle completion.

## M2 current partial gate

`compat/allocator/m2-memory-substrate-v3.5.0.json` is the current M2
contract. It names all eight closure categories in the milestone definition,
requires every partial category to state its remaining conditions, and keeps
later allocation and public-backend work as explicit exclusions. Its selected
PageMap check builds a source-private pinned-C producer that directly includes
`src/os.c`, `src/page-map.c`, and `src/init.c`, without duplicate normal-source
objects. It disables `mi_option_pagemap_commit`, fixes `max_vabits` to 48, and
requires a native 4-KiB page size. The C and Rust records compare the 23 stable
control and transition fields for initial partial commitment, lazy extension
across two submaps, one two-slice unregister, final-boundary rollback, and an
absent root after destruction.

The checked-in working set contains 67 native checks: fifteen VM-primitives
checks, twelve metadata checks, five bitmap C/Rust differentials plus four
Rust-only bitmap-observer check records, ten PageMap checks, five arena
checks, ten initialization checks, two fault-injection checks, and four
allocator-recursion checks. The fault records are the native one-page
protect/unprotect owner-and-retry regression and the initialized two-level
pinned-C/Rust PageMap lazy-commit failure/retry differential. The 37-, 38-,
39-, 40-, 41-, and 42-check reports are historical evidence for prior
contracts. At `7141570b6717dc590d962af139ffe08971cdc3bb`, a clean detached
native run executed the prior 53-check shape; it remains historical support.
At `4c2a8bfe2f9b2d1a2125b822a888c74b58971bde`, a clean detached native run
executed the prior 54-check shape: `allocator --quick` and `allocator-m1`
exited 0, while `allocator-m2` exited 3 as its partial-gate contract requires.
The M1/M2 reports attest clean source before and after execution and no source
change during it; M1 records all six components complete and no unmet IDs,
while M2 records exactly the seven unmet IDs below. That is native runtime
evidence for the 54-check revision only. At
`f379f03e9f562fc85111d541c2a17ebe1def0115`, the then-current 56-check
revision passed the same clean detached `allocator --quick`/`allocator-m1`
outcomes and its partial `allocator-m2` exit-3 outcome, with source unchanged
throughout; it is historical evidence for that exact revision. The preceding
57-check revision added the selected static-TLD NUMA caller. At
`685e9da10096feb44819dd5c470bb21fb52f70f3`, its clean detached native rerun
again returned 0 for `allocator --quick` and `allocator-m1` and 3 for the
partial `allocator-m2` gate, with source clean before and after and unchanged
during each recorded gate. `page-map` is complete within this M2 contract; the
other seven required components remain partial under their explicit remaining
conditions.

At `448b4cf4e8833394df1f96594e9e15ee6640bed7`, a clean detached native rerun
attested the then-current 59-check revision: `allocator --quick` and
`allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial contract
requires. Its M2 report records all 59 checks passing, clean source before and
after execution, and no source change during it. The contract retained the same
seven unmet component IDs; only `page-map` was complete. This is historical
evidence after the 60-check revalidation below.

At `22732b90eb379e2e654d99e966c62067c22f601b`, a clean detached native rerun
attested the then-current 60-check revision: `allocator --quick` and
`allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial contract
requires. Its M2 report records all 60 checks passing, clean source before and
after execution, and no source change during it. The contract retains the same
seven unmet component IDs; only `page-map` is complete. This is historical
evidence after the 61-check revalidation below.

At `f304bfb36a718e97a427c10bd6b628eee6904e3a`, a clean detached native rerun
attested the then-current 61-check revision: `allocator --quick` and
`allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial contract
requires. Its M2 report records all 61 checks passing, clean source before and
after execution, and no source change during it. The contract retained the
same seven unmet component IDs; only `page-map` was complete. This is
historical evidence after the 63-check revalidation below.

At `3012d983daaf02417496097abbf5dc2283e239a9`, a clean detached native rerun
attested the then-current 63-check revision: `allocator --quick` and
`allocator-m1` exited 0, while `allocator-m2` exited 3 as its partial contract
requires. Its M2 report records all 63 checks passing, clean source before and
after execution, and no source change during it. The contract retains the same
seven unmet component IDs; only `page-map` is complete. The added
initialization evidence is the direct 40-field pinned-C/Rust detached static
preimage trace and a selected Rust busy-lock refusal regression. The trace
excludes main-subprocess initialization, normal `mi_tld_init`/`mi_tld_create`,
and general TLD lifecycle; the busy-lock refusal is a Rust safety strengthening
rather than C lock parity. This is historical evidence after the later 65- and
66-check revalidations below.

At `46d179f7f2ca3830700be8cbd11b1185fe65f2d3`, two clean detached native
reruns attested the then-current 65-check revision: each `allocator --quick` and
`allocator-m1` command exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest clean source before and after
execution and no source change during it. M1 remains six-of-six complete with
no unmet IDs; M2 records all 65 selected checks passing—fourteen
VM-primitives, twelve metadata, nine bitmap, ten PageMap, five arena, nine
initialization, two fault-injection, and four allocator-recursion. The new
normal records are a 31-relation direct C/Rust `src/init.c:236-250` helper
trace and a Rust busy-lock safety regression; they do not establish
`mi_tld_create` or a caller lifecycle. The contract retains the exact same
seven unmet component IDs; only `page-map` is complete. This is historical
evidence after the 66-check revalidation below.

At `0e15fcbbb3775b6ff5a4f991f2751626c3d67f64`, two clean detached native
reruns attest the then-current 66-check revision: each `allocator --quick` and
`allocator-m1` command exited 0, while `allocator-m2` exited 3 as its partial
contract requires. The M1/M2 reports attest clean source before and after
execution and no source change during it. M1 remains six-of-six complete with
no unmet IDs; M2 records all 66 selected checks passing—fourteen
VM-primitives, twelve metadata, nine bitmap, ten PageMap, five arena, ten
initialization, two fault-injection, and four allocator-recursion. The added
record directly compares only the selected first-main/static
`src/init.c:253-272` `mi_tld_create` success arm. Pinned C calls file-static
`mi_tld_create(_mi_subproc_main())` exactly once with the source static
identities, zero total/live counts, and inert nonnull `theap_meta`; its
C-only trace also observes the actual selected predicate-to-return chain and
zero `_mi_meta_zalloc` calls. Rust begins only after separately modeled
selector and Heap-foundation prerequisites. The shared 36-key,
address-independent schema covers a normalized semantic suffix from ticket
zero through typed static memory identity, modeled normal body, live
registration, and labeled Release visibility. It does not establish equal
C/Rust predicate, caller, preflight, primitive, or return-boundary timing;
C/Rust layouts; `_mi_subproc_main_init`; actual Theap or metadata
initialization; failed, generic, or later arms; TLS/list/root publication;
teardown; races; pthread ABI; or allocator integration. The contract retains
the exact same seven unmet component IDs; only `page-map` is complete. This is
historical evidence; the current 67-check revalidation is recorded in the
Current handoff above.

The new VM slice maps only fixed normal/offset non-huge allocation:
`NormalOsAllocation` retains the complete map base/length in `MemoryId::os`
while keeping a distinct client pointer, zero offset delegates to ordinary
aligned allocation normalization, committed-prefix decommit remains
best-effort, reserved prefixes do not decommit, and a failed cleanup/unmap
retains the exact owner for retry. One selected `src/arena.c:1885-1912`
`mi_reserve_os_memory_ex2` regular-OS caller now consumes only the zero-offset
base-equals-client `NormalOsBaseAllocation`, transferring its exact `Mapping`
and `MemoryId` into one complete arena's in-place management; the selected
reserved/committed regression observes the published arena's retained mapping
provenance, while an offset allocation has no such conversion. It excludes huge
pages, hints, NUMA policy beyond the separately selected fixed no-option
wrapper, options, statistics, arbitrary memory-kind dispatch, and any other
source runtime caller. The new direct
TLS slice restores the exact `MetaRelease::Malloc`
capability, root/count/slots, and `Active` state only after a proven pre-claim
same-thread rejection; a successful retry keeps C's free-before-root-clear
order. Generic/free post-claim failures remain terminal. One selected outer
`DynamicTheapAttachment` continuation instead records
`AwaitingBackingRelease` after it clears the regular heap-key entry keyed by
its Heap's `theap_slot` and marks its binding unbound: only the exact Malloc
pre-claim result retains the distinct compiler-TLS backing root/allocation,
key lease, TLD, Theap, Heap binding, cached reference, and sealed engine image
to retry backing release. It never republishes the key entry or repeats
attached preflight, and ordinary page-engine operations remain suspended. The
separate final pre-mutation regular-key lock continuation remains
`AwaitingKeyRelease`; this is a Rust ownership boundary, not C retry/error or
mutex parity.

The selected fixed no-option NUMA wrapper maps pinned `src/os.c:860-898` and
one selected `src/init.c:236-250,260-272` ticket-zero static-TLD caller. Its
private zero-initialized count cache has the source Acquire read and Release
fill: raw zero or a count above `INT_MAX` becomes one, while `INT_MAX` itself
remains valid. `os_numa_node` first takes the source Relaxed cached-one
shortcut; otherwise it obtains the cached count, maps a raw current node at or
above `INT_MAX` to zero, and modulo-normalizes a lower out-of-range node. After
ticket issue, Rust forms that static TLD's `MemoryId`, synchronously obtains
this wrapper result, then writes one complete unpublished TLD image before its
live/root publication. The focused local-cache regression proves `8 % 3 == 2`,
zero and oversized raw counts normalize to a one-node result (node zero)
without a current-node probe, and the static-provenance, ticket, live-count,
and root-order boundaries. It
retains the raw M1 `numa_node_count`/`numa_node` trace unchanged. It does not
claim C's field-by-field `mi_tld_create`/`mi_tld_init` order, detached or
generic/later TLD callers, `mi_option_use_numa_nodes`, diagnostics, topology
or first-fill-race policy, arena placement, C/Rust differential parity, or
allocator integration.

The selected reuse primitive is narrower still. Pinned `src/os.c:643-653`
conservatively normalizes `_mi_os_reuse`; Linux
`src/prim/unix/prim.c:536-542` then returns zero without a VM operation.
`Mapping::reuse` returns `None` for no complete page and an explicit
`ReuseOutcome::NoOp` for a complete contained range, with no syscall, fault
edge, or mapping-state mutation. Its Rust input errors are checked safety
boundaries, not C error parity.

There is one separately selected non-owning allocator caller. In pinned
`src/arena.c:266-307`, after the binned free claim succeeds, the
`commit && already_committed == slice_count` branch invokes `_mi_os_reuse`
before `memid->initially_committed`. `ArenaView::try_claim_suitable_slices`
uses `os::reuse_arena_range`, not `Mapping::reuse`, for that exact aligned
span. The source-mapped call site establishes the ordering; its focused
precommitted two-slice witness observes one matching exact-span call. The
reuse operation takes neither a `Mapping` nor a release capability, so it has
no syscall, fault edge, reuse-state mutation, mapping-owner transfer, or late
failure. This does not establish partial/fresh commit behavior, another caller,
reuse policy/search, Apple behavior, statistics, C/Rust differential parity,
or allocator integration.

The selected bitmap observer ports only `src/bitmap.c:1383-1403`
`mi_bitmap_bsr`: it reads chunk-map/data fields Relaxed in descending order and
scans below a stale in-layout high map bit before returning a lower live bit,
without changing either image. Rust caps a final scan to initialized chunks
instead of deriving the source's assertion-invalid trailing-layout pointer.
The focused test proves only the in-layout stale-high case and map
preservation. A separate direct unit regression writes an out-of-layout high
map bit and proves the checked scan remains bounded, returns the lower live
bit, and retains that invalid map entry. Neither test is a C differential or
an allocator integration claim.

The selected ordinary popcount observer maps `src/bitmap.c:1406-1420` to
`BitmapView::popcount_relaxed`. It walks conservative chunk-map fields from
low to high with Relaxed observations, counts selected data without repairing
an in-layout stale map entry that contributes zero, and retains that map image.
The focused Rust regression also records the safety boundary for an
out-of-layout stale map entry: Rust skips its data access rather than deriving
C's layout-valid pointer. This is not a C differential, mutation, visitor, or
allocator-integration claim.

The selected binned highest-clear port maps the outer
`src/bitmap.c:1616-1634` `mi_bbitmap_bsr_inv` scan and its inner
`src/bitmap.c:997-1009` chunk/field walk to
`BinnedBitmapView::highest_clear_relaxed`. Its fifth direct C/Rust bitmap
differential uses valid caller-owned two-chunk images: a logical 513-bit image
observes source-rounded top padding at bit 1023, while a seeded image returns
963, 585, 511, then no result as each selected bit is restored; its binned
chunk map remains empty. The two focused Rust unit regressions remain
supplemental witnesses for rounded padding and descending chunk/field order.
This is a read-only Relaxed observer, not evidence for binned search, claim,
flexible-array ownership, Heap/Page/Arena integration, races, or statistics.

The selected canonical static main-Heap witness maps `src/init.c:196-198` and
the remaining `src/heap.c:102-126` initialization order. After its private
static-foundation claim, a `MainStaticHeapFoundation` reserves a pointer-free
`MainSubprocess` publication before mutating the candidate Heap image, writes
the candidate's kind-only static memid,
then Release-publishes its exact identity before the remaining selected Heap
initialization. Only after that initialization does it make an opaque ready
identity available. A stale candidate remains COLD with `MemoryKind::None`,
after a failed reservation releases the private claim, and an unfinished
publication remains non-ready. The Rust ready lookup is
comparison-only: it does not emulate C's dereference-capable
`_mi_subproc_heap_main`, grant Heap projection, prove general main-Heap
linkage, or close process initialization.

The first bitmap differential directly includes pinned `src/bitmap.c` as its
only C translation unit and compares 21 address-free facts with
`BitmapView::try_find_and_claim_abandoned`. Its static one-chunk image fixes
thread sequence five and candidate bit 17. A `KeepSet` rejection invokes one
callback and restores both the candidate and its conservative chunk-map bit; a
later accepted claim invokes one callback, clears the candidate, and leaves the
conservative map set; a final drained probe invokes no callback and repairs
that stale map bit.

The second directly includes the same pinned source file and compares 26
address-free facts with `BitmapView::visit_set_ranges_clear`, the selected
scalar port of `_mi_bitmap_forall_setc_ranges`. Its static one-chunk completed
walk emits maximal low-to-high runs without crossing a source 64-bit field and
retains the conservative map. Its stopped walk leaves the current visited range
clear, restores only the unvisited same-field residual, and leaves a later
field untouched. The trace calls the generic routine directly; it does not
execute or prove `_mi_bitmap_forall_setc_rangesn` policy, although the pinned
source's `<= 1` delegation makes this generic routine the frozen default-purge
implementation. Those first two bitmap differentials do not claim the C
`keep_set = false` rejection route, multi-chunk or sequence distribution, actual
arena/subprocess ownership, races, `clear_once_set`, other visitor families,
statistics, binned bitmaps, flexible-array allocation ownership, or allocator
integration.

The third directly includes the same pinned source file and compares 52
address-free facts with `BitmapView::visit_set_ranges_clear_aligned`, the selected
scalar port of `_mi_bitmap_forall_setc_rangesn`. Fresh `rngslices == 3` images
cover aligned completed windows, incomplete-window/top-suffix restoration, and
a stopped callback that restores a prior skipped window plus later snapshot
bits; fresh zero and one calls cover generic delegation, and 65 covers the cap
at 64. It does not execute `_mi_os_minimal_purge_size`, transparent-huge-page
policy, or an arena caller.

The fourth directly includes pinned `src/bitmap.c` and compares 30
address-free facts with `BitmapView::visit_set_bits`, the selected scalar port
of `_mi_bitmap_forall_set`. Fresh valid 65-chunk images span source chunk-map
fields zero and one: the completed walk emits bits 1, 65, and 32770 in source
order, while a stopped walk returns at its second callback and leaves the
selected raw data and chunk-map fields unchanged. The C fixture owns a
layout-valid 4,288-byte image; no Heap, Page, or Arena pointer, callback
mutation, binned bitmap, flexible-array ownership, arena/subprocess path,
race, statistic, or allocator integration is exercised. A Rust-only stale
out-of-layout map-bit regression separately documents the safe skip-and-retain
divergence outside the C routine's valid-layout precondition; it is source-level
safety evidence outside this selected C/Rust report.

A separate fresh C process makes only `src/page-map.c`'s first aligned PageMap
allocation fail, so the source `mi_atomic_do_once` state cannot contaminate
the success producer. Its Rust partner injects the first `FaultPoint::Map` in
`ProcessPageMapStorage`. Both records prove one failed initialization body, no
published dynamic map, and no replay. C retains `mi_page_map_empty`, keeps a
null lookup safe, and reports later `_mi_page_map_init` success after consuming
the failed body; Rust retains no fake live `PageMap`, exposes no cold lookup
route in its absent-root/poisoned state, and reports terminal typed poison.
Those values are a recorded, intentionally accepted bounded PageMap safety
divergence, not exact-equality or full-initialization claims. The pinned C
sentinel makes only its null lookup safe after the failed once body; it is not
a valid dynamic map or safe registration/mutation continuation. Rust must not
fabricate a `PageMap` or successful process continuation from that state: the
source-order coordinator has already prepared its Heap and detached metadata.
`process_init::tests::rejected_page_map_after_heap_and_metadata_retains_ticket_zero_without_tls_publication`
proves that the coordinator retains this terminal state without publishing
ticket-zero roots or admitting a later generic thread. A future public C ABI
or complete process lifecycle that needs cold `free(NULL)` semantics must
reopen this boundary with a distinct lookup-only cold-sentinel owner and
lifecycle evidence.

The selected Rust PageMap now carries a paired initial-commit/cleanup failure
through `PageMapInitializationError::Retained` rather than dropping its
non-RAII `Mapping`. `ProcessPageMapStorage` stores that exact unpublished
owner before terminal poison; `MetaAllocator` has a separate final slot for
the same failure before it publishes `FAILED`. The process-owner regressions
cover both the initial top-level and trailing-submap commit branches, and the
metadata regression proves the independent metadata caller cannot collapse a
retained mapping into a scalar error. They explicitly release the retained
owner after disabling the injected fault.

Four additional direct Rust PageMap regressions cover the reachable lazy and
destruction failure matrix: a failed top-level extension commit leaves the
same top-level `Mapping` usable; a failed lazy submap map leaves the same
PageMap usable; a failed lazy-submap reclaim leaves its exact raw slot
published; and a failed final top-level `unmap` leaves its exact `Mapping`
usable. Each test disables the fault and proves the corresponding retry. The
source-shaped CAS loser remains outside that fault matrix because
`PageMapHeader::submaps` and its atomic view are module-private and every
current Rust publisher holds the same PageMap private lock and rechecks the
slot; the M2 concurrent-publication check observes one allocated/published
candidate across four contenders. A future competing writer must retain a
losing candidate before it can make that branch reachable. The C release calls
are void/best-effort, so this is Rust ownership-safety evidence, not a C
retry-parity claim. Together with the explicit cold-root safety decision
above, these checks close the selected M2 PageMap component. They do not close
general process lifecycle, public C ABI behavior, concurrent map lifetime, or
allocator integration.

The selected VM-primitives evidence is deliberately narrower than M2 closure.
`Mapping::map_aligned_for_allocator` now preserves an exact non-RAII owner
through each native cleanup edge: a failed direct-candidate unmap retains that
direct map, a failed prefix trim retains the full overmap, and a failed suffix
trim retains the already prefix-trimmed aligned range plus its live suffix.
`AlignedMappingFailure` transfers that owner to the caller. `OsAlignedPageClaim`
retains it as a claim, `MetaAllocator` stores it beside its already-private
PageMap before terminal failure, and `ProcessSharedArenaStorage` stores it in
its final sidecar before terminal retention. The test adapter additionally
uses `TestContextInitFailure` to retain an unpublished PageMap together with a
failed aligned arena map until reverse-order cleanup succeeds. PageMap itself
uses the direct primitive because its requested alignment is exactly Linux's
base-page mmap guarantee, so no aligned-overmap cleanup owner can arise there.

The M2 manifest selects four direct `os` tests plus the `os_page`, `meta`, and
`process_arena` propagation tests. They use a native-only forcing seam solely
to make direct, prefix, and suffix cleanup deterministic; production retains
the pinned `length + alignment` overmap request. Pinned C's partial frees are
void/best-effort, so retaining the typed Rust owner is a safety strengthening,
not retry-parity or complete aligned-allocation evidence. Reserve, commit,
decommit, purge, protect, reuse, huge-page, hint, NUMA, remaining overmap
policy, and the wider failure matrix still keep VM primitives partial.

The selected native fault-injection evidence is equally narrow. Pinned
`src/prim/unix/prim.c:600-604` supplies `_mi_prim_protect`, and
`src/os.c:690-712` routes `_mi_os_protect`/`_mi_os_unprotect` through
`mi_os_protectx`. The one-page committed-mapping regression injects one
test-only pre-syscall `NOMEM` at each Rust transition. It checks the exact
mapping base and length after each failure; volatile access proves that failed
protect left the page writable, while the failed-unprotect route deliberately
does not dereference until retry. With injection disabled, each route succeeds,
restores access where needed, and unmaps once. This does not observe a live
kernel error, compare C diagnostics or failure behavior, prove state after
failed unprotect, or cover range policy, allocator callers, decommit/commit/
purge, PageMap, arena, metadata, bitmap, release, signals, or races.

The second selected fault record is an initialized two-level PageMap C/Rust
differential at pinned `mi_page_map_ensure_submap_at` and
`PageMap::ensure_submap_at`: one test-only commit failure occurs before
committed-prefix publication or lazy submap allocation, retains the top mapping
and original committed prefix, and a disabled-plan retry advances it and
allocates exactly one submap. It excludes cold init, range-writer rollback,
lazy submap-map and release failure, CAS losers, concurrency, routing, and
general PageMap fault parity.

The selected `arenas` evidence is deliberately narrower than arena closure.
With the frozen default `minslices == 1`, its unpinned external-arena fixture
holds the legal `[9, 63)` prefix, releases `[63, 65)`, and forces collection.
Pinned `mi_arena_try_purge` reaches `_mi_bitmap_forall_setc_ranges` through
`_mi_bitmap_forall_setc_rangesn`'s `minslices <= 1` delegation. Rust now
reaches that selected scalar source boundary through
`BitmapView::visit_set_ranges_clear`, whose separate bitmap differential proves
its one-chunk completed/stopped semantics. The boundary-spanning arena run
invokes the decommit hook twice, once for each source 64-bit bitmap field, while
the Rust test proves the free bits are restored and the purge bits cleared. This
still proves only default one-slice delayed-purge callback grouping;
configurable purge policy, multi-chunk traversal, other visitor families,
registry-wide collection, concurrent arenas, and arena lifecycle remain
unclaimed. Thus `arenas` and M2 remain partial.

The second selected arena test fixes the frozen Linux default error transition,
not a retry policy. After a valid unpinned page release, it injects the one
`MADV_DONTNEED` failure and forces collection. Pinned `src/prim/unix/prim.c`
still writes `needs_recommit = false` in this normal profile, while
`src/os.c:_mi_os_purge_ex` reports that outcome after its decommit helper
reports an error. Therefore the source keeps `slices_committed` set, restores
`slices_free`, leaves `slices_purge` and the arena-local expiry clear, and
continues collection. The Rust regression proves exactly those facts and that
the external mapping remains owned by its caller. It does not claim general
purge fault parity or error-reporting policy.

The third selected arena test is a sequential partial-reclaim fallback, not a
live allocation/purge race. It schedules the two-slice `[9, 11)` range, then
reclaims `[9, 10)` before forced collection. The source-shaped whole
`slices_free` claim therefore fails; the allocation-won low slice remains
unavailable and does not call the decommit hook, while the high free sibling is
individually claimed, calls that hook exactly once, and is restored to free.
The source-cleared purge bits for both slices remain clear. This does not claim
arbitrary spans or visitor outcomes, configurable/minimal/THP purge policy,
multi-chunk, registry-wide, or multi-arena collection, concurrency, lifecycle
closure, fault/retry behavior, or a C/Rust differential.

The fourth selected arena test isolates the all-committed reuse caller, not
purge. Pinned `src/arena.c:266-307` takes the `commit && already_committed ==
slice_count` branch only after its binned free claim succeeds. Its source-mapped
call site invokes `_mi_os_reuse` before `memid->initially_committed`; Rust calls
the non-owning `os::reuse_arena_range` at the same point. The precommitted
two-slice fixture's witness observes one matching exact-span call, and the
returned claim is initially committed. The Linux helper remains a no-op under
`src/os.c:643-653` and `src/prim/unix/prim.c:536-542`: it has no syscall,
fault-injection edge, reuse-state mutation, `Mapping` ownership transfer, or
late failure. This is not evidence for partial/fresh commit, another caller,
arena search/policy, general purge, statistics, Apple reuse, C/Rust
differential parity, or allocator integration.

The fifth selected arena test covers the other source purge outcome for one
external callback. Pinned `src/arena.c:2254-2282` first marks the owned exact
range committed, then `src/os.c:655-680` returns a custom callback's
`commit = false` boolean as `needs_recommit`. The callback fixture returns
true and records the exact two-slice span. Rust proves the committed bits clear
before free availability returns, the scheduled purge bits and expiry are
consumed, and a later `commit = false` claim reports
`initially_committed == false`. This is a source-shaped existing transition,
not a new allocator policy or a C/Rust differential; it does not cover general
callback behavior, purge policy, retry/error handling, concurrency, lifecycle,
or integration.

The manifest additionally selects
`os::tests::reset_retries_the_initial_advice_after_a_concurrent_global_fallback`.
Pinned `src/prim/unix/prim.c:_mi_prim_reset` takes one Relaxed snapshot of its
process-wide advice before it retries `EAGAIN`; another caller's Release store
from `MADV_FREE` to `MADV_DONTNEED` must not change the in-flight retry. The
regression uses a local atomic advisory mock to make that interleaving
deterministic: the old Rust implementation requested `MADV_FREE` then
`MADV_DONTNEED`, while the source-shaped implementation requests `MADV_FREE`
twice and leaves the shared cache changed for later callers. It proves only
that private control-flow rule, not a kernel `EAGAIN` schedule or complete
purge fault parity.

The record deliberately does not equate source representations that are not
the same: the pinned C header contains the Linux/musl `pthread_mutex_t`, while
the `#![no_std]` Rust header contains `PrivateLock`; its header-dependent
entry counts are retained on both sides of the report. Likewise, C destroys a
live global root and then restores its static empty root, whereas a Rust
`PageMapRoot` is a separate owner and must be unpublished before
`PageMap::destroy`. The report makes both facts explicit. This is selected
success-path plus one cold-init-failure differential, not C/Rust equality for
their cold-root policy, VM failure, full PageMap lifetime, or the remaining
VM, metadata, bitmap, arena, initialization, fault, and recursion closure
conditions.

The metadata witness is deliberately smaller still. `MetaRelease::Malloc`
carries one exact detached `MetaAllocation` and retrieves that capability's
recorded owner internally. Its selected typed boundary enters Rust's backing
lock and same-thread marker before changing LIVE to RELEASING, so only an
invalid entry thread, same-thread recursion, or backing-lock acquisition
failure can return the unchanged exact capability as `MallocRetryable`.
Stale/provenance rejection and every post-claim local-free error remain
`MallocTerminal`; the general `MetaAllocator::free` lifecycle route remains
terminal-on-error for admitted owners. This is a narrow Rust ownership rule,
not C free or mutex equivalence. `MetaRelease::RegularOs` carries only one
normal anonymous `Mapping` and returns it after a failed `munmap` for explicit
retry, but it is a synthetic standalone retry witness, not a C metadata
caller: pinned `_mi_meta_zalloc` forms Malloc IDs, while a real direct-OS
`_mi_arenas_free` owner needs the wider memory-ID/subprocess contract. A
no-free source branch carries no release token. `MetaRelease` deliberately
remains only `Malloc` and `RegularOs`; its separate typed
`ArenaSliceClaim::release_for_subprocess` boundary carries one live arena claim
and checks the selected `MainSubprocess` identity before Rust's
purge/free-bitmap transition. Huge, remap, sanitizer-tracking, integration,
and allocator-recursion coverage remain M2 conditions.

The selected later-TLD direct-Malloc check connects that exact Malloc lifetime
to one real caller without broadening the metadata route: ticket-zero static
storage tears down with no `MetaAllocation`; one injected post-ready
direct-zeroed later request consumes its source sequence without a capability
or live-count lease; and its sequence-two retry is a typed
subprocess-attached/no-theap Malloc TLD whose teardown returns the capability
count to zero while retaining high-water one. It is not normal C
`_mi_meta_zalloc` backing parity, generic `_mi_meta_free` dispatch, complete
`mi_tld_init`/`mi_tld_free` list or lock behavior, or arbitrary-thread/ticket
coverage.

The selected nonexclusive dynamic-Theap check follows one child thread after
ticket zero through a caller-pinned empty Heap with no exclusive arena. It
observes a sequence-one Malloc TLD and Malloc Theap in the selected one-member
TLD/Heap list shape, plus four attached metadata capabilities: TLD, Theap,
regular backing, and the distinct process-owned registry bitmap. The
implementation's no-page path releases regular backing, then the exact Theap,
then the TLD; the audit observes the three attachment-local capabilities gone
and the registry bitmap remaining, which test-only quiescent shutdown releases.
The paired injected-Theap-allocation failure occurs after TLD and registry
creation but before an allocated regular-backing metadata capability, consumes
its ticket without a live count, and retains only the immutable empty dynamic
root plus the registry bitmap in the metadata audit. Two separate selected
requested-parent records cover the exclusive-arena path:
`requested-parent-theap-one-slice-arena-reservation` is only the pre-init
allocation/provenance reservation, and
`requested-parent-arena-theap-prefix-lifecycle` is the synthetic no-page
Arena-prefix lifecycle described below. This nonexclusive check does
not establish normal C `_mi_meta_zalloc` backing, a complete exclusive-arena
Theap lifecycle, generic `_mi_meta_free`, general list/refcount policy, page
ownership, concurrency, or process/thread shutdown parity.

The selected backing-release retry is deliberately narrower than that no-page
lifecycle record. `dynamic_theap_backing_release_recursive_entry_retains_outer_lifecycle_for_retry`
holds the same-thread metadata entry with no pages and proves that the
compiler-TLS backing allocation/root plus the exact outer owner survive only
the pre-claim rejection. `dynamic_thread_exit_drain_resumes_a_retryable_backing_release`
uses one already retired PageMap-published page: it proves the retained engine
cannot allocate while its regular heap-key entry is clear, that the PageMap and
page image survive, and that the successful retry carries that unchanged page
into the dedicated drain. Neither witness establishes generic page-bearing
teardown, C error/retry or mutex behavior, callbacks/signals, cross-thread
continuation, pthread/process shutdown, ABI, or general allocator routing.

The `threadlocal-live-rezalloc-malloc-capability-lifetime` metadata record
narrows the live regular-TLS replacement branch in
`src/threadlocal.c:103-162,205-214` and `src/subproc.c:49-81`. It begins only
after the existing fresh 16-slot Rust image in one child thread with the
selected main-subprocess identity. An injected pre-allocation failure after
Rust's moving claim restores the exact old Malloc root, count, slot 15, null
slot 16, and capability; one 16-to-32 retry copies slot 15, publishes slot 16,
has one live capability with high-water two, and tears down to zero. This is
the Rust ownership equivalent of C's null replacement result, not production
fault policy. It does not compare C's initial count-zero
`_mi_meta_rezalloc(NULL, ...)` route with Rust's separate fresh zalloc image,
or establish arbitrary growth, normal C metadata backing, generic
`_mi_meta_free`, complete TLS/TLD/Theap/registry lifecycle, concurrency,
pthread/process lifecycle, or ABI integration.

The `meta-cold-demand-requires-prepared-theap-publication` metadata record
narrows only the source precondition at
`src/init.c:184-205` and `src/subproc.c:29-70`. While the Rust owner is COLD,
direct `zalloc`, aligned `zalloc`, and `rezalloc(None)` each return
`TheapMetaUnpublished` before either metadata lock, consuming a map fault,
or creating a capability. `prepare_for_main_subprocess` first forms the
selected static detached image, then one-way Release-CAS publishes its exact
pinned Theap identity through the selected `MainSubprocess` before BOUND; it
does not consume the pending backing fault. The first prepared demand may
consume that fault and return to BOUND, and a later prepared retry succeeds.
This is only a Rust safety strengthening of C's non-null assertion: it does
not provide the actual `mi_subproc_t::theap_meta` field/layout,
C pthread-lock semantics, other `theap_meta_lock` users or lifecycle, pointer
dereference through the subprocess, general or dereference-capable main-Heap
linkage beyond the selected opaque comparison identity, normal
`_mi_meta_zalloc` backing, or complete process initialization.

The `bound-subprocess-metadata-page-identity-query` metadata record maps only
`src/subproc.c:84-88` (`_mi_meta_is_meta_page`). `None` represents C's null
page pointer; a caller-readable `Page` with a null or foreign `theap` field is
false, and only the exact published bound-subprocess identity is true. The
focused test keeps two subprocesses BOUND with no private PageMap backing or
detached session, holds one selected metadata entry while querying, and proves
the query leaves entry attempts, map state, and allocation audit unchanged.
Rust's Release/Acquire identity slot is a safety representation, not C field
layout or memory-order parity. The query neither takes nor proves the separate
selected direct-allocation lock. This has no C/Rust differential claim and does
not provide byte-for-byte `mi_subproc_t`, C pthread-lock semantics, the
remaining `theap_meta_lock` users or lifecycle, a general Theap or
page-lifetime/abandonment API, normal `_mi_meta_zalloc` backing, generic free,
subprocess lifecycle, race proof, C ABI, or allocator integration.

The `bound-subprocess-theap-meta-lock-direct-allocation-phase` metadata record
maps `src/subproc.c:29-70`, the field context at
`include/mimalloc/types.h:667-668`, and the selected source pthread-lock
representation at `include/mimalloc/atomic.h:446-472`. After the existing
identity preflight, `MetaAllocator::enter_for_main_subprocess` takes
`MainSubprocess::lock_metadata_theap` inside Rust's backing lock and same-thread
marker for direct `zalloc`, aligned `zalloc`, and the replacement-allocation
phase of `rezalloc`. `MetaEntry::drop` releases that nested source-shaped guard
before rezalloc copy/free. Pinned `_mi_meta_free`'s `MI_MEM_MALLOC` branch
calls `mi_free` without `theap_meta_lock`; Rust keeps selected exact-owner free
on its separate backing lock. The focused test holds the selected subprocess
lock before first direct demand, observes BOUND with no private backing or
capability until release, and also covers aligned allocation and rezalloc copy
preservation. This is not C byte-layout or pthread-lock parity, other lock
users or lifecycle (including `src/free.c:744-778`, `src/init.c:524-530`, and
`src/subproc.c:141-148,249-251`), a general concurrency proof, normal C
metadata backing, or complete metadata/process initialization parity.

The separately selected
`metadata-same-thread-free-reentry-before-capability-mutation` recursion
record maps only `_mi_meta_free`'s `MI_MEM_MALLOC` branch. Its focused test
holds Rust's backing entry, proves `MetaRelease::Malloc` returns the exact live
pointer, `MemoryId`, and audit as `MallocRetryable` before LIVE-to-RELEASING,
then releases the same value after the entry drops. It deliberately does not
make general `MetaAllocator::free` retryable or claim C lock/deadlock,
callback/signal, cross-thread, other release/copy, backing, lifecycle, or
allocator-integration parity.

The `arena-release-subprocess-identity-gate` metadata record is deliberately a
separate typed arena-release witness, not a `MetaRelease::Arena` variant or a
generic `_mi_meta_free` dispatcher. It selects the `MI_MEM_ARENA` identity assertion in
`_mi_arenas_free`, reachable from the pinned non-Malloc metadata route. Its
one-slice unpinned fixture gives the arena one bounded `MainSubprocess`: a
foreign identity gets the exact unchanged live claim back while the free
bitmap, purge bitmap, and purge expiry remain unchanged; the matching identity
consumes the claim through the existing terminal free-bit result, and a fresh
claim proves the slice is reusable. Rust turns C's internal assertion into a
fail-closed safe refusal. This is source-level safety evidence, not C/Rust
invalid-input parity, normal C metadata-backing parity, generic dispatch,
general purge policy, full registry/subprocess lifetime, no-free/OS/huge/remap
coverage, retry behavior after a false terminal result, races, statistics, or
allocator integration.

The `requested-parent-theap-one-slice-arena-reservation` metadata record maps
only the first requested-parent allocation pass of `src/theap.c:_mi_theap_alloc`.
It treats an already-published direct parent as a caller-selected
`heap->exclusive_arena` value without binding or
inspecting a Heap, passes one caller-supplied `ThreadSequence` value, claims
one committed `MI_ARENA_MIN_OBJ_SIZE` slice, retains its `MI_MEM_ARENA`
`MemoryId`, rejects a foreign bounded `MainSubprocess` before bitmap mutation,
proves that exhaustion does not use the unrelated arena or an OS fallback, and
uses the selected release gate before exact dirty-bit reuse. The C-only `LAYOUT_PROBE`
asserts `sizeof(mi_theap_t) <= MI_ARENA_MIN_OBJ_SIZE`; Rust intentionally
makes no Theap storage/prefix or Rust/C size-equality claim. That C assertion
is companion `allocator --quick` baseline evidence, not a C compile performed
by the focused M2 Rust test. The selected reservation does not model the
nonnegative-NUMA second requested-parent pass, option gates, pinned-acceptance
evidence, or the separately recorded all-committed `_mi_os_reuse` caller
boundary; debug/tool memory-tracking instrumentation including `MI_DEBUG > 1`
zero validation, a Heap/TLD/thread assertion, `theap->memid`,
`_mi_theap_init`/`_mi_theap_create`, list/TLS/refcount/free lifecycle,
`MetaAllocation`, `MetaRelease::Arena`, generic `_mi_meta_free`, diagnostics,
statistics, races, or allocator
integration. Its foreign refusal is a Rust
fail-closed safety boundary, not invalid-input C parity.

The `requested-parent-arena-theap-prefix-lifecycle` metadata record is a
synthetic bounded subcall, not
`mi_heap_init_theap` or complete `_mi_theap_create` parity. It starts only
after an already-live static default TLD `D` and a fresh caller-pinned Heap
with one direct selected parent are supplied. That parent produces one exact
committed Arena slice for auxiliary Rust-Theap prefix `A`; `A` retains its
`MI_MEM_ARENA` `MemoryId`, is initialized only through the Rust prefix's
`memid` boundary, links before `D` on the TLD and as the caller Heap's sole
member, splits `D`'s random image, and uses the selected Release heap
publication. An unbound caller Heap is rejected before prefix materialization
and its exact reservation can be returned. A successful lifecycle returns the
selected slice, and a dirty second lifecycle reuses that exact slice.

Its page-free teardown composes only the selected heap-delete topology: remove
`A` from the `A → D` TLD list, then remove it from its sole Heap list, then
Rust Release-clears `A.heap` before the final `1 → 0` prefix transition,
typed-prefix drop, and selected-slice release. It deliberately omits C thread
initialization, the regular TLS get/null decision and slot store, cached-root
behavior, retry/yield contention, normal heap/subprocess list and counter
ownership, C subprocess Theap statistics increment/decrement/merge, the
complete C Theap layout/statistics tail, generic `_mi_meta_free` or
`MetaRelease::Arena` dispatch, pages, process/thread shutdown, option/NUMA
second pass, normal metadata backing, faults, races, and allocator
integration. This is therefore a source-mapped prefix-owner witness, not a
complete requested-parent Theap lifecycle.

The two detached-metadata initialization witnesses observe the image before it
can issue a session or acquire private backing. For only the bounded
same-subprocess, empty-head, non-threadpool input, the first observes kind-only
`_mi_memid_create(MI_MEM_STATIC)` provenance (zero union and flags), the frozen
normal `page_reclaim_on_free = 0` result (`allow_page_reclaim = true`), an
initialized possibly-weak random image, and an odd cookie. Its mapped source
order writes that random/cookie state before Release heap publication. The
second witness proves a nonempty head, mismatched subprocess, or thread-pool
input leaves the candidate static image untouched rather than pretending to
model C's locked list/split or option-adjustment paths. These witnesses do not
claim the rest of `_mi_theap_init`, mutable option processing, TLD/Heap list
relations or locking, guarded initialization/statistics, random-split parity,
general or dereference-capable main-Heap linkage beyond the selected opaque
comparison identity, `mi_subproc_t::theap_meta` field/layout, and
the C pthread-lock semantics or remaining `theap_meta_lock` users/lifecycle,
normal `_mi_meta_zalloc` backing parity, or complete process initialization.
The `meta-cold-demand-requires-prepared-theap-publication` record separately
claims only the comparison-only one-way identity-admission publication described
above. C writes the detached non-abandoning/retain special fields after `_mi_theap_init`
publication and list linking; Rust keeps its bounded final image before
publication because it does not model those lists.

Run `./scripts/dev.sh allocator-m2` from a clean native checkout to write the
current-commit `.work/reports/allocator/m2-memory-substrate-latest.json`
report. Its expected exit is 3 until all eight categories are complete; a
report with that exit documents the active gap rather than advancing M2.
At `33e9fc801935c02ac30bc50c82674ece93ebca95`, that clean native command
exited 3 after both PageMap checks passed: the success lifecycle remained
`matched`, while the cold-init check recorded three shared failure facts as
`modeled-safety-divergence`. The report retains all eight categories and the
remaining PageMap conditions as unmet.

At `0e68bcdf8255104eb982852fc3cd0602f62eaf12`, the same clean native command
again exited 3 as designed, with an unchanged source tree. Its five executed
M2 checks all passed: the metadata caller, the success and cold-init
PageMap differentials, and both initial-commit cleanup-owner branches. The
PageMap component now has exactly two remaining conditions: lazy
extension/destruction release fault evidence and the documented C
static-empty-root versus Rust typed-poison cold-root semantic gap.

At `e979923306e2c6e9ab0af724dfd0eb2b8b84af54`, the clean native command again
exited 3 as designed with an unchanged source tree. It passed the metadata
caller plus all nine PageMap checks: both differentials, both bootstrap
cleanup-owner branches, lazy commit and map retry, lazy-submap and top-level
release retry, and the four-contender private-lock publication witness. The
PageMap component has one remaining condition: the documented C
static-empty-root versus Rust typed-poison cold-root semantic gap.

At `265c49ddc21e614dfe055e1bc794e73a3ecf6f1e`, the clean native command again
exited 3 as designed with an unchanged source tree. It passed the metadata
caller plus all ten PageMap checks, adding the process-owner terminal-boundary
regression. `page-map` is now `complete` with no remaining condition. The
report's unmet component IDs are exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 itself remains partial.

At `5c0c707774dc575f65d9c64191d6cf789155c1cb`, a clean detached native
checkout ran the extended M2 gate with source unchanged during execution. It
exited 3 as designed and its report executed all seven new VM checks, the
existing metadata check, and all ten PageMap checks successfully. The unmet
component IDs remained exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`.
Thus the aligned-overmap cleanup-owner evidence is current for that allocator
source revision, but does not alter the seven unmet M2 components or authorize
advancement to M3.

At `c07fca49ef7dd0603a59dfcc92470862e1ab27e2`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2`. Its
`m2-memory-substrate-latest.json` attests that the source was clean before and
after execution and remains partial for exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. The runner defines that partial result as exit 3. This
is current-commit confirmation of the same M2 boundary, not evidence that any
later milestone has advanced.

At `1698ee9e9ef88894d2d68fcf2a0a806868f5a547`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the reset-advice fix. Its
report attests an unchanged clean source before and after execution, eight
passing VM-primitives checks, one passing metadata check, and all ten passing
PageMap checks. The new VM check is the deterministic reset-advice snapshot
regression described above. The report remains partial for exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; it does not advance M3 or any
later milestone.

At `0d153612edb33699d0235ccb69eb359f6802e9a8`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the arena field-boundary
fix. Its report attests an unchanged clean source before and after execution,
with 20 passing selected checks: eight VM-primitives checks, one metadata
check, all ten PageMap checks, and the one arena default delayed-purge
64-bit-field boundary check. The command exited 3 as designed; its unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. This adds
bounded arena evidence only and does not advance M3 or any later milestone.

At `242f3499c7e99224161b5aca855d537280061139`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after correcting the frozen
Linux default-decommit error result. Its report attests an unchanged clean
source before and after execution, with 21 passing selected checks: eight
VM-primitives checks, one metadata check, all ten PageMap checks, and two
arena delayed-purge checks. The command exited 3 as designed; its unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. This corrects
one source error transition but does not advance M3 or any later milestone.

At `9bf1d831f14caee780d6c818da6e52c03350983f`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after splitting static detached
metadata-image binding from first-demand private backing. Its report attests
an unchanged clean source before and after execution, with 23 passing selected
checks: eight VM-primitives checks, two metadata checks, all ten PageMap
checks, two arena delayed-purge checks, and one initialization check. The
metadata witness freezes one selected subprocess before any private Map #1,
rejects a foreign subprocess without consuming that fault, returns clean Map
#1 failure to BOUND, and retries only the selected identity. The initialization
witness proves the static image is bound before the global PageMap Map #1,
leaving no private metadata map or ticket-zero roots on that terminal global
map failure. The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This is bounded evidence for the
source image/order only: Rust's first valid metadata request still uses its
documented private direct-OS PageMap/external-arena backing rather than a claim
of C normal `_mi_meta_zalloc` backing parity. M2 remains partial and does not
advance M3 or any later milestone.

At `d89155128e00cb47c12269665bc5c3636f178ce5`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after matching the detached
metadata-Theap's source provenance and frozen page-reclaim image. Its
`m2-memory-substrate-latest.json` attests an unchanged clean source tree
before and after execution, with 24 passing selected checks: eight
VM-primitives checks, two metadata checks, all ten PageMap checks, two arena
checks, and two initialization checks. The new initialization witness runs
before any metadata session/backing and proves only the kind-only static
MemoryId (including zero union) plus enabled frozen normal page-reclaim image.
The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This advances neither M2
completion nor M3 or any later milestone.

At `9ddae0bcc4bd82146d71c95c10425c1330fa6e78`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after the detached first-head
random/cookie image and fail-closed invalid-input boundary were added to the
M2 contract. Its `m2-memory-substrate-latest.json` attests an unchanged clean
source tree before and after execution, with 25 passing selected checks: eight
VM-primitives checks, two metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The new pair covers the bounded
same-subprocess/empty-head/non-threadpool pre-demand image and rejects
nonempty-head, mismatched-subprocess, and thread-pool inputs before mutation;
it does not claim C list/split, option-adjustment, or normal metadata-backing
parity. The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This advances neither M2
completion nor M3 or any later milestone.

At `62ad1307d5b3686cc8654aefa4d9748ebcacc667`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
later-TLD direct-Malloc capability-lifetime check. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 26 passing selected checks: eight
VM-primitives checks, three metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The added real-caller witness proves
only ticket-zero's no-capability teardown, one injected post-ready direct-
zeroed failure that consumes its later sequence without a capability or live
lease, and one typed subprocess-attached/no-theap Malloc retry through exact-
owner teardown. It does not claim normal C `_mi_meta_zalloc` backing, generic
`_mi_meta_free` dispatch, or full TLD/list/lock lifecycle parity. The command
exited 3 as designed; its unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. M2 remains partial and does not advance M3 or any later
milestone.

At `e21eb06c076dcb5c0aca3d30f8c3ccf876f89212`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
nonexclusive dynamic-Theap direct-Malloc capability-lifetime checkpoint. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 27 passing selected checks: eight
VM-primitives checks, four metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The command exited 3 as designed; its
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The fourth
metadata witness selects only a child-thread, caller-pinned empty-Heap,
nonexclusive-Theap lifecycle after ticket zero. It observes the selected
sequence-one Malloc TLD/Theap one-member list shape, four attached metadata
capabilities, and the separate process-owned registry bitmap; it does not
establish normal C `_mi_meta_zalloc` backing, exclusive-arena allocation,
generic `_mi_meta_free`, general list/refcount policy, page ownership,
concurrency, or process/thread shutdown parity. M2 remains partial and does
not advance M3 or any later milestone.

At `a724db5a4ed63c5f689ee90bb101057c39df0a4f`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the selected
live regular-TLS metadata-rezalloc capability-lifetime checkpoint. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 28 passing selected checks: eight
VM-primitives checks, five metadata checks, all ten PageMap checks, two arena
checks, and three initialization checks. The command exited 3 as designed; its
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The fifth
metadata witness selects one post-first-image child-thread direct-Malloc
16-to-32 replacement: an injected pre-allocation failure restores the old
root/count/slots/capability, and one retry copies slot 15, publishes slot 16,
reaches live-one/high-water-two, then tears down to zero. It does not establish
the initial C count-zero `_mi_meta_rezalloc(NULL, ...)` route, normal C
metadata backing, arbitrary growth, generic `_mi_meta_free`, complete
TLS/TLD/Theap/registry lifecycle, concurrency, pthread/process lifecycle, or
ABI integration. M2 remains partial and does not advance M3 or any later
milestone.

At `ffaea4a9a2a3304dad0ff57ed081cc96e3b29978`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the detached-Theap
identity-admission prerequisite. Its `m2-memory-substrate-latest.json` attests
the source was clean before and after execution and unchanged during the run,
with 29 passing selected checks: eight VM-primitives checks, six metadata
checks, all ten PageMap checks, two arena checks, and three initialization
checks. The sixth metadata check proves COLD direct `zalloc`, aligned
`zalloc`, and `rezalloc(None)` return `TheapMetaUnpublished` before the
metadata lock, mapping, or capability creation; preparation binds and one-way
publishes only the exact selected detached-Theap identity, then the pending map
fault is consumed by a prepared demand and a later retry succeeds. This is an
identity-only Rust safety strengthening of C's non-null assertion, not the
actual `mi_subproc_t::theap_meta` layout/lock, pointer dereference, main-Heap
linkage, normal C backing, or complete initialization. The command exited 3 as
designed; its unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. M2
remains partial and does not advance M3 or any later milestone.

At `d965a6699bd65f92f98d96a665eac9ecf60e60f0`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after adding the one-chunk
abandoned-claim C/Rust differential. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 30 passing selected checks: eight
VM-primitives checks, six metadata checks, one bitmap differential, all ten
PageMap checks, two arena checks, and three initialization checks. The bitmap
record directly includes pinned `src/bitmap.c` and matches all 21 selected
control and transition fields: reject/restore, accept while retaining the
conservative map, and no-callback stale-map repair. The command exited 3 as
designed; its unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`,
`arenas`, `initialization`, `fault-injection`, and `allocator-recursion`. M2
remains partial and does not advance M3 or any later milestone.

At `9136162edf724287b64b381125ae4b01671e52bb`, a clean detached native
checkout reran `./scripts/dev.sh allocator-m2` after porting the selected
scalar clear-range visitor and correcting its explicit M2 nonclaim. Its
`m2-memory-substrate-latest.json` attests a clean source tree before and after
execution, unchanged during the run, with 31 passing selected checks: eight
VM-primitives checks, six metadata checks, two bitmap differentials, ten
PageMap checks, two arena checks, and three initialization checks. The bitmap
records matched all 21 abandoned-claim fields and all 26 clear-range fields.
The command exited 3 as designed; its unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. M2 remains partial and does not
advance M3 or any later milestone.

At `1e440d2a70d465cc90391983a986ea37853d24a9`, a clean detached native
checkout reran all current predecessor and M2 gates after porting the selected
scalar `_mi_bitmap_forall_setc_rangesn` wrapper. The clean detached
`./scripts/dev.sh allocator --quick` exited 0, and
`./scripts/dev.sh allocator-m1` exited 0 with all six M1 components complete
and no unmet IDs. `./scripts/dev.sh allocator-m2` ran
32 selected checks, attested a clean source tree before and after execution
and unchanged during the run, and exited 3 as designed. Its three bitmap
C/Rust records matched all 21 abandoned-claim fields, 26 generic clear-range
fields, and 52 direct rangesn-wrapper fields. The new wrapper trace directly
includes pinned `src/bitmap.c`: fresh `rngslices == 3` images cover aligned
completed windows, incomplete-window/top-suffix restoration, and a stopped
callback that restores a prior skipped window plus later snapshot bits; fresh
zero and one calls cover generic delegation, and 65 covers the cap at 64. It
does not execute `_mi_os_minimal_purge_size`, transparent-huge-page policy, or
an arena caller. The unmet IDs remain exactly `vm-primitives`, `metadata`,
`bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`. M2 remains partial and does not advance M3 or any later
milestone.

At `3db580e5ae052b5e6d61819ebe866ec9941b2c80`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected
same-thread metadata direct-demand recursion regression. The clean detached
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1`
exited 0 with all six M1 components complete, no unmet IDs, and 45 executed
check records. `./scripts/dev.sh allocator-m2` ran 33 selected checks, attested
that source was clean before and after execution and unchanged during the run,
and exited 3 as designed. Its added `allocator-recursion` check holds Rust's
same-thread entry marker while prepared direct `zalloc`, aligned `zalloc`, and
`rezalloc(None)` each reject before a pending map fault, private backing, or
metadata capability can be consumed; it separately confirms that
`rezalloc(Some(_))` preserves its live old capability before its claim and that
both routes recover after the marker drops. This is a Rust safety boundary over
the source nonrecursive metadata lock, not C lock/deadlock parity or coverage
of callbacks, signals, cross-thread races, PageMap/arena/OS, release/copy, or
general metadata lifecycle paths. The unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; M2 remains partial and does not
advance M3 or any later milestone.

At `f2f318194fdbc06a9d10d3cec3a7f01c675b6af9`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected native
protection failure-owner/retry regression. `./scripts/dev.sh allocator --quick`
exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six bounded
components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 34 selected checks, attested a clean source
tree before and after execution and unchanged during the run, and exited 3 as
designed. Its new `fault-injection` check uses two committed one-page mappings:
one injected pre-syscall `Protect` `NOMEM` retains exact base/length and still
permits volatile access; one successful protect followed by injected
pre-syscall `Unprotect` `NOMEM` retains exact base/length without dereference;
each disabled-plan retry succeeds and its mapping releases exactly once. This
is a test-only Rust owner/retry boundary, not C failure equivalence or
live-kernel failure evidence. The unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 remains partial and does not advance M3 or any later
milestone.

At `04e6f49c233c8d3d14d45a5299c54e255ad28917`, a clean detached native
checkout reran all predecessor and M2 gates after porting the selected scalar
read-only `_mi_bitmap_forall_set` visitor and correcting the bitmap nonclaim.
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1`
exited 0 with all six bounded M1 components complete, no unmet IDs, and 45
executed records. `./scripts/dev.sh allocator-m2` ran 35 selected checks,
attested a clean source tree before and after execution and unchanged during
the run, and exited 3 as designed. Its four bitmap C/Rust records matched all
21 abandoned-claim fields, 26 clear-range fields, 52 rangesn-wrapper fields,
and 30 read-only set-visitor fields. The new direct C/Rust trace uses fresh
valid 65-chunk images across chunk-map fields zero and one: completion visits
bits 1, 65, and 32770 in source order, and a second-callback stop leaves the
selected raw state unchanged. It is not heap/arena integration, callback
mutation, binned or flexible-array bitmap behavior, arena/subprocess
ownership, race, or statistics evidence. The unmet IDs remain exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`; M2 remains partial and does not
advance M3 or any later milestone.

At `5c2ce5414b8975e4507f7691c037f124850921a5`, a clean detached native
checkout reran all predecessor and M2 gates after adding the typed
arena-release subprocess-identity gate. `./scripts/dev.sh allocator --quick`
exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six bounded M1
components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 36 selected checks, attested a clean
source tree before and after execution and unchanged during the run, and exited
3 as designed. Metadata now has seven selected checks. The new check uses one
typed, unpinned, one-slice `ArenaSliceClaim`: a foreign `MainSubprocess`
returns the unchanged claim before Rust purge/free-bitmap state can change,
while the matching identity consumes it, returns the existing successful
terminal free-bit result, and permits reclaim of the same slice. This makes
C's internal arena/subprocess assertion a bounded Rust safety boundary; it is
not a C differential, a `MetaRelease::Arena` branch, generic `_mi_meta_free`
dispatch, normal C metadata backing, general purge behavior, full lifecycle,
or invalid-input parity. The unmet IDs remain exactly `vm-primitives`,
`metadata`, `bitmaps`, `arenas`, `initialization`, `fault-injection`, and
`allocator-recursion`; M2 remains partial and does not advance M3 or any later
milestone.

At `50049e9131f729b82615ac99c2a784974775aefd`, a clean detached native
checkout reran all predecessor and M2 gates after adding the selected
allocation-won arena-purge fallback regression. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded M1 components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` ran 37 selected checks, attested a clean source
tree before and after execution and unchanged during the run, and exited 3 as
designed. The `arenas` category now has three selected checks. Its new
two-slice external-arena witness releases `[9, 11)`, reclaims the low slice
before forced collection, then observes the failed full claim skip that
allocation-won slice while the high free sibling is individually hooked and
restored; both purge bits remain consumed. It is same-thread source-mapped
state evidence, not a live race, broader visitor/purge-policy proof,
multi-arena or lifecycle claim, fault/retry proof, or C/Rust differential. The
unmet IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`; M2 remains
partial and does not advance M3 or any later milestone.

At `03264676bddff8fdf94cd2ba3d9103124c9c200c`, a clean detached native
checkout reran the relevant baseline and predecessor gates after adding the
requested-parent Theap reservation. `./scripts/dev.sh allocator --quick`
exited 0 and compiled `LAYOUT_PROBE`, including its C-only assertion that the
complete pinned `mi_theap_t` fits one `MI_ARENA_MIN_OBJ_SIZE` object.
`./scripts/dev.sh allocator-m1` exited 0 with all six bounded components
complete, no unmet IDs, and 45 executed records. `./scripts/dev.sh
allocator-m2` executed all 38 selected checks and exited 3 as its partial-gate
contract defines. Its current category counts are eight VM-primitives, eight
metadata, four bitmaps, ten PageMap, three arenas, three initialization, one
fault-injection, and one allocator-recursion check; PageMap is the sole
complete category. The M1 and M2 reports attest the source was clean before
and after execution and unchanged during it. The seven unmet IDs remain
exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`.

At `5a2708d5c1e6b463c5eade8f60afa75d6131818a`, a clean detached native
checkout reran the relevant baseline and predecessor gates after adding the
separate synthetic requested-parent Arena-Theap-prefix lifecycle.
`./scripts/dev.sh allocator --quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all
six bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 39 selected checks and exited 3
as its partial-gate contract defines. Its current category counts are eight
VM-primitives, nine metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new ninth
metadata record is a bounded synthetic prefix-owner lifecycle; it does not
change M2's partial status or advance a later milestone.

At `9c19a64be59e7fb5dab4681136025fbc770b8f00`, a clean detached native
checkout reran the same baseline and predecessor gates after adding the
bounded lock-free metadata-page identity query. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 40 selected checks and exited 3
as its partial-gate contract defines. Its current category counts are eight
VM-primitives, ten metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`bound-subprocess-metadata-page-identity-query` record is only the source
read-only `page->theap == subproc->theap_meta` predicate under the bounded Rust
identity representation; it does not change M2's partial status or advance a
later milestone.

At `86143445817a7e1c4e10bb7bb49208faf1b3eeeb`, a clean detached native
checkout reran the baseline, predecessor, and M2 gates after adding the
selected metadata direct-allocation lock phase. `./scripts/dev.sh allocator
--quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 41 selected checks and exited 3
as its partial-gate contract defines. Its category counts are eight
VM-primitives, eleven metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and one allocator-recursion check; PageMap
is the sole complete category. The M1 and M2 reports attest the source was
clean before and after execution and unchanged during it. The seven unmet IDs
remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`bound-subprocess-theap-meta-lock-direct-allocation-phase` record holds the
selected subprocess lock before first direct demand, preserves BOUND with no
private backing or capability until release, covers aligned allocation and
rezalloc copy preservation, and proves exact-owner `Malloc` free stays outside
that lock. It does not change M2's partial status or advance a later milestone.

At `b09b1fd98cec6b811f52cf7e972e9dbda2127872`, a clean detached native
checkout reran the baseline, predecessor, and M2 gates after adding the
selected typed Malloc free pre-claim recursion boundary. `./scripts/dev.sh
allocator --quick` exited 0. `./scripts/dev.sh allocator-m1` exited 0 with all
six bounded components complete, no unmet IDs, and 45 executed records.
`./scripts/dev.sh allocator-m2` executed all 42 selected checks and exited 3
as its partial-gate contract defines. Its category counts are eight
VM-primitives, eleven metadata, four bitmaps, ten PageMap, three arenas, three
initialization, one fault-injection, and two allocator-recursion checks;
PageMap is the sole complete category. The M1 and M2 reports attest the source
was clean before and after execution and unchanged during it. The seven unmet
IDs remain exactly `vm-primitives`, `metadata`, `bitmaps`, `arenas`,
`initialization`, `fault-injection`, and `allocator-recursion`. The new
`metadata-same-thread-free-reentry-before-capability-mutation` record selects
only typed `MetaRelease::Malloc` free: it enters Rust's backing entry before
LIVE-to-RELEASING, and a held same-thread entry returns the exact pointer,
`MemoryId`, and audit as `MallocRetryable` with `MetaError::RecursiveEntry` for
post-drop retry. It does not widen general `MetaAllocator::free`, whose
admitted lifecycle errors remain terminal; stale/provenance and post-claim
Malloc failures remain terminal as well. Neither selected free route takes
`MainSubprocess::theap_meta_lock`. This is not C free/mutex/deadlock,
callback/signal, cross-thread, generic `_mi_meta_free`, copy, or lifecycle
parity, and it does not change M2's partial status or advance a later
milestone.

At `bdbcfc7173a7262ee12d4152a8c7c608a51bc086`, a clean detached native
checkout revalidated the then-current checkpoint: `./scripts/dev.sh allocator
--quick` exited 0; `./scripts/dev.sh allocator-m1` exited 0 with all six
bounded components complete; and `./scripts/dev.sh allocator-m2` executed 47
selected checks and exited 3 as its partial-gate contract requires. The M2
counts were twelve VM-primitives, eleven metadata, four bitmaps, ten PageMap,
three arenas, three initialization, one fault-injection, and three
allocator-recursion checks. Its reports attest clean source before and after
the run and no source change during it; the unmet IDs remained exactly
`vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. This is historical evidence for
that exact revision, not for the later 54-check contract.

## Active boundary and priority rule

The integrated owner-local mapped-abandoned medium reclaim slice is a narrowly
mapped M5/Phase-E regression: it is neither a general scan nor a milestone,
shadow, or promotion claim. Keep its source map, regression, and exact test
result, but do not use it to advance M5.

M0 and M1 are closed predecessors only under their bounded contracts; neither
claim is allocator-engine or lifecycle completion. Their latest clean detached
native revalidation is `8db445ea3cbc75da59b283fc2f40905b9f0131a5`: its
`allocator --quick` and `allocator-m1` runs exited 0, the M1 report attests all
six bounded components complete with no unmet IDs, and the following
`allocator-m2` run exited 3 as its partial contract requires. M2 is the
current closure gate. Its 67 selected checks are fifteen VM-primitives, twelve
metadata, five bitmap C/Rust differentials plus four Rust-only
bitmap-observer check records, ten PageMap, five arena, ten initialization,
two fault-injection records, and four allocator-recursion checks. Alongside
the historical detached and normal-helper records, the new static-first record
directly compares only the selected first-main/static
`src/init.c:253-272` `mi_tld_create` success arm. Its pinned C side calls
file-static `mi_tld_create(_mi_subproc_main())` once with the actual static
identities, zero total/live counts, and inert nonnull `theap_meta`; its
C-only trace observes the selected predicate-to-return chain and zero
`_mi_meta_zalloc` calls. Rust begins after separately modeled selector and
Heap-foundation prerequisites. The 36 matched address-independent relations
cover a normalized semantic suffix—ticket zero, typed static memory identity,
modeled normal body, live registration, and labeled Release visibility—not
identical C/Rust predicate, caller, preflight, primitive, or return-boundary
timing. They also do not establish C/Rust layouts, `_mi_subproc_main_init`,
actual Theap/metadata initialization, failed/generic/later arms, TLS/list/root
publication, teardown, races, pthread ABI, or allocator integration. The later
normal-OS record maps only one `mi_reserve_os_memory_ex2` regular-OS caller:
the sealed zero-offset/base-equals-client owner transfers its exact mapping and
`MemoryId` into one arena, while offset allocations cannot enter that route.
At that same clean detached revision, all 67 selected checks passed; source was
clean before and after execution and unchanged during it. PageMap remains the sole
complete component and exactly the other seven required components remain
partial: `vm-primitives`, `metadata`, `bitmaps`, `arenas`, `initialization`,
`fault-injection`, and `allocator-recursion`. Do not advance M3, M4, or later milestones until M2 has
its own complete current-commit contract and evidence. The narrowly scoped M5
work around the bounded process-once envelope does not advance M5. Existing
M3/M4 bounded evidence remains regression evidence, not permission to skip M2
or milestone closure. M5 remains open until its Phase A–G acceptance conditions
are met.

## Current M5 gate facts

The historical full report at `d5e5901bcfaf7d790632f3c6324afd4019c4e0f4`
recorded `m5.base`, `m5.5a`, `m5.5b`, and `m5.5c` as passed. `m5.5d` is
blocked because the canonical source-bound upstream stress matrix remains a
bounded nondefault shadow subset and the source-derived lane cannot accept
upstream cross-thread transfer or lifecycle. `m5.5e` is blocked because the
selected shadow ABI, pthread, differential, and stress closure is not
established. The Rust backend remains nondefault.
