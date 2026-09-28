# Complete crabc's native x86-64 runtime

## Goal

Implement this plan through integrated, qualified completion: reproduce the
frozen selected runtime on native Linux/x86-64, finish the faithful Rust
mimalloc port, make it the qualified x86 default, and promote public x86
support. “Implement plan.md” authorizes the necessary in-scope implementation,
tests, integration, performance work, and local promotion changes—not merely
another plan, private fixture, or intermediate handoff.

`AGENTS.md` owns scope and working rules. This file owns the complete active
completion contract and its one progress handoff. Machine-readable manifests
supply exact inventories and evidence requirements; technical guides explain
implementation and runner details, not additional independent plans. Continue
while useful independent work remains. A genuinely external blocker must remain
explicit, never be converted into a pass or a smaller completion claim.

## Progress status

Update this section in place when the frontier changes. Recorded checkpoints
are not transferable passes for a different revision.

- **State:** `campaign-status` reports 9/26 families `foundation-verified` and
  180 implemented, 43 selected-private, and 0 missing capabilities; all eight
  ordered qualification gates are executable and fail closed on named unmet
  conditions. On clean `34f742a7a`, capability accounting validates 223
  capabilities, 65 verified slices, and 381 verified artifacts; its gate still
  waits on 15 planned prerequisite families and 43 selected-private
  capabilities. `compat.abi-differential` reads all its evidence rows from one
  published set (`abi-differential-evidence assemble`); only the selection
  closure stays unmet: a clean `b879f8c86` pinned-image assembly named 567
  blockers (549 identities, 17 unadmitted families, one missing semantic
  receipt) after binding the owned `__libc_start_main` CRT imports; all
  18 companions were accepted. A read-only physical replay of that cohort
  binds the weak `_DYNAMIC` archive import to each final ELF's own dynamic
  table or static null resolution. The same replay binds `_init` and `_fini`
  startup imports to strong image-local CRT fragments, reducing the blocker
  count to 563. Three pinned Rust allocation-handler identities now bind to
  authenticated static archive members and exact ELF rows, with static ET_EXEC
  and static-PIE link controls. Two source-owned private provider classes now
  bind the three complex multiplication helpers and two float scanner helpers
  to retained static imports and shared definitions; the historical b879
  projection has 544 blockers after 23 are discharged. On a separate clean
  current-source cohort, the installed CRT receipt resolves `_DYNAMIC` through
  its weak zero archive import, static null result, and six image-local dynamic
  tables; selector blockers fall from 770 to 733, with 714 identities and
  declaration, family, and semantic receipts still open. A newer sealed
  current-source cohort resolves three private allocator VM imports to hidden
  Rust providers in both static link forms; its exact C allocator companion
  lowers selector blockers from 757 to 724, with 705 identities, 17 family
  admissions, one declaration companion, and one semantic receipt open. Full
  closure remains open. A later sealed cohort binds all six static C allocator
  `__errno_location` callers to the final TLS accessor in ET_EXEC, static PIE,
  and shared libc; its selector has 721 blockers after that ordinary-import
  reason is discharged. A later pinned same-source cohort also binds both
  ordinary `abort` archive importers through their distinct GOT and direct
  call forms to the final static and shared libc provider; its selector has
  720 blockers (701 identities, 17 family admissions, one declaration
  companion, and one semantic receipt). A further same-source cohort joins
  both `fputs` archive importers, including the C tail branch, to the final
  provider and reduces the selector to 719 blockers (700 identities).
  `libc.c-abi-compat` now runs a physical
  same-cohort text/math/locale/stdio family admission; its current assessment admits seven
  of ten components and retains three allocator components at the selected C
  backend. Independent physical replay of that same-source assessment and its
  three-pair POSIX matrix passes; the C ABI gate remains incomplete at seven
  components and nine of eleven capabilities. `consumer.rust-std-lto` passes its
  Rust, native-facade, LTO, and unwind leaves on clean `d6733f516`; its
  pinned-image receipt passed independent physical validation and public
  publication. `consumer.source-build` passes on a development cohort and
  publishes its receipt; a clean `0bb16e482` Lua source-build admission makes the
  latter evidence condition met while 14 prerequisite families remain open.
  A sealed `libc.resolver` assessment admits all six components with no gaps;
  its receipt passed independent physical validation, while final-candidate
  replay and public promotion remain separate.
  `performance.release` is a read-only receipt gate whose
  runtime, native-facade and allocator M9 inputs do not exist yet. The pinned
  standalone unwinder now returns a phase error for faulting CFI
  register or expression memory reads; a guarded source-built regression and
  valid cleanup control pass. A forked child fixture confirms that denied
  self-memory reads return a phase error without a fault while valid child
  unwinding reaches end of stack. A fault-contained, allocation-free EH-frame
  reader now guards metadata after `dl_iterate_phdr` callbacks: mapped controls
  succeed and unmapped, unreadable, truncated, or oversized cases return phase
  errors without child faults. On frozen `1b1511d19`, installed static and
  dynamic products each pass eight guarded metadata cases with a source-bound
  provider and physically reread link and execution receipts. Broader
  unwinder integration remains open. A direct Rust backtrace fixture crosses
  owned DSO and pthread frames on a freshly linked installed product, with a
  passing static control and physical reader. An earlier three-product dynamic
  qualification stopped after the installed arm passed all 73 cases because
  its producer exhausted disk space. A
  guarded CFI expression in a real installed DSO worker returns a phase error
  for an unreadable saved return address while the mapped control unwinds;
  the retained pre-guard provider faults on the same case. This focused
  diagnostic is folded into the installed backtrace matrix and does not
  qualify the older product for the current source. A further installed
  diagnostic crosses a mapped C DSO frame with direct Rust panic cleanup and
  `resume_unwind` on main and pthread workers; the selected provider, exact
  guard drops, and physical replay pass. The same matrix now has a focused
  installed static C-frame control for direct cleanup and `resume_unwind` on
  main and pthread workers, with selected-provider and final-ELF physical
  replay. A later clean `a6ada8af0` cohort passes all 219 dynamic cases,
  independent physical backtrace validation across static and both DSO forms,
  guarded CFI, and main/worker panic cleanup and resume. Its selected consumer
  unwind leaves have no unmet condition on primary and extracted pairs, with
  53 retained files physically reread; final merged-revision replay remains open.
  Allocator M5 remains open. C mimalloc remains the selected
  backend; allocator M2–M11 remain open. The six-component M1 gate passed on
  clean frozen `6431e9036` with no unmet conditions; final-candidate replay
  remains revision-bound. A later clean `ce1b3d556` M1 run also passes with
  the pinned-C bit arithmetic differential matching 71,190 records and
  120,816 results across zero, boundaries, rotations, and word geometry.
  A clean `9e7e7f3bd` M8 run passes all nine consumer and runtime leaves and
  all 16 evidence commands, with 13 physical receipts independently reread;
  final-candidate replay remains revision-bound.
  A frozen M5 source run at `e0b9ecbc7`
  passed seven gates, failed its churn and upstream stress gates on one seed-2
  static-PIE PageMap high-water spike, and left codegen/performance blocked;
  the same binary passed a focused replay. A later diagnostic reproduced one
  breach in sixteen native runs and localized the growth to medium pages;
  pinned v3.5.0 C also breached once in sixteen static-PIE runs of the same
  workload and PageMap slice metric. The PageMap reader now applies the same
  10% bound to sustained first/last-quarter medians, calibrated against 88
  pinned-C/native traces and accumulating-page controls. The canonical stress
  run at the earlier source revision passed PageMap checks but failed the
  unchanged RSS bound for native static PIE on seeds 1 and 3. After the
  source-shaped C ABI size-class correction, the canonical 113-case native
  stress receipt passes all three seeds, including PageMap and RSS bounds;
  the intermittent historical RSS growth has no proven root cause. A clean
  `46b408b16` full M5 run passes nine correctness gates with 27 independently
  reread physical logs. Only codegen/performance remains blocked: the local
  path is below the 0.25× pinned-C structural threshold, and qualifying timing
  still needs an uncontended host. Source-built
  C/Rust differentials pass for both dormant and active survivors of a non-abandoning
  full-medium/OS-singleton owner exit, including reclaim and retirement; a
  late remote free after that exit also matches all 17 retained observations.
  A mapped-large/medium mixed owner-exit differential matches 20 additional
  C/Rust transition values, including large reabandonment and medium retirement.
  An arena singleton beside a regular medium page matches 18 more owner-exit
  values and separate arena/PageMap terminal releases. Two survivor threads
  independently release split arena singleton claims after owner exit with
  17 matching C/Rust observations. An abandoned regular OS page now reclaims
  and releases after its owner exits; the source-built differential passes its generic-exit cases and
  retains the OS list ownership until terminal release. A second split-owner
  OS medium survivor matches 23 more C/Rust observations when final unmap
  fails, including exact retained range, PageMap removal, warning and VM
  counters. An abandoned OS regular medium page survives interleaved reclaim,
  local reuse, remote publication, collection, and final release across two
  survivors; 23 shared observations and four direct pinned-C list states pass.
  A further OS medium case publishes its first remote free before reclaim,
  crosses the source mostly-used threshold on the second, then reuses and
  releases; 29 shared observations and six direct pinned-C list checks pass.
  An arena-backed medium page now matches 41 C/Rust values across remote
  publication before reclaim, bitmap ownership, PageMap removal, and final
  slice release. A mixed arena-backed and OS-backed regular medium owner exit
  now matches 40 more C/Rust transition values after both remote frees precede
  reclaim, through independent reuse and terminal release. The clean M5
  generic-exit gate passes all thirteen evidence rows. A huge singleton and
  regular medium split between surviving threads match 36 more C/Rust values,
  including 84 arena slices for the huge allocation, 63 registered PageMap
  entries, independent reclaim/release, and no warning or VM loss; the gate
  passes all fourteen rows on its sealed source. A huge OS singleton whose
  terminal unmap fails now leaves the independently owned medium survivor
  freeable after PageMap mutation; the generic-exit gate passes fifteen rows
  on that sealed source. A final candidate must rerun the source-bound gate.
  A paired medium-churn
  diagnostic matches C/Rust page-class transitions under four option profiles;
  PageMap retirement precedes arena RSS release with the default purge delay,
  while immediate purge releases at collection. A two-arena pressure profile
  matches C/Rust medium and PageMap transitions in six profiles; three more
  paired replays found no canonical RSS step. A 65,536-byte medium-page
  capacity difference was traced to the native C ABI requesting explicit
  alignment for ordinary `malloc`; the source-shaped size-class dispatch now
  matches pinned C usable size and page transition on initial and worker
  owners while retaining 16-byte alignment for tiny C allocations. The full M2
  runner records complete metadata, bitmap, PageMap, and allocator-recursion components; VM primitives,
  arenas, initialization, and fault injection remain partial. Its direct fresh
  OS page-area metadata-commit receiver matches pinned C for both successful
  and failed cleanup, including warning timing and accounting. A fresh OS
  singleton publication, terminal release, and failed terminal unmap receiver
  matches 115 C/Rust relations for mapping extent, PageMap state, warning
  order, counters, and exact unmap or retained raw-only retry. Policy-first
  arena failed prefix/suffix trim paths match 16 more C/Rust observations,
  including escaped live mappings and warning-time counters. Fresh OS PageMap
  registration failure matches 122 C/Rust relations for rollback state,
  mapping lifetime, accounting, and warning order. External arena purge
  publishes its purge statistics before the callback, matching eight more
  C/Rust observations. A second regular arena claims the fourth 256-slice
  request after the first fills and matches pinned C across 33 claim,
  mapping, purge, and registry observations. A delayed partial release beside
  a live slice in that second arena matches 15 further purge, bitmap, mapping,
  and survivor observations. A second-arena reset policy with
  `purge_decommits=0` matches 15 more MADV_FREE and counter observations. A
  committed medium OS page matches 136 C/Rust
  publication, PageMap, terminal-release, and failed-unmap relations. A
  separate second-arena EIO purge regression now matches all 19 fields,
  including the pinned decommit warning and its callback order.
  A failed second-arena MADV_FREE reset regression now matches all 23 fields,
  including warning text and callback order.
  A separate source-built reset-advice matrix matches 78 C/Rust fields across
  isolated EIO, EAGAIN, and EINVAL policies, including advice retry, exact
  slice range, warning order, and live bitmap state. A clean full M2 run passed
  all 87 runnable checks with VM primitives, arenas, initialization, and fault
  injection still partial. The VM inventory now registers 48 checks, including
  direct process-owned successful and failed THP advice and disabled process
  policy and inherited process disable with source-selected advice; the clean
  rerun executed all 48, including 209 further matched external OS reset,
  retry, and no-advice relations. Five VM conditions remain open. A
  failed second OS-page block commit and failed rollback unmap match pinned C
  in eleven process-owned
  observations. The PageMap fallback suffix-trim fault is registered in its
  shared aggregate with ten matching C/Rust observations; lazy submap rollback
  adds twelve matched observations in the same aggregate. Selected process
  startup THP `prctl` GET and SET failures each match eight pinned-C/Rust
  observations, including READY state and no retry. A selected process-owned
  `MADV_HUGEPAGE` success matches 21 C/Rust observations, including the exact
  2 MiB advice, kernel mapping flag, accounting, and release; forced EIO advice
  failure matches 24 and preserves the live mapping. Disabled and inherited
  disabled THP process policies match 25 and 24 more observations. A legacy
  processless aligned OS-page claim preserves the same MemoryId, live escaped
  suffix, and raw cleanup as pinned C after failed suffix trim and terminal
  unmap. Its absent subprocess accounting and warning callback are recorded as
  exact source differences. A process-owned claim now matches 17 C/Rust suffix-trim,
  terminal-unmap, warning, escaped mapping, and accounting relations after
  terminal release charges only the committed block area; other process-owned
  callers remain separately qualified or open. Separate source-built explicit
  arena reservation receivers match 31 C/Rust fields each for failed prefix
  and failed suffix trim, through registry retirement, terminal release, and
  raw cleanup of the escaped mapping; both receivers are in the clean M2 VM gate.
  The metadata publication receiver also matches 15 recovery observations
  after three faulted requests, charging each actual lazy PageMap submap by
  its 64 KiB extent. The M2 fault component has four matched checks and four
  remaining conditions; its full gate remains partial.
  A second explicit arena metadata-commit fault now matches 34 pinned-C/Rust
  observations while an earlier registered arena remains usable and releases
  terminally; shared M2 registration is pending.
  A failed second-arena committed-slice claim and same-slice retry match 24
  C/Rust fields after the regular mapping uses the warning-preserving commit
  path; two additional pinned-C fields bind the attempted `mprotect` range.
  Failed second-arena reservation and retry match 25 more C/Rust fields,
  including registry, warning sequence, claim survival, and terminal release.
  Concurrent second-arena reservations publish one arena across two workers;
  24 C/Rust fields match claim, registry, ownership, and terminal release.
  A failed regular-arena parent unmap matches 15 C/Rust destroy, warning-order,
  registry, and raw-retry fields after restoring the source warning call.
  A failed huge-arena primitive unmap now emits the pinned-C warning before
  accounting; its focused differential matches while all eight M3 components
  pass, with M1/M2 prerequisites still required for the M3 gate.
  Every freestanding-C runner builds `libc.a` through
  `compat/x86_64/source_runtime_libc.sh` (source-built runtime, one archive
  member per libc module). On an idle host the development engine harness
  measures the Rust local path at about 0.33× pinned C single-thread with
  the ported direct-page malloc and local-free fast paths on the initial and
  worker owners (low-load, not qualifying). A source-matched 32 KiB medium
  queue-head fast path cuts its development malloc codegen from 779 to 157
  instructions and 12 to three calls; its C/Rust trace matches 38 events,
  including local-free reuse and page spill. The 8 KiB regular small
  queue-head path falls from 809 to 161 instructions and 13 to three calls;
  its 23-event C/Rust trace covers reuse, page spill, and `calloc` zeroing.
  Reusing the owner-local queue head across the generic count step reduces
  the 64-byte local malloc path from 153 to 150 instructions in 100 matched
  traces. Deferring regular-page classification past the direct small head
  reduces that initial path to 139 and the worker path from 143 to 132;
  trusting the selected small queue's class lowers those paths again to 136
  and 129 instructions, respectively. Reading the immutable empty-page
  sentinel's null free head lowers malloc to 132 and 125 instructions. Moving
  the medium-size check to queue lookup lowers these again to 131 and 124;
  fusing owner-local quick collection with the block pop lowers them to 130
  and 123. Two source-equivalent retirement changes put the 64-byte local
  free path at 109 and 102 instructions.
  Marking the existing out-of-line allocation fallback cold lowers a later
  clean 64-byte malloc trace from 121/114 to 111/104 Rust instructions on
  initial/worker owners, against 87/87 pinned C; owner traces and M5 pointer
  dispatch still pass. These are structural measurements, not qualified timing.
  Removing a redundant initial-owner readiness read lowers clean 64-byte local
  free from 98 to 95 Rust instructions, against 86 pinned C; the worker path
  remains at 91 against 86. Comparing the raw thread pointer against the
  validated published initial identity lowers the initial path again to 91;
  local-owner traces and pointer dispatch pass.
  34,084 source-built C/Rust local allocation and free trace lines match.
  A clean allocator-engine smoke physically rehashes final link maps and finds
  108,311 bytes of pinned-C allocator text/read-only data versus 717,923 bytes
  of Rust, a 562.8% increase; the single-thread unit is the largest attributed
  Rust contributor. A source-equivalent queue fullness comparison cuts 95 bytes
  from a later clean Rust final map to 717,456 bytes, while pinned C remains
  108,311 bytes. Moving queue-candidate success work directly into its success
  branch cuts another 38 bytes from its own clean final map; the measured
  candidate is 717,067 Rust bytes against the same 108,311 C bytes. This is a
  code-size investigation, not qualifying M9 timing.
  Remote publication is at 165 Rust instructions after source-equivalent
  owner-word and published-PageMap checks, with its 100-trace and 25-value
  differentials passing.
  Contended timing is not qualifying. Allocator M3 passes every own
  component and waits only on M2; M4 passes including the unmodified
  upstream `test-api.c` through the native adapter. M6 now source-differentiates
  quiescent non-main and isolated process-main Heap block visitation across 138
  adapter keys, including all five exported Heap membership and region queries
  and the quiescent page-utilization query; seventeen
  runnable evidence rows pass on a clean M6 gate, while ten required gates
  remain blocked by named missing producers. The passing rows include
  fresh-process Heap membership regressions and a ten-case source-built
  main-Heap population differential
  across one to 1000 non-main Heaps, direct/fork execution, and reserved-arena
  profiles. Detached Theap and replaced TLS slot images now retain the source
  remote-free lifetime through a visitor collection. A worker-abandoned
  regular page now matches six pinned-C area, live-block, and early-stop
  observations through `mi_heap_visit_abandoned_blocks`; an abandoned OS
  singleton matches five more rows, including freed-page omission. A combined
  regular-page and OS-singleton visitor preserves their source traversal order.
  A process-main abandoned regular page is selected from its arena bitmap
  while a same-size live main-thread page is excluded; six callback rows
  match pinned C. A process-main abandoned OS singleton follows the earlier
  live main-thread OS singleton in source list order, and six more callback
  rows match pinned C with freed-page omission.
  Mixed process-main abandoned regular and OS pages now preserve source
  traversal order and selection across ten pinned-C callback keys.
  Public default-Theap switching and direct allocation now match 32 pinned-C
  main, worker, and fork observations while retaining same-thread TLD ownership.
  A child subprocess's public Heap selection and lifecycle now match 17 more
  pinned-C keys, including Heap list order, dynamic TLS-key reuse, child main
  Theap cache restoration, direct allocation and default substitution, and
  teardown; the prior 161 private lifecycle
  values remain matched in the same M6 row. A process-main Heap selected from
  a live exclusive arena now matches twelve pinned-C allocation, Theap/page
  placement, fallback refusal, delete/destroy and failure keys. A child Heap
  selected from its subprocess arena matches twelve more source-built keys;
  prepublication Theap failures return their exact slice for reuse. All
  seventeen runnable M6 evidence rows pass on clean `b2fd43160`.
  A public main-process caller-owned external arena matches thirteen
  source-built C/Rust lifecycle keys across registration, selection, allocation,
  and caller-held terminal unmap. A child-subprocess external arena now matches
  eighteen C/Rust registration, selection, and caller-held release keys; the
  clean M6 gate passes all seventeen runnable rows.
  The public main-process `mi_reserve_huge_os_pages_at_ex` entry matches five
  source-built C/Rust return, output, errno, and warning observations on this
  host's unavailable 1 GiB huge-page path; physical success and nonzero child
  reservation remain unproved. Public main and child regular arena reservation
  failures now match pinned C on the return, null output, errno, and all six
  ordered warning lines. The clean source-bound M6 gate passes all eighteen
  runnable evidence rows, including this warning differential.
  All ten required gates
  remain blocked by 10 named missing API and lifetime evidence entries;
  accumulated mixed-workload main-Heap page-population parity remains unproved.
  Integrated products are
  compared against an evidence-only pinned v3.5.0 C product (the selected C
  backend is `libmimalloc-sys` 0.1.49, mimalloc 3.3.2); the port map
  classifies every intentional difference (`difference_kind`). The M8
  owned-libc integration gate exists; the named `unown_with`
  release-then-classify race has a source-bound regression, and the canonical
  native allocator stress plus three soak seeds pass. `m8.rust-std`,
  `m8.lua`, `m8.corpus`, `m8.threads-fork`, `m8.weak-interposed`,
  `m8.startup-constructors`, `m8.errno-c-abi`, and
  `m8.static-dynamic-products` pass on
  source-built native-shadow products with physically reread receipts on their respective source revisions;
  the corpus covers all 34 frozen cases. A separate cross-image FILE handoff
  proof has eleven musl and owned cells covering buffered writes,
  flush/readback, shared errno, and close lifetime
  across PIE and non-PIE kernel/direct entry, with static baselines. The same
  eleven-cell matrix now passes a main-owned cookie stream through a DSO,
  including read/seek/write callbacks, past-EOF reads, and one close callback.
  It also passes a DSO-owned cookie stream returned to main, which closes it
  through the DSO's callback after buffered I/O and shared errno checks.
  The same eleven-cell matrix passes a C.UTF-8 wide stream handoff: the DSO
  establishes wide orientation and writes U+20AC, main reads it back, and the
  underlying pathname contains the exact three UTF-8 bytes.
  A DSO-created buffered pathname stream also survives until ordinary exit:
  its DSO finalizer sees the descriptor live before one exit flush writes the
  payload. Pinned musl and all eleven owned/oracle cells preserve the exact
  finalizer marker, write order, and post-exit bytes.
  A cross-DSO `freopen` handoff now passes all eleven cells with exact old and
  replacement pathname bytes. It exposed and fixed a read-on-write-only stream
  defect: pending output must flush before the direction error is set.
  A DSO-created `open_memstream` also passes all eleven cells while main
  writes, seeks, flushes, and closes it, with the DSO retaining the published
  buffer until one final free; embedded NUL bytes and length match pinned musl.
  A DSO-owned fixed-buffer `fmemopen` passes the same matrix through writes,
  seeks, flushes, a capacity short write, close, and surviving buffer checks;
  its eight final bytes and error state match pinned musl.
  A DSO-created `open_wmemstream` passes all eleven cells while main and DSO
  alternate wide writes, inspect the published wchar_t buffer, and close it
  with one owner. Cross-image `fflush(NULL)` also passes the eleven-cell matrix:
  separate main and DSO buffered pathname streams flush in pinned-musl order
  on both calls, preserving exact writes, file bytes, shared errno, and close
  ownership. A further eleven-cell orientation handoff confirms that a DSO
  can select wide orientation on a main-owned FILE and main can select byte
  orientation on a DSO-owned FILE; both retain exact UTF-8 or byte output,
  shared errno, and one close by the owning image. A DSO-owned buffered
  `/dev/full` stream also passes eleven cells: main observes `fflush` return
  EOF, `ENOSPC`, and `ferror`, then the DSO closes its descriptor once. A
  second DSO-owned stream carries pending buffered bytes into `fclose` itself;
  all eleven cells return EOF with `ENOSPC` and close the descriptor once. A
  third stream passes all eleven cells across failed `fflush`, main-side
  `clearerr`, a no-write retry, another buffered failure, and owner-side close.
  A DSO-owned pathname stream also passes the eleven-cell matrix when main
  reads to EOF, pushes a byte back, saves and restores position, and the DSO
  reads both the pushed and original bytes before closing it once.
  The complete nine-leaf M8 gate
  passed again on clean `ea0c28759` with all 16 evidence entries passing and
  13 physical receipt identities matching a post-exit reread; the same nine
  leaves, 16 entries, and 13 post-exit identities passed again on clean
  `a5613516a`. The M8 dispatcher and private readers now pin the immutable
  core image. A clean `740c5e65c` full run passed seven leaves and failed
  two that share one native stress seed-3 static-PIE RSS breach; the same
  binary passed that soak in an earlier run. A clean `4ae4d70e3` rerun passed
  all nine M8 leaves and 16 evidence entries, with 13 physical receipts
  matching a post-exit reread; its seed-3 static-PIE RSS stayed within the
  unchanged bound. The static-PIE binary changed between these runs, so the
  intermittent growth remains under investigation. A clean frozen `f140eb666`
  run passed seven M8 leaves; Rust std lacked prepared fixture vendors in that
  lane, and Lua dynamic exposed a native-shadow materialization provenance
  rejection in the package reader. A clean `5613d3c39` rerun with exact
  lane-local vendors passed all nine leaves and 16 evidence entries, including
  Rust std, static/dynamic Lua, all 34 corpus cases, 113 stress cases, and three
  soak seeds. The independent eleven-cell FILE matrix passed. Final
  merged-revision M8 qualification remains open. All 57 `native_*`
  integration targets pass; the earlier attachment
  defect was stale. The M7 options/environment gate passes its source-matched
  profile and 660-key C/Rust differential; its default-artifact baseline audit
  also passes. The optional ISA differential matches 51 C/Rust keys across
  scalar, no-optimization, architecture, and AVX2 bitmap modes, including a
  stale-candidate retry; the gate still needs uncontended AVX2 throughput
  evidence. A selected `MI_STAT=1` binned allocation, merge/reset, free,
  and final-print differential passes; a separate level-one merge/final-output
  differential matches 28 C/Rust fields. A default-off `MI_STAT=2` requested-size
  merge/final-output trace also matches pinned C. Nonzero level-two allocation
  bin output matches 27 C/Rust fields for bin order, size units, merge peaks,
  freed rows, and empty-bin suppression. Synthetic huge/page merge and final
  rows match 35 more C/Rust fields. The public JSON buffer contract matches
  114 C/Rust trace fields at MI_STAT=0/1/2, including truncation and invalid
  images. A source-built 64-byte allocation now matches pinned C page-extension
  attempt and touched-byte counters before and after free. A fresh huge page
  now records its physical 589,824-byte allocation and one huge count; a
  nonlocal free brings current huge bytes to zero, matching pinned C. A
  cross-thread normal free records the freeing worker's 8,8,-64 binned row
  and merges to 72,72,0 process bytes. An OS-aligned huge allocation records
  589,824 physical bytes and prints `578.2 KiB` before owner merge; C/Rust
  agree on release and warning state. `MI_STAT=2` ordinary and OS-aligned
  allocation/free production matches 43 C/Rust requested-size, bin, and
  count values, including the source's retained requested count after free.
  Warmed 64-byte direct, 8 KiB small, and 32 KiB medium local `calloc`
  paths now match 88 pinned-C statistics fields for requested bytes, normal
  count, bin lifetime, owner merge, local free, and zeroed contents. A regular
  64-byte cross-thread free now matches 18 C/Rust requested-byte and bin
  observations, including the freeing Theap's debit before publication and
  the final merged zero count. An arena-backed 32 KiB medium cross-thread
  free now matches 53 selected C/Rust keys through owner merges, surviving
  PageMap membership, and terminal page-bin release without new OS mapping.
  A level-two arena-backed huge singleton now matches 39 selected C/Rust
  page-bin and worker-merge keys. The JSON caller-buffer differential uses a
  stable sufficient capacity while retaining small-buffer error and guard
  checks. A fresh worker's huge free through the metadata Theap and later
  first allocation each match 41 pinned-C/Rust keys after descriptor-only
  registration preserves delayed attachment. A fresh worker's usable-size
  query before remote free now leaves its default Theap unattached, matching
  21 source-built C/Rust statistics keys. A worker reset and local free at
  `MI_STAT=1` match 29 C/Rust state and output values; its extended `MI_STAT=2`
  payload, allocation/page bins, requested bytes, and selected output rows also
  match. Source-faithful peak adjustment now matches the physical VM
  reserved, committed, and process-commit peak rows. Counting the successful
  initial static Theap attachment makes all four worker-reset Theap stages
  and deterministic `MI_STAT=2` rows match pinned C; static teardown retains
  that count as pinned C does. Full raw output matched in one clean run; a
  later rerun differed only in elapsed and process system time.
  The prior 16 statistics evidence
  rows pass on a clean source, and the focused differentials pass; the
  source-built OS-large remote-free probe matches 35 statistics payload keys;
  its full 50-key stage trace remains unproved because a 64 KiB PageMap submap
  can be charged at different stages under different address placement. A
  source-built `MI_DEBUG=1`/`MI_PADDING=1` probe records a real gap: pinned C
  fills the requested bytes, returns the logical 17-byte usable size, and
  reports a corrupted padding byte; native Rust currently does none of these.
  The full current-source gate remains blocked by named unproved producers. Other
  page and fast-path shapes, other remote bin-free, and other metadata-Theap
  statistics producers remain unproved, so full M7
  stays open. Static
  replacement now has a source-bound installed sweep with zero divergent
  functions among 1,406 musl-replaceable entries and all 831 required entries
  passing; the final merged candidate must rerun it. A scoped current-source
  development observer measured crabc startup PSS below musl for both simple
  and dependency-graph rows; qualified scorecard evidence is still needed.
  `libc.c-abi-compat` has an executable family aggregate
  (`owned-c-abi-compat-family`); its two allocator capabilities admit only on
  the native-default candidate. libc-test and OS-test leave only the finite
  profile dispositions. Qualified performance runs use the host's
  `powersave` governor for both lanes and wait only for an uncontended host.
  Allocator M10 readiness exists:
  `--allocator-backend native` production products pass the C-mimalloc
  absence audit and `allocator-m10 --check` fails closed until M0–M9 and
  promotion pass; the default stays `accepted-c`. The loader's load-time
  checks are musl's (no hash-table, write-set or overlap audit;
  `_dl_debug_addr` is one export lookup). Startup is 1.18× musl user and
  1.05× kernel instructions (1.47M/2.43M against 1.24M/2.31M), still off the
  0.90× CPU gate: the two loader/libc images, symbol resolution and libc's
  allocator option parsing remain. Startup PSS is 0.86× musl (52 of 114
  perf-c rows pass PSS). A set-bit RELR walk, span-bound target validation,
  and cached file-backed dynsym record limit save medians of 5,481, 2,983,
  and 3,076 user instructions respectively in matched development startups
  with identical syscall traces. Single-pass GNU hash bucket validation saves
  another paired median 4,164 user instructions in 100 development startups.
  Direct use of retained object records for runtime symbol lookup saves a
  paired median 14,507 instructions in a 256-call GNU-hash `dlsym` probe and
  11,240 in a CRT startup control, at a 1,872-byte release-text cost.
  Reusing the bounded private relocation name cuts another 466 median user
  instructions in 100 paired simple and graph development startups, with
  unchanged syscall traces and 16 fewer release-text bytes.
  A sequential full-RELR-bitmap path saves another paired median 568 user
  instructions in both startup rows, with unchanged syscalls and 64 more
  release-text bytes.
  Initial TLS now uses zeroed builtin or fresh anonymous backing for module
  tails; that saves 19 median instructions and 64 release-text bytes in the
  same paired development rows.
  A retained file-backed dynsym record bound avoids a checked offset on the
  active lookup path, saving 281 and 288 median instructions in paired simple
  and graph startups with unchanged syscalls and 16 more release-text bytes.
  Zeroed initial TLS backing also supplies empty DTV and module-size slots,
  saving 28 median instructions in both paired startup rows and 80
  release-text bytes without changing their syscall traces.
  Deriving pooled loader block size and free-list index from one exponent
  saves paired medians of 186 and 206 user instructions in simple and graph
  startup with unchanged syscall traces and 16 fewer release-text bytes.
  Retaining the pool chunk's exclusive end instead of decrementing remaining
  bytes saves another 80 and 99 paired median instructions in the same startup
  rows, with unchanged syscalls and 16 fewer release-text bytes.
  Specializing the pool's zeroed and uninitialized allocation paths saves
  another 104 and 128 paired median instructions across 100 development
  startup pairs with unchanged syscall sequences; release text grows 192 bytes.
  Simplifying class rounding saves a further 108 and 122 paired median
  instructions and 32 release-text bytes in the same development rows, again
  with unchanged syscall sequences and all class boundaries checked.
  Normalizing zero length only on the pool's mapping-release branch saves
  another 18 and 19 paired median instructions in simple and graph startup;
  release text and syscall sequences remain unchanged.
  These remain unqualified under host contention. Allocator rows stay
  6.5–8× on the selected
  accepted-C backend, whose arena the host's THP `always` mode backs with
  huge pages on first touch. The native backend's arena reservations take the
  musl-defaults `MADV_NOHUGEPAGE` (`CRABC-MI-ARENA-RESERVATION-NO-THP`,
  pinned-C differential in the M2 arena lifecycle trace): its max RSS on the
  startup and allocator rows is 0.99–1.08× musl against 1.44–1.59× without
  it, and the divergence's `performance_qualified` flag waits on a qualified
  integrated report of `startup_first_alloc` and `churn_8k`. `memory.peak` ≤ 0.90
  cannot pass where musl charges one 256 KiB cgroup batch.
  `./scripts/dev-x86_64.sh qualification-candidate --work DIR` runs the whole
  chain as one restartable command on a clean candidate revision. The M9 report path measures
  throughput, p99 and peak RSS/PSS for all 38 rows but no report qualifies
  yet (contended host). A source-faithful remote-free cold-claim split improves
  the native 64-byte remote path from 177 to 176 instructions and its executed
  stack from 1,920 to 1,184 bytes, with all 42 C/Rust codegen regions replayed;
  reusing the checked canonical block alignment reduces that path to 175
  instructions; sharing the checked source CAS across captured live and
  abandoned states reduces it to 173 with the remote-publication gate passing
  on sealed source. Moving claim construction off the owned-head path reduces
  it further to 168; 100 paired traces, the 25-value differential, and the
  canonical remote-publication gate pass. The
  three-call versus pinned-C two-call excess remains. The 114-row runtime scorecard runs
  end to end; its older startup measure was 32 whole-process syscalls against
  musl's 11. A later scoped development smoke on the current loader is 27
  calls after canonical-alias reuse; a further same-root SysV header-load
  reuse lowers development instructions by a paired median 117 across
  100 rotated samples without changing syscall counts. A scoped source-built
  startup smoke has 23 whole-process calls after skipping exit-time `gettid`
  and reusing libc's initial TID for constructor ownership; finalizer controls
  still pass. The canonical scorecard startup fixture on clean `dde46571e`
  records 25 kernel-entry, 34 direct-entry, and 11 musl calls. Its published
  `/app/lib:/usr/lib` RUNPATH adds a required failed app-local libc probe
  compared with an ad hoc workload link.
  The x86 clock path now
  receives `AT_SYSINFO_EHDR` from validated startup auxv once, so libc-linked
  core clock lookup avoids reopening procfs; direct-core fallback remains.
  Full qualified CPU/PSS
  evidence still waits for an uncontended host and a final candidate revision.
  The release receipt gate now joins the owner-validated runtime C, native
  facade, and allocator reports by source revision and recorded CPU, kernel,
  and affinity facts; a rehashed allocator cohort from a different source or
  CPU model fails its read-only replay. It also rejects separately rehashed
  allocator reports that reuse the same raw timed and memory samples, or whose
  reported row CPUs exceed the retained host observation set. The runtime C
  collector reader also rejects a claimed benchmark or allowed CPU absent
  from the retained raw CPUinfo, and reconstructs the selected CPU's cache
  classes from retained sysfs bytes; no
  qualifying performance measurements exist yet.
- **Resume here, in order:**
  1. Family admissions are the critical path: every selected-private
     capability completes when its family is admitted. Admission receipts
     reconstruct against the current source seal, so a family transition
     only holds on the one clean candidate revision that names its receipt
     and regenerates it; the final transition is a single candidate on which
     the whole chain runs (`qualification-candidate --work DIR`). The frozen
     preflight at `4ddc94ebe` (lane `dynamic-product`, evidence under
     `.work/worktrees/lane-dynamic-product/.work/logs/pf/`) passed the
     dynamic qualification, POSIX family matrix and companions, pthread-tls,
     all 30 text producers and assemble, the loader family, consumer std/LTO
     and Lua admission. It failed `owned-posix-native` (OS-test: the old 600 s
     limit, fixed on main by `0f7359528`, and one `aio/aio_cancel` difference
     where pinned musl's `cleanup()` ordering makes the oracle print
     `EINPROGRESS`; this needs a finite OS-test disposition),
     `owned-resolver-family` (cross-member hidden TLS in the static link
     authority, fixed on main by the abi-closure commits), and the static and
     combined sysroots (the 33rd `atexit` expectation, fixed on main by
     `7fbcc1b5d`). The combined product's package-corpus reader now validates
     its embedded static/dynamic placement maps, rejects executable top-level
     manifests, and passes a focused physical
     34-workload replay; a full combined rerun remains open after identical
     oracle/candidate sqlite timeouts under host contention. The combined
     archive extractor also checks exact member modes, safe aliases,
     and every embedded component's claim before staging; retained archives
     passed its earlier read-only validation. Newly source-sealed static
     manifests and the dynamic product state must now carry one matching
     source digest before combined composition or extraction; older retained
     archives without the seal fail closed and need a fresh source-built run.
     Static package creation and extraction now require the installed
     manifest's source seal to equal the current checkout digest; physical
     forged and stripped archives fail before publication. The installed
     driver rejects missing or malformed seals, while source-bound receipt
     readers remain responsible for authenticating installed products. The
     static receipt reader now joins every retained primary and reproduction
     tree hash to its installed manifest payload roster; rehashed tree lists
     that disagree with the manifest fail physical replay. Dynamic package
     creation and extraction bind retained bytes to the materialization state
     before publication. Extraction now rejects altered modes, owner metadata,
     member order, padding, and PAX/GNU extensions by comparing each physical
     header with the writer's canonical USTAR encoding. The static extractor
     also compares the bounded decoded TAR stream against the writer's exact
     XZ bytes, rejecting trailing data and alternate compression. The dynamic
     qualification reader binds each base
     executable's declared DSO hash to its retained DSO bytes. Resolver and
     POSIX family readers now require the dynamic qualification receipt at
     its owning work path, rejecting copied rehashed receipts. The AIO reader
     also rejects success output on source cancellation timeouts and requires
     the retained installed-header trace to contain the preprocessed probe.
     The finite `aio_cancel` oracle disposition
     is integrated;
     a clean `80724223a` native OS-test replay profile-qualifies 5,395 outcome
     pairs with exactly six selected `stdatomic` dispositions. A full libc-test
     component on clean `02b6fa8a6` profile-qualifies
     all 434 cases with 428 raw passes and six finite dispositions; its reader
     and an independent reread verify all 682 runtime sidecars and 2,046 raw files.
     The text family row is
     executable, and current-source
     direct `posix-admission` passed on frozen `83e365c7c`, binding the
     54-cell POSIX family matrix and five native aggregate components.
     These receipts must be rerun on merged `main`.
  2. Sixteen Codex lanes resumed on 2026-09-26; `.work/tmp/lane-agents.txt`
     holds the active map, and the parent owns integration to `main`. The
     `lane/abi-closure` companion-reader refresh is integrated; its merged-source
     cohort and ABI assembly are running. The source-built static libc now compiles and links both
     freestanding C and stock Rust std consumers, and automatic exit selects
     the signed native `destroy_on_exit` behavior; their merged-revision
     qualification remains open. `m8.rust-std`, `m8.lua`, `m8.corpus`,
     `m8.threads-fork`, `m8.weak-interposed`, `m8.startup-constructors`,
     `m8.errno-c-abi`, and `m8.static-dynamic-products` pass on source-built
     native-shadow products; all nine M8 leaves pass on the clean frozen
     `4ae4d70e3` source, while final merged-revision qualification remains
     open. Known open items from the last lane reports:
     `materialized-dynamic-sysroot` still has load-sensitive deadlines (aio
     fresh-signal and behavior, credentials `threads`, message-queues,
     signal-handler-fork `raise-race`). Merge a `[[family.verified_slice]]`
     change only after rerunning its cited commands in a frozen checkout.
  3. Remaining low-churn repository-file pins (`compat/x86_64/core_image.py`
     now names the core image once): shadow-ABI and churn fixtures, and
     remaining image-input receipts. The native perf profile's operation
     denominator now matches its route geometry. The owned dynamic
     `.list` digests, mimalloc visibility, errno-alias, Lua admission, native
     allocator DSO bindings, utmpx oracle bytes, and
     resolver-network image inputs have passed physical source-built audits.
     The protocol database producer and reader now require the exact pinned
     musl 1.2.6 archive; its corrected source-built receipt passes.
     The syscall-alias reader now replays packed RELR against a
     source-built static/dynamic cohort; the timed pthread reader binds its
     four providers to their selected archive members. Their merged-source
     ABI assembly remains open. Keep the frozen AArch64 baseline, pinned-musl header identity,
     upstream reference copies, adapted-upstream-test patch pins, and
     archive/toolchain provenance.
- **Other open defects:** fourteen runners pin optimizer shape (raw-syscall
  provider counts, call edges; lane `pattern`). M3's direct-page pop retains
  `retire_expire` and its differential trace passes. M7 exact statistics
  receipts now match the 122-key C/Rust differential after startup defers the
  first arena; the gate still requires MI_STAT>0 and a merged-source receipt.
  The pinned musl `raise-race` workload itself can fail
  with the same late-handler-fork `ECHILD` pattern as the candidate, so that
  report alone is not a runtime defect. Timing-limited leaves under host load
  need same-oracle comparison and source-bound reruns.
- **Housekeeping:** superseded branches are archived under
  `refs/archive/branches/`, old stashes under `refs/archive/stash/`, and
  pre-campaign evidence receipts in `.work/archive/*-receipts.tar.gz`. A fresh
  worktree needs `scripts/lanes/prepare-worktree.sh` before offline builds.

## Parallel lanes

Use `.agents/skills/lanes/SKILL.md` for Codex coordination, or the
`.claude/skills/lanes` skill for Claude Code; both use
`.claude/agents/crabc-lane.md` for lane boundaries and handoffs. Keep at most 16
concurrent lane agents, each with one bounded, unique deliverable and an
exclusive write boundary in `.work/worktrees/lane-<id>`. The parent session
alone integrates to `main`. A failure outside a lane's boundary goes to one
owner. Nobody uses `git stash`. Qualifying performance measurements wait for an
uncontended host.

Validators check structure, cross-references, and runtime receipts; they do not
restate ledger prose, owner lists, or counts. Tests exercise behavior; they do
not pin source text. Add neither per-artifact validator functions nor
source-literal tests.

## Fixed contracts

| Boundary | Required contract |
| --- | --- |
| Active target | Native Linux/x86-64 little-endian, Linux >= 5.10; `x86_64-unknown-linux-musl` where a Rust target name is needed. No AArch64 execution or emulation. |
| Compatibility | Pinned musl 1.2.6, Linux ELF and System V AMD64 ABI, and `COMPATIBILITY-PROFILE.md`. Rustix remains test-only; no glibc or ambient target-runtime fallback. |
| Frozen runtime | AArch64 commit `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`: exactly **223 capabilities and 26 required families**. `compat/x86_64/aarch64_frozen_baseline.json` owns the three immutable ledger/ABI/header digests. Validate them, never refresh them to absorb drift. |
| Runtime accounting | `compat/x86_64/parity.toml` owns exact capability mappings, family dependencies, and promotion. Every capability and required family occurs exactly once. Export ratchets are not inventories, schedules, or semantic proof. |
| Allocator source | mimalloc **v3.5.0**, commit `18b08671c9302247bfb682286e6bf3cc1773f801`; archive hash, license, and source provenance in `crabc-mimalloc/UPSTREAM.md`. No silent upgrade or allocator redesign. |
| Allocator accounting | `compat/allocator/port-map.toml`, applicability inventories, milestone manifests, and `known-differences.md`. Source-unit implementation, bounded evidence, integration, and target qualification are distinct. |

Default behavior matches pinned musl's defaults (user decision, 2026-09-25):

- **Loader validation.** At load time the loader rejects what musl rejects.
  Up-front checks musl does not perform are not required and must not keep a
  startup or `dlopen` row off the 0.90× CPU gate.
- **Transparent huge pages.** The runtime leaves the process THP policy as
  musl does (no `PR_SET_THP_DISABLE`; upstream `allow_thp` stays 1). The
  native allocator's own arena reservations opt out of huge pages with
  `MADV_NOHUGEPAGE`, so first-allocation residency is musl-like. This is a
  recorded divergence from mimalloc v3.5.0 and carries a
  `known-differences.md` entry, a pinned-C differential, and performance
  evidence.
- **CPU governor.** Qualified measurements run on the host's configured
  governor (`powersave`). Candidate and reference interleave under the same
  governor, so it is recorded and must be one consistent governor for the
  whole run; it is not forced to `performance`.

The accepted `libmimalloc-sys` 0.1.49 backend bundles mimalloc v3.3.2; it is
**not** the exact v3.5.0 engine oracle. Preserve separate candidate, accepted-C
integration comparison, and pinned-v3.5.0 differential/performance inputs.
Preserve the resolved musl BSD-random exception and approved cryptographic
primitive boundaries in `AGENTS.md`; do not reopen them as blanket blockers.

## Execution

Start with current status, the relevant source and manifests, and existing
unfinished work. Distinguish missing implementation from missing evidence and
external qualification. Prefer coherent subsystem behavior with its tests to
one-symbol patches, receipt-only work, or a new audit of already settled facts.

Implementation dependencies and qualification prerequisites are different.
Develop successors against stable interfaces while prerequisites qualify, but
never mark a downstream family or milestone complete before its required gates.
Runtime work can continue with the accepted C backend; static delivery does
not need dynamic startup; allocator engine work need not wait for unrelated
hardware evidence. Prioritize shared prerequisites and the longest remaining
integration path, not the easiest counter to change.

Use current orchestration instructions, isolated persistent worktrees, one
owner per shared state transition, and one writer for integration and central
ledgers. Keep useful implementation, review, integration, and qualification
moving concurrently. A concise outcome, ownership boundary, dependencies, and
proving checks are enough for an assignment. Reuse warm private development
state; integrate reviewed work continuously and test the merged result. Do
not require synchronized waves, per-leaf handoff files, repeated global
rebases, a fixed model roster, or a repository scheduling framework.

Use focused regressions while developing, affected component/family and
installed-product checks at integration, and complete canonical suites for
qualification. A branch pass does not prove merged composition. Review unsafe
ownership, atomics, loader/unwinder trust boundaries, and promotion carefully;
ordinary changes do not need repeated ceremonial audits.

Keep a frozen qualification checkout separate from moving development. One
product cohort binds a clean revision, pinned tools/image/oracles, target,
backend, features, and build configuration. Reuse its immutable products via
existing supplied-product interfaces; keep required independent reproducibility
builds independent. No shared mutable build/report directories, cross-revision
receipt substitution, or relabeling of out-of-order diagnostics as qualification.
Do not throttle agent or compiler/test concurrency; retry a build killed by
memory pressure rather than treating it as a defect. Performance qualification
must not contend with builds or other measurements.

For runner changes, first exercise a small real dispatch → collector → physical
output → independent-reader round trip. Extend existing matrices and readers
rather than creating a proof schema for every case. Preserve raw failures,
upstream schedules, and exact source identity. Update existing machine state
when facts change; keep logs in ignored report paths and history in Git.

## Runtime completion

All 26 required families must reach `foundation-verified` in their validated
dependency order. All 223 capabilities must reach their promotion-recognized
completed states, with no `missing` or `selected-private` entries. The following
contracts describe the integrated outcomes; the frozen mappings define their
finite selected surface, not all of musl or all of POSIX.

### Families and public ABI

| Area | Completion requirement |
| --- | --- |
| Headers and layouts | Complete installed header paths, selected strict/POSIX/XOpen/GNU/BSD/large-file profiles, typedefs/records/enums/constants/macros/data/functions, C and selected C++ linkage, LP64/x87 layouts, transitive includes, and installed-tree isolation. Zero missing selected declarations or unclassified callable owners. A deferred provider disposition can close header routing, not implementation or archive extraction. |
| POSIX runtime | Coherent filesystem/directory/traversal, descriptors, environment, process control, signals, and kernel-administration behavior, including aliases, errno/TLS, shared state, cancellation where selected, errors, output writes, and ownership. Complete native OS/signal/process/libc-test evidence, not merely Rust-facade equivalents. |
| pthread/C11 and TLS | Selected lifecycle, attributes, identity, join/detach, synchronization, once, TSD, cleanup, cancellation, signals, timers/thread notification, atfork/fork, and exit. Main, loader, worker, static TLS, dynamic TLS, DTV/module IDs, and `__tls_get_addr` use one ownership model. Realistic static/dynamic composition and stress are mandatory. |
| Text, math, locale, stdio | Selected iconv/wide/multibyte, regex, word expansion, clock/calendar, and complete stream/path/position/format/scan behavior. One stream engine owns locking, buffering, byte/wide orientation, permanent/created/adopted/memory/cookie streams, positioning, errors, and exit flushing. Preserve restricted locales, x87/MXCSR/fenv and long-double ABI, rounding, signed zero, NaNs, and exceptions. |
| Resolver | End-to-end conventional files and bounded C netdb/resolver behavior: A/AAAA/CNAME, search, UDP/TCP fallback, timeout/retry/server failover, reply validation, errors, cancellation/thread interactions, and result lifetime. Prove controlled-network and file behavior through owned C products; a parser or typed Rust transport alone is insufficient. |
| C compatibility and binding | Selected crypt/crypt-helpers through approved primitives, allocation, legacy compatibility, process globals, and final callable/data provider closure. Verify names, aliases, bindings, visibility, sizes, versions where selected, and static/shared ownership. Use ordinary archive extraction or an explicit structural oracle/builtin/consumer boundary—not hidden unresolved providers that happen not to be extracted. |
| Loader | General admitted dependency graphs, not fixed fixture graphs: self-relocation/entry, kernel main image, search/RPATH/RUNPATH, mapping/protection/RELRO, supported RELA/RELR relocations, weak/global/protected scope, RuntimeV1, initial/runtime TLS, DTV growth, constructors/finalizers, and selected `dl*` introspection. Prove concurrency, callbacks/reentrancy, fork, retained handles, reopen, malformed input, and failed-load rollback. |
| CRT, builtins, sysroot | Owned static/static-PIE and dynamic PIE/non-PIE entry, libc handoff, main lifecycle arrays, finalization, compiler helpers, deterministic link interface, installation, packaging, extraction, and reproducibility. Prove real applications consume the owned artifacts. |
| Rust facade and remaining families | Preserve and complete every other frozen family and exact semantic mapping, including direct native API, error, ownership, dependency, and LTO evidence. A C ABI pass does not prove the Rust-native path or vice versa. |

For pinned musl parity, successful `dlclose` validates a handle but does **not**
unmap the object or invoke its destructors. Reopen observes retained state;
DSO destructors run at process exit. Failed load transactions still release
their owned mappings. Do not implement physical last-close unloading and call
it the selected musl contract.

Use existing family matrices for routine ABI probes, feature profiles,
C/C++ signatures, symbol/data ownership, oracle execution, and aggregate
membership. Keep bespoke fixtures for genuinely unusual ABI, floating-point,
callback/lifetime, TLS/fork/signal, ELF, privilege, or network behavior. Private
opt-in features and extra exports do not create new frozen capabilities or
waive family closure.

### Owned products

Deliver **all four modes**: ordinary static `ET_EXEC`, static PIE, dynamic PIE,
and dynamic non-PIE. The installed sysroot owns headers, CRT objects, `libc.a`,
shared libc, interpreter and required compatibility alias, compiler-builtins,
selected allocator, and deterministic link specifications. A pinned host
compiler is allowed; ambient target headers, CRT, libc, libgcc/compiler-rt,
loader, or other undeclared target libraries are not.

The static product must be admissible from owned headers/libc/allocator,
pthread/TLS, static CRT, builtins, and its link interface without depending on
dynamic startup. The combined sysroot still requires both static and dynamic
products. Preserve this separation in the machine dependency graph.

The static suite jointly proves argument/environment/auxv/program-name
publication; initialized, zero-filled, and high-alignment TLS; errno;
allocation/alignment/reallocation/failure and remote ownership; pthread/C11,
TSD/cancellation/fork/exit; stdio buffering/formatting/positions/errors/flush;
filesystem/process/signal/time; sockets/resolver; constructors/destructors,
`atexit`, and ordinary/immediate termination. Include a compiler-helper
consumer that fails to link when the owned builtins archive is removed.

The dynamic suite uses an installed main, an initial dependency graph, and a
runtime-loaded plugin. It jointly proves interpreter/RuntimeV1 handoff,
search/relocation/scope, lifecycle ordering and retained close/reopen, public
`dlopen`/`dlsym`/`dlclose`/`dlerror`/`dladdr`/`dlinfo`/`dl_iterate_phdr`,
initial-exec/general-dynamic TLS, DTV growth before and after worker creation,
and allocation/errno/stdio/pthread/TSD/signal/exit across DSOs. Include
concurrent lookup/open/close, callback reentrancy, selected fork repair, and
selected malformed, missing, stale, or cyclic-input failures.

For each final ELF inspect link traces/maps, target input identity, interpreter
or its absence, dependencies, relocations, symbols, TLS, stack flags, RELRO,
and unresolved references before execution. Require two independent clean
installed builds to match byte-for-byte over the declared regular-file set,
then package/extract into a fresh location and run the same complete product
suites. Private direct-extraction tests remain useful but do not replace
natural composed links and installed-product execution.

## Native allocator completion

### Engine and source parity

`crabc-mimalloc` is a `#![no_std]` Rust engine with no production `alloc`,
C/C++ implementation, bindgen implementation, native implementation build
script, dependency on crabc-libc, recursive allocator dependency, or hidden C
fallback. Its permitted direction is `crabc-mimalloc → crabc-core + chacha20 +
zeroize`, with libc depending on the engine, never the reverse. Additional
focused pure-Rust primitives must preserve source behavior and allocation-free
bootstrap. Keep errno and C ABI policy in libc.

Port complete source transitions rather than test-shaped routes. Maintain
exact file/function mappings, configuration/layout probes, applicable API/mode
inventory, intentional differences, and unit/differential/integration/stress/
performance evidence in the existing contracts. Each applicable Linux/x86-64
interface and mode must be implemented and verified; inapplicability requires
source-backed reasons, not unavailable hardware or an inconvenient test.
Upstream changes require separately reviewed source/inventory/map diffs and
correctness, model, stress, and performance requalification.

### Production architecture

1. **Persistent source owners.** Each allocating thread retains its TLD/Theap
   across operations; the initial thread preserves source-required static
   storage. Local small/direct-cache and generic queue operations remain
   owner-local. Independent owners can progress independently.
2. **Pointer-centered dispatch.** `free`, usable-size, and realloc derive the
   page from the pointer and PageMap, recover the canonical aligned block,
   and choose local, live-remote, or abandoned behavior from page/process
   state—not caller identity or an exact-client registry. Realloc follows
   `mi_theap_realloc_zero_ex`: source-permitted local in-place reuse, otherwise
   current-owner allocation, bounded copy, and general free; preserve the old
   allocation on failure and the selected zero-size policy.
3. **Page-local remote publication.** Translate the pinned remote-free atomic
   protocol without borrowing the owner's TLD/engine. PageMap and metadata
   remain valid through every legal live client and unfinished remote
   publication. Unregister/release only after source state proves no client,
   uncollected free, or producer can remain, in source ownership order.
   Ordinary lookup does not acquire a structural PageMap mutation lease.
4. **One owner-exit traversal.** `_mi_theap_collect_abandon` performs deferred
   free, retired-page collection, source queue traversal (including full
   queues where required), per-page collection, empty-page release or live-page
   abandonment, cache/list repair, and Heap/Theap/TLD detachment. Cover regular,
   large, arena/OS singleton, mapped/unmapped, mixed, and late-publication
   cases through that generic coordinator, not caller-selected geometry routes.
5. **Callbacks without invalid borrows.** Source fast-TLS clearing does not
   clear the still-live default Theap. Deferred callbacks may allocate through
   it; execute them outside owner/engine/TLD/Theap reference projections and
   revalidate attachment identity before resuming exclusive collection. Apply
   the same discipline to VM, output, and initialization callbacks.
6. **Abandonment outlives threads, not TLS.** Surviving pages belong to source
   page/process abandonment structures; release old TLD/Theap when safe.
   Any surviving thread can free/reallocate or reclaim as source permits.
   Terminal release does not retain worker A's admission until worker B exits.
   Failed reclaim preserves ownership; a one-way failure retains exactly one
   identifiable terminal owner rather than guessing, leaking a capability, or
   falling back to C.
7. **No production scaffolding.** Before qualification remove per-allocation
   side ledgers, live-TLS-owner/exact-post-exit registries, historical-thread
   scans, per-call park/resume, global ordinary-operation schedulers, and
   top-level fixture-geometry route products. Keep useful witnesses test-only.
   A constant-size page-local lifetime aid needs a documented source invariant,
   model and performance proof; it cannot recreate a side ledger.

The architecture ratchet requires zero local-path global scheduler operations,
structural PageMap leases, owner/client scans, remote owner-registry scans,
and extra control bytes per live allocation; no per-call suspend/resume,
ghost-owner admission, or compiled forbidden scaffolding. Actual source page
metadata is not extra per-allocation control state. Metadata must plateau
after warmup.

Keep `#![deny(unsafe_op_in_unsafe_fn)]`, explicit caller obligations, strict
provenance, atomics/`UnsafeCell` and short validated raw projections. Do not form
long-lived Rust references whose aliasing promises contradict remote access.
A legal free cannot return unavailable, and allocation cannot report OOM
merely because a scheduler token is busy. Contention uses source-backed
progress/retry, not indefinite global spinning or process poisoning. Reserve
intentional forgetting for explicit terminal-retained/abort paths. Invalid-use
hardening may differ from upstream UB; document it and test aborts in isolation.

### Bootstrap, memory, and lifecycle

Initialization must be idempotent, race-safe, reentrant, and allocation-free
until primitives are ready. Support lazy first allocation and explicit startup,
concurrent entry, partial failure, entropy/diagnostic recursion, and PageMap
failure. Receive raw nonowning startup auxv/page-size/`AT_RANDOM`/environment
facts; do not call public libc or read `/proc/self/environ` for startup plumbing.
An initializing-thread allocation lease is not completed process readiness.

Use target-probed page/virtual-address geometry, not assumptions of 4-KiB
pages, one VA width, or one arena mode. Complete raw Linux reservation,
mapping/unmapping, commit/decommit, purge/reset, protection, applicable remap,
time/identity/backoff, entropy, advice, and NUMA behavior. Put deterministic
fault injection at that primitive boundary without a generic public OS trait.

A test-only auditor checks queue uniqueness/links/counts/direct caches, exact
PageMap spans, arena and abandoned bits/counts, OS lists, free counts,
Heap/Theap/TLD relationships, thread counters, released-metadata reachability,
and unique retained owners. Preserve proven low-level mechanics; change them
for a demonstrated source or general-path defect, not a new architecture.

The final fork contract must use allocation-free hooks, preserve the parent,
repair inherited locks, vanished-thread ownership and child TLS, and permit
all standard allocation operations in the supported child. Prove public
`pthread_atfork` ordering and distinguish prepared libc fork from an unprepared
raw-fork image. A conservative bridge that disables normal child allocation
is not final completion.

### Milestones

Each row requires its existing full target-qualified evidence, not a selected
source anchor or bounded witness. Qualification is dependency-ordered;
implementation may overlap. M0–M2 must qualify before dependent milestones
can be declared complete.

| Gate | Required outcome |
| --- | --- |
| M0 | Exact source/archive/license pin, no_std skeleton, API/mode inventory, source map, separate C oracle, configuration/layout baseline, and canonical harness. Inventory closure is not engine parity. |
| M1 | The six manifest-defined bounded foundations: configuration/arithmetic, types/atomics/provenance, source random machinery, primitive and bootstrap foundations. Do not relabel this as whole-header/source-file completion. |
| M2 | All eight components: VM, metadata, scalar bitmaps, PageMap, arenas, initialization, fault injection, and no allocator recursion; full ownership and failure conditions, including required physical hardware evidence. |
| M3 | Heap/Theap bootstrap, page queues, local allocation/free, retirement/reuse, complete selected bin/page-class matrix, deterministic differential traces, and Miri-compatible execution. |
| M4 | calloc, realloc, aligned operations, usable size, medium/large/singleton, collection, OOM/failure preservation, C adapter, and applicable upstream operation tests. |
| M5 | General persistent concurrency/lifecycle: pointer dispatch, remote publication, generic exit, abandonment/reclaim/release, no forbidden scaffolding, selected libc shadow, state auditing, deterministic and soak churn, upstream pthread stress, and early codegen/performance proof. |
| M6 | All applicable Heap, Theap, arena, managed-memory and subprocess APIs, including destruction, cross-thread lifetime, and failure behavior. |
| M7 | All applicable options/environment, callbacks/deferred free, statistics, visitation, debug, secure, guarded and optional ISA profiles, without raising the baseline. |
| M8 | Complete owned-libc integration: startup/constructors, pthread/TSD/cleanup/cancellation/fork, errno/C ABI, weak/interposed symbols, static/dynamic products, DSOs/loader, Rust std, Lua, and the selected real-program corpus. |
| M9 | Full equivalent C/Rust performance/memory matrix, codegen audit, source-faithful convergence and at least three agreeing qualified full reports; correctness stays green. |
| M10 | Isolated qualified x86 default switch; C mimalloc absent from target production dependencies and artifacts, exact C v3.5.0 retained only as oracle, and required native commands rerun at the promotion revision. |
| M11 | Remove obsolete x86 transitional code/features, preserve anything required by paused AArch64, retain oracles/regressions, finalize v3.5.0 parity and the upstream-update procedure, and requalify the final simplified product. |

### Allocator verification and performance

Run real production entry points, not privileged test-only pointer routes.
Keep the permanent legal-C regression in which a worker allocates, exits, is
joined, and the initial thread frees its surviving block. Retain narrow
witnesses as tests while moving their behavior through the general engine.

Use separate pinned-C and Rust processes with logical allocation IDs and
normalized state, not pointer equality. Cover allocation/zeroing/alignment,
reallocation/content/size, heap/Theap/arena/collect, threads/transfers/exit,
post-exit free/reclaim, faults, and fork where normalization is meaningful.
Retain minimized failures and their original upstream workloads.

Miri must exercise provenance, initialization, pointer arithmetic, local
operations, and ownership/mapping lifetimes. Loom must model the production
atomic transitions for remote publication/collection, owner/unown,
abandoned claims, PageMap lifetime, and final release—not a model per numeric
page geometry. Inject failures at TLD/Theap, metadata/page allocation,
PageMap publish/unregister, arena claims, remote/abandon publication, reclaim,
purge/decommit, terminal release, and fork preparation; audit the unique owner.

Run applicable unmodified upstream tests with only environment/name binding.
In `test/test-stress.c`, preserve which thread frees, owner-exit timing,
transfer ownership, and cleanup/join order. Require **1, 2, 4, and 8 workers**,
multiple meaningful scale/iteration settings, and applicable large-object mode.
A fresh-thread cleanup workaround is not upstream acceptance. The smallest
configuration must pass before larger failures are called capacity issues.

Both deterministic bounded stress and a materially larger seeded,
watchdog-bound soak must cover independent owners, multi-producer remote
free, random transfer, partial/mixed pages, exit-before-free, initial-thread
participation, reclaim, constructors, cleanup/TSD, normal return,
`pthread_exit`, cancellation, and concurrent owners/releasers. Retain seeds,
counts, page distribution, final liveness, and metadata/PageMap/arena/abandoned/
TLD high-water. Equivalent thread churn must not cause unbounded growth.

Measure architecture early: local allocation/free/realloc, remote publication
and collection, scaling, churn, exit/reclaim, TLS codegen, syscalls/faults,
memory, and code size. Before broad optional-API expansion the persistent local
engine must reach at least **0.25× pinned-C single-thread throughput** and show
real independent four-thread scaling. This is an architecture sanity gate,
not final non-inferiority. Remove structural costs before micro-optimization.

Final allocator comparisons use equivalent opaque C/Rust boundaries and fully
integrated products on a qualified uncontended native x86 host:

| Metric | Promotion gate against exact C mimalloc v3.5.0 |
| --- | --- |
| Throughput | Suite geometric-mean lower 95% bound >= **0.95**; no critical workload lower bound < **0.90** without a separately reviewed exception. |
| Tail latency | Critical p99 upper ratio bound <= **1.10**. |
| Memory | Geometric-mean peak RSS/PSS upper ratio <= **1.05**; no critical workload > **1.10** without explanation; no unbounded metadata/mapping growth. |
| System and size | No material unexplained syscall/page-fault amplification or leak; investigate allocator-attributable code-size growth > **10%**. |
| Repeatability | At least **three qualified full reports** agree, with source/configuration/host identity and raw data. |

Audit optimized allocation, free, remote publication, PageMap/bin/TLS lookup,
realloc and alignment paths for spurious helpers, checks, fences, division,
formatting, zeroing and missed inlining. Preserve source memory orderings.
Threshold changes are independent decisions, never repairs to make a failing
implementation pass. Allocator parity does not waive the separate runtime
performance scorecard below.

## Allocator/runtime integration and Rust consumers

Libc owns standard malloc-family policy: weak/preemptible bindings and matching
allocation/free interposition, errno, zero-size and natural alignment, calloc
overflow, realloc failure and `realloc(p, 0)`, aligned allocation,
`posix_memalign` output preservation, and usable size. Internal allocation
ownership must remain coherent under a strong application allocator override.
A Rust pointer must never cross into the C backend as recovery.

Use the existing explicit `x86-owned-static-native-shadow` and
`x86-owned-dynamic-native-shadow` profiles and owned builders' native-shadow
selection. Keep accepted C default until promotion. Preserve backend-neutral
leaf/callable equivalence and target normal/build-graph plus archive/ELF purity
checks; native provider rows cannot inherit C receipts.

The dynamic RuntimeV1 handshake transfers validated runtime/TLS coordinates,
not allocator pointers. Loader metadata uses its raw mapping owners; libc
initializes its native process state after validated TLS/environment/auxv and
before constructors. Prove absence of cross-backend ownership in real installed
PIE/non-PIE and kernel/direct-loader execution, not just feature checks.
`docs/design/x86-dynamic-native-allocator.md` documents this implemented seam.

Worker attachment must establish its persistent owner before user code, even
before its first allocation. Cleanup and user TSD destructors precede native
owner teardown, which precedes TLS unmapping. Cover failed attachment,
allocation/realloc refusal with subsequent valid use, remote ownership,
final-worker ordinary exit, and fresh-owner reinitialization only after the
old owner is genuinely finished. Do not reopen a retained or borrowed owner.

Preserve source lifecycle placement: logical process-done runs from libc's own
`.fini_array`, not an invented point after all DSO/stdio callbacks. Dependent
and independent DSO finalizers can straddle it; retain the source-required
backing so later callbacks remain valid. Default-release process-done is not
physical destruction of all live allocations. Test the separately applicable
statistics/destroy/cache/TLS-key branches before claiming their source parity.

### Unwinder, std, and LTO

Complete the approved pinned Rust unwinder integration rather than asking for
approval again or copying an ambient unwinder:

```toml
unwinding = { version = "=0.2.10", default-features = false, features = ["unwinder", "fde-phdr-dl", "dwarf-expr"] }
```

Source commit: `0e2de8fb536b1ca42066024609f58d708cf80e69`. Lock and audit
`gimli 0.34.0` (`read-core`, no defaults) and `libc 0.2.186` as the reviewed
normal graph. The bindings target crabc's ABI, not an ambient libc. Keep the
path no_std/allocation-free; disable frame registration, extra personality,
panic-handler, printing, and allocator features. Rust std owns its personality.

Prove the real `_Unwind_*` ABI, ordinary archive extraction and shared symbol
resolution, executable/initial/runtime-DSO EH discovery, bounded malformed and
truncated metadata/DWARF expressions, context restoration, and mapping
lifetimes during `dl_iterate_phdr` callbacks. Preserve already landed bounded
EH/PT_DYNAMIC work rather than restarting it. Do not infer async-signal safety
from loader enumeration. Run backtrace and panic cleanup/resume across calls,
threads and DSOs through installed/extracted static/dynamic products.

Reproduce the frozen stock-std, dependency-bearing std, build-std and LTO
consumer contracts, including their controls and exact toolchain/IR provenance.
`panic=abort`, dummy unwind symbols, suppressed unresolved references, a
musl-hosted standalone pass, or an easier fixture cannot replace those gates.
Likewise reproduce the frozen Lua/source-build and real-software compatibility
rosters through owned products; do not substitute version probes for required
workloads or silently expand the active corpus.

## Runtime performance and qualification

Close runtime/products and family prerequisites, then execute the ordered
qualification chain. Independent diagnostics may run earlier; they do not
constitute an admitted final chain.

```text
compat.abi-differential
  -> compat.posix-process
  -> compat.resolver-network
  -> compat.loader-corpus
  -> consumer.rust-std-lto
  -> consumer.source-build
  -> capability.accounting
  -> performance.release
```

Use the existing finite native performance definition and preserve all
mandatory rows: startup/lifecycle and dependency graphs; clocks/identity;
files/descriptors; dynamic lookup at small and 128/1,024+ symbol scales;
memory primitives across sizes/alignments/cache and guard-page boundaries;
allocation/churn/live sets; stdio/parsing; threads/TLS/synchronization; and
hermetic sockets/resolver. Native-facade/Rustix and std-aware build-std/LTO
lanes remain distinct supporting comparisons, not a musl C-ABI claim.

The runtime release scorecard is **per workload**, not a compensating suite
average. Preserve these requirements under native x86 adaptation:

| Metric | Required result against pinned musl |
| --- | --- |
| CPU | One-sided 95% bootstrap upper bound for median candidate/reference user-plus-system CPU <= **0.90**. |
| Peak memory | Both protocol-controlled peak PSS and fresh cgroup-v2 `memory.peak` ratios <= **0.90**. |
| Syscalls | Candidate <= **2R** for reference count R > 0; a zero-call marked reference region requires zero candidate calls. No uncontracted error/retry/fallback calls. |
| Diagnostics | Retain wall median/p95, faults/context switches, RSS/private pages and size; investigate material regressions. All semantic gates remain green. |

Use identical fixture bytes except the explicitly admitted interpreter/runtime
substitution, symmetric inputs, pinned build modes, interleaved reference/
candidate samples, and complete raw provenance. Time without tracing,
profiling, or memory observers. Measure high water with ready/hold/continue
and `smaps_rollup`, plus a fresh delegated cgroup; count loader/runtime and
process memory, not only allocator requests or virtual reservations. Missing
cgroup access, invalid plateaus, omitted rows, or unsupported measurements
cannot pass. Keep syscall startup totals distinct from marked useful work.

Preserve the existing full-sample/statistical protocol and repeat clean runs;
use a second compatible native machine class when available. Attribute
regressions before optimizing; use the existing scorecard, not a new benchmark
framework. A provisional time-route **1.05** CPU ratio is at most development
status, never a relaxation of the **0.90** release gate.

The historical fully touched 32-MiB workload exposes a possible feasibility
conflict in the absolute 0.90 peak-memory rule: payload alone can exceed 90%
of the reference's total. Do not hide the row, subtract candidate-specific
baselines, shrink its live set, or silently replace the metric. Re-evaluate
with native x86 evidence; if the lower bound still precludes the requirement,
retain that precise acceptance-policy blocker for an explicit user decision
while completing independent work. The authorized faithful allocator port
supersedes old instructions forbidding all allocator work, not this scorecard.

## Commands and evidence

The active runtime dispatcher owns these aggregate commands:

```sh
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh campaign-family FAMILY
./scripts/dev-x86_64.sh campaign-static
./scripts/dev-x86_64.sh campaign-dynamic
./scripts/dev-x86_64.sh campaign-qualification
./scripts/dev-x86_64.sh campaign-promotion-check
./scripts/dev-x86_64.sh campaign-all
```

Use `--help` and the owning manifests for focused commands. In particular,
`materialized-dynamic-sysroot` is an executing installed-product gate; do not
confuse a plan-only seed with execution. Admission/replay must use the pinned
qualification dispatcher and its actual reader-enforced prerequisites.

The allocator has a separate contained native lane:

```sh
./compat/allocator/run-x86_64.sh allocator --quick
./compat/allocator/run-x86_64.sh allocator-m1
./compat/allocator/run-x86_64.sh allocator-m2
python3 compat/allocator/run.py --check --architecture x86_64 --offline
```

Use its current help/manifests and finish any missing native command capability
for full correctness, exact upstream tests, installed shadow integration,
seeded soak, performance smoke, qualified performance, and post-promotion
repository checks. Do not present paused AArch64 command spellings as native
x86 implementations. A full gate must name actual unmet conditions and fail
closed while incomplete, then pass at completion—not permanently report an
unspecified future milestone.

Keep each proving command and its raw/machine-readable report at the existing
predictable target-qualified location. Allocator M1/M2 reports live beneath
`.work/allocator-x86_64/reports/allocator/x86_64/`; runtime work uses
`.work/x86_64/` and the established ignored report paths. A host replay verifies
retained facts, not native execution by itself. Never hand-edit generated
measurements or infer a pass from a missing report.

## External qualification

The existing huge-page/NUMA job needs native x86 Linux with **two distinct
online allowed memory nodes (IDs <= 62), one free 1-GiB hugetlb page per node,
at least 2 GiB hugetlb cgroup headroom, readable `numa_maps`, the launcher's
canonical capabilities, and authorized `mbind(MPOL_PREFERRED, flags=0)`**.
Keep **RLIMIT_AS=unlimited**: existing composed simulated prerequisites may
reserve **36 GiB + 96 MiB** of virtual address space, separate from physical
huge pages and ordinary compiler/runtime RAM.

A prior private-mapping probe returned `EPERM`. Preserve its diagnostic;
do not infer the policy origin from a seccomp flag, repeat an unchanged denied
operation, or route around it through another agent/tool. After authorized
provisioning and validation of the pinned image, run:

```sh
./compat/allocator/run-x86_64.sh allocator-huge-numa-qualification
```

This proves its bounded native hardware contract, not all of M2. Simulated
fault paths cannot substitute for physical huge-page success and placement.
Do not rent resources, change shared pools/security policy, or reboot without
permission. Record a blocker once with the affected gate, evidence and clearing
action; revisit when those facts change, not after every commit.

## Final promotion and definition of done

Promote only through evidence-backed, isolated changes: first qualify the
native allocator and its owned integration, switch the x86 default without
changing AArch64, then complete the runtime/public-support transition when
its validator computes readiness. Each transition requires its post-change
reruns; neither can infer the other's completion.

Finish all applicable stabilization before selecting the final clean committed
candidate. Rebuild/requalify installed static and dynamic products with the
promoted allocator, including independent reproducibility builds and extracted
consumers. Run the complete native aggregate, allocator commands, ordered
qualification, model/fault/stress/soak, ABI/interposition/TLS/fork/loader/DSO,
std/LTO/source/corpus, dependency purity, and both performance contracts.
Former C-backend or different-revision evidence cannot satisfy this rerun.

The active goal is complete only when **all** of the following hold together:

- The frozen baseline and all digests validate; all 223 capabilities are
  complete exactly once, all 26 required families are `foundation-verified`
  in dependency order, and no required product or qualification remains open.
- Both owned products cover all four link modes, reproduce independently,
  and pass the same installed and extracted suites without ambient inputs.
- All native allocator M0–M11 gates, applicable APIs/modes, production
  architecture, correctness, lifetime, fault/model, upstream/stress/soak, and
  performance requirements pass; no remaining condition is hidden or waived.
- Rust mimalloc is the qualified x86 default. C mimalloc is absent from its
  target production dependency/build/artifact graph and survives only in
  explicitly isolated oracle/comparison inputs. AArch64 is not falsely promoted.
- `promotion_ready` is computed from complete evidence **before** public x86
  support is enabled; `public_support = true` and public documentation agree,
  and `campaign-promotion-check` plus `campaign-all` pass after that change.
- Final reports bind the same clean committed source, target, pinned inputs,
  and declared configurations, including post-promotion products. All required
  external qualification and runtime performance-policy issues are resolved.

Put final results in ignored reports. Do not create a new source commit merely
to write its own SHA into a file being hashed. A necessary source change selects
a successor candidate and requires affected requalification. The final response
names the commit, proving commands/reports, parity and purity results, measured
performance, and permitted limitations. Stop short only for explicit user
interruption or a precise external/policy condition after independent work is
exhausted; report that as incomplete, not as completion.

## Deferred work

These retained directions are **not active x86 completion gates**. They do not
resume AArch64 or enlarge the frozen consumer roster. Activating them requires
new direction consistent with the target pause and scope.

**Sustained software-corpus performance.** After the focused scorecard passes,
retain the C0–C4 progression: measurable pinned-corpus substrate; sustained C
baselines; cross-subsystem optimization; native application proof; reproducible
release evidence. Use unmodified package executables with symmetric runtime
overlays, exact outputs/state, pinned DSO/input hashes, fast and release sizes,
hermetic local state, and declared fresh/steady/high-water/concurrency modes.
C workloads cover grep/sed, tar, gzip/zstd, SQLite transactions/queries,
Python data/traversal/subprocess, Git local operations, loopback curl, ssh
configuration, and OpenSSL file digest strictly as a libc consumer. The five
direct `crabc-rs` applications are descriptor pipeline, local service/client,
thread/TLS worker, process/signal tool, and filesystem state tool. Their normal
builds exclude Rustix/libc/nix; compare overlapping Rustix operations only in
separate test builds, without pretending non-overlapping semantics are equal.
Each C workload must meet the same per-row 0.90 CPU/PSS/cgroup and 2R syscall
gates, with zero-call hot regions preserved; native targets are stated
separately. Keep synthetic ABI/loader/POSIX and stock/dependency-bearing std
lanes independent. Require three clean full runs and a second compatible
machine class when available; no dropped unfavorable row or generic distro,
public-network, cryptographic-performance, or package-manager scope.

**CPython source build.** The retained next candidate, only if selected, is
pinned CPython 3.14.3 through the native installed owned sysroot. First build
the interpreter/shared libpython without optional third-party extensions;
prove startup/imports, extension loading, files, threads, subprocess, Unicode,
and deterministic failures with a hermetic subset. Admit optional OpenSSL,
zlib/bzip2/xz, libffi, SQLite, expat, readline/ncurses and other libraries only
after each has independent owned-sysroot evidence. Audit headers, linker
inputs, interpreter/maps/dependencies and raw outcomes; an interpreter launch
is not broad CPython compatibility. A future true cross build must follow
build-Python/CONFIG_SITE requirements, not guessed configure answers. Neither
this direction nor completed AArch64 Lua/sysroot evidence supplies current x86
qualification.
