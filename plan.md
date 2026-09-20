# Combined native x86-64 completion goal

## Active continuation decisions — 2026-09-20

This section supersedes conflicting historical scheduling and policy text.
The owning document is `plan.md`; no separate `goal.md` is required. Preserve
local changes, historical worktrees, implementations and exact-revision evidence.
Native Linux/x86-64 remains active; AArch64 implementation and emulation remain
paused. The exact joint completion predicate below is unchanged.

The user authorizes the narrowly enumerated pinned-musl 1.2.6 Rust semantic
port of `random`, `srandom`, `initstate`, and `setstate` now recorded in
`AGENTS.md`, `SCOPE.md`, and `COMPATIBILITY-PROFILE.md`. Implement their actual
behavior, source attribution and differential tests, then prove installed
static, dynamic and extracted products and rerun `owned-posix-native` at a
clean integration checkpoint. Missing providers must not become dispositions.

Allocator metadata/arena/lifecycle, ordinary ELF loader/runtime work and the
already approved `docs/design/x86-rust-unwinder-proposal.md` integration have
project authorization. Historical project pauses do not prohibit these
subjects. Actual tool denials remain binding for their exact operations:
retain the original diagnostic, affected gates and required external review;
do not retry unchanged denials or reroute them through workers or tools.
Assess preserved implementations before replacing them. Preserve the pinned
unwinder dependency/features unless a concrete finding justifies a change.

Schedule implementation by actual dependencies, independently of family
admission and final promotion. Use isolated checkout-local workers and freeze
clean committed qualification checkouts while jobs run. Keep C mimalloc
selected until native promotion requirements pass. Final qualification still
requires the joint same-revision evidence; old receipts remain historical.

The BSD quartet is implemented in `5effd16d`, including musl's state classes,
seeding, switching, private futex synchronization and ordinary-fork lock repair.
At clean `20cedd47`, `./scripts/dev-x86_64.sh libc-bsd-random` passes against
pinned musl through the extracted native provider; retained evidence is
`.work/x86_64/tmp/libc-bsd-random.aoewif/` and
`.work/x86_64/bsd-random-main-20cedd47.log`. It covers default/reseeding,
high-bit seeds, invalid sizes 0–7, class boundaries, repeated ring wraparound,
returned pointers and restoration. The initial pre-port regression proved
musl execution and missing archive symbols; the subsequently strengthened
unresolved-link red mode was not executed against that old source.

Fresh products are being qualified at frozen clean
`3aaee6350f52c5fb89a2f4fa0fd4a0e1e6563698` in
`.work/worktrees/runtime_combined_3aaee635/`; its source must not change during
execution. Static preparation passes at
`.work/x86_64/public-data-products/static-3aaee635/preparation.json` there.
Installed BSD behavior passes all five scenarios across six execution modes
and three product pairs (90 candidate executions, plus pinned-musl runs),
including concurrency and active-worker fork. The retained roots are
`.work/x86_64/tmp/owned-bsd-random.AwOjEx` (primary),
`owned-bsd-random.NRM380` (reproduction), and `owned-bsd-random.NunJjU`
(extracted). Extraction is bound by the static preparation and dynamic
`materialized-dynamic.qpNz70/qualification-prepare.json`, not by the runner's
`--extracted` label alone. The full dynamic qualification and subsequent
owning native aggregate remain pending; no missing-provider disposition was
added. Main may advance independently without altering this frozen checkout.

Allocator `5c4e2746` removes the private test-only direct-commit failure-path
divergence without changing the already-fallback-eligible production mapping
path. Its new native regression passes at that clean revision, retained in
`.work/x86_64/allocator-direct-commit-main.log`; eight on-demand reader tests
also pass. The worker's existing 23-value C/Rust successful-commit differential
passes; it does not claim C fault-injection parity or backend promotion.
The real selected-native-shadow TSD-first-allocation/teardown case also passes
at clean worker `7b35111a4acebd29eadd076892358825df3ea7c0`; its revision-stamped
log is `.work/worktrees/allocator_resume/.work/allocator_resume-evidence/native-shadow-pthread-teardown-7b35111a4acebd29eadd076892358825df3ea7c0.log`.
This includes first-request rejection and later success, not a complete TLD
failure matrix or selection of the native backend by default.

The preserved approved standalone unwinder provider is now present on main
(`fbf8837e`, from `d3ca0e79`), without selecting it in runtime products. At
clean `1ccef617`, `./scripts/dev-x86_64.sh unwinder-build` passes in the pinned
native image, retaining `.work/x86_64/unwinder-builds/run-ty446s2i/provenance.json`
and `.work/x86_64/unwinder-host-readable-build.log`. Its archive with the
17-function unwind ABI is SHA-256
`c89cda364237e6c2efa71137351381ca73600dcd8c0143d03032e3f8e49d5ac9`;
the exact approved dependency/features audit and eleven host regression tests
pass. Duplicate/missing graph identities fail closed, and fresh build outputs
preserve prior evidence. This is standalone producer evidence only:
`qualified` remains false. The original dirty integration worktree is untouched.
The existing full Rust cleanup fixture additionally passes at clean worker
`c1f35f8b14e20cc362fb0ccfb4a7e7eebe5b7feb`, with the selected Rust archive and
no ambient unwind runtime. The retained receipt is
`.work/worktrees/unwinder_resume/.work/x86_64/unwinder-cleanup-runs/run-f6o9gmrq/receipt.json`;
twenty-one focused Python tests pass. This is standalone pinned-musl
valid-frame consumer evidence (`qualified: false`), not owned runtime,
malformed-metadata, DSO, build-std or cross-runtime LTO qualification.

Family admission machinery (`6110739d`) now reconstructs the existing matrix
and native aggregate, all 9 capabilities / 149 spellings, actual ledger
dependencies and post-proof source/product snapshots. Its 32 coordinator
tests pass; the real ledger remains planned. The text-family and `fopen64`
ABI joins require physical source/product-bound component receipts; they do
not discharge anything using old-source receipts or promote the text family.

### Current dependency blockers

| Category | Behavior/gates and evidence | Clearing action | Independent executable work |
| --- | --- | --- | --- |
| Aggregate qualification | BSD quartet behavior, installed/extracted synchronization and fork tests now pass at frozen `3aaee635`. Historical `owned-posix-native` at `deac7ae7` stopped on its missing provider; the new owning aggregate has not yet run. | Finish current dynamic qualification, then run the existing native aggregate and address its next genuine failure. | Allocator ordinary-page work and other runtime components. |
| Historical tool-denial record; exact operation unavailable | The retained rejection record names `rust_std_unwinder` and `allocator_m2_metadata`, but no original diagnostic or rejected command was recovered from repository history or preserved files. An exact prohibited action and its dependent gates cannot be inferred from those task names. | Obtain the original review transcript/tool-owner diagnostic to identify any denied operation before retrying it; use supported review where available. Preserve the historical record without inventing a blanket subsystem ban. | Approved standalone unwinder source/dependency/archive checks now pass; independent runtime and ordinary-page allocator work continues. |
| Technical correctness / unwinder qualification | The approved design and preserved provider README identify unbounded upstream unwind-metadata slices/indirect pointers; installed/extracted stock-std, build-std, DSO, LTO and malformed-metadata qualification remain open. Standalone archive production does not prove them. | Assess the preserved implementation and finish bounds/failure behavior and real owned-product consumer evidence with the approved dependency/features boundary. | Standalone build/provenance tests and unrelated runtime implementation. |
| Qualification pending: external resources; exact container syscall denial | Clean `2e18daef` observes only memory node 0, zero 1-GiB pages, and `mbind(MPOL_PREFERRED, flags=0)` returning `-1/EPERM` on a private 4096-byte mapping; unmap succeeds. This is the kernel/container execution boundary, not a repository pause. The precise policy origin is not inferred from seccomp mode. | Provision the resources and obtain platform/security-owner review for that exact syscall as requested below. Do not repeat it unchanged or route it through another container/tool. | Ordinary-page/single-node allocation paths not requiring that denied operation, deterministic failures and concurrency tests. |
| Family admission / final promotion | ABI checkpoint below retains 266 unresolved identity requirements and 25 unavailable family-semantic records; component passes do not close these. | Bind each requirement to its actual owner and complete current-source family evidence, then ordered same-revision promotion. | Existing implementation and focused checks need not wait for family admission. |

Update this table as blockers change; do not add repeated unchanged-blocker
audits. Resource simulations remain development evidence, never native huge-page
or multi-node PASS/N/A. Do not change shared-host configuration, rent resources
or reboot without separate authorization.

### One external provisioning request

Provide a native Linux/x86-64 runner exposing two distinct online memory nodes
with IDs at most 62 in both `Mems_allowed_list` and `cpuset.mems.effective`,
with one free **1-GiB hugetlb page per node** and at least **2 GiB of hugetlb
cgroup headroom**. Keep `/proc/self/numa_maps` readable and the canonical
launcher's `CAP_IPC_LOCK`; both already work on the observed host. Have the
platform/security owner approve the source's exact
`mbind(MPOL_PREFERRED, flags=0)` operation while retaining other controls;
do not use an unconfined policy or another tool to evade the retained denial.
Ordinary compiler/runtime capacity is additional and its numeric RAM floor is
not measured; the observed `RLIMIT_AS`/`RLIMIT_DATA` and ordinary-memory cgroup
are unlimited, with an 8-MiB memlock limit. The composed simulated prerequisite
also represents a 17-GiB virtual span, not 17 GiB of physical huge-page demand.

The original current-host diagnostic is retained in
`.work/worktrees/qualification_resources_resume/.work/allocator-x86_64/reports/allocator/x86_64/huge-numa-hardware-qualification-runs/legacy-pending-2e18daef/receipt.json`
(SHA-256 `f34bc7e81b3e9a46f9e304a44e7aa580ac50dc5558d42269107cfbb145d71f44`).
The runnable job is integrated through `94d80c24`; future runs retain separate
full receipts and actual executed binaries, with only a hash pointer at the
stable report path. Host tests pass (10 job tests, 52 launcher tests); no native
probe was repeated after the actual denial.

Once provisioned, use a clean committed checkout, retain its exact revision,
and execute with the pinned allocator image:

```bash
test "$(docker image inspect --format '{{.Id}}' crabc-allocator-evidence:x86_64)" = sha256:bd74f39c3f4c7ff3e9f31293a991ec1baa4d495d4962dc860e2b9abbac830c8d
./compat/allocator/run-x86_64.sh allocator-huge-numa-qualification
```

These runs close the bounded native 1-GiB allocation and physical two-node
placement gates, composed with existing source-policy/registry prerequisites.
They do not alone close M2, arena lifecycle, runtime integration, performance,
or native-backend promotion. Until then those hardware gates remain
**qualification pending: external resources**, never PASS or N/A.

## Current evidence and implementation frontier — 2026-09-20

Main through `ca817bae` adds independently reconstructable locale,
numeric/calendar, regex, and stdio component receipts, including the installed
`fopen64` macro consumer, and the installed 206-entry math/fenv component.
The math and regex readers replay symbol inspection against physical artifacts
before accepting retained provider observations. Focused reader tests and six-mode development replays pass using
the frozen `26dfb153` products. The math reader also passes a separate retained
report replay in the pinned image. These are mixed-source development checks,
not current-source qualification or family closure. The new math component
extends the dynamic catalog to 71 cases; the historical 210-run result below
still describes its original 70-case catalog.
The checked-in dynamic product contract and its non-promoting state digest now
include the same 71-case roster; an isolated catalog regression and all ten
dynamic product contract tests pass after repairing that integration mismatch.

Reconstructable component receipts are not complete capability coverage by
themselves. The family aggregate must also bind the existing numeric, locale,
ctype, wide-string, and UTF conversion observations to installed products.
The FILE engine needs its memory/cookie/process, wide formatting/scanning,
extended stream-helper, and ordinary-exit observations in addition to the
bounded path/buffering probe. Full calendar rows remain required as well;
the completed `fopen64` component still needs current-source aggregate binding.
The rich text component (`3a09dde0`), seven-row FILE-engine component
(`9ae2b5bd`), and five-row calendar component (`3ce8031b`) are now integrated.
Their six-mode frozen-product development replays and post-run readers pass.
Parent checks pass 6 text contract tests, 18 FILE-engine reader/dispatcher
tests, 16 calendar reader tests, and 23 combined coordinator/dispatch/contract
tests after integration. Full current-source three-pair binding remains open.
These are evidence requirements against the frozen family scope, not new APIs
or permission to replace behavior with symbol counts.

The full calendar component also needs explicitly pinned test-only timezone
fixtures. The current pinned core image lacks the named zone files used by
`owned_calendar_probe.c`; that older probe compares records without asserting
that those files were loaded. Its historical pass therefore does not prove
real-zone transitions. Preserve those records, supply authenticated fixtures,
and require known offset/transition checks as well as oracle comparison. This
does not authorize bundling timezone data into the runtime. The new component
pins test-only IANA 2025b archive hashes and independently fixed output hashes
for New York, Berlin, Lord Howe, and localtime. Known civil-time/offset checks
and a missing-fixture control pass; clock guards retain five capability-set
proofs excluding `CAP_SYS_TIME` and the existing syscall-denial tests.

The immutable family coordinator is integrated through `87f08e9b` in
`owned_text_math_locale_stdio_family.py`. Its fifteen focused tests cover
missing rows and modes, product/source substitution, mutation during
collection and output construction, and physical fresh-output handling.
It rejects missing rich text, full FILE-engine, and calendar receipts; these
tests do not establish real aggregate admission. Its snapshots include the
rich text aggregate's three declared pair-evidence roots, with direct-child
report hashes and exact execution-cell binding.

The full OS-test development replay with the compiler-mode fix completed all
ten suites using frozen `26dfb153` products and consumer `69f547a5`. Eight
suites match; the raw report retains nineteen differences: six atomic
addressability observations, four credential-profile observations, eight
missing BSD random observations, and an `aio_suspend` crash. Its report is
`.work/worktrees/os_test_mode_fix_full_replay/.work/x86_64/tmp/owned-os-test.dkxfi_6t/os-test.json`.
The AIO investigation observed that the upstream fixture can return while its
second stack-backed request is still active. The source-attributed repair for
both oracle and candidate is integrated through `d7d98984`; it preserves the
original assertion and drains both requests before cleanup. The prepared case
passes pinned musl and all four dynamic development routes, with the original
warning and feature flags retained. This does not identify the old faulting
instruction or close the ordered native aggregate; its full current-source
OS-test replay remains required.

Native allocator teardown commit `edddee58` is integrated. Its clean pinned
native replay passes with source-valid nonfull pages for retained-owner local
frees, including separate naturally aligned and interior-pointer cases. The
pinned C observations and eight focused initial/later-owner tests separately
cover full-page abandonment, partial-page mapping, all-free release, and late
remote frees. The process-finalizer bridge preserves source metadata after
automatic thread teardown is disabled; it does not promote the Rust allocator
or close M2. Parent source-map and evidence checks pass all 52 tests. The clean
native receipt is under
`.work/worktrees/allocator_processdone_native_finalizer/.work/x86_64/processdone-finalizer-native-20260920T015100Z-clean/`.

The terminal process-done preloading update is integrated in `3cd6d77e`,
with an unused-import cleanup in `11b50787`. It restores the pinned source's
reset-purge branch after logical finalization while retaining the permanent
VM owner. The selected-static destructor fixture passes; omitting only this
update makes that same fixture fail with candidate status 81. The isolated
source is restored byte-for-byte afterward. A pinned C oracle independently
observes the reset branch, no recommit requirement, retained mapping, and
successful release. Evidence is retained in
`.work/worktrees/allocator_processdone_preloading/.work/`; the merged tree
passes 73 focused evidence, parity-status, and source-map tests. This does not
change startup/publication, qualify the merged runtime, or close allocator M2.

Automatic regular-arena reservation now has a separate 21-value native C/Rust
comparison at clean worker `43a2ddf3`: an OS-disallow miss, sequential growth
to two arenas, and concurrent fresh reservation after exhausting an existing
arena. Raw C build/ELF/run and Rust test records replay successfully; parent
review verifies the pinned source ranges, clean source, image, and report
hashes. Evidence is under
`.work/worktrees/allocator_automatic_arena_reservation/.work/allocator-x86_64/automatic-arena-reservation-final-43a2ddf3/`.
This leaves M2 partial and does not qualify bootstrap, runtime first-arena
publication, or simultaneous reservation-lock misses.

Empty-name locale selection is implemented in `22647dd0` for the owned x86
runtime. Isolated failing regressions for both `setlocale` and `newlocale`
precede the repair; they remain under
`.work/x86_64/locale-environment-regression/`. Supported-name environment
selection now follows `LC_ALL`, category, then `LANG` precedence, with the
pinned musl default and object/base semantics. Unsupported names preserve
state on failure. General locale databases remain excluded, and the private
freestanding profile preserves its existing environment-free contract.
The locale v3 receipt seals the shared environment probe and separates common
oracle comparisons from candidate profile checks. Locale and rich-text
development replays pass all six product modes; both public readers pass
after commit with read-only mounts. Parent review authenticates 690 command
artifacts in `.work/x86_64/public-data-integration/locale-environment-final-parent-review.json`.
The merged tree passes 45 focused tests and the parity-ledger validator.
These development products do not replace current-source three-pair
qualification or establish locale-family closure.

Classic-netdb component `dedc02b9` is integrated with the existing executable
roster of 23 scenarios. Supplied frozen products pass all six candidate cells
and the read-only `--require-static` receipt reconstruction; the dynamic-only
replay remains explicitly insufficient for that requirement. The dispatcher
now forwards an optional supplied static product without preparing replacement
products. Eleven focused reader/dispatch tests pass. This remains bounded
`libc.resolver` evidence, with no resolver-family or Rust capability credit.

The native resolver/network collector now retains a physical v2 component
receipt (`88e03986`): raw command and execution files, DNS events, complete
source/tool/header and product identities, link artifacts, permission modes,
and execution trees. Its read-only reader reconstructs the existing two-arm,
twelve-candidate gate rather than accepting summary booleans. A fresh
supplied-`e44d771b` development run and independent reader replay pass, as do
37 focused tests and the optional real-report test. Missing-receipt,
raw-stream, source, and permission-only product changes are rejected; historical
summary-only reports remain inadmissible. Parent replay records are under
`.work/x86_64/resolver-physical-parent-review/mounted-products/`. Collector and
product source identities stay separate; this is not current-source runtime
qualification or resolver-family completion.

Combined checkpoint `417292cf` passes static preparation, all three calendar
pairs, and a same-source resolver/network collection. Its dynamic qualification
stops at classic-netdb because the new DNS readiness retention accidentally
made the shared `start_server` helper's second argument mandatory. The frozen
failure is preserved under
`.work/worktrees/runtime_combined_417292cf/.work/x86_64/qualification-start/dynamic/`.
`9da54fe8` restores the original one-argument interface while keeping explicit
raw-readiness retention for the physical resolver receipt. The isolated
regression fails before the repair; 38 focused tests pass afterward, and a
committed supplied-product development replay passes all 23 classic-netdb
scenarios across musl and six candidate modes. That replay is retained under
`.work/x86_64/resolver-shared-startup-regression/`. The failed checkpoint is
not qualified, and its evidence is not transferred to the repaired revision.

The replacement clean checkpoint `deac7ae7` passes all 213 dynamic cases and
the final qualification validator, all 54 POSIX matrix workloads and their
receipt validator, the installed pthread and loader components, and the
18-cell text/locale/numeric aggregate. Its checkout is
`.work/worktrees/runtime_combined_deac7ae7/`; the following paths are relative
to it:

| Verified result | Retained receipt |
| --- | --- |
| Dynamic qualification | `.work/x86_64/tmp/materialized-dynamic.zNqKXd/qualification.json` |
| POSIX workload matrix | `.work/x86_64/posix-family-deac7ae7/execution.json` |
| Pthread component | `.work/x86_64/pthread-family-deac7ae7/receipt.json` |
| Loader component | `.work/x86_64/loader-family-deac7ae7/receipt.json` |
| Text/locale/numeric aggregate | `.work/x86_64/text-family-inputs-deac7ae7/text-locale-numeric-aggregate.json` |

Parent review authenticates all 213 case logs. The nine text component groups
also pass all three product pairs. The public dynamic publisher independently
replays the qualification and publishes the local frozen-checkout pointer.
Text coordination writes its immutable receipt, but independent replay fails
because the public reader passes an absolute request path to the collector's
checkout-relative interface. The writer-to-reader regression reproduces the
failure; the reader now restores the validated relative path and all 19
coordinator tests pass. The frozen failed replay remains under
`.work/x86_64/text-family-pipeline-deac7ae7/`; qualification with the repaired
reader remains required.
The ordered native aggregate passes differential and stops at OS-test's exact
raw outcome comparison for `include/stdlib/initstate.out`. All ten OS-test
suites finish with successful make exits on both sides; eight match, while
include and basic retain the same 18 differences as the earlier checkpoint.
Atomic addressability and credential differences have bounded dispositions;
the missing BSD random quartet does not. Signal/process, pthread stress, and
libc-test were not launched. The retained incomplete receipt is
`.work/x86_64/posix-native-deac7ae7/incomplete.json`, with outer logs under
`.work/x86_64/native-aggregate-pipeline-deac7ae7/`.

The separate clean checkout
`.work/worktrees/runtime_component_batch_current_deac7ae7/` passes all 47
sealed ABI batch nodes and their finalizer without retries or imported pass
receipts. Its finalizer authenticates the saved receipts and derives the
selection audit and closure commands. The audit succeeds with 2,531 identities
and 30,684 occurrences; independent closure replay exits 2 with the same 293
blockers as the earlier checkpoint: 266 unresolved identity requirements, 25
unavailable family-semantic records, and one missing semantic and family
receipt set each. Both retain clean, unchanged source and authenticated raw
streams under `.work/x86_64/abi-selection-execution-deac7ae7/` in that checkout.
None of these receipts completes a family
or promotes x86 support. Later allocator harness commits do not inherit this
checkpoint's source-qualified evidence.

The clean replacement checkpoint `bf33fe6d`, containing the text reader repair,
passes static preparation but fails dynamic qualification after 210 successful
case receipts. In the extracted product's `resolver-cancellation` case,
`pie-direct-modern-dual-masked-dual-mixed-tcp` exits 77: its raw final errno is
`EAGAIN`, while the fixture requires `ECANCELED`. The oracle run in that matrix
retains `ECANCELED`; the lifecycle observations otherwise match. The unchanged
failed checkout is `.work/worktrees/runtime_combined_bf33fe6d/`, with producer
streams and terminal status under `.work/x86_64/qualification-start/dynamic/`
and authenticated partial case records under
`.work/x86_64/dynamic-parent-review-bf33fe6d/`. It has no dynamic qualification
receipt. Dependent text, POSIX, and pthread successor plans remain unlaunched;
the repaired text reader still requires full same-source qualification.

The resolver fixture now preserves the original stimuli while admitting only
`{ECANCELED, EAGAIN}` for the exact `modern-dual` /
`masked-dual-mixed-tcp` pair. Pinned musl reproduces the later nonblocking UDP
receive's `EAGAIN`; a dedicated post-TCP scenario requires that residue exactly.
All lifecycle fields and stderr still match, and other consumed-cancellation
cells retain exact errno checks. Seven focused tests pass. A supplied-product
development replay passes all 605 musl and dynamic entry cases, with parent
review of every raw stream and status, under
`.work/worktrees/resolver_cancellation_failure/.work/x86_64/resolver-cancellation-replay-tmp/owned-resolver-cancellation.2F1RSt/`.
That replay combines the repaired fixture with frozen products; it neither
qualifies the repaired revision nor changes the failed checkpoint's status.

The clean `0ff8e77e` checkpoint then passes static preparation and the complete
213-case dynamic gate, including all 605 resolver-cancellation executions on
each of the installed, independently rebuilt, and extracted products. Parent
review authenticates every case receipt and log hash. The producer exits zero
with clean, unchanged source; its qualification receipt is
`.work/worktrees/runtime_combined_0ff8e77e/.work/x86_64/tmp/materialized-dynamic.qZe2zD/qualification.json`.
This proves the repaired fixture through the full product gate. The same clean
checkpoint also passes the 54-cell POSIX matrix, pthread component reader,
three-pair text component workloads, and rich text aggregate. The text
coordinator writer and its separate public-reader replay both exit zero with
unchanged source and authenticated raw streams. Its nine-component,
16-capability receipt is
`.work/worktrees/runtime_combined_0ff8e77e/.work/x86_64/text-family-coordination-0ff8e77e/receipt.json`
(SHA-256 `dd0f2afaeaf9c0ca08b393be4f747ea0edb37ecd3ec109232fc92320d39ba1fb`).
Writer/replay evidence is retained beneath that checkout's
`.work/x86_64/text-family-pipeline-0ff8e77e/`, in
`coordinator-write-prepared-output/` and `coordinator-replay/`. The earlier
writer attempt remains recorded as a failure before collection because its
required output parent directory was missing; creating that directory enabled
the separately recorded successful attempt. This qualifies the text reader's
relative-request repair against real same-source products. It establishes
immutable component coordination only: component/family completion, promotion,
and public-support flags remain false. Native aggregate completion, dependency
family admission, and the remaining combined-plan gates are still required.

The earlier clean `e44d771b` checkpoint has a 71-case dynamic receipt covering all
213 executions across two independent builds and extraction, with identical
manifests and archives. Its worktree is
`.work/worktrees/runtime_component_batch_current_e44d771b/`; paths in this
paragraph are relative to that checkout. The non-promoting receipt is
`.work/x86_64/tmp/materialized-dynamic.wGWmPa/qualification.json`.
The first attempt stopped at an absent pinned APK cache after 70 installed
cases; the original failure and raw log remain under
`.work/x86_64/dynamic-qualification-e44d771b/`. After provisioning those inputs,
the missing case and both remaining complete product suites passed, followed
by the unchanged qualification validator. Parent review authenticates all 213
case receipts and logs. The full ten-suite OS-test replay also completed at
`.work/x86_64/tmp/owned-os-test.xs2k9kmn/os-test.json`: eight suites match, with
18 remaining differences (six atomic addressability, four credential-profile,
and eight BSD-random observations), and no adapter errors. `aio_suspend` now
records `exit: 0` for both musl and crabc. This standalone measurement does not
close the ordered native aggregate or waive any remaining difference.

At that checkpoint, all 47 component paths have passing evidence, with six
explicit successor steps after a historical header receipt was rejected.
Fresh header collection and replay precede the successful declaration retry;
the failed batch is preserved. Selection reconstruction passes at
`.work/x86_64/native-abi-selection/header-refresh-e44d771b/report.json`, retaining
2,531 identities, 30,684 occurrences, and 293 unresolved requirements.
Nine text/math/locale/stdio component groups also pass all three product pairs;
their 27 report identities are recorded under
`.work/x86_64/text-family-inputs-e44d771b/`. The same checkpoint now passes the
54-run POSIX matrix, installed pthread and loader component receipts, and the
18-cell rich-text aggregate. Installed crypt and addressable-atomic profile
companions also pass. Real family admission and the ordered native aggregate
remain required; these component receipts do not close them.

The first real text coordinator replay rejects the matrix product adapter:
the matrix's `request` field is a sealed file identity, but the adapter passed
it as inline producer request contents. The original failure is retained in
`.work/x86_64/text-family-coordination-e44d771b/execution/`. `c00d71de`
authenticates and reads that request before product replay; both new
regressions fail before the fix and all 17 coordinator tests pass afterward.
The next replay exposed rich-text mapping and calendar row/mode adapter
mismatches. `5222bff6` and `0d1f97db` repair those contracts; regressions use
the actual public component readers, with 35 focused tests passing after the
final repair. A full development replay now passes at
`.work/x86_64/text-family-all-repairs-development/replay/`, retaining command,
streams, terminal status, and an unchanged frozen source identity. It overlays
only the repaired reader functions and writes no qualification receipt.
The frozen checkpoint remains unchanged; this development result does not
transfer its products or receipts to the later source revision. Same-source
coordinator replay and genuine family admission remain required; the
replacement checkpoint above is pursuing those gates without overlays.

The checkpoint exposed a FILE-engine dispatcher argument mismatch before its
workloads ran. `da149adf` fixes the public command's translation to the runner's
two positional paths. The corrected regression fails before the fix; all 18
reader/dispatcher tests and a committed native public-command replay pass.
The frozen checkpoint remains unchanged and uses the runner's documented
positional interface for its three-pair component evidence. Qualification is
not transferred to the later dispatcher revision.

The combined goal remains incomplete. Main through `0158c312` includes the
locale source/product identity repairs, executable `libc.so` package mode,
host-readable wordexp expected-input capture, and preservation of compiler
product modes in OS-test. These fixes do not transfer qualification between
source revisions. The earlier product checkpoint below remains frozen at
`26dfb153`; the newer checkpoint above still requires full ordered qualification.

Paths in this paragraph are relative to
`.work/worktrees/runtime_component_batch_current_26dfb153/`. The 70-case
dynamic gate passed all 210 runs across two independent builds and extraction,
with identical manifests and packages; its retained producer receipt remains
`qualified-pending-review` at
`.work/x86_64/tmp/materialized-dynamic.JzRbWN/qualification.json`.
The eighteen-workload POSIX matrix passed all three product pairs at
`.work/x86_64/posix-family-26dfb153/execution.json`. The ten-behavior loader
component and fifteen-behavior pthread component passed at
`.work/x86_64/loader-family-26dfb153/receipt.json` and
`.work/x86_64/pthread-family-26dfb153/receipt.json`. These receipts retain
false family and promotion flags.

The same checkpoint's ordered native aggregate stopped in OS-test after its
differential stage passed. Its unchanged failure is
`.work/x86_64/posix-native-26dfb153/incomplete.json` beneath that worktree.
OS-test had removed write bits from its copied compiler product, violating
the existing exact-mode link contract. `0158c312` fixes the copy and adds
collector authentication of that payload. Focused regression tests and a
real supplied-product compile/link replay pass; the full native aggregate
has not been rerun. Signal/process, pthread-stress, and libc-test were not
reached by that aggregate.

A separate full libc-test measurement at `26dfb153` completed all 434 units:
427 raw passes, one candidate link failure, and six runtime comparisons
reported as failures. All 199 math candidates passed. The existing public
classifiers reproduce the three fixed musl math defects and the exact crypt,
strptime, and wordexp dispositions; the missing BSD random quartet remains
unresolved. The retained report and reproducible host classifier replay are
under `.work/x86_64/libc-test-measurement-26dfb153/` in that worktree, with
the latter bound by `classifier-replay-receipt.json`. This standalone
measurement does not replace the ordered aggregate.

The later `f1b18e01` checkpoint passed all 47 selected component jobs and the
final selection audit, but closure correctly exited incomplete. Its report is
`.work/worktrees/runtime_component_batch_current_f1b18e01/.work/x86_64/native-abi-selection/clean-f1b18e01/report.json`.
Installed math/fenv composition and fixed-mimalloc process-done/retained-worker
free integration have since landed as described above. Full runtime
family closure, allocator milestones, performance qualification, and the
same-final-revision promotion gates remain required.

## Earlier integration checkpoints — 2026-09-12

At `5328cb94`, the complete 70-case dynamic product gate passed across two
independent builds and the extracted package: 210 case receipts, identical
product manifests and byte-identical packages. Host replay and explicit local
publication passed. All 21 synthetic loader cases and all 34 frozen package
corpus cases passed on each product. Evidence paths below are relative to
`.work/worktrees/owned_posix_evidence_integration/` unless stated otherwise.
The retained dynamic receipt is
`.work/x86_64/tmp/materialized-dynamic.jSrBIm/qualification.json`.

The same revision passed reproducible static preparation and all eighteen
POSIX workloads across all three static/dynamic product pairs. The matrix
binds all 149 selected spellings to six static and twelve dynamic execution
cells. The installed-loader component covers ten behaviors, and the pthread
component covers fifteen behaviors with three passing composition runs.
Static preparation, the POSIX matrix, and both components passed independent
host reconstruction:

- `.work/x86_64/posix-static-products-5328cb94/preparation.json`
- `.work/x86_64/posix-family-5328cb94/execution.json`
- `.work/x86_64/loader-family-5328cb94/receipt.json`
- `.work/x86_64/pthread-family-5328cb94/receipt.json`

These are component measurements; family and promotion flags remain false.
This fresh pthread receipt proves `41c892cc`'s correction to tracked source
identity handling. The earlier `04c4cbd3` collection failed and still has no
valid pthread receipt.

The following integration batch adds explicit transitive application-DSO
inputs to the installed dynamic driver. Only direct application roots enter
the final link, while the complete declared dependency graph and typed input receipts
remain validated. It also adds the fixed-mimalloc reset-advice retry/fallback
matrix and the native performance supplement: forty fixed rows and a memory
phase map for the seventy-four existing rows. At integrated `54bb0eba`, all 85 focused tests and campaign
contract validation pass; logs are under `.work/x86_64/integration-54bb0eba/`.
These source changes require fresh product evidence at the next qualification
checkpoint. They do not transfer the preceding revision's qualification.

At `640c0939`, the selected native allocator producer adds normal large-page
retry/CAS/fallback ownership. The final selected VM producer matches 98 values
and 12 focused reader tests pass. The following allocator paths are relative
to the main checkout. Parent review is retained at
`.work/x86_64/allocator-retry-parent-review/verification-640c0939.json`; the
original logs and VM evidence remain under
`.work/worktrees/allocator_large_page_retry/.work/allocator-x86_64/`. Full M2
remains partial at historical `e13313c2`. The final C reaping fix has separate
red/green and selected-producer evidence. This is status documentation only;
it does not qualify full M2 or change any runtime or promotion gate.

At `4b1e6536`, the native ABI inventory collector passes all 25 focused tests,
produces two byte-identical reports from the `640c0939` product pair, and passes
both host replays. Parent replay rejects nine malformed reports, including
header deletion, changed product/source bindings, and truncated dynamic tags.
The reports are under
`.work/worktrees/native_abi_inventory/.work/x86_64/native-abi-inventory-4b1e6536/`;
parent proof is at that worktree's
`.work/x86_64/parent-input-review/verification-4b1e6536.json`.
These paths are relative to the main checkout. Preserve the clean collector
worktree for exact-revision replay. The subsequent generated header-accounting
refresh binds the added ledger route without changing declarations or providers.
See [`native-abi-inventory.md`](compat/x86_64/native-abi-inventory.md).

The same `640c0939` pair passes reproducible static preparation and dynamic
materialization validation. All five frozen differential workloads pass in
30 candidate cells, with one unchanged object per source shared by musl and
every candidate link; read-only summary reconstruction also passes. Evidence
is under `.work/x86_64/abi-inventory-products-640c0939/` in the integration
worktree, with the differential receipt at
`differential-tmp/owned-differential.01oK0U/summary.json` beneath that directory.
These remain separate component measurements of prepared/materialized,
unqualified products. The reviewed public-dynamic regression floor is now
defined by [`native-abi-ratchet.md`](compat/x86_64/native-abi-ratchet.md);
full ABI differential/family qualification and promotion remain open.

The native C performance adapter now stages all 114 rows, launches timed
clients through an isolated static supervisor, and collects separate memory
observers with ordered live checkpoints and whole-process cgroup peaks.
At `e54ccd35`, all 74 focused tests pass. Installed/extracted startup and
dependency-graph smokes preserve the same workload-object proof; seven selected
memory rows cover all six observer artifacts in both provider lanes. Independent
host replay passes the retained timing, trace-root, PID, mapping, PSS, cgroup,
and cleanup records. These bounded checks validate the collector. The retained
syscall and memory comparisons remain non-passing; full performance collection
still requires the complete correctness predecessor chain and three qualified
scorecards. See [`compat/perf/README.md`](compat/perf/README.md).

At `1c7977e8`, the native Rust-facade companion passes all 27 focused runner
and dispatcher tests, a fresh five-row crabc-rs/Rustix smoke, and independent
host replay. Nine malformed report variants are rejected at the public reader.
Evidence is under `.work/x86_64/performance-dispatcher-review/`, including
`facade-smoke-1c7977e8.json` and `parent-proof-1c7977e8.json`. These stock-std
measurement executables do not qualify the owned runtime or Rust-std consumer;
full collection still refuses execution before correctness-chain admission.

The full native libc-test measurement at `04c4cbd3` records 427 of 434 units
passing, one missing-provider link (`functional/random`), and six runtime
failures: `functional/crypt`, `functional/strptime`, `functional/wordexp`,
`math/fmaf`, `math/fmal`, and `math/powf`. Its full OS-test measurement passes
eight of ten suites. Include retains ten differences: four missing BSD random
state APIs and six atomic addressability extensions. Basic retains eight:
the same four BSD APIs and four selected credential aliases. Earlier AIO,
utmp, account-file, and `rand`/`srand` gaps are repaired. Both raw reports remain
under `.work/x86_64/{libc-test-measurement-04c4cbd3,os-measurement-04c4cbd3}/`.

Finite crypt, atomic, credential, and `strptime` dispositions retain their
original raw outcomes. The same-product crypt and atomic companions pass.
The selected word-expansion engine and its finite policy proof are described
below; complete aggregate qualification remains required. No
disposition admits a BSD random provider failure. See
[`owned-posix-native-dispositions.md`](compat/x86_64/owned-posix-native-dispositions.md).

The native x86 word-expansion provider now selects the owned parser and
evaluator, quote-aware pathname/passwd adapter, command-only shell adapter,
and transactional C result owner. Ordinary expansion works without `/bin/sh`;
undefined variables have typed `WRDE_BADVAL` errors, and only selected command
bodies run through the shell. Integrated checks pass 57 core/process tests,
all six retained arithmetic-delimiter line-join comparisons, and the static
C gate's 25 cases in both ET_EXEC and static-PIE modes. The final core worker
also passes 48 core tests, 907 extended cases, and allocation-failure sweeps
for both contiguous and joined ambiguous arithmetic openings. The retained
224-point core sweep and the selected private C result-allocation witness
prove cleanup and accepted-prefix ownership at their respective revisions.
Actual private spawn/wait and C/C.UTF-8 pathname/passwd fixtures pass.

At `59b5a64a`, the final 25-case installed object passed all 150 cells across
six modes. Its retained receipt is
`.work/x86_64/tmp/owned-wordexp-products.e8zvckbb/owned-wordexp-products.json`.
Read-only replay from the checkout path passes with the separately captured
`.work/x86_64/wordexp-inputs-59b5a64a/owned-wordexp-products.cngmeyn0/expected-native-inputs.json`.
The full native libc-test run on that same dynamic product retains 427 of
434 passing comparisons, the random link blocker, and the same six failed
comparisons at
`.work/x86_64/libc-test-wordexp-59b5a64a/tmp/owned-libc-test.zk5dUV/libc-test.json`.
The isolated wordexp policy reader validates exactly 20 candidate and 104
oracle diagnostics, raw status 1 on both sides and empty stderr, against the
complete companion. Its observation is
`.work/x86_64/wordexp-selection-review/finite-native-policy-59b5a64a.json`;
it does not qualify the full native aggregate. The fixed diagnostic reference
retains its earlier `96a4a847` measurement provenance.

The final C review fixes fresh `WRDE_BADCHAR` count publication while retaining
the exact append record. A new same-object selector proves the candidate's
zero count against musl's unchanged sentinel. The separate twenty-input
`source-policy` selector checks every reviewed status, word, captured
diagnostic, command effect, and parent-environment effect. Its fixed musl
trace remains distinct from the required candidate trace. Native accounting
requires a fully validated companion on the same dynamic product and a
separately captured native-input seal; it retains the upstream unit's failed
raw status. See
[`owned-wordexp-upstream-policy.md`](compat/x86_64/owned-wordexp-upstream-policy.md).

The selection logs are under `.work/x86_64/wordexp-selection-review/`, including
`combined-core-09afafea.log`, `selected-static-component.log`, and
`result-private-first.log`; `selected-static-25-cases.log` records the expanded
static gate. The former whole-input shell provider and its x86 scanner are
retired. The `5328cb94` dynamic product gate above includes the final count fix
and policy accounting. The fixed
musl observations and untouched upstream failures retain their raw outcomes;
finite POSIX interpretations do not waive arbitrary failures. See
[`owned-wordexp-engine.md`](compat/x86_64/owned-wordexp-engine.md).

At `b599efd2`, reproducible static preparation passes at
`.work/x86_64/posix-static-products-b599efd2/preparation.json`. The complete
dynamic run stops at `installed/pattern` because that fixture still requires
the retired wordexp scanner's error code. Its retained failure is
`.work/x86_64/tmp/materialized-dynamic.qQZYMq/qualification-cases/installed/pattern.log`.
The duplicate assertion is removed; the dedicated wordexp `nocmd-source`
selector retains exact candidate and oracle results. The complete filename
pattern workload then passes on that unchanged installed product in all four
dynamic modes at `.work/x86_64/pattern-after-wordexp-selection/tmp/owned-pattern.Hx2iVv`.
The later `5328cb94` run above passes the complete product gate.

At `3cc41ae8`, the next full product attempt passes the first 63 installed
cases, including pattern and wordexp, but independent wordexp replay exposes
an evidence-retention defect. The outer collector changes the already sealed
empty temporary directory from `0700` to `0755`. The attempt is stopped and
has no qualification receipt; its unchanged artifacts remain under
`.work/x86_64/tmp/materialized-dynamic.YFcEjU/` and the wordexp component under
`.work/x86_64/tmp/owned-wordexp-products.4m0e8cgn/`.
The version-5 wordexp receipt finishes retention before validating and
publishing its report, with exact separate execution and retained modes.
The isolated regression reproduces the mode change; all 58 wordexp-reader
and dynamic-collector tests then pass, including receipt idempotence under
a restrictive umask. At `5328cb94`, all 100 installed dynamic wordexp cells
pass; host reconstruction before and after repeated outer retention preserves
the exact receipt and artifact inventory. The complete product run above also
passes with the version-5 receipt. Reproducible static preparation at
`3cc41ae8` also passes, including host replay, at
`.work/x86_64/posix-static-products-3cc41ae8/preparation.json`.

`024b1563` corrects demonstrated `fmaf`, `fmal`, `powf`, and `nextafterl`
defects while preserving the pinned numerical algorithms. The integrated
`math-scalar-corrections` proof passes 25,632 exact-dyadic cases and accounts
for all 9,064 existing family records. The fixed musl oracle's failures remain
separate. Complete untouched upstream units also pass against the corrected
installed static product. A fresh full dynamic libc-test run at `111a96b3`
confirms candidate success with empty output for all three formerly failing
math units, while preserving the fixed musl diagnostic streams. The raw
aggregate still reports 427 passes, one random link blocker, and six failed
comparisons; the three math comparisons fail because the oracle fails.
`5cd0f0fb` and `0c2d4b40` add finite accounting that requires those exact
candidate passes, pinned oracle failures, and 39 unchanged proof sources.
It rejects candidate failures and any changed or unlisted outcome. This does
not close the aggregate's remaining random-provider blocker.
The dynamic measurement is retained at
`.work/x86_64/libc-test-math-111a96b3/tmp/owned-libc-test.EeqmUv/libc-test.json`.
Source mappings, numerical arguments, and reproduction commands are in
[`math-scalar-corrections.md`](compat/x86_64/math-scalar-corrections.md).

The dynamic Lua source-build runner now isolates the candidate in a private
execution root with copied owned runtime/application files, an explicit shell
fixture, sealed root inventories, and live mapping identities. Full installed
and extracted source/bytecode/module execution and reproducibility pass at
worker `8021735b`, integrated as `e82b9c51`; its report is
`.work/worktrees/owned_lua_runtime_root/.work/x86_64/lua-dynamic-source-build/run-nne_tr29/report.json`
relative to the main checkout. This remains separate component evidence.

Later source changes invalidate the preceding product selection. Preserve
these receipts as exact-revision measurements. The composite owner remains
`owned-posix-native`; fresh prerequisites and passing complete native results
are necessary for family acceptance. The combined goal remains active and
incomplete: public x86 support is false, C mimalloc remains selected, native
allocator M2 remains partial, and the restrictions below remain unresolved.
Continue the sequence below; the historical pause does not instruct work to stop.

## Historical handoff — 2026-09-05

Work resumed on 2026-09-05. The expanded 40-case dynamic gate passed at
`d0d3877a`: both clean builds and extraction, 120 case receipts, identical
product manifests. Host validation and explicit local publication passed for
`.work/x86_64/tmp/materialized-dynamic.7Vh9IW/qualification.json`; log
`.work/x86_64/owned-dynamic-integrated-batch.log`. The same revision passed the
native header provider audit and standalone group, message-queue, legacy-time,
filename-pattern, and GNU thread-join matrices, including both static modes.
The classic-netdb and Unix-mechanism additions then extended the catalog to
42. Later POSIX and resolver additions are described in the active integration
section above. Subsequent source changes invalidate the earlier
selection. These component results do not close the planned runtime families
or promotion chain. The paused narrative below records the preceding boundary,
not a renewed instruction to stop.

At the preceding pause, the user requested winding down the work, letting the
active tasks finish and commit, and leaving this handoff. The subsequent resume
instruction supersedes that pause. The
combined goal is **not complete**: AArch64 remains paused, C mimalloc remains
the production backend, and public x86 promotion remains false. The detailed
acceptance criteria below and in the two execution plans remain unchanged.

### Integrated state

- Loader/runtime: musl search/preloads and ORIGIN/AT_SECURE, direct interpreter
  entry, initial dependency cycles and constructor order, retained close,
  deferred GOT/PLT transactions, rollback/RELRO, kernel-main `dladdr`, all-thread
  DTV growth and runtime GD TLS, ELF visibility/scope and interpreter aliases.
  Preserve these implementations; do not restart the historical leaf queue.
- Pthread/process: mapping leases and target kill locks, main/last-thread exit,
  live attributes, dynamic fork/TLS/TSD/robust state, positive 65-live-thread
  pthread/C11 growth, and cancellation-safe join/condition ownership. Syscall
  cancellation covers I/O, sockets/readiness, sleep/waits, open/record locks,
  memory sync, semaphores, signal waits, entropy and SysV messages. SIGCANCEL
  is **33**; timer signal is 32. Ordinary FILE backends, `pclose`, `wait3/wait4`,
  empty `sendmmsg` and nonblocking fcntl retain source non-CP behavior.
- `e3624732` fixes `system` through its source-required public child wait;
  `pclose` keeps the raw wait. `e815c66f` adds timed/clock-selected and shared
  condition transactions, C11 timed status, a typed mutex relock seam,
  normal/shared mutex futex keys, and robust relock error precedence.
  The owned runtime now adds recursive/error-checking mutexes, robust owner
  tracking for those types, realtime timed locking with C11 timed status, and
  Linux 5.10 futex-PI mutexes through `PTHREAD_PRIO_INHERIT`. Its protocol
  setter retains musl's capability probe/cache; `PTHREAD_PRIO_PROTECT` remains
  `ENOTSUP`, mutex priority-ceiling get/set remain direct `EINVAL`, and the
  header-declared attribute-ceiling pair has no musl provider. The frozen
  archive is separate from the expanded owned runtime.
- `44f1684b` repairs the legacy condition evidence check: follow exact owned
  atomic helpers and raw syscall edges instead of requiring incidental
  inlining in public symbols. It changes evidence, not runtime algorithms.
- Resolver: `fce59ece` plus `f7015780` qualifies the same unchanged workload
  object through installed **and extracted** static/dynamic products, with
  local configuration files and Docker network isolation. `90bf7896` separates
  verified native evidence from family completion; `9bed2fd3` records the
  executed resolver command while both owning families remain planned.
- Dynamic product qualification: `84ece346`, `836e59b9`, `9bed2fd3` and
  `b1120fa5` wire the canonical gate to preparation, exact case receipts and
  final validation. Both clean builds and the extracted package execute all
  **17** catalog cases. Building remains unqualified; a fresh complete receipt
  is `qualified-pending-review`, followed by explicit local publication.
  Publication replaces only an atomic selection pointer; old receipts remain
  unchanged. Stale source becomes unqualified. Oracle bytes/manifests and
  actual artifacts are retained; evidence becomes host-readable after runtime
  permission tests finish, without following symlink targets.
- `dbc4bfa4` replaces claim-only qualification completion with v2 `planned`/
  `ready` declarations and ordered `qualification-manifest --through GATE`
  execution. All eight promotion gates are still planned; ready declarations
  and execution markers cannot qualify the full chain. Remaining work is in
  `compat/x86_64/qualification-prefix-execution.md`.
- Header aggregate: `66881393` integrated the completed native declaration
  foundation after all 69 aggregate runners and 1,337 installed-header checks
  passed. `libc.headers-layouts` is `foundation-verified`; callable provider
  and runtime-family closure remain separate obligations.

### Evidence retained at the wind-down boundary

These are component measurements, not final same-revision qualification.

| Evidence | Result and location |
| --- | --- |
| Canonical resolver matrix at `836e59b9` | PASS: one musl reference plus 12 candidate entries, installed/extracted payload identity and expected DNS transitions. Log `.work/x86_64/resolver-extracted-stable.log`; products `.work/x86_64/tmp/owned-resolver-network.KIdHdB/products`; execution `execution/run-1i7isxml/report.json` beneath that run root. The earlier `beihDc` attempt rejected a concurrent source edit during preparation and is not a pass. |
| Canonical system/pclose cancellation | PASS: static ET_EXEC/static PIE and dynamic PIE/non-PIE kernel/direct entry, including contained supervisor failure/timeout cleanup. Log `.work/x86_64/system-cancellation-integrated.log`; product `.work/x86_64/tmp/owned-system-cancellation.8Vba55`. |
| Timed/shared condition component | Worker commit `f5368833`, integrated as `e815c66f`: all 41 scenarios pass against musl and all four installed modes. Worker log `.work/worktrees/owned_pthread_lifecycle/.work/cond-timed-identity-final.log`; product beneath that worktree at `.work/x86_64/tmp/owned-pthread-cond-timed.VgnQF2`. Its earlier aggregate `materialized-dynamic.1WJeci` predates the final identity/error-precedence refinements; use the final focused run for those refinements. |
| Last complete old dynamic matrix | PASS at the `550bb254` runtime plus `906e6d6c` harness: 51 loader, 22 driver, two CRT tests and all then-current cases on both clean builds/extraction. Log `.work/x86_64/three-dynamic-products-integrated.log`; product `.work/x86_64/tmp/materialized-dynamic.uyzJLv`. It predates later cancellation/condition additions and the receipt protocol; do not publish it as current evidence. |
| Shared-runtime I/O cancellation | PASS: 40 ordinary/direct PIE/non-PIE runs at `88fcc133`. Log `.work/x86_64/dynamic-cancellation-integrated.log`; product `.work/x86_64/tmp/owned-dynamic-io-cancellation.gft0iz`. |
| Lua | Dynamic installed/extracted source execution and reproducibility PASS: `.work/x86_64/lua-dynamic-source-integrated.log`, report `.work/x86_64/lua-dynamic-source-build/run-0t1zwhlc/report.json`. Static source/bytecode qualification is also integrated. |
| Allocator huge reservation | `5a48b06f`: 69 C differential values and ten tests PASS; `.work/x86_64/allocator-huge-reservation-integrated.log`. Worker also passed 956 allocator unit tests, quick evidence and performance smoke. Native M2 remains partial; simulated primitives do not replace native huge-page success. |

### Resume sequence and remaining boundaries

1. Read this handoff, `STATUS.md`, `x86-64.md`, `native-mimalloc.md`, and the
   current campaign/ledger before selecting work. Keep source stable during
   builds: the dynamic producer hashes **all nonignored source content and
   modes**, so even a concurrent documentation merge rejects a run.
2. Run `./scripts/dev-x86_64.sh owned-dynamic-sysroot` from a clean committed
   checkout. Replay the complete catalog in
   `compat/x86_64/owned_dynamic_qualification.py` across all three products
   after the latest integrations. Review its generated
   `qualification.json`, then use
   `python3 -B compat/x86_64/owned_dynamic_qualification.py publish --receipt PATH`
   to select that exact ignored receipt. Later source edits invalidate the
   selection. This does not close prerequisite families or promote x86.
3. Finish ordered qualification receipt production and validation as specified
   in `compat/x86_64/qualification-prefix-execution.md`: clean revision/content,
   real tools/runtime/artifacts, retained logs/results, fixed pinned Rust paths
   in the scrubbed environment, and retained same-object ABI evidence. Register
   and run real dependency-ready family prefixes. The current first promotion
   gate correctly rejects execution while planned; the private five-case
   admission remains separate and non-promoting.
4. Complete pthread family evidence using the integrated normal, recursive,
   error-checking, robust, timed, and priority-inheritance mutex behavior.
   The Linux pinned Rust `std::Condvar` uses futexes; its Unix pthread fallback
   is not evidence that Linux Rust-std uses this condition implementation.
5. Continue POSIX family completion from actual current providers. Installed
   static and dynamic matrices now cover spawn semantics, `clone`, `daemon`,
   `vfork`, signal helpers, and the owned Linux-control mechanisms. Close the
   family through its complete selected capability roster, realistic shared
   runtime behavior, and native differential/OS/signal-process/libc-test gates.
   Private leaf selection and component passes do not replace that aggregate.
   Preserve the selected credential profile: four effective-ID aliases reject
   changes with `EOPNOTSUPP`; direct setters retain calling-task semantics. Resolver cancellation
   cleanup now has a focused installed-product regression; retain it alongside
   the parser-ordering evidence and complete the later resolver family through
   its own aggregate contract.
6. Continue independent allocator M2–M11 work while preserving the specific
   metadata and unwinder tool-review restrictions described below. Resume
   those restricted routes only after their restrictions are resolved.
   Requalify installed products after native Rust allocator promotion. All 223 capabilities,
   26 families, full product/corpus/performance gates and both plans' final
   predicates must hold at one final source revision.

### Preserved work and external restrictions

All new worktrees, scratch and generated state belong beneath checkout `.work`.
Do not remove historical dirty worktrees or move their contents while resuming.
Completed current worker slices are integrated into main; no new task should be
inferred from their old branch names. Useful source/evidence worktrees are
`owned_dynamic_sysroot`, `owned_pthread_lifecycle`, `owned_stdio_engine`,
`header_declaration_parity`, `native_resolver_network` and `cond_private_evidence`.

Automatic tool review rejected work in `rust_std_unwinder` and
`allocator_m2_metadata`; these tasks were stopped, not retried through another
agent or route. Preserve the unwinder's initial provider `d3ca0e79` and its
unfinished producer/driver/metadata files, and the allocator's uncommitted
snapshot/arena-destruction ownership files. Neither is qualified or integrated
as completed work. The user approved the unwind configuration and delegated
dependency selection; the design record is
`docs/design/x86-rust-unwinder-proposal.md`. Approval of that design does not
resolve the tool restriction. Dummy unwind symbols, libgcc or reduced Rust-std
fixtures cannot replace the required behavior.

The host had zero configured/free 1-GiB huge pages and one NUMA node at the last
inspection. No host huge-page configuration was changed; native huge success
and multi-node qualification remain distinct from simulation.

## Goal prompt

> Implement `plan.md` to completion: fully complete both `x86-64.md` and the
> native Linux/x86-64 scope of `native-mimalloc.md`, working their independent
> critical paths in parallel and integrating them into one qualified runtime.
> AArch64 implementation and qualification work is paused. Preserve its
> existing contracts, implementation, evidence, and frozen parity baseline;
> do not emulate it or transfer its milestone claims to x86. Continue through
> all runtime product/qualification gates and allocator milestones M0–M11,
> including qualified native Rust allocator promotion, final installed-product
> requalification, and public x86 support. Commit coherent completed slices
> with conventional commit subjects. Do not stop at a plan, selected fixture,
> intermediate milestone, stable checkpoint, or handoff. Completion requires
> both plans' full predicates at the same final committed source revision.

This is an execution goal, not a request for another planning exercise.
The two linked plans remain the detailed acceptance contracts; this file
coordinates their scheduling and joint finish without weakening either one.

## Throughput and process budget

Prefer larger, dependency-ready component or family batches over isolated
leaf tasks. The user authorizes revising task boundaries and planning process
to accelerate delivery; no approval is needed merely to widen a coherent
in-scope batch. This does not authorize new product scope or weaker final gates.

The user delegates workflow decisions to the implementer. Treat these documents
as editable execution guidance, not a fixed sequence of paperwork. Prioritize
ordinary installed applications and complete runtime/allocator behavior; revise
task boundaries, sequencing, duplicated checks, and obsolete intermediate gates
when that shortens the path. Preserve the final behavioral, provenance, purity,
and performance requirements, and correct stale contracts rather than repeatedly
working around them. No approval round trip is needed for these in-scope choices.

Use focused tests during development and run expensive aggregate, model, corpus,
or performance suites at meaningful integration or milestone checkpoints.
Do not rerun unchanged suites for every local edit or documentation commit.
Keep a reproducing regression for bugs and verify changed unsafe/interface
boundaries, but do not manufacture a failing test for prose or a behavior-neutral
mechanical change. Reuse existing harnesses and matrices.

Proactively improve test throughput and isolation as harnesses are touched:
parallelize independent checks with bounded concurrency, reuse development
artifacts where valid, and give each run private scratch, reports, and process
ownership. Preserve cold-build reproducibility and clean-revision qualification
at the final gates; faster iteration must not hide failures or weaken evidence.

Record a result once with its owning contract or report. Update planning/status
only when priorities, prerequisites, or completion state materially change;
do not require a new report, handoff essay, or every-document update per slice.
Commit coherent validated slices promptly. Final qualification still requires
all acceptance predicates against the same final committed source revision.

## Scope and authority

Read `AGENTS.md`, `SCOPE.md`, `COMPATIBILITY-PROFILE.md`, `STATUS.md`, both
execution plans, and their relevant machine-readable contracts before choosing
work. Explicit user direction and the governing scope take precedence. This
combined goal supersedes historical instructions that pause all mimalloc work
or resume AArch64 allocator development; only native x86-64 is active here.

- Target native Linux/x86-64 little-endian, Linux 5.10 or newer, using the
  pinned native environment. Do not introduce new platforms or a portability
  framework.
- Preserve the runtime baseline fixed by `x86-64.md`: source
  `3e100d45c5a0798c2d3862d5e2eef584c610ccf9`, all 223 capabilities, all 26
  required families, and the recorded digests. Never refresh it to absorb
  drift or eliminate required work.
- Port mimalloc v3.5.0 at its immutable upstream revision and hash. Preserve
  algorithms, memory orderings, ownership, lifecycle, and observable behavior;
  do not invent an allocator. Keep the exact C source as a separate test oracle.
- Use pinned musl 1.2.6 for C/POSIX evidence and Rustix only in its permitted
  test role. Glibc and ambient target runtime inputs are never fallbacks.
- No AArch64 implementation/qualification campaign, emulation, CI-workflow
  work, unrelated cleanup, formatting, linting, pre-commit hooks, or remote
  pushes. Shared source changes must preserve the paused target's contract.

## Two parallel workstreams, one integration owner

### Runtime parity

Follow `x86-64.md` and `compat/x86_64/parity.toml`, closing finite capability
families and the owned static and dynamic products in dependency order.
Advance static delivery without waiting for unrelated dynamic work; establish
general loader architecture while independent runtime families progress.
Do not resume a one-symbol/export-count campaign or replace ordinary installed
runtime behavior with private fixtures.

Continue runtime work with the accepted C allocator until the native Rust
backend qualifies. Allocator development must not unnecessarily serialize
independent syscall, ABI, CRT, loader, facade, or sysroot work.

### Native x86-64 mimalloc

Follow the active x86 handoff in §26 of `native-mimalloc.md`, its full milestone
definitions, source map, API/mode inventories, and gate manifests. Preserve the
allocator launcher's checked `.work/` containment, then establish target-qualified
baseline and milestone gates. Imported AArch64 M0/M1 closure and partial M2
records are preserved evidence, not x86 completion.

Milestones are qualification boundaries, not blanket implementation barriers.
Work against stable interfaces and actual dependencies: dependent implementation
and integrated regressions may proceed while prerequisite qualification finishes.
M3 cannot be declared complete until all eight M2 components qualify. Work
independent components in parallel where ownership permits. Never substitute
additional trace counts, documentation, selected leaves, or a partial-gate exit
for component closure.

### Shared runtime/allocator boundary

The root integrator owns shared contracts and final integration. Assign one
writer to each shared file or interface, and land interface changes before
dependent implementations. Coordinate these boundaries explicitly:

- raw memory/entropy/syscall primitives, page and address geometry;
- allocation-free bootstrap, process state, errno, and recursion behavior;
- TCB/TLS ownership, pthread creation, teardown, cancellation, and fork;
- pointer-derived allocation ownership, ABI exports, weak symbols, and
  interposition; and
- CRT startup, loader/DSO lifecycle, installed sysroot, and dependency purity.

Allocator engine/API work may proceed before the general runtime is complete.
M8 integration and M10 promotion must wait for their actual owned-runtime
prerequisites. Neither an oracle-hosted allocator test nor a runtime test with
the C backend proves final native Rust allocator integration.

Use independent agents for bounded parallel work under the current orchestration
skill and explicit user model restrictions; do not duplicate that routing policy
here. Give each worker a concrete deliverable, nonoverlapping ownership, required
evidence, and a repository-local worktree. The root reviews and integrates results.

### Relationship to `sysroot.md`

`sysroot.md` describes the earlier AArch64 owned CRT/sysroot work. Its recorded
CRT/sysroot-purity deliverable is complete; full target-runtime Rust purity
remains blocked by the C allocator. Its literal no-native-dependency hard gate
is therefore not a completed whole-runtime claim. See
`docs/design/crt-and-sysroot.md` and `docs/evidence/crabc-owned-sysroot.md` for
that explicit distinction. These are recorded AArch64 results, not current
x86 qualification.

Do not defer the x86 sysroot until after mimalloc or start another AArch64
campaign from `sysroot.md`. The owned x86 static/dynamic sysroots are required
products inside `x86-64.md`; build them in parallel using the accepted backend,
then requalify their final Rust-allocator integration and purity here. Native
x86 allocator completion does not clear the paused AArch64 full-runtime purity
blocker; that requires separate future AArch64 promotion and evidence.

## Execution and evidence discipline

1. Inspect the current commit, dirty work, worktrees, contracts, and available
   evidence. Preserve accepted work and recover unfinished changes before
   replacing them. Derive the next work from unmet gates, not old narratives.
2. Keep all new mutable development state under checkout-local `.work/`:
   worktrees, scratch, sources, Cargo caches/targets, sysroots, and report
   backing storage. Validate physical paths and reject traversal/symlink
   escapes. Override tool defaults before execution; do not use external
   `/tmp` or named external Docker storage. Keep separate workstream paths.
3. Choose coherent behavior or component slices that shorten a required
   product's critical path. For bugs, observe the smallest isolated failing
   regression before fixing the pinned-source root cause.
4. Run the nearest hard judge first, then relevant boundary, differential,
   aggregate, lifecycle, fault, model, and performance evidence as required.
   Repair demonstrated test-contract defects with oracle evidence; never
   weaken acceptance merely to make a gate green.
5. Commit completed slices promptly using `feat`, `fix`, `test`, `refactor`,
   `perf`, `build`, or `docs` subjects with a meaningful scope. Do not bundle
   unrelated work, invoke hooks, or push. Run required clean-revision gates
   at milestone/integration checkpoints; rerun affected evidence after later
   code changes rather than inheriting an unrelated revision's pass.
   Fold trivial documentation/comment fixes into the related implementation
   or next coherent batch; reserve standalone docs commits for substantial
   planning or contract changes. Do not rewrite settled history just to regroup
   earlier small commits.
6. Update concise architecture-qualified handoffs and machine-readable state
   with exact remaining conditions, commands, revision, report paths, and
   results. Do not inflate status files with per-leaf histories or count stale
   generated reports as current evidence.
7. Continue from the next unmet gate. Expected partial results, preexisting
   failures, or task size are unfinished work, not successful terminal states.
   If genuinely blocked on new authority or unavailable external resources,
   report the exact blocker and required action without claiming completion;
   pursue safe independent in-scope work while available.

## Exact joint completion predicate

The goal is complete only when all of the following hold together:

1. Every item in `x86-64.md`'s exact full-completion definition passes: the
   immutable baseline and complete accounting, all 26 required families,
   reproducible installed static and dynamic products, the ordered consumer
   and qualification chain, native performance, computed promotion readiness,
   validated public support, and the post-promotion aggregate rerun.
2. Every applicable native x86 allocator milestone M0–M11 and every item in
   `native-mimalloc.md`'s final definition of done passes. There are no hidden
   incomplete components, remaining conditions, unclassified applicable
   upstream behavior, waived required tests, or unqualified performance gates.
3. Native Rust mimalloc is the default backend for the qualified x86 product.
   Its final target production graph/artifacts exclude C mimalloc; the pinned
   C oracle remains isolated for tests. Do not remove the paused AArch64
   backend or imply its promotion to satisfy an x86 purity check.
4. Rebuild and requalify both installed x86 static and dynamic products after
   backend promotion, including allocator ABI, TLS/pthread/fork, loader/DSO,
   consumers, reproducibility, dependency purity, and performance. A runtime
   pass earned only with the former C backend is insufficient.
5. Required final reports attest the same committed, clean source revision,
   target, pinned inputs, and applicable test configuration. Documentation and
   machine-readable status agree with those results; no required work remains.

Finish with the final commit, the proving commands and report locations,
upstream/source-map and dependency-purity results, measured performance, and
any explicitly supported limitations already permitted by the contracts.
Do not mark the goal complete if either linked program remains incomplete.
