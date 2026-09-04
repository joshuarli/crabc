# Project status

## Active program

Implement [`plan.md`](plan.md): native Linux/x86-64 runtime parity and native
x86-64 mimalloc, in parallel where dependencies permit. AArch64 implementation
and qualification are paused. Public support remains Linux/AArch64 until the
x86 runtime's promotion gates pass; C mimalloc remains the selected backend
until qualified target-specific Rust-allocator promotion.

This file is a short orientation and handoff, not an acceptance contract or
per-commit journal. Detailed requirements and current evidence belong to their
owners:

| Question | Authority |
| --- | --- |
| What is in scope? | [`SCOPE.md`](SCOPE.md), [`COMPATIBILITY-PROFILE.md`](COMPATIBILITY-PROFILE.md) |
| What must the combined goal finish? | [`plan.md`](plan.md) |
| What closes x86 runtime parity? | [`x86-64.md`](x86-64.md), [`compat/x86_64/parity.toml`](compat/x86_64/parity.toml) |
| What closes the allocator port? | [`native-mimalloc.md`](native-mimalloc.md), its active x86 handoff, source map, and target-qualified milestone contracts |
| Which commands and reports prove it? | [`compat/x86_64/README.md`](compat/x86_64/README.md), [`compat/allocator/README.md`](compat/allocator/README.md), exact-revision native reports |
| Where are the design and recorded AArch64 results? | [`docs/README.md`](docs/README.md) |

## Starting state and next work

The `main-wip` allocator work is integrated in `be7e74ce`. The native x86 runtime
dispatcher contains build/cache/temp state under `.work/` as of `d2bb49ac`.
`50fcb75d` establishes the combined plan. These commits are integration and
planning checkpoints, not runtime or allocator completion.

1. Runtime: verify the frozen 223-capability/26-family baseline, reconcile
   generated evidence, and choose dependency-ready family/product blockers
   from the campaign contracts. Do not restart the one-export-at-a-time queue.
2. Allocator: use the contained `compat/allocator/run-x86_64.sh` launcher,
   then complete native x86 M2 qualification. Imported
   AArch64 milestone passes do not count as x86 passes.
   Native unit tests pass with target-qualified PageMap address-bit controls.
   The native quick gate passes after correcting legacy fixture allocations
   that crossed allocator ownership. Native M1 passes all six bounded
   components and source contracts at clean revision `0daef148`; the exact
   report and next M2 work are recorded in `native-mimalloc.md` §26.
   Native M2 independently qualifies PageMap at `b32c4183`. Scalar bitmap
   implementation and native differential evidence are committed; aggregate
   bitmap qualification and the remaining memory-substrate components are open.
3. Integration: agree on bootstrap, errno, TLS/TCB, pthread exit, fork, and
   loader ownership. Continue independent runtime work with the accepted C
   backend; requalify installed x86 products after native allocator promotion.
   Installed static/static-PIE allocator, TLS, POSIX, and stdio consumers pass, including
   extracted-package and two-clean-build checks. Complete runtime composition
   and allocator lifecycle remain open; this is not static-product completion.
4. Recovery: inspect existing worktrees before duplicating work. The legacy
   `x86/reboot-feature-20260904` branch still has unfinished uncommitted work
   outside the checkout; preserve and reconcile it. Create no new external
   scratch or worktrees.

## Evidence caveats at settlement

The merge qualification recorded 720 passing allocator Python tests, focused
native x86 header gates, backend-selection compile probes, and a passing
frozen-baseline validator. It did not run AArch64 qualification or establish
full x86 parity.

Runner source-contract repairs and per-validation artifact reuse are committed.
The owned aggregate feature's planned provider accounting is being reconciled;
the full current campaign baseline is not yet green. Installed-consumer jobs
now use bounded parallel workers with private evidence and process cleanup;
serial benchmarking is opt-in. Rerun affected checks against committed source;
historical passes are not current qualification.

The recorded AArch64 owned CRT/sysroot and Lua deliverables are complete at
their documented evidence boundary. Full target-runtime Rust purity remains
blocked by the C allocator. The x86 installed sysroot belongs to the current
runtime goal, not a follow-up after mimalloc. See
[`docs/design/crt-and-sysroot.md`](docs/design/crt-and-sysroot.md).

## Historical detail

The previous 4,952-line status narrative is preserved in the
[dated snapshot](docs/history/project-status-2026-09-04.md). Consult it only
for implementation provenance or an exact historical evidence boundary.
Do not append leaf histories here; update a contract, test, report, or nearest
design explanation, and keep this handoff focused on actual blockers.
