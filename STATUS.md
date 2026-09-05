# Project status

## Active program

Work has resumed from the committed wind-down handoff in [`plan.md`](plan.md).
The combined goal remains incomplete.

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

## Current integration frontier

1. Runtime: close `libc.posix-runtime` through a complete family aggregate
   using the installed components; the header declaration foundation is now
   `foundation-verified`. The frozen 223-capability/
   26-family baseline validates; current accounting does not imply full parity.
   Wide stdio, scalar math, signal transactions, semaphore cancellation, and
   loader search/direct-interpreter entry compose in installed products.
   Timed/shared conditions and installed/extracted resolver differential
   evidence are integrated. Priority-inheritance mutexes are implemented;
   priority-protect retains musl's unsupported status. Family closure and
   ordered qualification receipts remain open.
   Do not restart an export-by-export queue.
2. Allocator: use the contained `compat/allocator/run-x86_64.sh` launcher,
   then complete native x86 M2 qualification. Imported
   AArch64 milestone passes do not count as x86 passes.
   Native M1 passes all six bounded components and source contracts at clean
   revision `0daef148`; the exact
   report and next M2 work are recorded in `native-mimalloc.md` §26.
   Native M2 qualifies PageMap and scalar bitmaps at `62d6435c`; the other six
   memory-substrate components remain partial.
3. Integration: agree on bootstrap, errno, TLS/TCB, pthread exit, fork, and
   loader ownership. Continue independent runtime work with the accepted C
   backend; requalify installed x86 products after native allocator promotion.
   Installed static/static-PIE consumers cover allocator, TLS, POSIX, wide and
   byte stdio, filesystem traversal, IPC, spawn, selected fork/exit, and normal,
   recursive and error-checking robust mutexes. Earlier extracted-package and
   two-clean-build checks remain recorded measurements. Priority-inheritance
   mutexes add focused installed-product evidence; refreshed aggregate checks,
   runtime composition and allocator lifecycle remain open.
   Installed/extracted dynamic PIE and non-PIE consumers cover runtime-new
   dependency graphs, existing/new-worker DTV growth, retained close, scope,
   rollback, and constructor exit with reproducible builds. Deferred GOT/PLT binding and kernel-main `dladdr` mapping results are
   integrated, as are musl search policy, direct interpreter entry and dynamic
   fork ownership. Campaign-level product publication remains open; see
   [`materialized-dynamic-sysroot.md`](compat/x86_64/materialized-dynamic-sysroot.md).
4. Recovery: inspect existing worktrees before duplicating work. The legacy
   `x86/reboot-feature-20260904` branch still has unfinished uncommitted work
   outside the checkout; preserve and reconcile it. Create no new external
   scratch or worktrees.

## Evidence boundaries

The full campaign is not yet green. Installed-consumer jobs use bounded
parallel workers with private evidence and process cleanup; the Python runner
also shards the large parity-ledger test module with per-case progress and
fail-closed completion accounting. Serial benchmarking is opt-in. Rerun affected
checks against committed source; historical passes are not current qualification.

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
