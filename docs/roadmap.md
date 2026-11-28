# Roadmap

This is the single plan for this repository: all current and future work, and the handoff for resuming it. Campaigns are sections below, and their items interleave in **Sequence**. "Resume the roadmap" means continue from **Status**.

## Status

**Active (owner direction 2026-11-27):** all work that runs on the Apple Silicon Mac, in parallel: the Rust allocator port, Linux/AArch64 feature completion in the arm64 VM, and the CRAB-7 macOS `crabc-rs` backend. The owner then finishes the rest of the roadmap on a native x86-64 host. See [owner direction](../plan.md#owner-direction-2026-11-27).
**D25:** M6 candidate `84a8b07b3` was started on both native hosts; its x86 side and the dual-native acceptance belong to the x86 phase.
No F2 revision is accepted and no full candidate has completed. The last integrated checkpoint is `5add38189`.
The active campaign plan remains in [plan.md](../plan.md) because the allocator source-map validator requires that file as evidence and the parity ledger asserts its ownership. Migrate it here after those dependencies are removed.
Follow the [current status and first action](../plan.md#status-and-first-action), including the parked branches and their conditions, until the migration is complete.
