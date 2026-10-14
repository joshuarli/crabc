# Review: crabc

Scope: the campaign changes through `45ff6332c`, excluding unchanged code and the unmerged promotion bridge. Checks run: independent caller and retained-product review; focused cancellation, engine-reader and arena regressions; merged Rust profiles, host tests and native comparisons recorded in `plan.md`. Closing merged-tree checks are in progress. Not covered: a passing qualification cohort, native promotion, qualifying performance, or the paused AArch64 target.

## Summary

The campaign keeps qualification claims separate from selected behavioral evidence. The receipt readers now bind physical products and handle interruption without leaving children running. Cleanup preserves live owner and release custody while compiling isolated models only for their intended evidence configurations. Native promotion still has one open integration finding; its cross-image fix remains outside main until verified.

## Findings

### R1 · P2 · native default cannot pass the promotion closure

- **Area:** allocator promotion
- **Where:** `compat/x86_64/campaign_promotion_closure.py:73`
- **Problem:** the source-default and product ownership checks require accepted C unconditionally. After the planned native switch, the same terminal promotion check rejects the selected backend even when its prerequisites are admitted. The native engine and runtime qualification readers also own different pinned images, so calling both within one image cannot establish the missing proof.
- **Recommendation:** keep the accepted-C route strict and compose the existing allocator and runtime owning readers in their correct images, with synchronous source and input custody. Recompute current native promotion evidence and inspect published products before reporting complete readiness. Finish and verify the existing draft rather than selecting a new implementation.
- **Fix with:** durable-state, lifecycle-concurrency, os-boundaries
- **Effort:** M (days)

## Strengths to keep

- Qualification requires current physical evidence; a passing status field alone cannot supply an executed producer.
- Default-client failures and admitted source corrections retain their distinct raw controls.
- Cancellation tests use real child processes and prove termination and reaping.
- Source accounting distinguishes shipping implementation from test and audit models.
