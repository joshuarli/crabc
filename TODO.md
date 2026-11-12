Prefix: CRAB
Next: 3
### CRAB-1 · P2 · Resolve timezone transitions across adjacent rule years

- **Area:** Time and calendar
- **Where:** crabc-rs/src/timezone.rs:189-203,264-272,379-391,504-506; crabc-rs/tests/timezone_rules.rs:65-108
- **Problem:** Priority assumed. PosixZone::offset_at considers only the query's UTC year even though accepted signed transition times and offset conversion can move a rule into an adjacent year. For STD0DST,M1.1.0/-167,M6.1.0/0 at Unix second 1672444800 (2022-12-31 00:00 UTC), the 2023 start occurred on 2022-12-25 01:00 UTC, so DST/+3600 is in force. The code instead compares the 2022 start (2021-12-26 01:00 UTC) and end (2022-06-04 23:00 UTC), selecting standard/+0. TZif continuations use the same lookup. This is source-proven with independent Gregorian date arithmetic; native reproduction is unproven because the required pinned Docker runtime was unavailable. Existing timezone tests cover ordinary in-year and leap-day boundaries, not this spillover.
- **Recommendation:** Evaluate candidate transitions from adjacent rule years in UTC order and select the latest applicable transition, retaining exact-boundary behavior and checked wide arithmetic. First reproduce the stated case in the pinned native x86 environment, then cover transitions spilling both ways, wall/standard/UTC bases, southern-hemisphere rules, leap years and TZif continuation reuse. Keep lookup pure and caller-owned; no global TZ state or bundled database is needed.
- **Fix with:** root-cause
- **Effort:** M


### CRAB-2 · P3 · Align child wait options with ownership after nonterminal results

- **Area:** Process ownership
- **Where:** crabc-rs/src/process_x86_64.rs:75-97,460-512; crabc-rs/tests/x86_64_child_ownership.rs:158-177; docs/design/crabc-rs.md:520-535
- **Problem:** Priority assumed; this is an intentional current contract, not a regression. Child is the unique wait owner, but wait(self, options) consumes it for NOHANG/None, stopped or continued reports, and non-EINTR errors even when the process remains unreaped. The synchronized ownership test obtains None for a live child and later uses unsafe wait4_raw to reap it. The design explicitly excludes polling/retry contracts, yet the safe method accepts the corresponding nonterminal options, leaving callers without a safe retained owner for completion.
- **Recommendation:** Decide whether to narrow the consuming wait to terminal blocking waits or return the unique Child on nonterminal results and errors. The draft recommends explicit ownership-returning outcomes for the already accepted options, subject to an owner decision about the current scope limit. Preserve a single owner, EINTR retry, exact Linux status decoding and explicit PID transfer; do not add supervision, a background reaper or blocking Drop behavior.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** M
- **Design:** docs/rfc/CRAB-2-child-wait-ownership.md
