Prefix: CRAB
Next: 5
### CRAB-4 · P3 · Decide whether the x86 facade selects process-directed signals

- **Area:** Rust facade
- **Where:** crabc-rs/src/process.rs:1547-1580; crabc-rs/src/process_x86_64.rs; crabc-rs/tests/process_system.rs:8-10; docs/design/crabc-rs.md:162-175
- **Problem:** Priority assumed; this is a scope question, not a regression. The generic facade offers `kill_process`, `test_kill_process`, the process-group variants and `kill_current_process_group`; the x86 facade selects only thread-directed `signal::kill_thread` (`tgkill`). No x86_64_* test covers delivering or probing a signal to a process or process group, so process_system's signal-zero probe is gated off x86.
- **Recommendation:** Decide whether process and process-group `kill` belong to the selected x86 facade. If they do, add typed `kill`/signal-zero entries with exact errno mapping and an x86 test (self probe, ESRCH for an exited child, EPERM where observable) and remove the process_system gate. If not, record the exclusion in docs/design/crabc-rs.md.
- **Fix with:** api-surface-and-module-boundaries
- **Effort:** S


### CRAB-2 · P3 · Align child wait options with ownership after nonterminal results

- **Area:** Process ownership
- **Where:** crabc-rs/src/process_x86_64.rs:75-97,460-512; crabc-rs/tests/x86_64_child_ownership.rs:158-177; docs/design/crabc-rs.md:520-535
- **Problem:** Priority assumed; this is an intentional current contract, not a regression. Child is the unique wait owner, but wait(self, options) consumes it for NOHANG/None, stopped or continued reports, and non-EINTR errors even when the process remains unreaped. The synchronized ownership test obtains None for a live child and later uses unsafe wait4_raw to reap it. The design explicitly excludes polling/retry contracts, yet the safe method accepts the corresponding nonterminal options, leaving callers without a safe retained owner for completion.
- **Recommendation:** Decide whether to narrow the consuming wait to terminal blocking waits or return the unique Child on nonterminal results and errors. The draft recommends explicit ownership-returning outcomes for the already accepted options, subject to an owner decision about the current scope limit. Preserve a single owner, EINTR retry, exact Linux status decoding and explicit PID transfer; do not add supervision, a background reaper or blocking Drop behavior.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** M
- **Design:** docs/rfc/CRAB-2-child-wait-ownership.md
