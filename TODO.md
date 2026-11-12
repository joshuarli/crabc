Prefix: CRAB
Next: 4
### CRAB-3 · P2 · Restore compiling crabc-rs integration tests on x86-64

- **Area:** Rust facade
- **Where:** crabc-rs/tests/{accessat,core_os,descriptor,directory,directory_position,event_time,fcntl_getlk,futimesat,pause,ppoll,process_system,pty_session,sleep,statx,terminal_control,termios_exclusive,termios_special_codes,time_realtime_millis,time_timers,time_timespec_get,truncate,ttyname}.rs; crabc-rs/src/lib.rs:136-139
- **Problem:** Priority assumed. At bdbaf8874, 22 of 250 crabc-rs test targets fail to compile in the pinned x86 image, so `cargo test -p crabc-rs --lib --tests` stops before running any of the remaining suite. They are ungated and call the generic module APIs, while x86 selects `fs_x86_64.rs` and the other x86 modules: `process::ForkResult`/`fork_raw` (14 uses), `process::Signal`, `process::setsid`, `pty::ioctl_tiocgptpeer`, fields on `Result<Timespec, Errno>`, `fs::AtFlags` where x86 `unlinkat` takes `UnlinkAtFlags`, and a `PathArg` bound. The behaviors these tests cover are unverified on the active target.
- **Recommendation:** Per target, port the test to the x86 facade API when that API provides the behavior, or gate it with `#![cfg(not(target_arch = "x86_64"))]` and name the x86 test that covers the same contract. Do not add generic-API shims to the x86 facade to satisfy old tests. The paused AArch64 build of these files must keep compiling unchanged. Finish with the whole suite compiling and running in the image.
- **Fix with:** test-audit
- **Effort:** M


### CRAB-2 · P3 · Align child wait options with ownership after nonterminal results

- **Area:** Process ownership
- **Where:** crabc-rs/src/process_x86_64.rs:75-97,460-512; crabc-rs/tests/x86_64_child_ownership.rs:158-177; docs/design/crabc-rs.md:520-535
- **Problem:** Priority assumed; this is an intentional current contract, not a regression. Child is the unique wait owner, but wait(self, options) consumes it for NOHANG/None, stopped or continued reports, and non-EINTR errors even when the process remains unreaped. The synchronized ownership test obtains None for a live child and later uses unsafe wait4_raw to reap it. The design explicitly excludes polling/retry contracts, yet the safe method accepts the corresponding nonterminal options, leaving callers without a safe retained owner for completion.
- **Recommendation:** Decide whether to narrow the consuming wait to terminal blocking waits or return the unique Child on nonterminal results and errors. The draft recommends explicit ownership-returning outcomes for the already accepted options, subject to an owner decision about the current scope limit. Preserve a single owner, EINTR retry, exact Linux status decoding and explicit PID transfer; do not add supervision, a background reaper or blocking Drop behavior.
- **Fix with:** make-invalid-states-unrepresentable
- **Effort:** M
- **Design:** docs/rfc/CRAB-2-child-wait-ownership.md
