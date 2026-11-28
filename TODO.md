Prefix: CRAB
Next: 24

### CRAB-6 · P2 · Unreproduced fork-child SIGEV_THREAD timer wait failure

- **Area:** POSIX timers
- **Where:** compat/x86_64/owned_posix_timers_probe.c (`wait_count_at` and the fork child's `kernel_timer(0); thread_timer()`)
- **Problem:** In the fresh `f402e22c6` candidate, `dynamic-products` failed once on `installed/posix-timers`: the dynamic non-PIE consumer's fork child exited 1 at `CHECK(atomic_load(word) >= wanted)` after the ~2 s callback wait, so the parent failed `waitpid ... WEXITSTATUS == 0`. The same retained binary then passed 400 idle reruns and 300 reruns with every CPU saturated in the pinned image, and the identical runtime passed this case six times at `c3fd88bab`. It is either a rare fork-child timer race or a host stall over 2 s; the evidence does not separate them. Evidence is preserved in `.work/tmp/timer-flake-evidence/`. `9965c101d` adds failure-only caller, counter, observed/target values and PID/PPID while preserving the wait bound, atomic observation, errno and failure status. The pinned-image diagnostic regression passes, fails on the old probe, and the ordinary sealed static/static-PIE/dynamic PIE/non-PIE workload passes. The original failure's cause remains unknown.
- **Recommendation:** Use the retained context on recurrence, then stress the fork-child path under `perf sched`/`strace -f` to decide between a lost callback and a scheduling stall. Fix a lost callback in the timer owner; never widen the wait to hide one.
- **Fix with:** root-cause
- **Effort:** M

### CRAB-9 · P2 · Harness tests assert source text instead of behavior

- **Area:** Qualification harness tests
- **Where:** compat/x86_64/tests/test_access_header_abi.py:64-80; compat/x86_64/tests/test_owned_posix_signals.py:164-166; compat/x86_64/tests/ (202 files read source text and assertIn)
- **Problem:** AGENTS.md forbids source-literal and prose-count tests, yet about 1,300 assertions across 202 test modules check that literal phrases, flags, scenario strings or roster counts appear in runner and probe source (e.g. `for phrase in (...): assertIn(phrase, runner)`). Equivalent edits fail them, a matching string proves no behavior ran, and every runner change, including the AArch64 convergence, must hand-edit these mirrors.
- **Recommendation:** Audit by module: delete assertions that only mirror source text where a compiled header-profile or runtime case already exercises the behavior, and replace the rest with a behavioral run; do this per family as each is touched, preserving checks that establish ABI or dispatch behavior.
- **Fix with:** test-audit
- **Effort:** L

### CRAB-10 · P2 · Architecture facts are hard-coded across hundreds of harness files

- **Area:** Qualification harness / AArch64 convergence
- **Where:** compat/x86_64/qualification_candidate.py:48; compat/corpus/run_x86.py:52; compat/lua/run.py:1235; compat/x86_64/ and scripts/ (`.work/x86_64` in ~353 Python/shell files, the musl loader path in ~73)
- **Problem:** Target triple, ELF machine, loader and oracle paths, relocation names and the `.work/x86_64` work root are written independently in producers and readers. The AArch64 convergence has repeatedly failed one step at a time on a missed x86 literal (oracle paths, control loader, COPY relocation, tmp roots), each found only by a multi-hour candidate run, and a reader that keeps an x86 fact can validate the wrong architecture.
- **Recommendation:** Make compat/x86_64/native_arch.py the sole owner of per-architecture facts (arch, triple, machine, loader/oracle paths, work root) and have drivers read them from it; migrate consumers family by family with the CRAB-8 harness work, leaving genuinely x86-only probe data local.
- **Fix with:** single-source-of-truth
- **Effort:** L
- **Design:** docs/rfc/CRAB-8-linux-aarch64-feature-completion.md

### CRAB-11 · P2 · pthread_getspecific takes a process-wide spin lock

- **Area:** Thread-specific data
- **Where:** libc/src/c_abi/x86_64/pthread_tsd.rs:182-195,397-414,431-456,357-384
- **Problem:** The original TSD and worker-registry spins could livelock under SCHED_FIFO; `3b7e26327` and `dc8b2094b` replaced them with futex-backed locks. Signal reentry previously deadlocked in both main and worker handlers (6/6 each on AArch64). Current-thread get/set now use the owned thread's atomic slots without either lock. On native AArch64, six trials each of `signal`, `signal-worker`, `delete`, and `registry` completed, including signal-handler get/set concurrent with key creation/deletion. The dynamic reproducer remains unrun. The separate `getset` setup stall is not specific to crabc: under the same pinned-image watchdog, SCHED_FIFO priorities and CPU affinity, the pinned-musl control also stayed in setup with zero waiter rounds until RLIMIT_RTTIME killed it; its owner had already executed billions of operations. A crabc trial showed the same state. Both implementations can also complete in this environment. The observation does not establish the underlying VM scheduling cause or rule out other crabc defects.
- **Recommendation:** D25 M4 owns the remaining progress question. Investigate the shared native arm64 VM scheduling stall or repeat the test on another native arm64 host; retain the control and limits. Run the dynamic reproducer. Contention cost alone stays deferred.
- **Fix with:** lifecycle-concurrency
- **Effort:** M

### CRAB-23 · P4 · Validators and the parity ledger read plan.md, blocking its move into the roadmap

- **Area:** Qualification harness tests
- **Where:** compat/x86_64/tests/test_owned_posix_runtime_catalog.py:90; compat/x86_64/parity.toml:66,1611,2812; plan.md
- **Problem:** The owned POSIX runtime catalog test reads ../plan.md as a source, and parity.toml lists plan.md as evidence and ownership, so the campaign plan must stay at the repository root beside docs/roadmap.md, the single plan.
- **Recommendation:** Point the catalog test and the parity ledger at docs/roadmap.md (or a dedicated machine-readable record), then fold plan.md into the roadmap and delete it. Acceptance: the catalog test and parity checks pass with plan.md removed.
- **Fix with:** none
- **Effort:** S

