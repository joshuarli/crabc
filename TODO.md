Prefix: CRAB
Next: 7

### CRAB-6 · P2 · Unreproduced fork-child SIGEV_THREAD timer wait failure

- **Area:** POSIX timers
- **Where:** compat/x86_64/owned_posix_timers_probe.c (`wait_count_at` and the fork child's `kernel_timer(0); thread_timer()`)
- **Problem:** In the fresh `f402e22c6` candidate, `dynamic-products` failed once on `installed/posix-timers`: the dynamic non-PIE consumer's fork child exited 1 at `CHECK(atomic_load(word) >= wanted)` after the ~2 s callback wait, so the parent failed `waitpid ... WEXITSTATUS == 0`. The same retained binary then passed 400 idle reruns and 300 reruns with every CPU saturated in the pinned image, and the identical runtime passed this case six times at `c3fd88bab`. It is either a rare fork-child timer race or a host stall over 2 s; the evidence does not separate them. Evidence is preserved in `.work/tmp/timer-flake-evidence/`.
- **Evidence:** `9965c101d` adds failure-only caller, counter, observed/target values and PID/PPID while preserving the wait bound, atomic observation, errno and failure status. The pinned-image diagnostic regression passes, fails on the old probe, and the ordinary sealed static/static-PIE/dynamic PIE/non-PIE workload passes. The original failure's cause remains unknown.
- **Recommendation:** Use the retained context on recurrence, then stress the fork-child path under `perf sched`/`strace -f` to decide between a lost callback and a scheduling stall. Fix a lost callback in the timer owner; never widen the wait to hide one.
- **Fix with:** root-cause
- **Effort:** M

### CRAB-5 · P2 · Bounded text-family validation reuse landed

- **Area:** Qualification harness
- **Where:** compat/x86_64/owned_text_math_locale_stdio_family.py:880-915,1008,1038,1093; the per-component `_report_adapter`/`_*_adapter` readers at :560-862
- **Status:** Landed at `2adf13539`. The bounded reader-pass cache retains full snapshots and changed-during-collection rejection. All 120 focused tests passed, including mutation rejection. Full-run speedup remains unmeasured.
- **Follow-up:** No implementation or new measurement requirement is open. Revisit only if current evidence shows verification overhead obstructing F2 completion. Preserve every correctness check.
- **Fix with:** make-it-fast
- **Effort:** M

