Prefix: CRAB
Next: 7

### CRAB-6 · P2 · Unreproduced fork-child SIGEV_THREAD timer wait failure

- **Area:** POSIX timers
- **Where:** compat/x86_64/owned_posix_timers_probe.c:125-130 (`wait_count`), :716-718 (fork child `kernel_timer(0); thread_timer()`)
- **Problem:** In the fresh `f402e22c6` candidate, `dynamic-products` failed once on `installed/posix-timers`: the dynamic non-PIE consumer's fork child exited 1 at `CHECK(atomic_load(word) >= wanted)` after the ~2 s callback wait, so the parent failed `waitpid ... WEXITSTATUS == 0`. The same retained binary then passed 400 idle reruns and 300 reruns with every CPU saturated in the pinned image, and the identical runtime passed this case six times at `c3fd88bab`. It is either a rare fork-child timer race or a host stall over 2 s; the evidence does not separate them. Evidence is preserved in `.work/tmp/timer-flake-evidence/`.
- **Recommendation:** Record which `wait_count` caller and which counter missed (the probe prints only the line), then stress the fork-child path under `perf sched`/`strace -f` to decide between a lost callback and a scheduling stall. Fix a lost callback in the timer owner; never widen the wait to hide one.
- **Fix with:** root-cause
- **Effort:** M

### CRAB-5 · P2 · Stop text-family assembly re-reading product trees

- **Area:** Qualification harness
- **Where:** compat/x86_64/owned_text_math_locale_stdio_family.py:880-915,1008,1038,1093; the per-component `_report_adapter`/`_*_adapter` readers at :560-862
- **Problem:** Priority assumed; D23 waives cost budgets, but this sets qualification wall time. In the `fb4583ae2` candidate, `text-family assemble` ran over 2.5 hours on one core and had read 864 GB (`rchar`, 90 M read syscalls, about 19 MB/s) while the whole candidate output is about 20 GB, including a 14.7 GB dynamic product. Each component adapter revalidates and snapshots the product pairs, and `_require_snapshots_current` repeats the directory snapshots, so the same trees are hashed dozens of times per run. Every fresh correctness candidate repeats this step.
- **Recommendation:** Measure which calls read the product trees, then validate and snapshot each physical product path once per assembler process and reuse that identity across components and pairs, keeping the final changed-during-collection comparison. Do not drop any check or narrow what is hashed. Prove with the existing text-family tests plus an injected product mutation between components that is still rejected.
- **Fix with:** make-it-fast
- **Effort:** M

