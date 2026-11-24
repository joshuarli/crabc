Prefix: CRAB
Next: 23

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
- **Problem:** Every pthread_getspecific/setspecific on every thread takes SELECTED_TSD_LOCK, a pure spin CAS with no futex fallback, and pthread_key_delete holds it while scanning the worker registry. musl reads the caller's own slot lock-free. Under SCHED_FIFO a spinner can livelock against a preempted holder on the same CPU, and all TSD access serializes process-wide.
- **Recommendation:** D25 M4 owns the progress question. It is correctness, not waived cost. Reproduce natively with pinned affinity, SCHED_FIFO priorities and an external watchdog. If it reproduces, fix progress with the smallest correct design (e.g. lock-free current-thread get/set over per-thread atomics with per-key generations as musl does, futex only for create/delete), preserving key deletion, destructors, fork and worker-mapping lifetime. If the environment cannot run it, record the missing proof and keep this open. Contention cost alone stays deferred.
- **Status:** `3b7e26327` and `dc8b2094b` replace the TSD and worker-registry spins with futex-backed locks. The static x86 SCHED_FIFO reproducer fails before and passes after. The reproducer now runs natively on AArch64: `getset`, `delete` and `registry` make progress under the watchdog. Still open: a signal handler calling `pthread_getspecific` deadlocks when it interrupts a same-thread lock holder (6/6 with `--include-signal` on x86 and on AArch64, while the musl control completes), and the dynamic reproducer has not run. The AArch64 run is not yet a valid proof: in the OrbStack VM some `getset` trials of both crabc and the musl control never leave setup, because the priority-20 waiter is not woken from its 100 µs sleep while the priority-10 owner spins on the same CPU, and `RLIMIT_RTTIME` kills the trial at about 4 s. That VM timer/wakeup behavior must be explained, or the reproducer run on another native arm64 host, before arm64 progress is proven.
- **Fix with:** lifecycle-concurrency
- **Effort:** M
