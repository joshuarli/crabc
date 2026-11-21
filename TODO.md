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

### CRAB-11 · P3 · pthread_getspecific takes a process-wide spin lock

- **Area:** Thread-specific data
- **Where:** libc/src/c_abi/x86_64/pthread_tsd.rs:182-195,397-414,431-456,357-384
- **Problem:** Every pthread_getspecific/setspecific on every thread takes SELECTED_TSD_LOCK, a pure spin CAS with no futex fallback, and pthread_key_delete holds it while scanning the worker registry. musl reads the caller's own slot lock-free. Under SCHED_FIFO a spinner can livelock against a preempted holder on the same CPU, and all TSD access serializes process-wide.
- **Recommendation:** Make current-thread get/set lock-free over the existing per-thread atomics, rejecting deleted keys with a per-key generation as musl does; keep a futex lock only for key create/delete.
- **Fix with:** lifecycle-concurrency
- **Effort:** M

### CRAB-12 · P3 · crabc-rs owns a second process-global atfork registry

- **Area:** Process-global state ownership
- **Where:** crabc-rs/src/process.rs:1890-1924,1941-1965,1985-2069; docs/design/architecture.md:36
- **Problem:** architecture.md says neither crabc-core nor crabc-rs may own libc or loader singleton state, but crabc-rs keeps its own static-mut atfork table and spin lock. C pthread_atfork handlers do not run on crabc_rs::process::fork and facade handlers do not run on C fork, each linked copy of crabc-rs has its own table, and a prepare callback that registers another handler spins forever on the non-reentrant lock.
- **Recommendation:** Route facade atfork registration to libc's single registry through the existing RuntimeV1 bridge; otherwise document the split semantics and single-copy requirement in the public API and architecture.md.
- **Fix with:** api-surface-and-module-boundaries
- **Effort:** M

### CRAB-22 · P3 · Evidence readers still take x86 image pins from the retired Dockerfile

- **Area:** Core image / qualification inputs
- **Where:** docker/Dockerfile.x86_64; compat/x86_64/validate_parity_ledger.py:181,4321; compat/x86_64/header_callable_inventory.py:71; compat/x86_64/native_abi_inventory.py:95; compat/x86_64/owned_posix_native_execution.py:84; compat/x86_64/parity.toml (`source_owners`)
- **Problem:** `docker/image/build.py` now builds the x86 image from `docker/image/sources.lock.json`, but the parity ledger, header inventories and evidence-input digests still read UAPI and Alpine pins from `Dockerfile.x86_64`, which no build consumes. The two records can drift without any check failing.
- **Recommendation:** Move each reader to the lock (or to `build.py`'s constants), then delete `Dockerfile.x86_64` and its `source_owners` entries in one change, refreshing the affected evidence inputs.
- **Fix with:** single-source-of-truth
- **Effort:** M

### CRAB-21 · P3 · Two readers still reject a same-source cross-revision resume

- **Area:** Qualification harness
- **Where:** compat/x86_64/owned_resolver_alias_contract_reader.py `_source_identity`; compat/x86_64/owned_resolver_family.py `_validate_admission_sources`; compat/x86_64/compiler_helper_evidence.py `_source_seal`, `_aggregate_record`
- **Problem:** The CRAB-19 fix (`source_seal.same_evidence`) lets readers accept a recollected seal that differs only in revision, but these readers bind a retained git revision outside the seal pattern (`selected_source {revision, tree, source_sha256}` and `checkout {revision, clean}`) and compare it with the current HEAD. A resumed candidate whose later steps run at a different revision with the same product source therefore still fails at the resolver alias and compiler-helper readers. Not reproduced in a full run.
- **Recommendation:** Record a product-source seal in these receipts and compare it with `same_product`, keeping the tree/clean checks, then add the same move-HEAD regression the CRAB-19 tests use.
- **Fix with:** none
- **Effort:** S
