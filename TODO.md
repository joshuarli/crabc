Prefix: CRAB
Next: 21

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

### CRAB-17 · P2 · Concurrent or recursive exit runs handlers and finalizers twice or truncates output

- **Area:** Process exit lifecycle
- **Where:** libc/src/c_abi/x86_64/static_startup.rs:124-134; libc/src/c_abi/x86_64/dynamic_main_thread_runtime_v1_lifecycle.rs:209-228; libc/src/c_abi/x86_64/process_exit.rs:215-243
- **Problem:** musl 1.2.6 exit (oracle src/exit/exit.c) takes a static exit_lock CAS on the caller's tid: a recursive exit crashes and a second thread pauses forever. crabc's static exit has no gate, so two threads both drain __funcs_on_exit (which drops its lock around callbacks), both take EXECUTABLE_FINI through a non-atomic ptr::replace on a static mut (a Rust data race; C++ destructors can run twice), and either can _exit while the other is mid-handler. The dynamic exit's failed READY->EXITING CAS calls _Exit(status) immediately, killing the first exiting thread mid-flush and losing buffered stdout with the second caller's status. Reachable whenever a worker thread calls exit while main returns, or an atexit handler calls exit.
- **Recommendation:** Add one exit gate shared by both compositions, matching musl: CAS a static owner tid before __funcs_on_exit, crash on recursion, pause forever on contention; remove the dynamic _Exit fallback. Add a native differential case with two threads exiting while stdout is buffered.
- **Fix with:** lifecycle-concurrency
- **Effort:** S

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

### CRAB-13 · P3 · Stopping a candidate leaves its dispatcher and containers running

- **Area:** Qualification candidate lifecycle
- **Where:** compat/x86_64/qualification_candidate.py:763-765; scripts/dev-x86_64.sh:3295
- **Problem:** _run waits on the dispatcher with subprocess.run and installs no signal handling or process-group ownership; the dispatcher runs `docker run --rm` against writable checkout mounts. Killing only the candidate process (as nohup-launched runs are stopped) leaves the container writing into the work tree while a resume renames and reuses those output paths, so a resumed run can mix outputs. Not reproduced.
- **Recommendation:** Run the dispatcher in its own process group, forward SIGTERM/SIGINT to it and to named containers, and verify termination before a resume may reuse a step's outputs.
- **Fix with:** lifecycle-concurrency
- **Effort:** M

### CRAB-14 · P3 · Rust consumer timeout can hang on a surviving child

- **Area:** Rust std consumer qualification
- **Where:** compat/rust-std/run.py:236-240; compat/rust-std/fixtures/src/main.rs:133; compat/rust-std/dependent-fixture/src/main.rs:136
- **Problem:** On timeout run_binary kills only the immediate binary and then calls process.communicate() with no timeout. Both fixtures spawn children that inherit the pipes, so a stuck descendant keeps the pipes open and the timeout handler never returns, turning one timed-out case into a hung consumer gate. Not reproduced.
- **Recommendation:** Start each case in its own process group, kill the group on timeout, and bound the post-kill communicate.
- **Fix with:** lifecycle-concurrency
- **Effort:** S

### CRAB-15 · P3 · Rebuilding the pinned images is not reproducible

- **Area:** Build environment
- **Where:** docker/Dockerfile.x86_64:34-51; docker/Dockerfile:26-42; compat/x86_64/core_image.py
- **Problem:** Base images are digest-pinned but `apk add` installs gcc, binutils and other tools by unversioned name, so recovering a lost image (as happened when the x86 host changed and the image was rebuilt and re-pinned) yields whatever the Alpine mirror serves that day. The re-pinned image ID then differs, and toolchain drift can change native results with no record of the resolved versions.
- **Recommendation:** Record resolved package versions in the image build and pin them (or the repository snapshot), and keep an exported copy of each pinned image so recovery does not depend on a rebuild.
- **Fix with:** none
- **Effort:** M

### CRAB-19 · P3 · Cross-revision candidate resume cannot pass the qualification chain

- **Area:** Qualification harness
- **Where:** compat/x86_64/owned_posix_family_execution.py `revalidate_receipt` (whole-receipt `same_json` against a recollection whose `inputs.source` is `source_seal.seal(root)`); same full-equality pattern in `owned_pthread_family.validate_receipt` and other family readers; contract in compat/x86_64/source_seal.py `seal` docstring and compat/x86_64/qualification_candidate.py module docstring
- **Problem:** `qualification_candidate.py` resumes steps across revisions with the same product source, and `source_seal.seal` says seals compare with `same_product`, never by revision. But family readers recollect a receipt and compare it with the retained one by full JSON equality, and the recollection embeds the current revision. A resumed run therefore fails at the gate readers: the 2026-11-20 x86 trial (steps 00-56 at 30db5b770, the rest at aae1b553a) stopped at step 84 `qualification-chain` with `compat.posix-process` evidence[0] `ExecutionError: family execution receipt changed`, and the only differing field was `inputs/source/revision`. Fresh single-revision runs are unaffected, so acceptance still works, but the plan relies on same-source resume for development completion.
- **Recommendation:** In each revalidating reader, require `source_seal.same_product` for embedded seals and compare the rest of the receipt with the retained revision substituted; add a regression that revalidates a receipt after moving HEAD to a different commit with identical product source.
- **Fix with:** none
- **Effort:** M

### CRAB-16 · P4 · Public unsafe functions lack a Safety section

- **Area:** Rust facade API documentation
- **Where:** crabc-rs/src/event.rs:496; crabc-rs/src/stdio.rs:131,148,165; crabc-core/src/pipe.rs:90
- **Problem:** AGENTS.md requires documented caller obligations for every public unsafe API; these functions state them only in prose or not at all, so rustdoc and clippy::missing_safety_doc do not surface them. (posix_madvise is already fixed on the CRAB-8 branch.)
- **Recommendation:** Move the obligations under `# Safety` headings and enable clippy::missing_safety_doc for crabc-rs and crabc-core.
- **Fix with:** none
- **Effort:** S
