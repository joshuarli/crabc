# Radically simplify crabc before resuming qualification

**Owner direction, 2026-10-30: simplification first; all allocator work frozen.**
This file is the only active plan. It is written as a runbook: every step names
its inputs, allowed files, exact commands, outputs, done checks and stop
conditions. If a step does not say you may do something, you may not. If a
command in this plan fails for a reason the step does not cover, stop and
report (see [P5](#p5--stop-and-escalate)); do not improvise a replacement.

The old plan, decisions and campaign log are in
[Git at the reset baseline](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md).
They are history, not a second plan.

## How to use this plan

1. Read, in order: [AGENTS.md](AGENTS.md), this file to the end,
   [docs/lanes.md](docs/lanes.md), then only the design document your step names.
2. Find the first step in [Sequence](#sequence) whose **Done** checks are not all
   met and whose **Requires** are met. That is the only step you may work on,
   unless the coordinator assigned you a different one in writing.
3. Follow the step's numbered actions in order. Use the standard procedures
   (P1–P6) exactly where a step refers to them.
4. Finish by filling the [report template](#p6--report-template) and handing it
   to the coordinator. Only the coordinator edits this file and `AGENTS.md`.

Words used with one meaning throughout:

| Term | Meaning |
| --- | --- |
| **reference** | musl from the exact `[musl_native]` snapshot in `compat/upstreams.toml`, built as S1.2 specifies. |
| **candidate** | the crabc product built from the commit under test with the accepted C allocator backend. |
| **row** | one workload mode, at fixed arguments, linked from one compiled object against both runtimes. |
| **R** | the reference's value for a row (syscalls or instructions). |
| **mechanism** | a unit of code or tooling a reader must understand: a Cargo feature, a product root, a dispatcher subcommand, a runner, a reader/validator, a generator, a runtime bridge, a duplicated implementation. |
| **frozen** | may be read and built as an unchanged dependency, never edited, tuned, benchmarked or investigated. |

## Goal

A small, auditable Linux runtime implementing the required semantics with
musl-like economy: few mechanisms, one owner per piece of mutable process state,
thin C ABI adapters, direct syscall/vDSO paths. Acceptance is measured in four
separate dimensions; none substitutes for another:

1. **Syscalls:** candidate <= R per row. Reference zero requires candidate zero.
2. **Retired user instructions:** candidate <= 1.10 × R per operation and,
   separately, for startup.
3. **CPU and memory:** the existing per-row no-regression bounds stay.
4. **Structure and footprint:** the S0 budgets for mechanisms, handwritten
   source and linked sections are met.

Semantics, C ABI/interposition, cancellation, TLS, errno, hardening and safety
are preserved. Fewer calls or instructions than musl are always acceptable;
never add work to reach equality.

## Baseline reconnaissance (2026-10-30)

Measured by the coordinator before writing this plan. They are leads for S0
to confirm on a fresh HEAD build, not the baseline itself.

**Startup cost is far from the target.** One `hello.o` (clang 23.1.3, `-O2`,
calls only `write`) was linked against host musl 1.2.x and against the retained
installed dynamic-PIE product of cohort `4d3`, and run under the same
`unshare -r chroot` wrapper. The wrapper's own cost was measured with a static
exit-only binary and subtracted.

| Dynamic hello | Syscalls after `execve` | User instructions |
| --- | --- | --- |
| musl | 9 | ≈36,170 |
| crabc | 25 | ≈274,800 (≈7.6×) |

Repeated `instructions:u` counts were identical to the instruction, and the
subtraction method agreed with a direct, wrapper-free musl count (36,167) to
within 2 instructions. Of crabc's 16 extra syscalls:

- **12 come from the split loader/libc images**: 4 `openat` (the
  `/etc/ld-musl-x86_64.path` file, then three search directories for
  `libc.so`), `fstat`, `pread64`, 5 `mmap` and `close`. musl has no second
  image to find or map. A split design can reduce this but never remove it.
  (This chroot layout made two search probes fail; a better layout saves 2.)
- **≈5 come from the accepted C allocator's eager start-up** (`sysinfo`,
  `open` of the overcommit and THP files, a 2 MiB `mmap`, `getrandom`) in a
  program that never calls `malloc`. The allocator is frozen; see
  [D1](#owner-decisions).
- The remainder: `arch_prctl(ARCH_GET_FS)` right after `ARCH_SET_FS`, `gettid`
  where musl uses `set_tid_address`, and one more `mprotect`; musl's own `brk`
  ×2, `mmap` and `set_tid_address` offset part of the difference.

**Mechanism counts at HEAD `c0bb51603`:**

| Area | Count |
| --- | --- |
| `scripts/dev-x86_64.sh` | 12,803 lines; `--help` lists 942 subcommands |
| `compat/x86_64` | 3,572 tracked files; 571 Python files, ≈300k lines; 35 `generate_*.py` |
| `ldso` | 32 files, ≈26k lines (musl's `ldso/` ≈2.6k); 7 Cargo features, 6 of them private milestone roots (`x86_64-initial-interpreter`, `x86_64-general-initial-{interpreter,lifecycle,tls-interpreter,tls-runtime-v1-interpreter,tls-runtime-v1-dynamic-main-thread-interpreter}`) beside the one installed product `x86_64-owned-dynamic-runtime`; parallel `initial_graph`/`general_initial_graph` and `relocation`/`general_relocation` modules |
| `libc/src` | ≈177k lines of Rust plus ≈81k lines of checked-in `.S` compiled from musl C by generator scripts; 37 Cargo features, most of them per-family leaves (`x86-ualarm`, `x86-a64l`, …) that every shipped product enables |
| Linked images | crabc `libc.so` text ≈1.26 MB + `ld-crabc` ≈95 KB vs Alpine musl `ld-musl` (loader + libc) ≈660 KB text. Different compilers, so this is a lead only |
| Installed C driver | `bin/crabc-cc-dynamic` is a Python program that validates receipts before linking |
| Release gate | `compat/x86_64/performance_release_gate.py:54` still has `RUNTIME_SYSCALL_FACTOR = 2`; there is no instruction gate |

**Tooling facts that S1 depends on:**

- Host: `perf_event_paranoid = 2`; `perf stat -e instructions:u` works without
  privileges. Do not change any sysctl.
- `rustc -vV` reports LLVM 23.1.1. The current `crabc-core-evidence:x86_64`
  image has clang 22.1.3 and no `perf`. The existing perf harness's reference
  is GCC-built musl (`crabc-x86_64-musl-gcc`), so no matched-LLVM comparison
  exists yet.

### Reproducing the startup measurement by hand

Use this recipe only for exploratory checks. S1 makes the harness produce the
same numbers. Run from the repository root; the root copy lives in
`.work/tmp` and never touches retained evidence.

```sh
R=<an installed dynamic product root containing lib/ld-crabc-x86_64.so.1 and usr/lib/libc.so>
W=.work/tmp/startup && mkdir -p $W/root $W/rootm/lib
cp -r $R/lib $R/usr $W/root/
cp -L /lib/ld-musl-x86_64.so.1 $W/rootm/lib/
printf '#include <unistd.h>\nint main(void){write(1,"hi\\n",3);return 0;}\n' > $W/hello.c
cat > $W/nop.c <<'EOF'
void _start(void){__asm__ volatile("mov $60,%%eax; xor %%edi,%%edi; syscall":::"memory");}
EOF
clang -O2 -fPIC -c $W/hello.c -o $W/hello.o
clang -O2 $W/hello.o -o $W/rootm/hello
clang -O2 -static -nostdlib -fno-pic $W/nop.c -o $W/rootm/nop
L=$W/root/usr/lib
ld.lld -pie --allow-shlib-undefined --dynamic-linker=/lib/ld-crabc-x86_64.so.1 \
  -o $W/root/hello $L/Scrt1.o $L/crti.o $W/hello.o $L/crabc-dynamic-attach.o \
  -L$L -lc $L/libcrabc-builtins.a $L/crtn.o
for r in rootm/nop rootm/hello root/hello; do
  perf stat -x, -r 5 -e instructions:u unshare -r /usr/sbin/chroot $W/${r%%/*} /${r#*/} 2>&1 >/dev/null | tail -1
done
unshare -r strace -f -qq -o $W/trace.txt /usr/sbin/chroot $W/root /hello
```

Startup instructions = `hello` count − `nop` count. Syscalls are the lines in
`trace.txt` from the `execve("/hello"` line onward, excluding that `execve`.

## Allocator freeze

Until S5 has passed **and** the owner has recorded a separate restart decision,
all malloc/allocator development is stopped.

| Allowed | Forbidden |
| --- | --- |
| Building and linking the accepted C backend (`libmimalloc-sys` 0.1.49, mimalloc v3.3.2) unchanged as part of an ordinary product | Any edit under `crabc-mimalloc/`, `compat/allocator/`, allocator-only tests or integration modules |
| Running existing non-allocator regression suites that happen to call `malloc` | Allocator benchmarks, including the `allocator_live` and `allocator_after_ready` perf modes |
| Writing down an allocator failure or allocator-attributed cost in a report, in one line | Investigating, profiling, bisecting or reproducing an allocator failure |
| `cargo check` of a feature set that includes the shadow/native backend, to prove a shared edit still compiles | Building or running native-shadow products; changing the native/default backend selection |
| Reading allocator code only to attribute a measured cost to it (S0.6) | Merging parked allocator branches; dead-code cleanup, receipts or milestone tooling for the allocator |

Rules:

- A non-allocator change that would need an allocator or allocator-lifecycle
  change is **parked**: report it and stop that change.
- Allocator-attributed rows and syscalls stay visible in every report, labeled
  `allocator-attributed`. They never count as a pass and never block a
  non-allocator step's **Done**.
- The old G2, A0–A5, M1–M10, T4, allocator P0, O3/O4, D5 and allocator part of
  C0/C1 are parked. Passing S5 does not reactivate them.

## Hard rules for every agent

1. **Delete mechanisms, keep semantics.** A win removes a mechanism listed in the
   S0 table, or removes executed work. Moving code, renaming, splitting files,
   deleting comments or deleting tests is not a win and is never counted.
2. **Never weaken a check to pass.** Do not edit thresholds, expected outputs,
   oracle inputs, receipts or tests to make a failure disappear. If a test is
   wrong, say so in the report with evidence; the coordinator decides.
3. **No new frameworks.** No new runner, validator, receipt format, schema,
   plugin system, config knob, feature flag, or per-symbol/per-artifact proof.
   A consolidation must be smaller than what it replaces (P3 step 6).
4. **One writer per file set.** Edit only the files your step allows. If you need
   another file, stop and ask the coordinator.
5. **Native x86-64 only.** Never run, emulate or modify AArch64 paths, and never
   refresh `compat/x86_64/aarch64_frozen_baseline.json` or the three inputs it
   digests. Never run `scripts/dev.sh`.
6. **Pins stay.** Do not change `rust-toolchain.toml`, `compat/upstreams.toml`
   pins or the Alpine base digest. S1.1 may add packages to the image.
7. **Nothing outside the repository.** No sysctl, host package, reboot, push,
   release or publication. Container flags on a single `docker run` invocation,
   such as `--cap-add=PERFMON`, are allowed where a step says so.
8. **No removal under `.work/`** of anything you did not create in this step.
   See [Holds](#preserved-checkpoint-and-holds).
9. **Commit as you go** on your lane branch (P1). Never `git stash`. Never push.
10. **Honest status.** Missing counters, failing tests, stale receipts and
    unbuilt products are `blocked` or `unavailable`, never `pass`.

## Standard procedures

### P1 — Branch, commit, integrate

1. Create the lane: `git worktree add -b lane/<step>-<slug> .work/wt/<step>-<slug> main`
   then `(cd .work/wt/<step>-<slug> && scripts/lanes/prepare-worktree.sh)`.
2. Make one coherent change per commit. Message: Conventional Commit,
   `type(scope): subject`, lowercase imperative, ≤72 characters; the body says
   why and quotes the before/after numbers. Add `!` for a contract change.
3. Before handing off: `git -C .work/wt/<lane> log --oneline main..HEAD` shows
   only your commits; `git status` is clean.
4. The coordinator rebases or merges onto `main`, reruns the step's **Done**
   checks on the merged tip, and only then fills the result table.

### P2 — Measure a row

Use the S1 counts route once S1.3 is done. Before that, use the hand recipe
above. For every row:

1. Compile the workload object **once** (`compat/perf/fixtures/workload.c`
   with `-O2 -fno-builtin`), then link it against reference and candidate with
   the same link mode (both dynamic PIE, or both static PIE).
2. Pick `N1` so the reference loop runs for at least 10⁶ instructions, and set
   `N2 = 2 × N1`. Run `workload MODE N1` and `workload MODE N2` for each
   runtime.
3. Instructions: `perf stat -x, -r 3 -e instructions:u`. The three counts for
   each (runtime, N) must agree within 0.01 % for single-threaded rows. If they
   do not, record `nondeterministic` with all values and do not compute a
   ratio.
4. Per-operation instructions = `(I(N2) − I(N1)) / (N2 − N1)`. Startup
   instructions = startup-mode count − wrapper (`nop`) count.
5. Syscalls: `strace -f -qq -o FILE` in a **separate** run. Per-operation
   syscalls = `(S(N2) − S(N1)) / (N2 − N1)`; whole-process syscalls = total
   lines after the target `execve`. Keep the per-syscall-name breakdown.
6. Check the linear fit: also run `N3 = 3 × N1`; `I(N3) − I(N2)` must equal
   `I(N2) − I(N1)` within 0.5 %. If not, the row is `nonlinear`; report it
   without a ratio.
7. Record per row: `ratio_insn = cand/ref`, `delta_insn = cand − ref`,
   syscall counts for both runtimes, and attribution (`runtime`,
   `allocator-attributed`, or `harness`).
8. Tiny rows (reference ≤ 20 instructions/op): also attach the candidate's and
   reference's disassembly of the hot function (`llvm-objdump -d --no-show-raw-insn`).

Never take a best-of-N sample. Never run counters, `strace` and timing in the
same process.

### P3 — Delete or consolidate a mechanism safely

1. **Name it** exactly as it appears in the S0 table row.
2. **Find every consumer.** Run all of these and paste the hit list into your
   notes:
   - `rg -n '<name>' --hidden -g '!.git' -g '!.work'` (literal name)
   - `rg -n '<file-stem>'` for each file of the mechanism (catches imports,
     globs, `subprocess` paths, dispatcher `case` arms, Cargo features)
   - `rg -n '<name>' docs README.md AGENTS.md COMPATIBILITY-PROFILE.md` (manual
     consumers)
   - for a Cargo feature: `rg -n '<feature>' --glob '*.toml' --glob '*.rs' --glob '*.sh' --glob '*.py'`
   - for a dispatcher subcommand: also check `scripts/lanes/`, `compat/**/README.md`,
     and every `run_*.sh`/`*.py` that calls `dev-x86_64.sh`.
3. **Classify each consumer**: (a) dies with the mechanism; (b) needs a behavior
   the mechanism proved, and that behavior has another existing test; (c) needs
   a behavior with no other test.
4. **Move behaviors of class (c)** into the existing shared case table or test
   module that already covers that family. Add the case **before** deleting,
   run it against the current code, and confirm it passes there. Keep negative
   and error cases: malformed ELF, TLS, cancellation, errno, interposition and
   lifecycle cases must survive.
5. **Delete** the mechanism and its class (a) consumers in one commit. Do not
   leave a stub, alias, deprecation shim or `legacy` wrapper.
6. **Prove the reduction.** Re-count with the S0.3 commands. The commit body
   lists: mechanisms removed, lines removed, lines added, cases moved, and
   check commands run. If lines added ≥ half of lines removed, stop and ask the
   coordinator whether the change still earns its place.
7. **Run the step's focused checks** plus any test file you touched:
   `python3 -B scripts/test_python.py --module <path>` for Python and
   `scripts/lanes/rust-check.sh cargo check -q --locked -p <crate> --features <product feature>`
   for Rust.

### P4 — Change runtime code

1. Write or locate a behavioral test that pins the touched contract (errno,
   return value, cancellation, ordering) and run it against the **unchanged**
   code first. For a bug fix the test must fail first.
2. Measure the affected rows with P2 **before** editing. Save the numbers.
3. Make the change. Compare the musl source for the same function before
   designing anything new; prefer removing a redundant syscall, allocation,
   lock, copy, scan, conversion or indirection over adding a fast path.
4. Re-measure with P2. Rows may only improve, or stay level when the change is
   a structural deletion. Any row that gets worse blocks the change.
5. Re-run the behavioral tests and the hardening checks for the touched area.
6. Forbidden shortcuts: blanket `#[inline(always)]`, unchecked pointer access
   added for speed, weaker atomic orderings, SIMD dispatch frameworks, skipping
   cancellation points, replacing a POSIX entry point with a raw syscall stub,
   disabling a hardening feature.

### P5 — Stop and escalate

Stop the current action and report to the coordinator when any of these happen:

- A required command fails, and the failure is not explained by your change.
- The step would require editing a file the step does not allow.
- The change would touch the allocator, AArch64, pins, or a frozen manifest.
- A check fails and the only fix you see is to edit the check.
- A tool or permission denies an action. Record the exact command and message;
  do not retry it in another form.
- The work grows beyond the step's stated **Size**.

Report: what you were doing, the exact command and output, what you believe
the cause is, and options. Then continue any independent work in your step,
or stop.

### P6 — Report template

```text
Step:          S?.?
Branch/commit: lane/... @ <sha>
Changed:       <one line per mechanism removed or behavior changed>
Numbers:       <table: metric | before | after | budget>
Checks run:    <exact commands> -> <pass/fail>
Not verified:  <anything skipped and why>
Allocator-attributed: <rows/syscalls, one line each, or "none">
Blockers:      <or "none">
```

## Sequence

```text
S0 ──┬── S1 ── S4 ── S5
     ├── S2 (parallel with S1)
     └── S3a (parallel with S1) ── S3b (needs S1) ── S4
```

S3a and S2 may start as soon as S0 is done because they delete mechanisms that
no shipped hot path executes. Any change to code that a shipped product
executes waits for S1.

### S0 — Baseline and budgets

**Owner:** one `worker` agent; the coordinator approves the budgets.
**Requires:** nothing. **Size:** bounded to the actions below; no new scripts
are committed except as S0.7 allows.
**Allowed files:** `plan.md` result section (coordinator only),
`.work/s0/**` scratch.

1. **Build the HEAD products** with the accepted C backend, recording the
   commit SHA:
   - `./scripts/dev-x86_64.sh image`
   - `./scripts/dev-x86_64.sh materialized-dynamic-sysroot --work .work/s0/dynamic --prepare`
   - `./scripts/dev-x86_64.sh owned-static-sysroot`

   If a command runs product cases after building, let it finish and record
   pass/fail; do not resume or repair failing cases. Confirm the dynamic root
   contains `lib/ld-crabc-x86_64.so.1`, `usr/lib/libc.so`, `usr/lib/Scrt1.o`.
   If the build itself fails, apply P5.
2. **Build the hand reference**: until S1.2 exists, use the host musl as in the
   recipe, labeled `unmatched (host musl, gcc/Alpine build)`.
3. **Count source by category** with these exact commands, from the repository
   root, at the recorded SHA. Use `git ls-files` so ignored files never count.

   ```sh
   loc() { git ls-files -z -- "$@" | xargs -0 cat | rg -c -v '^\s*(//|#|$)'; }
   files() { git ls-files -- "$@" | wc -l; }
   ```

   Categories, one row each: `libc/src/**/*.rs` minus `*_tests.rs`;
   `libc/src/**/*.S` (generated from musl); `ldso/src/*.rs` minus `*_tests.rs`;
   `*_tests.rs` and `tests/**` (external tests); `crt/`, `builtins/`;
   `crabc-core/src`, `crabc-rs/src`; `unwinder/`; `scripts/**`;
   `compat/x86_64/**/*.py`; `compat/perf/**`; other `compat/**` excluding
   `compat/allocator`; frozen `crabc-mimalloc/` + `compat/allocator/` (one row,
   count only); third-party vendored source. Inline `#[cfg(test)]`
   modules: report only `rg -c '#\[cfg\(test\)\]'` per crate, not lines.
4. **Count mechanisms.** One row per kind:
   - Cargo features per crate: lines under `[features]` in each `Cargo.toml`.
   - Dispatcher subcommands: `./scripts/dev-x86_64.sh --help | rg -c '^  [a-z0-9-]+'`.
   - Python entry points: `git ls-files 'compat/**/*.py' | xargs rg -l '__main__'`.
   - Generators: `git ls-files 'compat/**/generate_*.py'`.
   - Report/receipt formats: `rg -o --no-filename '"format": *"[^"]+"|FORMAT = "[^"]+"' compat scripts | sort -u`.
   - Runtime bridges: `RuntimeV1` table entries and every symbol `libc.so`
     imports from the loader: `llvm-nm -D --undefined-only usr/lib/libc.so | rg crabc`.
   - Process-state owners: for errno, TLS/thread list, stdio, loader state,
     environment, atexit, locale and signal state, the single file that
     defines the state. List any state with two definitions (Rust statics in
     two crates, or the same data mirrored in two structures).
5. **Measure linked footprint**: `llvm-size -A` on `ld-crabc-x86_64.so.1`,
   `libc.so`, the static archive members actually linked by a static hello
   (`-Wl,--Map=` map file), and the same for reference musl. Report `.text`,
   `.rodata`, `.data`, `.bss`, and `.data.rel.ro` separately.
6. **Measure startup** for dynamic hello and static hello with P2 against both
   runtimes, then attribute crabc's startup:
   `perf record -e instructions:u -c 1000` with an unstripped product (point
   `perf report --symfs` at the build output, not the stripped install), and
   group by DSO and top 30 symbols. Label allocator symbols
   `allocator-attributed`. Give each extra syscall a one-word cause.
7. **Measure the S1 seed rows** (list in S1.5) by hand with P2, using the host
   reference, labeled `unmatched`. If the hand route needs a helper script,
   keep it in `.work/s0/` and do not commit it.
8. **Rank the deletion list.** For each candidate below, write: mechanisms
   removed, approximate lines removed, consumers (P3 step 2), risk, and what
   checks prove it. Start from these candidates; add others only with numbers:
   1. the six `ldso` private milestone features and their source roots
      (`*_source_root.rs`, fixed-graph vs general duplicates);
   2. `libc` per-family leaf features that every shipped product enables
      (leave `native-*`, `*-shadow`, `x86-allocator-*` and
      `x86-owned-allocator-lifecycle-test-audit` untouched: frozen);
   3. dispatcher subcommands with no consumer except the plan/receipt chain,
      and their `compat/x86_64` runners/readers;
   4. per-artifact readers/validators that duplicate a shared one;
   5. the split loader/libc images (S3b);
   6. the Python receipt-validating installed C driver;
   7. the generated-assembly mechanism (only if the owner chooses it; see [D2](#owner-decisions)).
9. **Propose budgets** using this rule: for each selected area,
   `budget = baseline − 0.8 × (sum of the deletions you identified)`, rounded
   to two significant figures. Give budgets for: ldso features (target: one
   product feature or none), ldso lines, libc feature count, dispatcher
   subcommands, `compat/x86_64` Python files and lines, `scripts/dev-x86_64.sh`
   lines, and dynamic/static startup syscalls and instructions. Budgets are
   fixed once the coordinator writes them here and are never relaxed later.

**Done:** the coordinator has filled the [S0 baseline table](#s0-baseline-table)
with the SHA, the commands above, every count, the ranked list and the budgets.
Old numbers whose raw data is gone are not used.

### S1 — Make the cost contract executable

**Owner:** one `worker` agent per sub-step, in order; one `expert` reviewer for
S1.4. **Requires:** S0. **Allowed files:** `docker/Dockerfile.x86_64`,
`compat/perf/**` (not the allocator modes), `compat/x86_64/performance_release_gate.py`,
`compat/x86_64/tests/test_performance_release_gate.py`, the `perf-c` arms of
`scripts/dev-x86_64.sh`, `compat/perf/README.md`, `docs/design/performance.md`.

**S1.1 — Image tools.**
1. In `docker/Dockerfile.x86_64` add the Alpine packages that provide a clang
   and lld whose LLVM **major** version equals `rustc -vV`'s `LLVM version`
   major (currently 23), and `perf`. Check what the pinned Alpine offers with
   `docker run --rm alpine@<pinned digest from the Dockerfile> sh -c 'apk update -q && apk search -x clang23 lld23 perf'`. Do not change the base digest.
2. If the pinned Alpine has no matching clang, stop (P5). Do not upgrade the
   base image or build LLVM from source without an owner decision.
3. Rebuild with `./scripts/dev-x86_64.sh image`. In the image, check
   `perf stat -e instructions:u true`. If it is denied, add
   `--cap-add=PERFMON` to the docker invocation used by the counts route only
   (S1.3). Never change `perf_event_paranoid`.
4. Done when both checks print versions/counts inside the image.

**S1.2 — Matched reference build.**
1. In the image, build musl from the `[musl_native]` tarball (verify its
   sha256 against `compat/upstreams.toml`) with
   `CC=<matched clang> ./configure --prefix=<.work path> --target=x86_64-linux-musl`
   and no extra `CFLAGS`, so musl's own optimization defaults apply. Then
   `make` and `make install`.
2. Record `config.mak`'s `CFLAGS_AUTO`/`CFLAGS`, the clang version and
   `rustc -vV` in the counts report header.
3. Keep the existing GCC-built reference for the existing timing rows. Label
   counts rows from the clang build `matched-llvm-<major>`; anything else is
   `unmatched` and diagnostic only.

**S1.3 — Counts route.** Add a `counts` subcommand to the existing
`perf-c` command (`plan|run|collect|check` gains `counts`). It must:
1. reuse the existing object-compile-once and dual-link code in
   `compat/perf/run_x86_64.py`; no new runner file;
2. implement P2 exactly (N1/N2/N3, separate `strace` and `perf` runs, wrapper
   subtraction for startup, determinism and linearity checks);
3. write one JSON report per invocation with a header (SHA, image digest,
   compiler versions, reference label, CPU model, kernel) and one record per
   row: `row`, `mode`, `args`, `N`, raw counts for both runtimes,
   per-op/startup values, per-syscall breakdown, `ratio_insn`, `delta_insn`,
   `status` (`pass`, `fail`, `nondeterministic`, `nonlinear`, `unavailable`,
   `allocator-attributed`);
4. reuse the existing report writer/reader helpers in
   `compat/perf/x86_64_evidence.py`; add fields, not a new schema family;
5. run without a qualification receipt, and say `development` in the report
   header. A `development` report can never be read as release evidence.

**S1.4 — Gates.** Write the tests first, and run them so they fail before the change:
1. In `compat/x86_64/performance_release_gate.py` replace
   `RUNTIME_SYSCALL_FACTOR = 2` by a single definition of the cost contract
   (`SYSCALL_LIMIT_FACTOR = 1`, `INSTRUCTION_LIMIT_RATIO = 1.10`) that both the
   release gate and the S1.3 `check` path import. `rg -n 'SYSCALL|1\.10|2R'` in
   `compat/perf` and `compat/x86_64` afterwards must show no second copy.
2. Required tests in `compat/x86_64/tests/test_performance_release_gate.py`
   (and the evidence module's tests if the reader changes): extra syscall over a
   nonzero R fails; R = 0 with candidate 1 fails; equal passes; fewer passes;
   `ratio_insn` 1.10 passes, 1.1001 fails; 0.5 passes; absent instruction
   fields → `unavailable`, never pass; `unmatched` reference → cannot pass;
   `nondeterministic`/`nonlinear` → cannot pass; an old-version report without
   the new fields is read as `unavailable`, not rejected silently and not
   passed.
3. Update the docstring at the top of the gate (it still says `<= 2R`).
4. Run `python3 -B scripts/test_python.py --module compat/x86_64/tests/test_performance_release_gate.py`
   and the touched `compat/perf/tests` modules.

**S1.5 — Seed rows.** Run `perf-c counts` for these existing `workload.c`
modes, dynamic PIE and static PIE: `startup`, `getpid`, `clock_gettime`,
`gettimeofday`, `open_close`, `stdio_format_parse`, `pthread_mutex_uncontended`,
`pthread_create_join_tls` (counts include all threads; syscalls labeled
stress-diagnostic if nondeterministic), `memcpy_matrix`, `memset_matrix`,
`strlen_matrix`, `memchr_matrix`, `strstr_matrix`, `memmem_matrix`,
`span_matrix`, `dlopen_graph`, `loader_dynamic_tls_growth`. Use the matrix
sizes 16, 256 and 4096 at offset 0, and 4096 at offsets 1/3. Do **not** run
the `allocator_*` modes.

**Done:** S1.4 tests pass; one `development` counts report from the merged tip
covers every S1.5 row with a `matched-llvm-<major>` reference; the coordinator
copies the per-row status table into the [result table](#result-table). Rows
that fail are expected here. They feed S4 and are not S1 failures.

### S2 — Shrink build and evidence machinery

**Owner:** one `worker` per mechanism group; one writer at a time for
`scripts/dev-x86_64.sh`. **Requires:** S0. **Allowed files:** the files of the
mechanism being removed, the shared case tables/tests receiving moved cases,
`scripts/dev-x86_64.sh` (holder only), the READMEs that document the removed
commands. Never `compat/allocator/**`, `crabc-mimalloc/**`, AArch64 manifests.

Work through the S0 ranked list, items 3 and 4, in rank order. For each item
apply P3. Specific rules:

1. Start with dispatcher subcommands whose only consumers are other
   subcommands, receipts or the old plan. Delete the subcommand, its
   `compat/x86_64` runner and reader together.
2. When several readers validate the same report shape, keep the one with the
   most callers. Port the others' **behavioral** assertions (exit status,
   output, errno, ELF facts), not their source-literal or prose-count checks.
3. Keep: declarative case tables, one process-execution helper, one
   provenance/identity helper, the S1 counts route, and the readers the
   release gate needs.
4. Keep `scripts/dev-x86_64.sh` a thin dispatcher: an arm parses arguments and
   calls one script; logic longer than ~20 lines moves into that script or is
   deleted.
5. Ordinary development must work without a receipt: building a product and
   running a family's tests may not require reading a receipt. Release
   qualification keeps its clean-commit/source/artifact binding.
6. Retained failed reports under `.work/` stay untouched.

**Done:** the S0 budgets for dispatcher subcommands, `compat/x86_64` Python
files/lines and `scripts/dev-x86_64.sh` lines are met; every removed
behavioral case is listed with its new location; `./scripts/dev-x86_64.sh --help`
and the commands in AGENTS.md still work; the focused suites of every touched
family pass on the merged tip.

### S3a — Retire non-shipping product roots and feature variants

**Owner:** one `worker` for ldso, one for libc (never both on the same file);
`expert` reviewer. **Requires:** S0. **Allowed files:** `ldso/**`,
`libc/Cargo.toml`, `libc/build.rs`, `libc/src/lib.rs`, and the `cfg`
attributes and runners that select the retired features.

1. **ldso.** Make `x86_64-owned-dynamic-runtime` the only x86-64 loader
   product, with no other x86-64 feature.
   - The product already enables `x86_64-general-initial-interpreter`,
     `x86_64-general-initial-lifecycle` and
     `x86_64-general-initial-tls-runtime-v1-dynamic-main-thread-interpreter`.
     Their code becomes unconditional in the product; delete the feature names
     and their `cfg` gates.
   - `x86_64-initial-interpreter`, `x86_64-general-initial-tls-interpreter` and
     `x86_64-general-initial-tls-runtime-v1-interpreter` are not in the product.
     For each one apply P3 steps 2–4: known consumers include
     `compat/x86_64/run_ldso_initial_graph.sh`,
     `compat/x86_64/run_ldso_general_initial_tls.sh`,
     `compat/x86_64/run_general_loader_lifecycle.sh`,
     `compat/x86_64/tests/test_loader_libc_general_tls_runtime_v1.py` and
     `compat/x86_64/parity.toml`. Their behavioral cases must run through the
     installed product. Then delete the feature, its `*_source_root.rs`, and
     every module only it selected.
   - Where a fixed-graph module and a general module do the same job
     (`initial_graph` vs `general_initial_graph`, `relocation` vs
     `general_relocation`), keep the one the product uses and delete the other
     after moving its unique tests.
   - Leave `aarch64.rs` and every AArch64 `cfg` arm unchanged.
2. **libc.** Fold every leaf feature that both the static and dynamic owned
   aggregates enable into unconditional code. Keep a feature only where it
   marks a real dependency boundary (an optional external crate) or is
   allocator-frozen. Edit the frozen `x86-owned-static-native-shadow` list only
   to drop names that no longer exist, and prove with
   `scripts/lanes/rust-check.sh cargo check -q --locked -p crabc-libc --features x86-owned-static-native-shadow`
   that it still compiles. Build nothing else
   for it.
3. **Prove shipped bytes did not grow:** compare `llvm-nm -D --defined-only`
   export lists and `llvm-size -A` of `libc.so`, `ld-crabc-x86_64.so.1` and
   `libc.a` before and after. Exports must be identical; sections may shrink.
4. Run the loader product cases (`materialized-dynamic-sysroot` on a new
   `--work` directory) and the static product suite.

**Done:** ldso has one x86-64 product feature (or none); libc's feature list is
reduced to the S0 budget; export lists are identical; loader and static product
cases pass as before (same failures, none new).

### S3b — Single loader/libc image

**Owner:** one `god`-tier implementer and one independent `expert` reviewer.
**Requires:** S1 done, S3a done for ldso. **Allowed files:** `ldso/**`,
`libc/**` outside allocator integration modules, `crt/**`, the product
builders. Never the allocator.

Why this is not optional: the reconnaissance shows the split costs about 12
startup syscalls that musl does not make. No search-path tweak removes the
`openat`/`mmap` pairs for a second image, so the dynamic startup rows cannot
meet R while the split stays. The only alternative is an owner waiver ([D3](#owner-decisions)).

1. **Design note first** (in the lane, ≤ 1 page, given to the reviewer): how
   one ELF serves as both `PT_INTERP` and `libc.so` (musl's model:
   `/lib/ld-musl-x86_64.so.1` is `libc.so`); how loader code relocates itself
   before TLS, errno or the allocator exist; which `RuntimeV1` entries
   disappear (loader↔libc calls become direct) and which remain (only what
   `crabc-rs` needs to reach process state); which libc imports from the
   loader (`__crabc_x86_64_runtime_open`, `__crabc_x86_64_reset_current_tls_v1`,
   …) disappear; startup/finalizer order; how interposition works for symbols
   both halves define.
2. **Reviewer approves** the note before code changes. The reviewer checks it
   against `docs/design/architecture.md` and the hardening profile.
3. **Implement** behind no runtime switch: the product changes in place. Keep
   the old split only on the lane branch until the new one passes.
4. **Prove**, on the new product: static, static-PIE and dynamic products all
   build; the loader product cases, `dlopen`/TLS growth cases, interposition
   cases, cancellation/TLS cases and hardened-runtime cases pass with no new
   failures; startup syscalls and instructions (P2) drop; the S0 bridge count
   drops.
5. **If any proof fails** in a way that needs an allocator change, or the
   unified product is not smaller in bridges and startup cost, stop. Report
   the specific invariant that forces the split; the owner then decides
   between a waiver and another design. Do not keep both arrangements.

**Done:** one installed runtime ELF; `RuntimeV1` reduced to the facade's needs
(or removed); dynamic startup syscalls ≤ R plus only the `allocator-attributed`
calls; all listed product cases pass as before.

### S4 — Remove residual cost by mechanism

**Owner:** one `worker` per row family (string, stdio, pthread, time, loader,
startup); `expert` review for loader and pthread. **Requires:** S1 (and S3b
for loader/startup rows). **Allowed files:** the implementation files of the
row's functions in `libc/`, `ldso/`, `crabc-core/`, `crt/`, `builtins/`, and
their tests.

1. Sort the failing non-allocator rows from the latest counts report by
   `delta_insn × typical call frequency`, with startup first, then syscall
   failures, then instruction ratios.
2. For each row: read musl's implementation of the same function; read the
   candidate's disassembly (`llvm-objdump -d`) for the hot path; list every
   extra syscall, allocation, lock, copy, scan, conversion, bounds check or
   indirect call compared with musl.
3. Apply P4. One row family per branch; one mechanism per commit.
4. Known first targets: redundant `arch_prctl(ARCH_GET_FS)` after
   `ARCH_SET_FS`; `gettid` where `set_tid_address` already returns the tid;
   any startup `mprotect` musl does not make (check RELRO coverage first: the
   hardened profile's RELRO requirement wins).

**Done:** every selected deterministic non-allocator row is `pass` on a counts
report from the merged tip; `allocator-attributed` rows are listed; no row got
worse than its S1 value.

### S5 — Acceptance

**Owner:** coordinator, plus one fresh `god` reviewer who did not work on S0–S4.
**Requires:** S0–S4 done.

1. On one clean commit: rebuild products, rerun the S0.3–S0.5 counts, a full
   counts report, the static and dynamic product suites, hardened-runtime, and
   the non-allocator suites the touched families own.
2. Compare against every S0 budget. A budget not met is a failure, not a note.
3. Reviewer checks: no new runner, schema, framework or feature replaced a
   removed one; every removed behavioral case has a new location; no check was
   weakened; no allocator, pin or AArch64 file changed
   (`git diff <S0 SHA>..HEAD --stat -- crabc-mimalloc compat/allocator rust-toolchain.toml compat/upstreams.toml compat/x86_64/aarch64_frozen_baseline.json`
   is empty).
4. Coordinator writes the [result table](#result-table).

**Done:** all of the above pass. Full x86 qualification, public support and
an allocator restart are separate owner decisions after S5.

## Cost contract

[docs/design/performance.md](docs/design/performance.md) owns measurement
details; this table is the acceptance rule.

| Dimension | Rule |
| --- | --- |
| Syscalls | Candidate <= R per row, for per-operation and whole-process counts. R = 0 requires 0. Every per-syscall-name difference is explained in the report; an explanation never waives an extra call. |
| Instructions | `ratio_insn <= 1.10` for per-operation and, separately, startup user instructions, counting vDSO code and all threads in the row. No rounding allowance. Lower is always fine. |
| Matched backend | The reference musl is built by clang with the **same LLVM major version** as the pinned rustc (`rustc -vV`). Record both full versions. Different major, or a GCC-built musl, makes the row `unmatched`: diagnostic only. Exact LLVM revision equality is not required, because rustc ships its own LLVM fork and no clang release is built from it. |
| Determinism | Single-threaded instruction counts must repeat within 0.01 %; they are compared directly, without bootstrap statistics. Multi-threaded or scheduling-dependent rows use the existing repeated-pairs protocol and one-sided 95 % upper bound, and never count as exact syscall parity. |
| CPU and memory | Existing per-row bounds unchanged. |
| Structure | S0 budgets met. |

## Owner decisions

The coordinator applies the default in **bold** until the owner answers.

- **D1 — Eager allocator start-up syscalls.** The accepted C backend makes
  about 5 syscalls at start-up even when a program never allocates. Under the
  freeze nobody may change that, so dynamic and static startup rows cannot
  reach R. Options: **(a) keep the freeze; those calls stay
  `allocator-attributed` and startup is judged on the remainder**; (b) allow
  one narrow exception: libc defers its allocator initialization call to first
  use, with no change inside the backend.
- **D2 — Generated musl assembly.** `libc/src` ships ≈81k lines of `.S`
  compiled from musl C by ≈35 generator scripts (math, scanf, float parsing,
  …), with hash/provenance headers. Options: **(a) leave the mechanism alone in
  this campaign**; (b) replace it by compiling the pinned musl C sources with
  the pinned clang at build time, which deletes the generators and checked-in
  output but adds a C compile step to the product build; (c) port to Rust.
- **D3 — Split images.** **Unified image required (S3b).** The owner may
  instead waive the dynamic-startup syscall rule for the image split, in which
  case S3b is skipped and the waiver is written into the cost contract.
- **D4 — Matched backend definition.** **Same LLVM major version** (above),
  instead of the earlier "rustc's exact revision/configuration", which no clang
  release can satisfy.

## Runtime hardening

The hardening requirement stays mandatory before any future x86 qualification
or public-support claim: PIE, non-executable stacks, page-level W^X, effective
RELRO, eager binding and explicit library search rules, as defined in
[COMPATIBILITY-PROFILE.md](COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
and [architecture](docs/design/architecture.md#native-x86-64-runtime-hardening).
Every S3/S4 change runs the hardening cases for its area. A cost win that
weakens hardening is rejected.

## Qualifying a revision

Full release qualification stays parked until after S5. Development counts
reports never change capability, support or default claims. A future
qualification uses one clean commit and a detached cohort worktree and reruns
everything for that commit. `COMPATIBILITY.md` stays generated; the complete
behavior/ABI requirements remain in
[docs/completion-requirements.md](docs/completion-requirements.md).

## Preserved checkpoint and holds

- At the October 28 pause the last accepted source was `44451281a`. The
  matched `4d3b9091a` cohort and resolver family passed; the dynamic Lua
  receipt reader timed out; the qualification chain was incomplete; nothing
  was promoted. These are history, not current-source results.
- If the Lua replay timeout blocks an S-step check, find its cause and repair
  it narrowly; never weaken receipt validation to get past it.
- POSIX `math/pow` and C-ABI admission stay held under the
  [October 25 decisions](https://github.com/joshuarli/crabc/blob/fe7f1874289d7f54ef27af4fb639cf307104540f/plan.md#decision-log)
  (24 oracle vs ten candidate diagnostics; raw evidence in
  `.work/tmp/pow-discriminator-ad7e18d35`). Do not trim the libc-test
  aggregate, change backends or invent an exception.
- All unmerged branches (`archive/*`, `cohort/*`, `integration/*`, `lane/*`,
  `parked/*`, `proof/*`, `recovery/*`, `review/*`) stay parked. Before reusing
  non-allocator work from one, compare with `git cherry main <branch>` and
  rerun its tests. Never merge allocator branches.
- **Nothing under `.work/wt/`, `.work/retained/`, `.work/allocator-x86_64/`,
  `.work/x86_64/kache` or `.work/tmp/pow-discriminator-*` is removed by any
  agent during this campaign**, registered or not. Earlier removal attempts
  were refused by Git, the filesystem or review; the per-path record is in
  this file at commit `c0bb51603`. `git worktree list` and the directories
  themselves are the inventory. Agents create new scratch only under
  `.work/s0/`, `.work/tmp/<step>-*` or their own `.work/wt/<lane>`.

## Fixed contracts

Linux/x86-64 little-endian, kernel ≥ 5.10; exact `[musl_native]` oracle;
AArch64 and its frozen manifests unchanged
(`compat/x86_64/aarch64_frozen_baseline.json`, `compat/crabc-rs/coverage.toml`,
`compat/abi/musl-1.2.6/aarch64/manifest.json`,
`compat/abi/musl-1.2.6/aarch64/headers.tsv`). Preserve `dlclose`'s retained-object
behavior, failed-load rollback, interposition, pthread/cancellation/TLS and the
selected error conventions. The runtime leaves process THP policy unchanged.
The accepted C backend (`libmimalloc-sys` 0.1.49, mimalloc v3.3.2) is distinct
from the frozen v3.5.0 port oracle. Keep upstream licenses, pins, corrections
and the reviewed unwinder dependency graph.

[Scope](docs/scope.md), [selected behavior](COMPATIBILITY-PROFILE.md),
[completion requirements](docs/completion-requirements.md),
[qualification chain](compat/x86_64/qualification-chain.md),
[architecture](docs/design/architecture.md),
[allocator design (frozen)](docs/design/allocator.md) and
[performance methodology](docs/design/performance.md) keep their contracts.

## Decision log

- 2026-10-30: owner requires radical simplification before further malloc
  work. Allocator frozen; accepted C backend unchanged; S0–S5 replace the
  expansion-first sequence; syscall ceiling R and instruction ceiling 1.10
  under matched LLVM; CPU/memory and correctness/hardening retained.
- 2026-10-30: plan refined into a runbook after a startup measurement (25 vs 9
  syscalls, ≈7.6× instructions for dynamic hello). Matched backend defined as
  same LLVM major. Single-image loader/libc becomes the default S3b outcome.
  S2/S3a may run in parallel with S1. Instruction parity for single-threaded
  rows uses exact counts instead of bootstrap statistics. D1–D4 opened.

## S0 baseline table

**Not yet measured.** The coordinator fills this from S0 with: SHA; product
commands; one row per S0.3 category (files, non-comment lines); one row per
S0.4 mechanism kind; S0.5 sections per image; S0.6 startup rows and
attribution; the S0.8 ranked list; the S0.9 budgets.

## Result table

**No S0–S5 results yet.** One row per completed step: step, merged SHA, the
numbers against budget, checks run, blockers. Replace rows; do not append
narrative.

## Non-goals

Allocator work; new capabilities, platforms or public surface; AArch64
execution or emulation; weakening semantics, safety, hardening or evidence; a
new validation framework; whole-toolchain integration; physical NUMA/huge-page
qualification; publication; counting documentation or test reduction as
runtime simplification.
