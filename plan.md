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
   **Never run `./scripts/dev-x86_64.sh image` unless your step says so.**
   Rebuilding retags `crabc-core-evidence:x86_64`; with Docker's containerd
   store the previously pinned image is deleted, and every native command fails
   until `CORE_IMAGE_ID` in `compat/x86_64/core_image.py` is re-pinned. The
   step that rebuilds the image owns that re-pin, in its own commit. Until that
   commit reaches `main`, create every new worktree from it, not from `main`:
   a checkout with the old pin cannot run native commands.
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
   commit SHA. First check that the pinned image exists:
   `docker image inspect "$(python3 -B compat/x86_64/core_image.py)" >/dev/null`.
   If it does not, stop (P5); do not rebuild it. Then:
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
   - Python entry points:
     `git ls-files -z 'compat/*.py' ':(exclude)compat/allocator' | xargs -0 rg -l '^if __name__ == .__main__.:' | wc -l`.
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
   6. the Python receipt-validating installed C driver.

   The generated musl assembly is excluded by [D2](#owner-decisions).
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

**S1.1 — Image tools.** S1.1 and S1.2 are one lane; the image is rebuilt once.
1. Add `perf` (Alpine 3.24 ships `perf-7.1.5`) to the main `apk add` list.
2. The pinned Alpine 3.24.1 has only clang 22, but rustc uses LLVM 23
   (checked 2026-10-30). Apply [D5](#owner-decisions): add a builder stage at
   the top of `docker/Dockerfile.x86_64`,
   `FROM alpine:edge@sha256:<digest> AS musl-clang`, pinned by digest, that
   installs `clang` and `make`, then asserts that `clang --version` reports
   LLVM major 23 and fails the build otherwise. S1.2 runs in this stage.
   The main stage's base digest does not change. Do not build LLVM from source.
3. Rebuild with `./scripts/dev-x86_64.sh image`, then re-pin `CORE_IMAGE_ID`
   in `compat/x86_64/core_image.py` to
   `docker image inspect --format '{{.Id}}' crabc-core-evidence:x86_64` in a
   separate `build(x86)!` commit and run
   `python3 -B scripts/test_python.py --module compat/x86_64/tests/test_core_image_dispatch.py`
   and `./scripts/dev-x86_64.sh musl-oracle`. In the image, check
   `perf stat -e instructions:u true`. If it is denied, add
   `--cap-add=PERFMON` to the docker invocation used by the counts route only
   (S1.3). Never change `perf_event_paranoid`.
4. Done when both checks print versions/counts inside the image.

**S1.2 — Matched reference build.**
1. In the `musl-clang` stage, acquire the `[musl_native]` tarball exactly as
   the existing GCC oracle `RUN` does (`compat/x86_64/musl_oracle.py acquire`,
   which checks the pinned sha256). Configure with
   `CC=clang ./configure --prefix=/opt/musl-clang-${MUSL_VERSION} --syslibdir=/opt/musl-clang-${MUSL_VERSION}/lib`
   and no extra `CFLAGS`, so musl's own optimization defaults apply; `make`,
   `make install`; copy `config.mak` into the prefix. Repeat the existing
   `test -f` checks for `lib/libc.so` and `lib/ld-musl-x86_64.so.1`.
   In the main stage, `COPY --from=musl-clang /opt/musl-clang-<version> /opt/musl-clang-<version>`.
   Leave the existing GCC oracle `RUN` unchanged.
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
**Requires:** S1 done, S3a done for ldso. S3a-ldso is blocked on 71 cases;
because the merged image is the better migration target, S3b proceeds first
and S3a-ldso is revisited after it (coordinator decision, 2026-10-31).
**Allowed files:** `ldso/**`, `libc/**` outside allocator integration modules,
`crt/**`, the product builders, and the evidence consumers of the startup and
identity contract that the merge changes
(`compat/x86_64/installed_crt_startup_probe.c`,
`compat/x86_64/installed_crt_startup_evidence.py`,
`compat/x86_64/native_abi_selection.py`,
`compat/x86_64/run_owned_loader_libc_identity.sh`,
`compat/x86_64/owned_loader_libc_identity_receipt.py` and their tests).
Never the allocator.

Spike result (2026-10-31, uncommitted lane): one `mold -shared` image with
`SONAME libc.so` and `_start` as entry booted `hello`, a malloc/TLS probe and
`dlopen("/usr/lib/libc.so")`; 12 startup syscalls against 25 split (musl 9),
7 non-allocator against musl's 9, 0 libc→loader imports, 229,617 vs 238,686
startup instructions. Reviewer rejected the design as-is: early `_start`
relocation writes are unvalidated, identity loses `(st_dev,st_ino)` and
`ldso.name`, and the weak-slot ownership check fails open. Those three, the
product builder, and the evidence consumers above are the remaining work.

Why this is not optional: the reconnaissance shows the split costs about 12
startup syscalls that musl does not make. No search-path tweak removes the
`openat`/`mmap` pairs for a second image, so the dynamic startup rows cannot
meet R while the split stays. The owner has ruled out a waiver ([D3](#owner-decisions)).

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
   the specific invariant that blocks unification and a proposed design that
   satisfies it; the owner decides the next attempt. Do not keep both
   arrangements, and do not treat the blocker as a waiver.

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

Decided by the owner on 2026-10-30 and 2026-10-31. Reopening one needs a new
owner decision.

- **D1 — Eager allocator start-up syscalls: keep the freeze.** The accepted C
  backend makes about 5 syscalls at start-up even when a program never
  allocates. Nobody changes that during this campaign, including by moving
  libc's initialization call. Those calls are labeled `allocator-attributed`;
  startup rows are judged on the remaining calls and instructions.
- **D2 — Generated musl assembly: leave it alone.** The ≈81k lines of `.S`
  compiled from musl C and their ≈35 generator scripts are out of scope for
  S0–S5. S0 counts them as their own category; no step edits, regenerates or
  replaces them.
- **D3 — Split images: unify.** S3b is required. The dynamic-startup syscall
  rule is not waived for the split.
- **D4 — Matched backend: same LLVM major version** as the pinned rustc, as
  defined in the [cost contract](#cost-contract).
- **D5 — Matched clang source: a builder stage.** The pinned Alpine 3.24.1
  ships clang 22; LLVM 23 clang is only in Alpine edge. A digest-pinned
  `alpine:edge` builder stage compiles only the reference musl, asserts the
  LLVM major, and is copied into the unchanged main image (S1.1/S1.2). When
  the next stable Alpine ships the matching clang, the stage moves to it.
- **D6 — libc leaf folding may change the default archive.** The shipped
  static archive is built from `x86-owned-static-runtime` and already exports
  the 19 leaves; the no-feature archive is a test artifact only. Folding the
  leaves into unconditional code may therefore widen that test artifact's
  export surface. Accepted: update the absence-proof runners to presence tests
  for the folded families, and keep the shipped `libc.so`/`libc.a` export
  lists identical. The libc-feature budget stays 25.
- **D7 — migrate the ldso cases rather than keep the features.** The 71
  behavioural cases of the three non-product loader features move into the
  installed product's case table before those features and their source roots
  are deleted. The ldso-feature budget stays 2.
- **D8 — startup instructions are judged on the total.** D1's allocator
  exemption covers the start-up syscalls it names; it does not create an
  instruction exemption that the harness cannot measure. Startup rows report
  the allocator-attributed share as evidence, and the gate compares the total
  against 1.10 × R. No sample-based subtraction is added.
- **D9 — the allocator label applies to every row.** A row's whole-process
  count includes the process start-up, so the frozen allocator calls (and its
  arena `madvise` pair) are labeled and removed from the judged total for loop
  rows as well as startup rows. Per-name excess on the remaining calls still
  fails; per-operation counts are unchanged.
- **D10 — startup instructions: narrow allocator-lifecycle reopening, no
  exemption.** The owner delegated the choice. Bounded measurement (below)
  confirms mimalloc's eager process init and option scan dominate startup, and
  that a lifecycle-only lazy initializer can remove them without an allocator
  algorithm change. Reopen the freeze only for that lifecycle change: make the
  existing init and option scan run on the first allocation. No allocator
  development, port work, tuning or benchmarks. The measurement also shows the
  allocator-free remainder is still above 1.10 × musl, so the change may land
  only with an S4 startup-instruction lane and only if the combined startup
  rows meet 1.10 ×. Otherwise record the measured floor as a standing blocker.
  D8's total judgement and D1's syscall attribution are unchanged. The counts
  route measures a 118,966-instruction drop, not the direct 169,278; the
  post-change `startup` remainder is 132,328, which is the S4 budget basis.
  A thread-creating no-allocation program initializes at its first
  `pthread_create`, so a worker cannot become mimalloc's process main and free
  the static main theap. A diagnostic profile of the allocator-free dynamic
  floor puts 58.7 % of sampled loader instructions in
  `__crabc_x86_64_self_relocate` (300-exec run, one merged DSO); the static
  floor is dominated by the static-TLS bootstrap (`from_auxv`, `materialize`,
  `bootstrap_initial_thread`). Those are the S4 startup targets, subject to the
  same 1.10 × gate.
- **D11 — `dlopen_graph`: startup, not symbol resolution.** S5's 2.6403× row
  was 303,603 startup instructions against musl's 114,988, while the dlopen
  operation itself was 15,582 against 15,592. D10 removes the allocator share;
  the post-D10 row is 184,845 against a 126,490 target. The remaining gap is
  the same relocation transaction as D16, so it is covered by the standing
  startup blocker and no separate resolver lane is opened. The judged syscall
  total is 60 against 61.
- **D12 — static startup 759-byte `mmap`: remove the preallocation.** Do not
  relax the static syscall budget from 9 to 10. The mapping is static TLS
  (`StaticInitialTlsPlan::materialize`), not allocator lifecycle, so it is not
  folded into D10. If evidence later shows it is allocator lifecycle work,
  stop and fold it into D10 instead of changing it separately.
- **D13 — hardened exit 116: diagnose the harness, not the product.** The
  failing runner was the evidence harness, not a runtime regression; the
  acceptance suite must pass at the final tip before S5 can claim it.
- **D14 — CPU and memory are re-accepted only on a quiet host.** The S5
  attempt was deferred at load 20–27; a re-acceptance run must satisfy the
  existing host-load policy. Counter runs under load remain diagnostic. The
  owner deferred the gate again on 2026-10-31 because the host stayed noisy;
  this is not permission to record a smoke run as acceptance.
- **D15 — the ldso line budget is x86-product-only.** The budget counts x86
  product lines (11,000 at D15, raised to 11,161 by D17); the paused AArch64
  `loader.rs`/`aarch64.rs`
  (4,436 non-comment lines) is preserved and reported separately. At
  `b28cb221d` the x86 product is 12,175 lines and the total is 16,611, so the
  lane must remove about 1,175 dead or fixed-graph-only x86 lines. It must not
  delete live product mechanisms to reach the number.
- **D16 — startup instructions are a standing blocker.** The owner chose to
  keep eager binding and every hardening check rather than authorize a new
  indexed resolver. S4 measured the post-D10 floor: 132,394 dynamic startup
  instructions against a 77,101 target (`dlopen_graph` 184,845 against
  126,490), with 34,721 non-relocation instructions and 107 relocations
  (90 symbolic). Musl's bare eager PLT relocation costs 349 instructions per
  relocation; crabc additionally enforces writable-target bounds, RELRO
  coverage and full symbol-extent validation, so the remaining gap cannot be
  removed by P4 deletion or inlining. The loader-syscall lane removed the
  `dlopen_graph` per-name excess (`gettid`, `mmap`, `newfstatat`, `pread64`
  now match the reference; judged 53 vs 61). The formerly unavailable
  `loader_dynamic_tls_growth` row is measured at its fixed eight-module cap:
  after the TCB fold it is 421,075 vs 174,307 instructions (2.5682) with 90
  judged calls against 128 and no per-name excess, so the former required
  worker-TCB `munmap` is gone. S5 is not accepted on the startup instruction
  dimension; the CPU/memory gate is also deferred under D14. Reopening this
  needs a separate owner decision and a semantics-preserving resolver design.
- **D17 — the ldso x86 budget is 11,161.** The owner accepted the 161-line
  increase on 2026-10-31 to retain the loader-syscall and worker-TCB wins; the
  other budgets are not waived.
- **D18 — the remaining performance gates are deferred.** On 2026-11-01 the
  owner deferred the D16 instruction ratios and the D14 CPU/memory
  re-acceptance. They are not run for S5 and are not passes: `startup`,
  `dlopen_graph` and `loader_dynamic_tls_growth` remain above 1.10×, and
  CPU/memory has no quiet-host measurement. Recorded syscall results stay as
  evidence. S5 may be accepted on the structure, correctness and hardening
  dimensions; any later performance claim needs a new owner decision and a
  fresh quiet-host run.

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
  rows uses exact counts instead of bootstrap statistics.
- 2026-10-30: owner decided D1–D4: keep the allocator start-up calls frozen
  and attributed; leave generated musl assembly out of scope; unify the
  loader/libc image with no waiver; matched backend means same LLVM major.
- 2026-10-30: the first S0 run rebuilt the core image, which deleted the
  pinned image; it was re-pinned in `180bbaaae`. Rebuilds are now forbidden
  unless a step requires them. S1.4 landed (R and 1.10 in the release gate).
  S1.1 stopped because Alpine 3.24.1 has no LLVM 23 clang; D5 opened and
  decided: a digest-pinned `alpine:edge` builder stage for the reference musl.
- 2026-10-31: **D9 — D1's allocator label applies to every row.** A row's
  whole-process count includes the process start-up, so the five frozen
  allocator calls (plus its own arena `madvise` pair) are labeled and removed
  from the judged total for loop rows as well as startup rows. Per-name excess
  on the remaining calls still fails; per-operation counts are unchanged.
- 2026-10-31: S3a (libc leaves) and S3b (one image) landed. S3b ran before the
  blocked S3a-ldso; the installed product is one ELF with 7 non-allocator
  startup syscalls against musl's 9. Startup instructions are still 237,541
  against musl's 35,106, dominated by the frozen allocator, so S5 cannot pass
  the instruction dimension without an owner decision on D1/D8.
- 2026-10-31: owner delegated the three open S0 questions and they are decided:
  D6 accepts the default-archive export change for the 19 folded leaves, D7
  funds moving the 71 ldso cases and deleting all six private features, and D8
  judges startup instructions on the total while reporting the allocator share
  as evidence. The libc (25) and ldso (2) feature budgets stand.
- 2026-10-31: S1.1–S1.3 and the S1.5 seed rows landed and merged; S0 was then
  completed on the merged tip. S0 budgets are fixed above. The S0.8 test for
  chain-only dispatcher subcommands finds none: the dispatcher is behavioural
  coverage, so its reduction lever is the 314-case `*-header-abi`
  consolidation, not deletion of the receipt chain.
- 2026-10-31: owner resumed the campaign after the rejected S5 attempt and
  decided D10–D14. The bounded startup measurement corrected the empty-env
  accounting: the 118,862 figure counted the host `env` process; direct static
  startup is 54,997, and allocator eager init is 169,387 static / 169,278
  dynamic instructions. Lazy allocator lifecycle alone leaves 2.15× dynamic
  and 5.52× static, so it lands only with the S4 startup-instruction lane.
  `dlopen_graph`, the ldso case migration and the static TLS mapping get
  dedicated lanes; the hardened 116 was the missing record-offset input and is
  fixed in `02d7ffed4`.
- 2026-11-01: owner deferred the remaining performance gates (D18): the D16
  instruction ratios and the D14 CPU/memory re-acceptance are outside S5
  acceptance, not waived as passes. Structure, correctness and hardening remain
  the acceptance dimensions; no new performance work is authorized.

## S0 baseline table

**Measured 2026-10-31 at `0780439b3`** (coordinator). Product sources are
byte-identical to the `90dd65bee` build used for the startup/footprint rows
(`git diff --stat 90dd65bee..0780439b3 -- libc ldso crt builtins crabc-core
crabc-rs unwinder` is empty), so those rows carry over unchanged. Image pin
`sha256:6e35810928ea…a0129a`; reference `matched-llvm-23` (clang 23.1.4, musl
1.2.6 `[musl_native]`). Raw data: `.work/s0/report.md` (Run 2),
`.work/s3a/`, `.work/campaign/lanes/s1-counts/`.

Products: `materialized-dynamic-sysroot --work … --prepare` (PASS; installed
root has `lib/ld-crabc-x86_64.so.1`, `usr/lib/libc.so`, `usr/lib/Scrt1.o`) and
`owned-static-sysroot` (PASS, 72-path suite).

### Source (files / non-comment lines; `git ls-files`, `loc()` from S0.3)

| Category | Files | Lines |
| --- | --- | --- |
| `libc/src/*.rs` minus `*_tests.rs` | 555 | 122,697 |
| `libc/src/*.S` (generated musl asm, D2) | 37 | 80,215 |
| `ldso/src/*.rs` minus `*_tests.rs` | 28 | 18,293 |
| `*_tests.rs` + `tests/**` | 457 | 36,079 |
| `crt/` | 47 | 7,786 |
| `builtins/` | 125 | 12,550 |
| `crabc-core/src` | 36 | 9,026 |
| `crabc-rs/src` | 55 | 23,392 |
| `unwinder/` | 57 | 12,387 |
| `scripts/` | 37 | 27,711 |
| `compat/x86_64/*.py` | 571 | 271,054 |
| `compat/perf/` | 60 | 26,552 |
| other `compat/` (excl. allocator, x86_64, perf) | 294 | 127,943 |
| frozen `crabc-mimalloc/` + `compat/allocator/` (count only) | 922 | 533,552 |
| third-party vendored source | 0 | 0 |

Paths are git pathspecs: `*` matches `/`, so `libc/src/*.rs` is every depth.
`libc-test-harness/` (10 files, 1,618 lines) is outside the plan's category
list and is not counted above.
Inline `#[cfg(test)]` sites (`rg -c` summed): libc 13, ldso 33, crabc-core 9,
crabc-rs 14, builtins 1, unwinder 1.

### Mechanisms

| Kind | Baseline |
| --- | --- |
| Cargo features: libc / ldso / crabc-core / crabc-rs / perf-native | 40 / 7 / 2 / 7 / 3 |
| Dispatcher subcommands (`--help \| rg -c '^  [a-z0-9-]+'`) | 942 (940 distinct; 314 `*-header-abi` arms, 273 documented) |
| `scripts/dev-x86_64.sh` lines | 12,817 |
| Python entry points (plan's corrected command) | 647 |
| `compat/**/generate_*.py` | 35 |
| Distinct report formats | 22 |
| `RuntimeV1` fields | 30 |
| Symbols `libc.so` imports from the loader | 14 (13 undefined + 1 weak object) |
| Process-state owners | see below |

Process-state owners (S0.4; x86-64 roots):

| State | Defining file |
| --- | --- |
| errno | `libc/src/c_abi/x86_64/errno.rs` (`%fs` slot) |
| initial TLS block / DTV | `ldso/src/x86_64_general_initial_tls_state.rs`, `ldso/src/x86_64_initial_worker_tls.rs` allocate; `libc/src/c_abi/x86_64/dynamic_tls.rs` views the DTV; `libc/src/c_abi/x86_64/static_tls.rs` bootstraps the static form |
| thread identity | `libc/src/c_abi/x86_64/pthread_identity.rs` (`%fs:0`), `pthread_create_join.rs` (worker state) |
| stdio | `libc/src/c_abi/x86_64/stdio_standard.rs` (+ `owned_static_stdio.rs`) |
| loader graph / runtime DSOs | `ldso/src/x86_64_general_initial_loader_state.rs`, `ldso/src/x86_64_runtime_registry.rs` |
| environment | `libc/src/c_abi/x86_64/environment.rs`; `environment_runtime.rs` behind `x86-environment-runtime` |
| atexit / exit | `libc/src/c_abi/x86_64/process_exit.rs` |
| locale | `libc/src/c_abi/x86_64/locale_objects.rs`, `locale_multibyte.rs` |
| signal | `libc/src/c_abi/x86_64/signal_control.rs` |

Two states have two live definitions: the initial TLS generation (loader-owned
block) is mirrored by libc's DTV view, and loader graph state is mirrored in
`RuntimeV1` (`loader_snapshot`, `loader_information`). Both are S3b's target.
The environment pair is feature-selected, so only one is live per product.

### Linked footprint (`llvm-size -A`)

| Section | `ld-crabc` | `libc.so` | musl `libc.so` |
| --- | --- | --- | --- |
| `.text` | 83,737 | 938,821 | 360,954 |
| `.rodata` (incl. `.cst*`/`.str*`) | 1,118 | 148,972 | 219,542 |
| `.data.rel.ro` | 480 | 19,296 | 760 |
| `.data` | 192 | 18,616 | 1,048 |
| `.bss` | 78,433 | 35,848 | 11,568 |
| total | 176,353 | 1,361,890 | — |

Static hello (crabc `ld.lld -static` from owned objects): `.text` 368,488,
total 590,820. Host-musl static hello: `.text` 2,824, total 34,165.

### Startup (hand P2, wrapper subtracted, `unmatched` host musl)

| Row | musl syscalls | crabc syscalls | musl insn | crabc insn | ratio |
| --- | --- | --- | --- | --- | --- |
| dynamic hello | 9 | 25 | 35,095 | 238,681 | 6.80× |
| static hello | 4 | 10 | 856 | 173,432 | 202.6× |

Crabc dynamic +16 syscalls: split image 11 (`openat`×4, `fstat`, `pread64`,
`mmap`×4, `close`), allocator-attributed 5 (`sysinfo`, `open`×2, 2 MiB `mmap`,
`getrandom`), redundant 3 (`arch_prctl(ARCH_GET_FS)`, `gettid`, extra
`mprotect`), offset by musl-only `brk`×2 + `set_tid_address` (−3).
Static +6: allocator-attributed 5, static-TLS `mmap` 759 B
(`StaticInitialTlsPlan::materialize`), `gettid` replacing `set_tid_address`
(net 0).
Attribution. Run 2's `perf record` split (`ld-crabc` 82.6 %, `libc.so` 13.0 %)
rests on 46 samples and is not quantitative. A deterministic static probe
(`hello-static` built from this baseline) measured 173,930 instructions with
the normal 41-variable environment. The recorded 118,862 empty-environment
figure was a harness artifact: it put the host `env` process inside the
counted process (`perf stat env -i hello-static` measures 119,084), while the
same binary run directly with an empty environment measures 54,997. Corrected
2026-10-31, the environment-dependent allocator option scan is therefore
119,130 instructions, not 55,068. Kernel-patched no-init builds isolate the
allocator's complete eager share exactly: 169,278 of 244,878 direct dynamic
startup instructions (69.1 %) and 169,387 of 174,109 static startup
instructions (97.3 %). The allocator-free floors are 75,600 dynamic
(2.15 × musl's 35,105) and 4,722 static (5.52 × musl's 856), still above
1.10 ×. Sampling cannot quantify the remaining non-allocator work; the S4
startup lane owns it.

### Seed rows (S1.5, `matched-llvm-23`, dynamic PIE)

58 rows: **0 pass**, 46 fail, 11 nondeterministic, 1 unavailable
(`loader_dynamic_tls_growth` client failure). 43 of the 46 deterministic fails
are syscall-only: instructions are at or below musl and the row fails solely on
the whole-process +13/+14 startup delta. Instruction regressions:
`memcpy_16k_aligned` 1.4375, `stdio_format_parse` 1.4778,
`memcpy_64_aligned` 1.1875. The `startup` row reads `nondeterministic`: its
musl trials were 85,712 / 85,731 / 85,730 (a 19-instruction spread, 0.022 %,
over the 0.01 % allowance) while crabc's were 266,432 / 266,431 / 266,432. A
direct musl hello is deterministic (35,147 ×3, and 35,148 ×3 under
`setarch -R`), so the spread enters through the counts route's launcher, not
musl's initialisation. That row cannot be judged until the route is fixed.

### Ranked deletion list (S0.8)

1. **314 `*-header-abi` dispatcher arms (273 documented).** 244
   `compat/x86_64/run_*_header_abi*.sh` (34,461 lines) plus 179 three-line
   inline wrappers and 314 five-line arms. The scripts follow one template but
   differ per case in header, symbol, probe, `CRABC_EXPECT_*` and profile set,
   so the reduction is a declarative case table plus one runner, not a rename.
   Consumers: `tests/test_runner.py` (84 commands), `docs/evidence/**`, the
   dispatcher. Risk: medium (per-case data must be extracted verbatim).
   Checks: every case's `PASS` line unchanged; `test_runner`; parity ledger.
2. **ldso six private milestone features, source roots, fixed/general
   duplicates.** 6 features, 12 files, 9,626 lines. Consumers: 3 runner
   scripts, 2 test modules, `parity.toml`, and 71 behavioural cases with no
   product equivalent at base. The committed mapping is
   [docs/evidence/x86-retired-loader-fixtures.md](docs/evidence/x86-retired-loader-fixtures.md);
   the working row table is `.work/campaign/lanes/s3a-ldso/migration.md`.
   Risk: high. Checks: loader product cases, static suite, export identity.
3. **19 libc per-family leaf features** enabled by both owned aggregates.
   Consumer evidence: `.work/s3a/5.2-skips.md` — folding makes them
   unconditional in the frozen default archive too, changing its export
   surface and deleting the absence proofs. Risk: contract; accepted by D6.
4. **Seven per-symbol `native_abi_*_import_receipt.py` modules** (1,782 lines
   + 7 fixtures / 98 lines) reproduced from one template. Consumers:
   `native_abi_selection.py`, `abi_differential_evidence.py`, 4 test modules.
   Risk: low. Checks: identical receipt JSON, same 4 link modes.
5. **Split loader/libc images (S3b).** 1 image, 14 imports, 30 `RuntimeV1`
   fields, 11 startup syscalls.
6. **Python receipt-validating installed C driver.** 4 files, 2,505 lines
   (`crabc_cc_owned_dynamic.py`, `crabc_cc_static.py`,
   `owned_dynamic_receipt.py`, `owned_dynamic_elf.py`).

The S0.8 test for item 3 of the candidate list (subcommands consumed only by
the plan/receipt chain) is **empty**: of 940 distinct subcommands, 720 are
referenced by a real runner, 116 by nothing outside the dispatcher (107 of
them behavioural header matrices), 84 only by test tables, 20 only by docs.
The dispatcher is a behavioural surface, not chain scaffolding; its reduction
lever is the item-1 consolidation.

### Budgets (S0.9, fixed; rule: baseline − 0.8 × identified deletions)

| Area | Baseline | Identified | Budget |
| --- | --- | --- | --- |
| ldso features | 7 | 6 | **2** |
| ldso x86 product lines (AArch64 4,436 preserved separately, D15/D17) | 13,857 | 9,626 | **11,161** |
| libc features | 40 | 19 | **25** |
| dispatcher subcommands | 942 | 272 | **720** |
| `scripts/dev-x86_64.sh` lines | 12,817 | 2,380 | **11,000** |
| `compat/x86_64` Python files | 571 | 6 | **566** |
| `compat/x86_64` Python lines | 271,054 | 1,482 | **270,000** |
| dynamic startup syscalls | 25 | 14 (11 split + 3 redundant) | **14** (≤5 allocator-attributed) |
| static startup syscalls | 10 | 1 | **9** |
| dynamic startup instructions | 238,681 | none identified | **≤ 1.10 × R total (D8)** |
| static startup instructions | 173,432 | none identified | **≤ 1.10 × R total (D8)** |

D15 and D17 replace the formula for the ldso x86 line row: the rule would give
6,156, but the owner set 11,161 to keep live product mechanisms. Every other
row uses the rule.

The two instruction rows have no itemised deletion. The measured costs are
the allocator's eager init and option scan (169,278 dynamic and 169,387 static
instructions, D10) and a non-allocator loader/CRT/TLS remainder of 75,600
dynamic and 4,722 static instructions after that init is removed. Both
remainders are still above 1.10 × musl on their own, so D10's lifecycle change
lands only with the S4 startup-instruction lane and the combined rows decide
S5; there is no fabricated deletion count and no instruction exemption. `libc`
features are budgeted on the identified 19 but cannot be executed now that D6
accepts the default-archive change.

## Result table

**S0–S4 landed. S5 attempts were rejected twice; the final re-run at
`1faf5ab6f` is accepted on the structure, correctness and hardening dimensions
after independent review.** Numbers are against the budgets above.
`allocator-attributed` costs are listed, never passed. D18 deferred the
remaining instruction and CPU/memory gates; they remain unmeasured, not passed.

| Step | Merged at | Numbers vs budget | Checks | Blockers |
| --- | --- | --- | --- | --- |
| S0 | `0780439b3` | table above; nothing measured against it yet | both sysroot builds PASS; counts reproducible ≤0.0017 %, linear ≤0.0026 % | none |
| S1.1/S1.2 | `0aef1d890` (`90dd65bee`) | perf 7.1.5 in image; clang 23.1.4 matches rustc LLVM 23.1.1; matched musl installed at `/opt/musl-clang-1.2.6` | image build; `test_core_image_dispatch` 11 pass; `musl-oracle` PASS | none |
| S1.3 | `ac87382e8`, `cd4e70b80` | `perf-c counts` route; startup row now deterministic (spread ≤2 instructions) after the launcher's rusage `snprintf` was replaced; D1 allocator calls classified by name and removed from the judged total | `test_run_x86_64` 41 pass 1 skip; `test_x86_64_evidence` 46 pass; gate 23 pass; startup record on the merged product | static-PIE has no counts path; the startup row still fails on the image's own probe calls, which S4 owns |
| S1.4 | `10de7c2d9` | `SYSCALL_LIMIT_FACTOR = 1`, `INSTRUCTION_LIMIT_RATIO = 1.10`; one definition | `test_performance_release_gate` 23 pass | none |
| S1.5 | (runs, no commit) | 58 dynamic-PIE rows: 0 pass, 46 fail, 11 nondeterministic, 1 unavailable; 43 fails are syscall-only | 4 `counts` invocations exit 0 | static-PIE rows unavailable; `startup` row nondeterministic |
| S2 | `e5118b5da`, `124606078` | 942→701 commands (budget 720); 12,817→10,593 dispatcher lines (budget 11,000); Python files 572→566 (budget 566); lines 271,148→269,998 (budget 270,000) | parity ledger PASS; test_runner 92 pass; 12 dependent header modules pass; receipts byte-identical for all seven symbols; CLI replayed on the installed product | none |
| S3a (libc) | `d6cf5c2ab` | libc features 40→25 (budget 25); shipped `libc.a` 2488 names / 1,540,483 section bytes identical; `libc.so` 1661 exports and section sizes identical; default-archive ratchet +44, exactly the folded names | 15 folded-family commands pass; legacy-misc/des-compat pass; both product suites pass; parity ledger PASS | none |
| S3a (ldso) | `b7c9ab7ad` | features 7→1 (budget 2); x86 product lines 12,175→10,941 (budget 11,000, D15); total 15,377 with AArch64 4,436 preserved separately; dispatcher 678 (budget 720); 71/71 cases on the installed product; `libc.so`/loader exports 1661 identical | prepare PASS (160 loader tests); four installed-product case families PASS; static 72-path PASS; parity PASS; campaign-status 0; cargo check; structure PASS | none; full counts pending |
| S3b | `f7dcaafb5` | one ELF (same inode at both paths); startup syscalls 25→12 = 7 non-allocator (musl 9) + 5 allocator-attributed, budget 14; instructions 238,686→237,541 (empty env 116,582, so 120,350 is environment-dependent allocator work); bridges 44→30; 1661 exports, 0 undefined, 0 loader imports | full F roster PASS: loader, static 72-path, dlopen/TLS, both interposition suites, cancellation, hardened, identity 5 cases, CRT evidence, loader debug; debug payload merged | startup instruction ratio still ~6.8× musl (dominated by the frozen allocator), so the instruction dimension is not met |
| S4 instructions | `b704eec12` | memcpy_16k_aligned 1.4375→0.8750; memcpy_64_aligned 1.1875→0.8750; stdio_format_parse 1.4778→1.0997 (pass); no measured row worse | libc-memory PASS; owned-stdio PASS; counts route on the merged product; rust-check | 256k rows read nondeterministic (unchanged); stdio margin 2.4 instructions |
| S4 startup syscalls | `4b897c553` | judged startup syscalls 14→8 against musl's 11 with no per-name excess; whole 19→13; allocator-attributed 5 unchanged | prepare, identity 5 cases, dlopen PIE/non-PIE, hardened, pthread-exit, CRT evidence tests | none; startup row still fails on instructions (D8) |
| S4 static TLS | `b9f9554df` | static startup syscalls 10→9 (budget 9): the 767-byte initial-TLS `mmap` is gone, the main thread installs from 1,024 bytes of in-image `.bss`; judged non-allocator 5→4 (musl 4); startup instructions 55,184→55,171 (env -i); `.bss` +1,024 | new in-image TLS audit fails on the old product and passes on installed ET_EXEC and static-PIE; merged-tip `owned-static-sysroot` 72-path PASS; rust-check libc/crt; parity ledger PASS | focused `libc-*-static-tls` runners fail identically on the unchanged base (pre-existing mold/PLT harness rot), so the static product suite is the evidence |
| D10 lazy allocator | `26a2cb0cb` | `startup` 251,294→132,328 instructions, 3.5852→1.8879 (measured drop 118,966); `dlopen_graph` 303,601→184,635 startup, 2.6403→1.6057; allocator-attributed syscalls 5→0; static no-malloc hello 104,030→2,751 instructions and 14→5 syscalls | counts route matched-LLVM-23; lazy-init probe matrix across static/static-PIE/dynamic PIE and non-PIE; static 28-job and 72-path suite PASS; startup-errno 72 lazy cases PASS | neither startup instruction row meets 1.10; the residual 132,328/184,635 is the S4 startup lane |
| S5 hardened evidence | `02d7ffed4` | harness gap: the probe has required `CRABC_CONVENTIONAL_RECORD_OFFSET` since `1469f9e51`; the hardened runner omitted it, so the owned startup exited 116 before emitting output | `hardened-runtime` PASS on a fresh current-source compatibility product; startup probe tests 37 pass / 11 skip | none |
| S4 startup (blocked) | no commit, base `bd4c54743` | hard stop: `startup` 132,394 vs 77,101 and `dlopen_graph` 184,845 vs 126,490. Non-relocation startup is 34,721; 107 relocations (90 symbolic); musl's bare eager PLT relocation is 349 instructions each, while crabc also enforces writable-target, RELRO and symbol-extent validation. No P4 removal or inlining variant closes the gap | prepare PASS; counts deterministic twice; every experimental variant built, cased and reverted; tree clean | D16: owner keeps eager binding and hardening; startup/dlopen are a standing blocker, so S5 is not accepted on instructions |
| S4 stdio margin | `d9623b8c7` | `stdio_format_parse` 1.100061→1.096561 (9758.70→9727.67 instructions/op, +30.5 margin); `stdio_file_4k` 0.8599→0.8455; one duplicate FILE-holder load removed | counts determinism 0.0011 %, linearity 0.287 %; owned-stdio PASS; libc-stdio-format-scan PASS; rust-check; parity PASS | none for this row |
| S5 (attempt) | `d398d3ec0` rejected | **FAILED.** 58-row counts: 49 pass, 2 fail (`dlopen_graph` 2.639; `startup` 3.585 with judged syscalls 8 vs 11), 6 nondeterministic, 1 unavailable. Structure 5/7: libc 25, dispatcher 701, dispatcher lines 10,593, Python 566 / 269,998; ldso 7 features and 19,442 lines unmet. Static startup syscalls 10 vs 9. | products rebuilt at the acceptance commit; dynamic prepare, static 72-path, identity, dlopen, owned-stdio and memory suites PASS; counts report; hardened was a harness gap fixed in `02d7ffed4` | budgets unmet; startup instructions under D10; `dlopen_graph` under D11; ldso under D7; static 759-byte mmap under D12; CPU/memory under D14 (host load 20-27) |

| Counts TLS-growth | `e141118b5` | `loader_dynamic_tls_growth` unavailable→fail at fixed N=8; 421,415 vs 174,244 instructions (2.5703); per-name excess `gettid` 8, `mmap` 23, `munmap` 9, `newfstatat` 1, `pread64` 8 | single-row counts reproduced twice; `test_run_x86_64` 63 pass/1 skip; `test_x86_64_profile` 11 pass; development report | exposes a real loader/TLS-growth residual; not forced to pass |
| S4 loader syscalls | `a0ad25ead` | `dlopen_graph` judged 60→53 vs 61, per-name excess gone (`pread64` 5→0, `read` 0→5, `newfstatat` 1→0, `gettid` 1→0, `mmap` 25→20 vs 21); TLS-growth judged 133→92 vs 128 (`mmap` 58→34, `munmap` 10→2, `gettid` 8→0, `newfstatat` 1→0, `pread64` 8→0); only the required worker-TCB `munmap` 2 vs 1 remains; `ratio_insn` 1.6073→1.5977 and 2.5703→2.5666 | prepare 161 loader tests; four installed-product cases; hardened; static 72-path; parity; exports 1628 identical | `dlopen_graph` syscall dimension passes; TLS-growth retains one required `munmap`; instruction rows remain D16 |
| S4 TCB fold | `025e104b2` | worker TCB/initial TLS embedded in the guarded stack mapping, one `mmap`/`munmap` per owned worker; TLS-growth judged 92→90 vs 128 with no per-name excess, `munmap` 2→1 vs 1; instructions 421,411→421,075 vs 174,307 (2.5682); pthread row 2320.99 vs 2127.27 (1.09106), 7009 vs 7187 judged, no excess | rust-check both features; prepare 163 loader tests; cycle/dlopen-pie/dlopen-non-pie/pthread-exit/ldso-general-initial-tls PASS; hardened PASS; static 72-path PASS; parity PASS; campaign-status; `check_structure` PASS | startup/dlopen/TLS-growth ratios remain D16; pthread row nondeterministic under host load; four focused static suites were red at base, repaired by `015ef85a9`; ldso x86 product 11,161 non-comment lines, within the adjusted D17 budget (structure 7/7); D14 deferred |
| Static pthread harness | `015ef85a9` | four pre-existing red suites now PASS: create-join, cancel-deferred, detach, identity. Final static links localize weak aliases (`pthread_self`/`thrd_current`, `pthread_equal`/`thrd_equal`) and the deliberately hidden `__membarrier_init`; the archive weak bindings, same-address pairs and caller STB_GLOBAL override execution remain checked | all four suites exit 0 on the merged tip; parity validator PASS; `bash -n`; `git diff --check` | `test_runner` and `test_parity_ledger` still fail at base on unrelated command/evidence drift; separate lane needed |
| Test drift | `dff45cb88` | 23 loader commands retired by `8672fe86e` were still admitted and silently exited 0; removed their admission arms and 102 lines of stale help prose. The dispatcher closed-set audit and the two Python modules now match the ledger's intentional `owned-*` evidence commands and source owners | both modules exit 0 on the merged tip (91 tests/1 skip; 80 tests); parity validator PASS (26 families); `campaign-status`; `check_structure` PASS; `bash -n`; retired-name scan; `git diff --check` | the two dead loader runners left for a separate cleanup decision are now removed; D16/D14 still block S5 |
| S5 (second attempt) | `b255ccf2e` rejected | **NOT ACCEPTED.** 58 selected rows: 50 pass, 3 fail (`startup` 1.8886, `dlopen_graph` 1.6073, `loader_dynamic_tls_growth` 2.5703 after the fixed-N counts fix), 5 nondeterministic (128m matrices and `pthread_create_join_tls` under load), 0 unavailable. Structure 7/7: libc 25, ldso 1, ldso x86 10,941, dispatcher 678, dispatcher lines 10,357, Python 557 files / 266,174 lines. Dynamic startup syscalls 8 vs 11; static 9. | final-tip prepare, four installed-product case families, static 72-path, hardened, counts, parity, campaign-status, structure all PASS | D16 startup/dlopen/loader-TLS-growth instruction standing blockers; TLS-growth retains one required worker-TCB `munmap`; D14 CPU/memory deferred (host load 26.9); 5 load-dependent nondeterministic rows |
| S5 counts rerun | no commit, `e6fc6bf6c` | 58 rows: 49 pass, 2 fail (`startup` 1.8898, `dlopen_graph` 1.5984), 7 nondeterministic under load (`loader_dynamic_tls_growth` 2.5611, four 128m matrices, `memcpy_256k_unaligned`, `pthread_create_join_tls`); no judged syscall total exceeds its reference. Product sources identical to `025e104b2` | `perf-c counts` on `e6fc6bf6c`; `.work/tmp/tcb-merged/installed`; development report `.work/x86_64/resume-counts/counts.json` | D16/D14 deferred by D18; counts diagnostic only |
| S5 (accepted) | `1faf5ab6f` | **Structure 7/7:** libc features 25/25; ldso features 1/2; ldso x86 11,160/11,161; dispatcher 676/720; dispatcher lines 10,227/11,000; Python 556/566; Python lines 265,615/270,000. Dynamic products: 231/231 cases across installed, second and extracted; identical manifest `17357c58…`. Static product: declared 72-path suite. Syscall evidence is the diagnostic 58-row dynamic run at `e6fc6bf6c`: no judged total exceeds musl (startup judged 8 vs 11); static startup total 9 is within its 9-call budget, judged 4 vs musl 4. D18 did not re-run either at the final tip. D18: `startup` 1.8898, `dlopen_graph` 1.5984 and `loader_dynamic_tls_growth` 2.5611 are not passes; D14 CPU/memory unmeasured. | Prepare PASS (59+163 tests); full dynamic roster PASS (`qualification.json`); static 83 tests (1 skip) and 28/28 consumer jobs PASS; hardened PASS; parity ledger 26 families, structure, campaign-status, TLS runtime validator and 9 focused unit modules PASS; forbidden diff `0780439b3..HEAD` empty; independent review PASS. | none for structure/correctness/hardening; D16 instruction ratios and D14 CPU/memory remain deferred and unclaimed (D18). |

**Status — S5 accepted 2026-11-01 on structure, correctness and hardening.**
Resume prompt: "Resume the crabc simplification campaign from plan.md Status; no
allocator work." First command: `./scripts/dev-x86_64.sh campaign-status`
(exits 0). Product evidence is bound to `1faf5ab6f`; the result row and this
status are a docs-only commit after it. The owner deferred the remaining
performance gates under D18: the D16 instruction ratios and the D14 CPU/memory
re-acceptance are not measured for S5 and are not passes. The 58-row counts at
`e6fc6bf6c` stay diagnostic. Start no new performance work. Parked work: 7
`lane/*` and 2 `parked/winddown-20261026-*` worktrees under `.work/wt/`, plus 230
refs under the `cohort/*`, `lane/*`, `parked/*`, `recovery/*`, `review/*`,
`proof/*`, `archive/*` and `integration/os82` names (178 not merged into
`main`). Cause: superseded or unverified pre-reset lanes. The 13 `cohort/*` checkouts were retired on 2026-11-01 after
their reports were preserved under `.work/retained/` and every branch ref was
kept; only the 9 lanes above remain registered. Retry only on explicit owner
direction. `git worktree list` is authoritative. Custody rules:
`docs/lanes.md`. The two dead loader runners named in the test-drift lane were
removed; no owner decision remains open there.

### Decisions from the rejected S5 attempts (2026-10-31)

The earlier S5 attempts were rejected; each unmet dimension got an owner
decision and a lane, and the remaining work produced the acceptance above.

1. **Startup instructions — D10.** Eager allocator init is 169,278 of 244,878
   dynamic startup instructions (69.1 %) and 169,387 of 174,109 static
   instructions (97.3 %). A kernel-patched no-init build leaves 75,600 dynamic
   (2.15 × musl) and 4,722 static (5.52 × musl), so the lifecycle change alone
   cannot pass; it lands with an S4 startup-instruction lane and the combined
   rows decide S5. No instruction exemption is taken. The lazy-init lane
   measures `startup` 3.5852→1.8879 and `dlopen_graph` 2.6403→1.6057; the
   remaining 132,328/184,635 instructions are the S4 target, led by
   `__crabc_x86_64_self_relocate`.
2. **ldso — D7 done at `b7c9ab7ad`.** 71/71 cases run through the installed
   product; features 7→1; x86 product lines 10,941 against the then-D15
   budget of 11,000 (D17 later raises it to 11,161); parity and
   campaign-status pass.
3. **`dlopen_graph` — D11/D16.** Its operation delta is already at parity
   (15,582 vs 15,592 instructions); the post-D10 row is startup-bound at
   184,845 against 126,490 and shares D16's standing blocker. No separate
   resolver lane is opened.
4. **Static 759-byte `mmap` — D12 done in `b9f9554df`.** The main thread
   installs from in-image `.bss`; static startup is 9 calls against the 9
   budget, with the allocator-attributed five unchanged. Oversized templates
   and workers retain the private mapping.
5. **Hardened exit 116 — D13 done in `02d7ffed4`.** The evidence probe had
   required `CRABC_CONVENTIONAL_RECORD_OFFSET` since `1469f9e51` and the
   hardened runner never passed it. `hardened-runtime` passes on a fresh
   current-source compatibility product.

CPU and memory remain deferred under D14 until the host satisfies the existing
load policy. The 2026-10-29 S0 questions were already answered as D6–D8; their
evidence stays in Git history.

The owner chose D16 over a new indexed resolver. The second S5 attempt at
`b255ccf2e` therefore remains unaccepted on the startup-instruction and
CPU/memory dimensions: 50 of 58 selected rows pass, with `startup`,
`dlopen_graph`, `loader_dynamic_tls_growth` and five load-dependent
nondeterministic rows left. Structure, loader, static-TLS, stdio, hardened
evidence and the remaining selected rows are addressed. The later
loader-syscall, TCB-fold, static-pthread-harness and test-drift lanes removed
the per-name syscall excess, the last required `munmap`, the four red static
suites and the two red Python modules; the three instruction ratios remain
deferred under D18, and ldso x86 is 11,160 non-comment lines within the D17
budget. The final re-run at `1faf5ab6f` is the acceptance above.

## Non-goals

Allocator work; new capabilities, platforms or public surface; AArch64
execution or emulation; weakening semantics, safety, hardening or evidence; a
new validation framework; whole-toolchain integration; physical NUMA/huge-page
qualification; publication; counting documentation or test reduction as
runtime simplification.
