# crabc Repository Structural Cleanup

Perform a complete, disciplined, repository-wide structural cleanup. The objective is to leave the repository in a pristine state: easy to navigate, explicit about ownership, internally consistent, free of dead architectural residue, and protected against returning to its current accreted shape.

This is a **zero-feature, zero-semantics-change refactor**. Everything that currently works must continue to work. Do not add new libc capabilities, broaden compatibility, redesign APIs, pursue performance work, or begin x86-64 support.

Work autonomously. Do not stop merely because a refactor is large. Break it into independently verifiable tranches and keep the repository green after every tranche.

## Mission

The finished repository should make these boundaries obvious from its directory structure:

```text
crabc-core
    Stateless, typed, no_std Linux/AArch64 operations.
    Direct kernel/vDSO boundaries.
    No process-global runtime ownership.

libc
    Public C ABI translation.
    TLS errno, FILE, pthread, locale, process-global state, and other libc-owned state.
    C compatibility machinery that must not leak into crabc-rs.

ldso
    The one production dynamic linker.
    ELF loading, relocation, symbol resolution, loader TLS, and loader-owned state.

crabc-rs
    Idiomatic Rust-facing OS/runtime capabilities.
    Primarily a consumer and contract oracle during this cleanup.

compat / tests / libc-test-harness
    Executable evidence.
    They must follow moved code without having their assertions weakened.
```

A new contributor should be able to determine where any implementation belongs without searching a 5,000-line file or reverse-engineering an `include!` graph.

## Current findings that must be resolved

### 1. Remove the obsolete root loader helper

The root package exists only to build `src/main.rs` and `src/loader_core.rs`. This helper is separate from the real `ldso`, retains x86-64 and RISC-V code, and assumes a fixed 4 KiB page size.

Remove it completely.

Required outcome:

* Search for all users, tests, scripts, and documentation referring to:

  * the root `loader` binary;
  * `src/main.rs`;
  * `src/loader_core.rs`;
  * root-package execution.
* If it contains a genuinely useful test scenario not already covered by `ldso`, preserve the scenario as a focused `ldso` or integration test. Do **not** preserve or transplant the helper implementation.
* Delete the root `src/` directory.
* Delete the root `[package]` and `[[bin]]` sections.
* Make the root `Cargo.toml` a virtual workspace manifest.
* Regenerate `Cargo.lock` through Cargo; do not edit it manually.
* Update every code map and document that describes the root helper.
* Confirm `cargo metadata` reports only the four real workspace members:

  * `crabc-core`;
  * `crabc-libc`;
  * `crabc-ldso`;
  * `crabc-rs`.

Do not move its dead multi-architecture abstractions into `ldso`.

### 2. Replace all references to deleted `TODO.md`

`TODO.md` has been deleted, but active documentation still treats it as the authoritative work list.

Create a concise root `STATUS.md` as the durable status router. It should state:

* the current Linux/AArch64 implementation profile is closed;
* compatibility evidence and generated measurements live in `COMPATIBILITY.md`;
* performance completion is governed by `docs/roadmap/performance-completion.md`;
* real-software/native-application validation is governed by `docs/roadmap/software-corpus-validation.md`;
* source-build and sysroot progression is governed by `docs/roadmap/source-build.md`;
* historical documents are provenance, never an active backlog;
* no chronological microtask list is the project authority.

Then replace every active reference to `TODO.md`, including statements such as “the sole prioritized work list,” with the correct durable authority.

At minimum audit:

```text
README.md
AGENTS.md
docs/README.md
docs/roadmap/performance-completion.md
docs/roadmap/software-corpus-validation.md
docs/roadmap/source-build.md
all other Markdown, scripts, comments, and manifests
```

Historical documents may mention that a TODO once existed only when that fact is genuinely historical and cannot be mistaken for active direction.

Final repository search must return no dangling active `TODO.md` links.

### 3. Fix all stale Cargo repository metadata

Replace every stale repository value pointing at the prior upstream with:

```text
https://github.com/joshuarli/crabc
```

Do this repo-wide, not only in the root manifest.

Use `[workspace.package]` for metadata that is genuinely identical across all packages:

```toml
[workspace.package]
version = "0.3.0"
edition = "2021"
license = "MIT OR Apache-2.0"
repository = "https://github.com/joshuarli/crabc"
```

Have member manifests inherit those values with `.workspace = true` where supported and clear.

Keep crate-specific names, descriptions, readmes, crate types, features, and dependencies local.

Make the Cargo feature resolver explicit. Prefer resolver 2 because the workspace is Rust 2021, but verify the resulting locked feature graph and all builds before accepting the change. Do not silently change dependency versions or feature activation as collateral cleanup.

### 4. Regenerate the compatibility dashboard from the cleaned source state

The checked-in dashboard must correspond to the final cleaned code, not an earlier implementation revision.

Use this evidence sequence:

1. Complete and commit all source, manifest, test, harness, and documentation changes.
2. Start from a clean tree and record the exact tested source commit.
3. Run the complete required evidence suite against that commit.
4. Ensure generated reports record:

   * tested source commit;
   * `dirty = false`;
   * Docker image/toolchain provenance;
   * hashes of the built `libc`, `ldso`, headers, and relevant inputs.
5. Generate `COMPATIBILITY.md` only from those fresh reports.
6. Commit the generated dashboard in a final evidence-only commit.
7. Verify that the evidence commit changes no source, manifest, test, harness, toolchain, or build input relative to the tested source commit.

If the dashboard generator does not currently retain tested-source provenance, add that capability. Do not create an impossible self-referential “commit hashes itself” scheme; the tested source commit plus an evidence-only child commit is the correct model.

## Non-negotiable compatibility constraints

Preserve all of the following:

* Linux/AArch64 little-endian only.
* Linux 5.10 kernel baseline.
* Musl 1.2.6 as the C/POSIX oracle.
* Rustix as a test-only native comparison oracle.
* No glibc fallback or oracle.
* Existing dynamic C symbol names, types, bindings, visibility, and linkage.
* Existing static-link behavior.
* Installed header declarations, constants, layouts, and include behavior.
* Exact errno values and error selection.
* Signal, cancellation, pthread, TLS, loader, relocation, constructor, destructor, and `dlopen` semantics.
* Existing private `RuntimeV1` wire ABI layout and versioning.
* Existing public `crabc-rs` API paths and feature combinations.
* Existing `crabc-core` public paths used by `libc` and `crabc-rs`.
* Current allocator and crypto decisions.
* Current panic, LTO, linker, and code-generation profiles.
* Current intentional compatibility limitations and skip classifications.

Do not:

* add x86-64, RISC-V, portability abstractions, or inactive architecture scaffolding;
* add dependencies or upgrade dependency versions;
* redesign the allocator;
* hand-roll crypto;
* change locale, resolver, NSS, or text policy;
* remove C symbols because Rust code does not reference them;
* alter tests to accommodate a refactor;
* add skips, exclusions, normalization, or `continue-on-error`;
* mix behavior changes or optimization experiments into module-movement commits;
* turn this into a style-only rewrite with enormous blame-destroying diffs.

## Definition of “pristine”

The cleanup is complete only when the following are true:

* Root entry files are composition roots, not implementation containers.
* Every module has one clear responsibility.
* Stateful ownership is obvious.
* Public and private interfaces are narrow and named deliberately.
* There is no generic architecture abstraction for hypothetical ports.
* There is no obsolete root package or duplicate loader.
* There are no stale metadata URLs or dead documentation links.
* There are no unexplained root-level `include!` chains.
* There are no broad visibility changes merely to make splitting easy.
* There are no indiscriminate glob imports or re-exports.
* There are no new crate-wide lint suppressions.
* Tables and cohesive algorithms may remain large; accidental multi-domain files may not.
* Tests and evidence reference the new source locations accurately.
* The complete compatibility suite is baseline-or-better.
* `COMPATIBILITY.md` describes the cleaned source state.

Do not create “tiny file soup.” Split by ownership and domain, not by arbitrary line count or one function per file.

## Execution discipline

### Work in small, reviewable tranches

Use a dedicated branch or worktree. Preserve unrelated work.

For every extraction:

1. Add or identify the characterization test that protects the boundary.
2. Move code mechanically.
3. Repair imports and visibility narrowly.
4. Run the smallest relevant tests.
5. Run the symbol/ABI ratchet where C or loader code is involved.
6. Review the diff for accidental logic changes.
7. Commit the tranche.
8. Only then perform local naming, documentation, or formatting cleanup in a separate commit if needed.

A file move and an algorithm rewrite must never share a commit.

Use explicit imports. Avoid solving module-boundary errors with `pub(crate)` everywhere or `use super::*`.

Preserve useful source history with `git mv` when moving whole files. When extracting ranges from monolithic files, keep the moved text as close to byte-for-byte as Rust module syntax permits before applying cleanup.

### Establish an authoritative baseline first

Before editing, record:

```sh
git status --short
git rev-parse HEAD
git submodule status 2>/dev/null || true
```

Build the pinned image and capture a fresh baseline from the current source. Store temporary before/after reports outside checked-in generated outputs so they cannot be confused with final evidence.

At minimum run:

```sh
./scripts/dev.sh image
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh compat
./scripts/dev.sh crabc-rs
./scripts/dev.sh ldso
./scripts/dev.sh differential
./scripts/dev.sh libc-test all
```

Also record:

* workspace package graph;
* all production dependencies and feature combinations;
* public dynamic symbol inventory;
* static archive inventory;
* installed-header inventory;
* loader feature inventory;
* release `.text` and stripped artifact sizes;
* current test pass/fail/skip counts;
* current corpus and loader results.

The fresh baseline, not assumptions or stale prose, is the comparison authority.

## Structural tranche 1: clean the workspace root

Perform the root-helper deletion and workspace conversion first.

The root manifest should end as a concise virtual workspace containing:

* workspace members;
* an explicit resolver choice;
* shared package metadata;
* the existing development and release profiles.

It should not describe or build a root crate.

After this tranche:

```sh
./scripts/dev.sh build
./scripts/dev.sh test
cargo metadata --no-deps --format-version 1
```

Run the canonical commands inside the project’s pinned environment rather than introducing a parallel host workflow.

Search the whole repository for stale helper references before committing:

```sh
rg -n 'src/main\.rs|src/loader_core\.rs|name\s*=\s*"loader"|root loader|loader helper' .
```

Any retained match must be intentional historical provenance, not active architecture.

## Structural tranche 2: decompose `crabc-core`

`crabc-core/src/lib.rs` must become a small crate composition root.

It currently mixes:

* `Errno`, result, and raw descriptor types;
* the private versioned runtime wire ABI;
* raw syscall numbers and AArch64 syscall entry functions;
* descriptor I/O;
* filesystem operations;
* pipes;
* randomness;
* time and vDSO dispatch;
* polling/events;
* networking;
* resolver transport;
* memory management;
* signals;
* processes;
* threads;
* system information;
* IPC;
* inotify;
* mounts;
* unit tests.

Split these into coherent external modules while preserving all existing public paths.

An appropriate target shape is:

```text
crabc-core/src/
    lib.rs
    error.rs
    runtime.rs
    syscall.rs

    io.rs
    fs.rs                 or fs/
    pipe.rs
    rand.rs
    time.rs
    event.rs
    net.rs                or net/
    resolver.rs           or resolver/
    mm.rs
    signal.rs
    process.rs
    thread.rs
    system.rs
    ipc.rs
    inotify.rs
    mount.rs

    fenv.rs
    iconv.rs
    iconv_iso8859.rs
    param.rs
    pattern.rs
    text.rs
    vdso.rs
```

The exact use of a single file versus a directory should follow cohesion:

* Keep a domain in one file when it remains understandable and focused.
* Use a directory when a domain contains several independently understandable concerns.
* Do not create generic `platform`, `backend`, or `arch` frameworks for a target that has only one implementation.
* A concrete private AArch64 syscall or vDSO module is acceptable; a trait with one implementation is not.

### Required `crabc-core` invariants

Keep these public paths stable:

```text
crabc_core::Errno
crabc_core::Result
crabc_core::RawFd
crabc_core::AT_FDCWD
crabc_core::runtime::...
crabc_core::io::...
crabc_core::fs::...
crabc_core::process::...
crabc_core::thread::...
and every other existing public module path
```

Use private modules plus root `pub use` only where necessary to preserve an existing root path.

`runtime.rs` must remain a data-only private-runtime wire contract. Do not place runtime ownership or process-global state in `crabc-core`.

`syscall.rs` should own:

* the concrete Linux/AArch64 syscall instruction boundary;
* syscall result decoding;
* syscall numbers or their single authoritative source;
* no public policy abstractions.

Do not duplicate syscall constants across domain modules.

Move unit tests to the module that owns the behavior, or to a clearly named internal test module when cross-domain access is necessary. Do not leave thousands of lines of tests at the bottom of `lib.rs`.

The final `crabc-core/src/lib.rs` should contain only:

* crate documentation and attributes;
* target compile guard;
* module declarations;
* carefully chosen root re-exports;
* no large tables;
* no syscall implementation;
* no inline domain modules;
* no substantive function bodies.

A reasonable target is under roughly 300 lines, but structural clarity is the real gate.

### Validate every core extraction

After each domain or closely related group:

```sh
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh crabc-rs
```

Also run the domain-specific integration tests and direct-boundary verification scripts that mention the moved source.

Search machine-readable evidence for old file references:

```sh
rg -n 'crabc-core/src/lib\.rs' compat tests scripts docs crabc-rs libc ldso
```

Update:

* capability-ledger evidence paths;
* source-shape verifiers;
* assembly/direct-syscall verifiers;
* performance source references;
* documentation links.

Do not delete an assertion merely because its source moved. Teach the verifier where the invariant now lives.

## Structural tranche 3: rationalize `libc`

Treat `libc` more conservatively than `crabc-core`. It owns delicate C ABI and process-global behavior.

### Remove dead portability residue

The active crate is Linux/AArch64-only, yet `libc/src/lib.rs` contains:

* a generic `Syscalls` trait;
* `X86_64`, `Aarch64`, and `Riscv64` marker types;
* x86-64 syscall assembly;
* RISC-V syscall assembly;
* architecture-selected constants.

Remove the x86-64 and RISC-V production code and eliminate the one-implementation trait abstraction.

Replace it with one concrete private Linux/AArch64 syscall boundary.

Audit all production Rust sources for similar dead target branches:

```sh
rg -n 'target_arch\s*=\s*"(x86_64|riscv64)"|X86_64|Riscv64|R_RISCV|R_X86_64' \
    libc ldso crabc-core crabc-rs
```

Do not blindly remove architecture names from:

* pinned upstream evidence;
* ABI inventory data;
* historical documentation;
* deliberately cross-target host tooling.

Every retained production-code match needs a current, documented reason.

### Make `libc/src/lib.rs` a composition root

The current root-level `include!` chain and inline implementation make ownership opaque.

Refactor toward domain modules such as:

```text
libc/src/
    lib.rs

    aarch64/
        mod.rs
        syscall.rs
        atomic.rs
        memory.rs
        startup.rs

    runtime/
        mod.rs
        errno.rs
        startup.rs
        auxv.rs
        termination.rs

    allocator/
    filesystem/
    descriptor/
    stdio/
    process/
    pthread/
    signal/
    time/
    network/
    resolver/
    locale/
    text/
    math/
    loader_bridge/
    compatibility/
```

This is a conceptual ownership map, not a requirement to create every directory. Reuse sensible existing files and avoid needless renaming.

The critical conventions are:

* `lib.rs` composes modules; it does not implement every subsystem.
* C-export modules contain C ABI adaptation and symbol definitions.
* Substantive algorithms and state machines live in the domain that owns them.
* A file named `*_exports.rs` should primarily contain C entry points and ABI translation, not an unrelated implementation pile.
* Architecture-specific assembly and calling-convention glue are visibly AArch64-specific.
* Process-global state remains in `libc`, not moved into `crabc-core`.
* Loader-owned state remains in `ldso`.

### Handle `include!` safely

Do not mechanically convert all `include!` calls in one patch.

Classify every include:

1. **Ordinary Rust module**
   Convert it to a normal `mod` declaration and explicit imports.

2. **Cohesive lexical family**
   For example, math fragments that intentionally share private helpers. Move the include list into a focused domain aggregator such as `math/mod.rs`. This removes it from the crate root while preserving lexical coupling.

3. **Generated table or generated source**
   Place it in a clearly named generated/table location, add a generated-source header or provenance comment, and retain `include!` only when justified.

4. **Assembly/linkage-sensitive fragment**
   Retain the include only with a concise explanation of why an ordinary module would alter the required boundary.

The final root `lib.rs` must contain no unexplained include chain.

Do not force every math file into an independent module if that creates broad visibility churn and risks numerical behavior. A focused `math` aggregation module is cleaner and safer than root-level inclusion.

### Preserve ELF and C ABI details

Moving a `#[no_mangle]` function into a Rust module must not change its exported C symbol, but verify rather than assume.

For every libc tranche, compare before and after:

* dynamic symbol names;
* symbol type;
* strong/weak binding;
* visibility;
* static archive surface;
* weak aliases and linkage;
* relevant ELF sections;
* relocation behavior;
* installed headers;
* loader interaction;
* release artifact sizes.

Pay special attention to:

```text
#[no_mangle]
#[linkage]
#[link_section]
#[used]
global_asm!
weak aliases
thread-local objects
constructor/destructor arrays
panic/personality symbols
startup and TLS symbols
```

Do not move such definitions casually across visibility or macro boundaries.

### Do not over-consolidate `libc` and `crabc-core`

There may be duplicated-looking syscall or conversion code.

Use this ownership rule:

* Stateless typed kernel operation: potentially `crabc-core`.
* C argument decoding, errno translation, ABI layout, TLS errno: `libc`.
* `FILE`, pthread, locale, termination, process-global caches: `libc`.
* Loader graph, relocations, symbol scope, loader TLS: `ldso`.

Do not move substantive implementation between crates merely because two functions look similar. Prefer within-crate organization during this cleanup.

Consolidate a duplicate only when:

* both copies have the same contract;
* a characterization test protects each caller;
* the direct-boundary and performance implications are understood;
* no process-singleton state changes owner;
* the resulting diff remains reviewable.

Otherwise leave the implementations separate and document why.

## Structural tranche 4: repository-wide hygiene

After the major module splits are green, perform a focused hygiene pass.

### Naming and comments

* Replace temporary, milestone, migration, or chronology-based names in active code with durable domain names.
* Preserve historical names only under `docs/history/`.
* Replace informal or cryptic comments with explanations of invariants and ownership.
* Remove comments that merely narrate syntax.
* Preserve comments explaining ABI, unsafe, memory ordering, cancellation, loader, and numerical subtleties.
* Give every new module a concise module-level responsibility statement.
* Do not produce essay-length module comments that duplicate architecture documentation.

### Visibility and imports

* Prefer private by default.
* Use `pub(crate)` only for an identified cross-module contract.
* Keep public exports intentional.
* Replace broad imports with explicit names.
* Avoid cyclic domain dependencies.
* Do not introduce a generic “util” dumping ground.
* Shared primitives need a precise owner such as `error`, `syscall`, `runtime`, or a specific domain.

### Lints and formatting

* Remove broad crate-level allowances when they are no longer necessary.
* Scope unavoidable C-naming or generated-code allowances to the smallest module.
* Do not replace warnings with blanket `allow`.
* Format touched and moved Rust code with the pinned toolchain.
* Keep pure formatting separate from semantic or structural changes when the diff would otherwise be difficult to review.
* Run `git diff --check`.
* Do not reformat generated upstream evidence or large untouched tables merely for churn.

Every touched unsafe block must retain or gain an accurate `SAFETY:` explanation where its invariant is not self-evident. Do not turn this cleanup into an unrelated whole-repository unsafe rewrite.

### Documentation architecture

Add a concise canonical architecture document, preferably:

```text
docs/design/architecture.md
```

It should explain:

* the five repository layers;
* state ownership;
* allowed dependency direction;
* the distinction between `ldso` and libc;
* the private runtime wire boundary;
* where C ABI adaptation ends and typed native operations begin;
* where compatibility evidence lives.

Update `README.md`, `AGENTS.md`, and `docs/README.md` to route to it rather than duplicating it.

The final documentation hierarchy should be unambiguous:

```text
SCOPE.md
    project doctrine and non-goals

COMPATIBILITY-PROFILE.md
    supported semantic profile and deliberate limitations

STATUS.md
    current completion state and roadmap router

docs/design/architecture.md
    code ownership and dependency architecture

COMPATIBILITY.md
    generated current evidence

docs/roadmap/*
    detailed future acceptance contracts

docs/history/*
    provenance only
```

## Structural regression guard

Add a small, dependency-free structural check using the existing project scripting language—prefer Python standard library—and expose it through:

```sh
./scripts/dev.sh structure
```

The check should reject at least:

* a root `src/` directory or root Cargo package;
* references to deleted `TODO.md` outside explicitly historical provenance;
* the stale prior repository URL;
* production x86-64 or RISC-V target branches outside a narrow explicit allowlist;
* new inline domain modules in `crabc-core/src/lib.rs`;
* a return of substantive implementation to the composition roots;
* unexplained root-level `include!` additions in `libc/src/lib.rs`;
* stale references to removed source paths in machine-readable evidence.

Do not add arbitrary maximum sizes for every file. Large generated tables and cohesive numerical algorithms are legitimate.

It is appropriate to ratchet only composition roots, for example:

* `crabc-core/src/lib.rs` remains a small declaration/re-export file;
* `libc/src/lib.rs` remains a composition/linkage root;
* no new root-level implementation is added without an explicit allowlist rationale.

Add this check to the existing fast CI path. Do not redesign the complete CI system as part of this cleanup.

Remove `continue-on-error` from any currently selected compatibility check that the repository now expects to pass. A green gate must actually gate.

## Per-commit validation

Use this minimum matrix.

### Pure documentation or manifest metadata

```sh
./scripts/dev.sh structure
./scripts/dev.sh build
```

### `crabc-core` movement

```sh
./scripts/dev.sh structure
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh crabc-rs
```

### `libc` movement

```sh
./scripts/dev.sh structure
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh compat
./scripts/dev.sh differential
```

Add the directly affected libc-test subset and integration cases.

### `ldso`, startup, TLS, symbol, or linkage-adjacent movement

```sh
./scripts/dev.sh structure
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh compat
./scripts/dev.sh ldso
./scripts/dev.sh pthread-stress
./scripts/dev.sh static-pthread-tls
```

Run any narrower loader regression before the broad suite.

## Final exhaustive proof

From a clean tree at the final source commit, run:

```sh
./scripts/dev.sh structure
./scripts/dev.sh build
./scripts/dev.sh test
./scripts/dev.sh compat
./scripts/dev.sh abi-probe
./scripts/dev.sh loader-inventory
./scripts/dev.sh ldso
./scripts/dev.sh differential
./scripts/dev.sh libc-test all
./scripts/dev.sh os-test
./scripts/dev.sh pthread-stress
./scripts/dev.sh static-pthread-tls
./scripts/dev.sh signal-process
./scripts/dev.sh resolver-network
./scripts/dev.sh corpus --tier all
./scripts/dev.sh rust-std
./scripts/dev.sh rust-std-dependent
./scripts/dev.sh crabc-rs
./scripts/dev.sh lto
./scripts/dev.sh lto-native-facade
./scripts/dev.sh lua
./scripts/dev.sh dashboard
```

Use the exact options documented by the owning harness when a command needs an explicit full-suite flag.

No test may be omitted merely because it is slow or because the affected source “only moved.”

Where an external test-only checkout is required, use the pinned revision and record it. Do not add it as a production dependency.

### Acceptance rule

The freshly measured baseline is authoritative. Final results must be baseline-or-better.

At minimum preserve the current checked-in expectations:

* no required musl dynamic symbol missing;
* no public dynamic ABI metadata mismatch;
* no new unexpected symbol without explanation;
* no libc-test failure, build error, or timeout;
* no new libc-test skip;
* all selected loader cases pass;
* all Alpine corpus cases pass with exact status/stdout/stderr behavior;
* all Rust `std` workloads pass;
* all native `crabc-rs` capability and direct-boundary checks pass;
* all selected POSIX, signal/process, resolver/network, pthread/TLS, and static-link evidence remains green;
* no capability changes from verified to deferred or merely documented;
* no header or private runtime wire ABI regression.

Do not convert a failure into a skip, scope exclusion, normalization rule, or informational-only result.

## Performance and code-size guard

This is not a performance project, but source organization can alter code generation.

Record before/after release evidence for:

* `.text`;
* stripped `libc.so`;
* stripped `libc.a` composition;
* `libldso.so`;
* startup mappings and syscall counts;
* a representative set of existing hot paths.

Use the existing performance harness and its established methodology. Do not use ad hoc wall-clock timing.

A reproducible material regression must be investigated. Fix structural causes or revert the responsible tranche. Do not begin unrelated optimization work, and do not weaken existing performance contracts.

Binary identity is not required: moving Rust code can alter internal layout and debug provenance. Public ABI, semantics, evidence, and non-regressing measured behavior are required.

## Commit structure

Keep commits coherent and independently green. A suitable sequence is:

1. `chore: record cleanup baseline and add structural guard`
2. `chore: remove obsolete root loader package`
3. `docs: replace deleted todo authority with status router`
4. `chore: centralize workspace package metadata`
5. `refactor(core): extract error and syscall substrate`
6. `refactor(core): extract private runtime wire contract`
7. Several domain-sized `refactor(core): ...` commits
8. `refactor(libc): remove inactive architecture scaffolding`
9. Several domain-sized `refactor(libc): ...` commits
10. `docs: document runtime ownership architecture`
11. `chore: finish naming lint and formatting cleanup`
12. `test: regenerate complete compatibility evidence`

Adjust the exact sequence to dependency order, but do not squash the entire cleanup into one opaque commit.

Every commit message should name the ownership or structural improvement, not “cleanup part 7.”

## Final review

Before declaring completion, perform these searches:

```sh
rg -n 'TODO\.md' .
rg -n 'https://github\.com/mengzhuo/crabc' .
rg -n 'src/main\.rs|src/loader_core\.rs|root loader|loader helper' .
rg -n 'target_arch\s*=\s*"(x86_64|riscv64)"' libc ldso crabc-core crabc-rs
rg -n 'crabc-core/src/lib\.rs|libc/src/lib\.rs' compat tests scripts docs
rg -n 'include!\(' libc/src/lib.rs
```

Classify every remaining match. Do not accept accidental leftovers.

Then review:

* `git diff --check`;
* `cargo metadata`;
* workspace package list;
* dependency graph;
* feature graph;
* public Rust API paths;
* dynamic and static symbol reports;
* header inventory;
* generated dashboard provenance;
* final source tree.

## Completion report

Return a precise report containing:

1. The tested source commit and final evidence commit.
2. The final top-level and crate-level module map.
3. Every deleted obsolete file.
4. Every public path intentionally preserved through a re-export.
5. The before/after size of the main composition roots.
6. The before/after package and dependency graph.
7. Dynamic/static ABI comparison.
8. Complete test and evidence results.
9. Performance and artifact-size comparison.
10. Any retained large files and why they are cohesive or generated.
11. Any retained `include!`, architecture reference, broad visibility, or lint allowance and its exact rationale.
12. Confirmation that the final evidence commit contains no post-test code changes.

Do not finish with vague statements such as “all tests seem fine.” Include commands, report paths, counts, and exact outcomes.

The desired end state is not merely smaller files. It is a repository with a visible architecture, disciplined ownership, no dead layers, no stale authority, and executable proof that the cleanup changed structure rather than behavior.
