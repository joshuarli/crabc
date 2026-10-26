# Ordered qualification chain

Qualification runs eight gates in one fixed order. Each gate is also the
`parity.toml` family of the same id; the family status records an earlier
admission, while the chain re-proves the gate against the current checkout.
Nothing here is a pass until a receipt revalidates (see Receipts).

| # | Gate | What it consumes (published as) | Producer command |
| - | ---- | ------------------------------- | ---------------- |
| 1 | `compat.abi-differential` | one current-source cohort of ABI inventory, ELF facts, declaration inventory, public-data link report and selection companions (`abi-evidence`) | `abi-differential-evidence assemble` |
| 2 | `compat.posix-process` | the native POSIX aggregate receipt (`posix-native`) | `owned-posix-native` |
| 3 | `compat.resolver-network` | the retained resolver-network report (`resolver-network`) | `owned-resolver-network`, or the network step of `owned-resolver-family` |
| 4 | `compat.loader-corpus` | the loader family receipt (`loader-family`) | `owned-loader-family --work DIR` |
| 5 | `consumer.rust-std-lto` | the Rust std/LTO consumer receipt (`rust-std-lto`) | `consumer-rust-std-lto run` |
| 6 | `consumer.source-build` | the Lua source-build admission (`lua-source-build`) | `lua-source-build-admission --output DIR` after `lua-static-source-build` and `lua-dynamic-source-build` |
| 7 | `capability.accounting` | `parity.toml` and the frozen baseline; no publication | `python3 compat/x86_64/validate_parity_ledger.py` |
| 8 | `performance.release` | retained performance receipts; never measures (`performance-release`) | `python3 compat/x86_64/performance_release_gate.py evaluate` |

All commands are `./scripts/dev-x86_64.sh <command>` except the two Python
validators. Each producer's own contract document owns its inputs and flags;
`./scripts/dev-x86_64.sh --help` lists them.

## Declarations

`qualification_manifest.json` declares every gate `ready` with a finite,
hash-pinned case manifest. `generate_qualification_manifest.py --check` keeps
the generated projection (`generated/qualification_manifest.json`) current.
`consumer.source-build` runs `compat/lua/qualify_source_build.py`
(`qualification_source_build.json`, see `compat/lua/README.md`); the loader gate
uses `qualification_loader_corpus.json`; every other gate names a manifest in
`qualification-gates/` whose single `gate-conditions` case runs
`run_qualification_gate.py GATE`. Ready means executable and hash-pinned, never
passed. `promotion_ready` stays false and `completed_gate_count` stays zero in
the declaration.

## Profiles

`qualification_profile` in the declaration selects the default scope, currently
`full`. `--profile` overrides it for ordered execution and `--status` only.

- `full`: all eight gates.
- `correctness`: the first seven gates; `performance.release` is deferred
  because it needs an uncontended host.

A correctness receipt records its deferred gate, so it is never a full-chain
result (`complete_profile` is true only when the profile's last gate passed).

## Gate conditions

`qualification_gates.py` evaluates one gate as named conditions:

- `prerequisite-families` lists every transitive `depends_on` family and every
  earlier chain gate that is not `foundation-verified`.
- `evidence[N]` covers each `native_evidence` command of the gate family. A
  command needs a registered reader; a prose placeholder or unregistered
  command is itself the unmet condition. Readers call the leaf's own validator:
  `publication` readers reread a published retained receipt, `report` readers a
  fixed-location report, `ledger` readers checked-in source, and `execution`
  readers run a self-contained native leaf (only once every other condition is
  met).
- `capability.accounting` adds `capability-completion`, naming every frozen
  capability not yet `implemented-foundation`.

The gate case prints the condition record and exits 1 with
`x86 qualification gate GATE: UNMET (...)`; only a native evaluation with every
condition met ends with `x86 qualification gate GATE: PASS`. Host evaluation
(`campaign-qualification` while blocked) reports prerequisites, registration and
completion checks and leaves native reads unevaluated. A gate is closed by
making its ledger command executable and registering its reader in
`qualification_gates.py`; no case-manifest pin changes.

## Publication

Leaves that write caller-chosen directories are selected with

```sh
./scripts/dev-x86_64.sh qualification-manifest --publish GATE PUBLICATION RECEIPT
```

Publishing runs the leaf reader first, then atomically writes
`.work/x86_64/qualification-evidence/GATE/PUBLICATION.json` holding the
receipt path and byte hash. The gate rereads the receipt through the leaf reader
on every evaluation, so a replaced, stale-source or partial receipt fails.
Publication names are the ones in the table above; each is paired with its
gate and the receipt file its producer writes: `abi-evidence.json`,
`native-execution.json`, the resolver report copy `STATE_ROOT/report.json`,
`receipt.json` (loader, Rust std/LTO, performance) and `admission.json` (Lua).

`abi-evidence` binds one current-source set: the static preparation and
product, the materialized dynamic product, and the native ABI inventory, ELF
facts, declaration inventory, public-data link report and selection companion
receipts. `collect-companions` runs each companion's runner (`PRODUCERS` in
`abi_differential_evidence.py`) against that one cohort and writes
`companions.json`; a failed runner, and any companion that consumes its receipt,
is recorded and never bound, so its selection blockers stay open. The text-family
and POSIX `__sysv_signal` receipts come only from their family admission flows.
Five bounded component producers also retain directory companions:
`installed_math_work`, `installed_stdio_work`, `signal_process_work`,
`bootstrap_primitives_work` and `binary80_feature_work`. The first four use
the cohort's installed products. The binary80 producer retains its isolated
baseline and feature archives. These producers do not run the POSIX aggregate.
Directory seals admit copied loader symlinks only at the selected manifest's
alias path, with its exact target and selected loader bytes. Other directory
companions retain their existing symlink policy.
Every product and report must come from the evaluated clean revision, and
assembly runs in the pinned image because the reports record checkout paths.
Each of the gate's retained evidence rows reruns its own leaf reader; the last
applies `native-abi-selection require-closure`. The manual path is:

```sh
mkdir -p .work/x86_64/abi .work/x86_64/native-abi-inventory \
  .work/x86_64/header-declaration-inventory .work/x86_64/public-data-ordinary-link \
  .work/x86_64/abi-differential
./scripts/dev-x86_64.sh owned-posix-static-products .work/x86_64/abi/static
./scripts/dev-x86_64.sh materialized-dynamic-sysroot --work .work/x86_64/abi/dynamic --prepare
DYN=.work/x86_64/abi/dynamic/installed
P="--static-product .work/x86_64/abi/static/products/primary --dynamic-product $DYN --static-preparation .work/x86_64/abi/static/preparation.json"
./scripts/dev-x86_64.sh native-abi-inventory collect $P --output .work/x86_64/native-abi-inventory/abi
./scripts/dev-x86_64.sh native-abi-elf-facts collect --base-inventory .work/x86_64/native-abi-inventory/abi/report.json $P --output .work/x86_64/abi/elf
./scripts/dev-x86_64.sh header-declaration-inventory collect --output .work/x86_64/header-declaration-inventory/abi --workers 8
./scripts/dev-x86_64.sh public-data-ordinary-link collect $P --output .work/x86_64/public-data-ordinary-link/abi
R="--native-abi-inventory .work/x86_64/native-abi-inventory/abi/report.json \
  --native-abi-elf-facts .work/x86_64/abi/elf/report.json \
  --header-declaration-inventory .work/x86_64/header-declaration-inventory/abi/report.json \
  --public-data-ordinary-link .work/x86_64/public-data-ordinary-link/abi/report.json"
./scripts/dev-x86_64.sh abi-differential-evidence collect-companions $P $R --output .work/x86_64/abi-differential/companions
./scripts/dev-x86_64.sh abi-differential-evidence assemble $P $R \
  --companions .work/x86_64/abi-differential/companions/companions.json \
  --output .work/x86_64/abi-differential/abi
./scripts/dev-x86_64.sh qualification-manifest --publish compat.abi-differential abi-evidence .work/x86_64/abi-differential/abi/abi-evidence.json
```

Create these output parents as the host user before the container produces
their children. Bounded dynamic preparation supplies a materialized product
for ELF inspection; it does not run or claim the full runtime qualification
matrix. ABI selection closure and the other runtime gates remain separate.

`resolver-network` publication replays the report that the retained copy names
and requires identical bytes, so a stale `latest.json` from an older producer
revision is never read implicitly.

`lua-source-build` rereads only while a fresh admission of the current source,
both latest Lua lane reports and their products is identical to the retained
one:

```sh
./scripts/dev-x86_64.sh lua-static-source-build
./scripts/dev-x86_64.sh lua-dynamic-source-build
./scripts/dev-x86_64.sh lua-source-build-admission --output .work/x86_64/lua-admission/NAME
./scripts/dev-x86_64.sh qualification-manifest --publish consumer.source-build lua-source-build .work/x86_64/lua-admission/NAME/admission.json
```

`performance-release` never measures. `performance_release_gate.py evaluate`
reads the three-attempt runtime C collector through the `perf-c check` reader,
rechecks each attempt's CPU and syscall gates and each row's three-attempt PSS
and `memory.peak` one-sided 95% upper bounds at 1.00, and replays one
`perf-native --mode full` report. Both retained reports must carry an
`uncontended_host` record. Allocator promotion has its own M9 gate in
`compat/allocator/x86_64_m9_gate.py`. The receipt names every unmet condition;
publication reruns that evaluation and admits only a pass.

The staged native promotion path separates the CORE runtime/M10 reader from
the ALLOC source/M9 reader. Runtime qualification still requires the complete
full chain. Allocator qualification retains its selected baseline or full
profile; baseline keeps physical NUMA and 2-MiB/1-GiB pages explicitly
unqualified. `allocator-m9 --validate-retained` rereads the canonical report
without publishing or measuring, while ordinary M9 production remains writable.
M10 baseline and full qualification use the canonical allocator work directory
and the CORE tool environment. Correctness checks and audits accept physical
work descendants. Allocator JSON producers atomically publish reports with
mode `0644`, so the invoking UID can read root-produced reports without write
access.
Direct CORE native closure remains partial and exits 3. The host composition
runs CORE, ALLOC, then CORE again. The terminal CORE phase replays runtime
owning readers, including transitive performance attempts, binaries,
diagnostics and upstream source directories. Source and concrete input
snapshots must match across every phase. Snapshots include selected M9 report
parents and adjacent codegen artifacts, including reports outside canonical
directories. Allocator mount aliases resolve to their physical host inputs.
Relative checkout paths, absolute
checkout paths and `/workspace` paths select the same physical receipt.

This native bridge remains unqualified until actual current native products
pass both owning readers. Host phase mutation and partial-readiness controls
exercise the composition protocol. Installed-product tests exercise physical
source and payload custody. The allocator image reader tests exercise report
readability after changing UID and GID. These controls do not authorize changing
the accepted-C default or claiming native promotion readiness.

## Running the chain

```sh
./scripts/dev-x86_64.sh qualification-manifest [--profile correctness|full] [--through GATE]
./scripts/dev-x86_64.sh qualification-manifest [--profile correctness|full] --status
./scripts/dev-x86_64.sh qualification-manifest --validate-receipt PATH
./scripts/dev-x86_64.sh qualification-manifest --validate-receipt PATH --json
./scripts/dev-x86_64.sh qualification-manifest --private-admission
```

With no operation the command executes the active profile's chain;
`--through GATE` executes the contiguous prefix ending at `GATE`. Every selected
predecessor runs again, a planned gate is a named blocker, and execution stops
at the first failing case. It requires clean committed source and the pinned
image (it runs only through the dispatcher; never directly on the host), runs
each case in a fresh session under the receipt process's child-subreaper
boundary with a scrubbed environment, and writes `receipt.json` below
`.work/x86_64/qualification-receipts/chain-*` for failure as well as success.

`--status` evaluates every gate independently in the pinned image as a
diagnostic; it writes no receipt and is not a chain result.
`campaign-qualification` reports family blockers plus each gate's host
conditions while families are incomplete; once every chain family and its
dependencies are `foundation-verified` it runs exactly the full chain.

### Receipts

The receipt binds the clean revision and content hash, tool/Rust/GCC/musl inputs
before and after, the contract and case-manifest hashes, and each case's
command, runner hash, status, timing and raw stdout/stderr. `qualified_gates`
lists the leading gates whose cases all passed.

`--validate-receipt PATH` rereads a chain receipt: the current source, inputs,
contract, case pins and runner bytes must match, every log must hash to its
record, outcomes must follow from raw status and markers, and no case may follow
a failure. A failed receipt validates as an intact failure and exits 1; only
`outcome: passed` is qualification evidence for its prefix.
The optional `--json` mode emits the validated chain record only after this
same replay succeeds. Host-side admission uses that mode so tool and runtime
snapshots are checked in the pinned image, while in-image readers call the
validator directly.

### Environment

The scrubbed case environment fixes `/opt/cargo/bin` and `/opt/rustup`, while
`CARGO_HOME` and temporary state stay under the mounted checkout's
`.work/x86_64/`. That mutable Cargo home must contain no `config` or
`config.toml`, so ignored wrapper, linker or rustflags injection cannot alter a
recorded build; each input snapshot rechecks it. Input identity covers every
resolved directory on the scrubbed `PATH`, rustup's selected Cargo/Rustc and
their sysroot, GCC's builtin include tree, and the pinned musl runtime, loader,
specs, manifests and header tree.

### Private admission

`--private-admission` is the closed five-case static POSIX/ABI admission
(`qualification_posix_abi.json`). It writes per-case receipts under a prefix
receipt with the same source/tool/runtime bindings. A timeout kills the named
active leaf, then the runner, then every orphan adopted through the subreaper
boundary, including `setsid` and double-fork escapees. The prefix fixes
`non_promoting: true`, `promotion_ready: false` and zero completed gates; it
cannot satisfy or replace any chain gate.

## One-command candidate run

```sh
./scripts/dev-x86_64.sh qualification-candidate --work .work/x86_64/NAME [--profile correctness|full] [--inputs FILE] [--through STEP] [--dry-run]
```

[`qualification_candidate.py`](qualification_candidate.py) is the unattended
final qualification of one clean candidate checkout. It runs on the host and
every step is itself a dispatcher command that owns its container. `--work`
must be a physical child of `.work/x86_64`. It has no `--profile`: the final
`qualification-chain` step receives the selected profile, which defaults to
`full`. `--profile correctness` skips `performance-release` and its publication
while passing that profile to `qualification-manifest`.

`plan()` fixes the step order; step ids, in order:

1. Cohort: `static-products` (`owned-posix-static-products`),
   `dynamic-products` (`materialized-dynamic-sysroot`), then
   `publish-dynamic-product` after its receipt passes the product reader.
2. POSIX: `posix-family`, `crypt-profile`, `atomic-profile`,
   `wordexp-profile`, `wordexp-inputs`, `posix-native`, `publish-posix-native`,
   `posix-admission`; then `pthread-family`.
3. Text family: `text-{primary,reproduction,extracted}-<producer>` for the
   producers in `TEXT_PRODUCERS` (the primary pair has no `wordexp` step; the
   reproduction and extracted pairs add a `wordexp-inputs` step), then
   `text-family`.
4. `resolver-family`, `c-abi-compat-family`.
5. Loader: `loader-inventory-{installed,second,extracted}`, `loader-request`,
   `loader-family`, `publish-loader-family`.
6. `crt-dynamic-startup`, `static-sysroot`, `publish-static-product` after its
   receipt passes the product reader, then `combined-sysroot`.
7. ABI: `abi-inventory`, `abi-elf-facts`, `abi-declarations`,
   `abi-public-data`, `abi-evidence`, `publish-abi-evidence`.
8. Consumers: `rust-std-lto`, `publish-rust-std-lto`, `lua-static`,
   `lua-dynamic`, `lua-admission`, `publish-lua-source-build`.
9. Full profile only: `performance-release`, `publish-performance-release`.
10. `publish-resolver-network`, `qualification-chain`, `parity-ledger`.

`python3 -B -c 'import qualification_candidate as q; print([s.id for s in
q.plan(profile="correctness")])'` run from `compat/x86_64/` prints the
correctness-profile list; pass `profile="full"` for the full list.

Receipt paths are fixed by `--work`. A family row that names a `receipt` must
name the path this run produces; a different path is a preflight blocker, and a
row without one is reported unattached. `--inputs FILE` is JSON naming the
pre-seeded inputs the native container cannot fetch or must not measure under
contention: `lua_source_build.archive_seed`,
`rust_std_lto.{provider_vendor, dependency_vendor}` and
`performance_release.{runtime_c_collector, native_facade_report,
rustybench_source, rustix_source}`. The pinned OS-test and
libc-test source checkouts (`SOURCE_ORACLES` in the module) and the package
corpus archives (`.work/x86_64/owned-package-corpus-input/apks`) and signed
index (`.work/x86_64/owned-package-corpus-input/index/main-x86_64.APKINDEX.tar.gz`)
must also be seeded under `.work/x86_64/`. Preflight checks that the archive
directory has exactly the manifest roster and every APK matches its pinned
digest; the native corpus runner separately verifies signatures and index
contents.

The run is bound to the clean source identity and core image recorded in
`NAME/candidate.json`. Each `--inputs` group is sealed immediately before its
first consuming step runs, and is checked again on resume and after each
consumer. This lets a correctness prefix resume after performance inputs are
added for `performance-release`. A restart on the same revision skips each step whose
recorded outputs still hash identically and resumes at the first incomplete one;
a failed attempt's step directory and fresh outputs are renamed `*.failed-N`.
A different revision, changed inputs or environment, a changed completed output,
or a failed step stops the run; `NAME/summary.json` names the step and every step
not run. `--through STEP` runs the prefix ending at that step id (staged
preflights; never reported complete). `--dry-run` resolves every command with
placeholders for not-yet-produced outputs, prints the preflight blockers as
JSON, and runs nothing. Exit status: 0 for a complete run or a finished
`--through` prefix, 1 for an incomplete run, 2 for a candidate error.
