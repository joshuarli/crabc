# Ordered qualification chain

The eight `plan.md` qualification gates run in one fixed order:
`compat.abi-differential`, `compat.posix-process`, `compat.resolver-network`,
`compat.loader-corpus`, `consumer.rust-std-lto`, `consumer.source-build`,
`capability.accounting`, `performance.release`. Each gate is also the
`parity.toml` family of the same id; its family status records an earlier
admission, while the chain re-proves it against the current checkout.

## Declarations

The v2 `qualification_manifest.json` declares every gate `ready` with a
finite, hash-pinned case manifest. `consumer.source-build` runs its dedicated
`compat/lua/qualify_source_build.py` case (`qualification_source_build.json`,
described in `compat/lua/README.md`); every other gate names a manifest in
`qualification-gates/` whose single `gate-conditions` case runs the pinned
`run_qualification_gate.py GATE`. Ready means executable and hash-pinned,
never passed. `generate_qualification_manifest.py --check` keeps the generated
projection current; the declaration's `promotion_ready` and
`completed_gate_count` stay false and zero.

## Gate conditions

`qualification_gates.py` evaluates one gate as named conditions:

- `prerequisite-families` lists every transitive `depends_on` family and every
  earlier chain gate that is not `foundation-verified`.
- `evidence[N]` covers each `native_evidence` command of the gate family. A
  command needs a registered reader; a prose placeholder or unregistered
  command is itself the unmet condition. Readers call the leaf's existing
  validator: `publication` readers reread a published retained receipt,
  `report` readers a fixed-location report, `ledger` readers checked-in
  source, and `execution` readers run a self-contained native leaf (only once
  every other condition is met).
- Gate-specific checks: `capability.accounting` adds `capability-completion`,
  naming every frozen capability not yet `implemented-foundation`.

The case prints the condition record and exits 1 with
`x86 qualification gate GATE: UNMET (...)`; only a native evaluation with every
condition met ends with `x86 qualification gate GATE: PASS`. Host evaluation
(`campaign-qualification` while blocked) reports prerequisites, registration
and completion checks and leaves native reads unevaluated.

The owning lane closes a gate by making its ledger command executable and
registering its reader in `qualification_gates.py`; no case manifest pin
changes. `consumer.rust-std-lto` and `performance.release` currently name
their prose evidence as unmet in exactly this way.

## Evidence publication

Leaves that write caller-chosen directories are selected by
`./scripts/dev-x86_64.sh qualification-manifest --publish GATE PUBLICATION RECEIPT`.
Publishing runs the leaf reader first and atomically writes
`.work/x86_64/qualification-evidence/GATE/PUBLICATION.json` with the receipt
path and byte hash. The gate rereads the receipt through the leaf reader on
every evaluation, so replaced, stale-source or partial receipts fail. Current
publications: `compat.posix-process posix-native` (`native-execution.json`
from `owned-posix-native`) and `compat.loader-corpus loader-family`
(`receipt.json` from `owned-loader-family`). `compat.resolver-network` reads
the published `compat/reports/resolver-network/x86_64/latest.json` and
`consumer.source-build` the Lua admission's fixed reports.

## Execution and receipts

`./scripts/dev-x86_64.sh qualification-manifest` executes the complete chain;
`--through GATE` executes the contiguous prefix ending at `GATE`. Every
selected predecessor runs again, a planned gate is a named blocker, and
execution stops at the first failing case. The runner requires clean committed
source and the pinned image, runs each case in a fresh session under the
receipt process's child-subreaper boundary with the scrubbed environment, and
writes `receipt.json` below `.work/x86_64/qualification-receipts/chain-*`
for failure as well as success. The receipt binds the clean revision and
content hash, tool/Rust/GCC/musl inputs before and after, the contract and
case-manifest hashes, and each case's command, runner hash, status, timing and
raw stdout/stderr. `qualified_gates` lists the leading gates whose cases all
passed; `complete_chain` is true only for a passing full chain.

`--validate-receipt PATH` independently rereads a chain receipt: the current
source, inputs, contract, case pins and runner bytes must match, every log must
hash to its record, outcomes must follow from raw status and markers, and no
case may follow a failure. A failed receipt validates as an intact failure and
exits 1; only `outcome: passed` is qualification evidence for its prefix.
`--status` evaluates all eight gates independently in the pinned image as a
diagnostic; it writes no receipt and is not a chain result.

`campaign-qualification` reports family blockers plus each gate's host
conditions while families are incomplete. Once every chain family and its
dependencies are `foundation-verified`, it runs exactly the full chain, never
the families' placeholder-bearing development commands.

The scrubbed case environment fixes `/opt/cargo/bin` and `/opt/rustup`, while
`CARGO_HOME` and temporary state stay under the mounted checkout's
`.work/x86_64/`. That mutable Cargo home must contain no `config` or
`config.toml`, so ignored wrapper, linker or rustflags injection cannot alter a
recorded build; each input snapshot rechecks it. Input identity covers every
resolved directory on the scrubbed `PATH`, rustup's selected Cargo/Rustc and
their sysroot, GCC's builtin include tree, and the pinned musl runtime,
loader, specs, manifests and header tree.

## Private admission

`qualification-manifest --private-admission` remains the closed five-case
static POSIX/ABI admission. Its private runner records per-case receipts (the
same-object ABI leaf also retains its selected `libc.a`, shared workload
object, pinned-musl reference, freestanding candidate and ELF/stream
inspection outputs) under a prefix receipt with the same source/tool/runtime
bindings. A timeout kills the named active leaf, then the runner, then every
orphan adopted through the subreaper boundary, including `setsid` and
double-fork escapees. The prefix fixes `non_promoting: true`,
`promotion_ready: false` and zero completed gates; it cannot satisfy or
replace any chain gate.
