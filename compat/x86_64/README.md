# Native x86-64 foundation evidence

This directory records the native Linux/x86-64 little-endian campaign defined by
[x86-64.md](../../x86-64.md), coordinated by [plan.md](../../plan.md).
It is private foundation evidence until the completion predicate in x86-64.md
passes; it is not a public-support claim.

## Current authority

The frozen comparison target is the AArch64 snapshot at commit
3e100d45c5a0798c2d3862d5e2eef584c610ccf9: 223 capabilities, 26 required
families, and the three digests recorded in [aarch64_frozen_baseline.json](aarch64_frozen_baseline.json).
The validator rejects drift and has no refresh mode. Do not rebaseline or turn
historical checkpoints into current status.

[parity.toml](parity.toml) is the authoritative finite capability/family
mapping and promotion ledger. Every capability is mapped exactly once; every
required family must reach foundation-verified in dependency order.
The generated inventory is orientation only. Export rosters and selected
artifacts are ratchets or evidence, not completion predicates.

For current state and the exact completion contract, use x86-64.md,
plan.md, COMPATIBILITY-PROFILE.md, and executable contracts. The
large prior status narrative is preserved in
[historical-evidence.md](historical-evidence.md); its instructions and
checkpoint statuses are historical, not a live queue.

## Campaign commands

Run from the repository root in the pinned native environment:

```sh
./scripts/dev-x86_64.sh campaign-status
./scripts/dev-x86_64.sh campaign-family FAMILY
./scripts/dev-x86_64.sh campaign-static
./scripts/dev-x86_64.sh campaign-dynamic
./scripts/dev-x86_64.sh campaign-qualification
./scripts/dev-x86_64.sh campaign-promotion-check
./scripts/dev-x86_64.sh campaign-all
```

The campaign status/family commands validate the frozen baseline, ledger, and
generated C-ABI evidence matrix. Product and promotion commands report blockers
until their real gates pass; a private fixture or focused leaf never promotes.

The case-pinned qualification runner executes only through the pinned
`qualification-manifest` dispatcher surface. Inside that native image it
requires the checkout-local `.work/x86_64` work, temporary and mutable Cargo
directories, the fixed `/opt/cargo/bin` and `/opt/rustup` Rust paths, and the
pinned musl oracle compiler before starting a registered case. It never
executes a qualification case directly on the host. Its
`qualification-manifest --private-admission` operation records the closed
five-case POSIX/ABI admission as ignored per-case and prefix receipts; it is
explicitly non-promoting. `qualification-manifest --validate-receipt PATH`
rechecks the current source, tools, musl inputs, logs and retained same-object
artifacts. Ready ordered prefixes may be selected with
`qualification-manifest --through GATE`; planned predecessors remain blockers,
and prefix execution makes no completion claim. The full receipt contract and
remaining gates are recorded in [qualification-prefix-execution.md](qualification-prefix-execution.md).

Use `./scripts/dev-x86_64.sh --help` and the owning ledger's evidence commands
for focused gates. The dispatcher owns the command roster; this guide does not
duplicate it or define alternate host paths.

For Python-only iteration, `python3 -B scripts/test_python.py --directory
compat/x86_64/tests --jobs 4` runs isolated modules with immediate failure
diagnostics and private logs under `.work/python-test-runs/`. The large parity
ledger module is automatically split into exact test-ID shards, with live test
progress and fail-closed completion accounting. Select the nearest module
while developing; reserve the full campaign for integration.

`./scripts/dev-x86_64.sh core --cached` reuses a checkout-local Cargo target for
development. Each invocation copies Cargo's exact current test binary into
private scratch and runs the same serial core tests and fenv code-generation
check. Builds serialize; private executions may overlap. `core` without the
flag retains its cold qualification build. Cancellation kills/reaps owned
children and retains failure logs; cached results do not establish cold-build
reproducibility.

The installed static sysroot gate runs independent consumers with four workers
by default. Set `CRABC_X86_64_OWNED_STATIC_CONSUMER_WORKERS=1` for a serial replay
(valid range: 1–8). The extra same-input serial comparison is disabled unless
`CRABC_X86_64_OWNED_STATIC_CONSUMER_BENCHMARK=1` is set with four workers. Cold
producer reproducibility checks remain mandatory. Failed jobs retain private
logs and artifacts; timed-out or interrupted jobs have their process groups
terminated and reaped.

`./scripts/dev-x86_64.sh materialized-dynamic-sysroot` builds the real shared
runtime twice and tests installed and extracted PIE/DSO consumers. See
[materialized-dynamic-sysroot.md](materialized-dynamic-sysroot.md) for the
initial-graph boundary and remaining loader work. The older
`owned-dynamic-sysroot` command is a plan-only seed, not this executing gate.

## Boundary and caveats

The campaign covers Linux 5.10-or-newer, native x86-64 little-endian execution,
the x86_64-unknown-linux-musl Rust target where a target name is required, and
the selected runtime profile. It does not widen support to another architecture,
endianness, operating system, or portability layer.

Counts are accounting aids, never a burn-down target. A selected-private row,
header probe, export ratchet, direct Rust probe, static archive, fixed loader
fixture, or passing focused test does not establish family completion or public
support. Evidence must cover the owning family and its declared boundary.

Keep intentional differences from pinned musl and Rustix in the nearest durable
evidence document. Do not use glibc, ambient CRT/libc, compiler-runtime,
interpreter, headers, or libraries as candidate inputs. The accepted allocator
backend remains the runtime backend until the separately qualified native
mimalloc program is promoted; allocator parity alone never closes this campaign.

## Product and capability workflow

Close finite work in dependency order: ABI/header and crabc-core foundations;
libc/runtime state, allocator, errno/TLS, pthread and process lifecycle; CRT and
static PIE; loader, relocations, TLS and dynamic products; then consumers,
qualification, performance, and promotion. Independent families may progress
in parallel, including the static and dynamic product tracks. Integration and
final qualification require each product's actual owned prerequisites.

The owned static product must use installed crabc headers, CRT objects,
libc.a, compiler-builtins, the accepted allocator backend, and explicitly
admitted application objects. It must reject ambient CRT/libc/compiler-runtime/
loader/header inputs, be reproducible, and pass static and static-PIE smoke
tests from an extracted sysroot.

The owned dynamic product must use the installed interpreter/shared libc and
general loader, with relocation, symbol scope, RuntimeV1 handoff, initial-exec
and dynamic TLS, DTV/module lifecycle, DSO init/fini, dl*, locking, retained close/reopen,
and admitted reentrancy covered by its contracts. Fixed graphs and isolated
artifacts are not equivalent.

The ordered qualification chain is:

```
compat.abi-differential
  -> compat.posix-process
  -> compat.resolver-network
  -> compat.loader-corpus
  -> consumer.rust-std-lto
  -> consumer.source-build
  -> capability.accounting
  -> performance.release
```

The selected AArch64 consumer set is reproduced on x86. Musl 1.2.6 is the
C/POSIX oracle; Rustix is a pinned test-only native-API oracle. Glibc and
ambient target inputs are never fallbacks. AArch64 implementation and
qualification remain paused, and native mimalloc work follows
[native-mimalloc.md](../../native-mimalloc.md) without weakening runtime
gates.

## Evidence and repository layout

- compat/x86_64/: probes, manifests, ledgers, validators, fixtures, and
  product state. Keep durable evidence beside its owning contract.
- compat/x86_64/parity.toml and aarch64_frozen_baseline.json: finite
  accounting and immutable baseline.
- static-product.toml and dynamic-product.toml: owned product requirements
  and machine-readable state.
- compat/*/README.md, docs/design/, and docs/evidence/: harness mechanics,
  architecture, and durable rationale.
- COMPATIBILITY.md: generated dashboard; never edit by hand.
- .work/: all mutable worktrees, scratch, source extracts, caches,
  sysroots, and generated report backing storage. Do not create new external
  scratch or target state.

Evidence must identify the source revision, target, pinned inputs, command,
scope, and report path. Generated reports are measurements, not policy.
Requalify after source or backend changes; do not inherit a prior revision's
pass. Keep unique behavior differences and intentional exclusions in the
nearest contract or evidence document.

## Completion boundary

Native x86-64 becomes publicly supported only after the full predicate in
x86-64.md passes: frozen accounting, all 26 families, reproducible owned
static and dynamic products, complete ordered qualification, native
performance, promotion validation, public-document update, and a final clean
aggregate rerun. Until then, describe results as private foundation evidence.

## Owned pthread scheduling and defaults

`./scripts/dev-x86_64.sh owned-pthread-scheduling` links one project-header
object to pinned musl and the installed static, static PIE, dynamic PIE and
non-PIE products; both dynamic entry paths run. The runner accepts an existing
dynamic product for aggregate qualification. The [component contract](owned-pthread-scheduling.md)
records source mapping, lifecycle ownership, failure reclamation and the GNU/C11
default rules. This component is registered in the dynamic product matrix; it
does not itself complete the pthread family or qualify a public platform.

## Installed descriptor control

`./scripts/dev-x86_64.sh owned-message-queues` checks installed POSIX queue
transfer, cancellation, signal notification, and the source SIGEV_THREAD
worker lifecycle against the same pinned-musl object. The
[component contract](owned-message-queues.md) records source mapping, ABI,
private IPC isolation, callback lifetime, and provider accounting.

`./scripts/dev-x86_64.sh owned-named-ipc` checks installed named semaphore and
shared-memory namespace, mapping/reference lifetime, concurrent creation,
fork, saturation and cancellation against the same pinned-musl object. Its
[component contract](owned-named-ipc.md) records the exact source map,
256-entry registry, private chroot evidence, and required dynamic coverage.

`./scripts/dev-x86_64.sh owned-fcntl` checks the installed command/variadic ABI
against pinned musl, including duplication, pipe/owner/signal/seal/lease/hint
controls and POSIX/OFD locking/cancellation. The [component contract](owned-fcntl.md)
records argument categories, source mapping and the frozen-private distinction.
The same-object runner is also a required dynamic product qualification case.

## Owned VM mechanisms

`./scripts/dev-x86_64.sh owned-vm-mechanisms` qualifies the installed C
`mremap`, `brk`, `sbrk`, and `remap_file_pages` boundaries through pinned musl,
owned static/static-PIE, and dynamic PIE/non-PIE products. The
[component contract](owned-vm-mechanisms.md) records the exact musl mapping,
VM-lifetime seam, same-object matrix, and remaining scope.

## Owned C11 quick termination

`./scripts/dev-x86_64.sh owned-quick-exit` compares one installed-header C11
workload against pinned musl and the installed static, static-PIE, dynamic PIE,
and dynamic non-PIE products, including kernel and direct interpreter entry.
The [component contract](owned-quick-exit.md) records the fixed 32-slot
registry, fork guard, callback contract, and excluded ordinary-exit behavior.
The same runner checks strong static and global-default shared providers and is
a required dynamic product qualification case.

## Owned local group database

`./scripts/dev-x86_64.sh owned-group` checks installed C `getgr*`,
`getgrouplist`, and `initgroups` against pinned musl through one source object,
owned static/static-PIE, and dynamic PIE/non-PIE kernel and direct-interpreter
products. The [component contract](owned-group.md) records the local
`/etc/group` scope, explicit nscd/NSS omission, source storage and cancellation
boundaries, and disposable credential-transition evidence.

## Owned legacy time and clock adjustment

`./scripts/dev-x86_64.sh owned-legacy-time` compares one installed-header C
workload with pinned musl and the installed static, static-PIE, dynamic PIE,
and dynamic non-PIE products, including kernel and direct interpreter entry.
The [component contract](owned-legacy-time.md) records raw `times` result
handling, reused interval-timer leaves, source-shaped `settimeofday`/`stime`,
and seccomp-contained clock-mutation errors. The same runner checks
static/shared provider binding and is a required dynamic product qualification
case.
