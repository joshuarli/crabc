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

Use `./scripts/dev-x86_64.sh --help` and the owning ledger's evidence commands
for focused gates. The dispatcher owns the command roster; this guide does not
duplicate it or define alternate host paths.

For Python-only iteration, `python3 -B scripts/test_python.py --directory
compat/x86_64/tests --jobs 4` runs isolated modules with immediate failure
diagnostics and per-module logs under `.work/python-test-runs/`. Select the
nearest module while developing; reserve the full campaign for integration.

The installed static sysroot gate runs independent consumers with four workers
by default. Set `CRABC_X86_64_OWNED_STATIC_CONSUMER_WORKERS=1` for a serial replay
(valid range: 1–8). The extra same-input serial comparison is disabled unless
`CRABC_X86_64_OWNED_STATIC_CONSUMER_BENCHMARK=1` is set with four workers. Cold
producer reproducibility checks remain mandatory. Failed jobs retain private
logs and artifacts; timed-out or interrupted jobs have their process groups
terminated and reaped.

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
and dynamic TLS, DTV/module lifecycle, DSO init/fini, dl*, locking, unload,
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
