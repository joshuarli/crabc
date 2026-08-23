# Historical `crabc-rs` delivery record

This concise record preserves the rationale for the completed M0–M12
`crabc-rs` delivery sequence. It is historical provenance, not a current
queue. `TODO.md` owns priority, `docs/design/crabc-rs.md` owns present
architecture, and `compat/crabc-rs/coverage.toml` owns exact capability
classification.

The complete contemporaneous delivery plan is recoverable from Git blob
`e0446edba04a71f19a0c9ce1f6b231ea954e7d3e` at the baseline recorded in
[`semantic-migration.md`](semantic-migration.md). Its milestone names, dated
counts, and deferred-language snapshots do not override current policy.

## Architecture provenance

The delivery sequence established that `crabc-rs` is a Linux/AArch64 typed OS
and runtime facade, not generated C wrappers. The following decisions remain
current and are described in [`docs/design/crabc-rs.md`](../design/crabc-rs.md):

- syscall-like APIs call typed Linux operations through `crabc-core` rather
  than public C ABI or TLS `errno` routes;
- descriptor, path, flag, error, buffer, ownership, and unsafe preconditions
  are explicit in the Rust API;
- shared Rust source and `rlib` code do not make one process-global singleton;
  libc/ldso retain loader, pthread/TLS, resolver, and opt-in stdio state, with
  the append-only versioned `RuntimeV1` bridge for necessary cross-boundary
  state; and
- Rustix is a pinned API/behavior/source oracle for tests, never a production
  dependency or an implementation to copy.

## Rustix provenance

The historical correspondence manifest and dual-backend tests were evidence
tools, not a promise of unconditional source compatibility or a public Rustix
dependency. Current Rustix harnesses retain their own machine-readable inputs,
and direct native contracts remain separate from C ABI compatibility claims.

## Capability-accounting rationale

Full `crabc-rs` coverage means semantic accounting of the C/runtime surface,
not a wrapper for every symbol. The categories `native-safe`, `native-unsafe`,
`native-higher-level`, `rust-subsumed`, `abi-only`, `internal-runtime`, and
`scope-exception` exist to make every boundary explicit. A documented C group
is not automatically deferred native work; its exact evidence and rationale
are in [`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml).

The allocator exception, C `long double` mismatch, global process mutation,
and C storage/lifetime machinery remain examples of why a surface can be
accounted for without a native facade. Current exclusions and native seams are
governed by `SCOPE.md`, `COMPATIBILITY-PROFILE.md`, and the ledger.

## Historical completion and bounded proof

The M0–M12 chronology records the progression from direct primitive probes,
filesystem/core OS/process slices, signals and runtime facilities, semantic C
facilities, capability accounting, scope alignment, through the bounded native
LTO proof. The latter proves direct `getpid`/`write` routes in its selected O3
and fat-LTO application lanes; it does not prove whole-program optimization or
LTO inside dynamically loaded `libc.so`.

Historical capability-count checkpoints are intentionally retained only in the
original blob. Do not replace the present ledger with an old count or infer
implementation from an old milestone's past tense.

## Superseded directions

The original plan considered or deferred broad wrapper expansion, generic
portability, `io_uring` as a broad agenda, general policy frameworks, broad
locale/codec machinery, and global process/thread/time abstractions. Current
scope and the exact ledger classify the remaining pieces; these historical
ideas do not become TODO items merely because their delivery-plan prose was
future tense.

The project deliberately does not grow an async runtime, a process supervisor,
a security-policy framework, a C-varargs-shaped native facade, or an unsafe
global coordination abstraction disguised as a safe API.

## How to use this record

Read it for historical design rationale. For current behavior read the design
document and capability ledger; for active work read `TODO.md`; and for future
acceptance contracts read `docs/roadmap/`.
