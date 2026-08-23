# Historical runtime delivery record

This is a concise provenance record for the completed M0–M12 delivery
sequence. It is not a planning document. Current completion and future
acceptance contracts are routed by [`STATUS.md`](../../STATUS.md) and
[`docs/roadmap/`](../roadmap/).

The complete contemporaneous plan is recoverable from Git blob
`674b4b98cf210efce09f32af656dc41bbf43383f` at the migration baseline recorded
in [`semantic-migration.md`](semantic-migration.md). Its dated counts,
measurements, and “next” language are historical snapshots, not current
claims.

## What the delivery sequence established

| Historical subject | Durable result and current owner |
| --- | --- |
| Compatibility laboratory | Docker-first Apple-Silicon-to-native-Linux/AArch64 workflow, pinned musl 1.2.6 C oracle, pinned Rustix test oracle, and generated ABI/evidence machinery. See `AGENTS.md`, `compat/upstreams.toml`, and the nearest `compat/*/README.md`. |
| Evidence states | `exported`, `implemented`, and `verified` are distinct. A capability becomes verified through inventory, implementation, ABI/direct-boundary proof, focused observable tests, appropriate musl/POSIX/external evidence, and ledger accounting. See `SCOPE.md` and `COMPATIBILITY-PROFILE.md`. |
| Compatibility ratchet | Dynamic ABI inventory, headers, libc-test, differential, loader, stress, corpus, and dashboard evidence are contracts rather than a raw symbol-count chase. Generated status is measurement, not scope policy. |
| Loader and TLS | AArch64 ELF loader correctness requires focused evidence for `DT_NEEDED`, symbol scope/versioning, relocation, RELRO/RELR, constructors/destructors, TLS, `dlopen`/`dlclose`, auxv, and vDSO behavior. Current invariants and cost model live in `docs/design/` and `compat/ldso/`. |
| Source and corpus evidence | The completed Lua adapter-sysroot gate is current evidence; CPython/owned-sysroot and broad corpus work retain their future contracts in `docs/roadmap/`. |
| LTO evidence | Bounded LTO observations are not whole-program or dynamic-libc LTO proof. The native-facade proof and its unsupported dependency-bearing route are described by `compat/lto/README.md` and the performance roadmap. |

## Historical completion chronology

The M0–M12 labels are retained only because chronology is the point here.
They describe the delivery sequence that built the laboratory, foundational
vertical slices, ABI and libc-test evidence, loader and concurrency evidence,
Alpine/Rust application probes, capability accounting, scope alignment, and a
bounded native LTO proof. Completion of a milestone never means that every
historical libc facility became current scope or that all later performance and
corpus contracts are complete.

Several historical status checkpoints reported different capability and
measurement counts. They are intentionally not reconciled into a single
retrospective number. The current exact capability state is
[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml); current
generated measurements belong to `COMPATIBILITY.md` and ignored report owners.

## Superseded directions

The following historical aspirations remain recoverable from the original
blob, but are not backlog:

- portability to non-Linux/AArch64 targets, portability abstractions, and
  architecture-general design;
- unlimited historical libc breadth or symbol-count-driven expansion;
- a native Rust wrapper for every C ABI symbol;
- allocator research, a general locale/charset database, NSS/provider systems,
  bundled tzdata, gettext, IDNA policy, async runtime, process supervisor,
  security-policy framework, or hand-rolled cryptography; and
- any suggestion that a successful bounded probe, stub, or generated dashboard
  proves a complete subsystem.

`SCOPE.md` and `COMPATIBILITY-PROFILE.md` record the governing decisions. The
machine-readable capability ledger records the exact C-only, Rust-subsumed,
internal-runtime, scope-exception, and verified-native dispositions.

## How to use this record

Use [`STATUS.md`](../../STATUS.md) for current status; the relevant design
document for a current invariant; the relevant roadmap for detailed unfinished
acceptance criteria;
and harness-local documentation for runner mechanics. Use this document and
the original blob only to understand why the present project boundaries and
evidence standards exist.
