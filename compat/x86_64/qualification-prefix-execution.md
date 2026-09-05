# Qualification declarations and ordered execution prefixes

The v2 `qualification_manifest.json` declares gates as `planned` or `ready`.
Ready means that a finite case manifest and each runner have matching pinned
hashes. It does not mean that a case has run or that its owning family is
complete. A checked-in receipt containing an outcome string and case count is
no longer accepted as completion evidence. The generated projection reports
readiness separately and always leaves completion/promotion false.

`./scripts/dev-x86_64.sh qualification-manifest --through GATE` selects the
contiguous prefix from `compat.abi-differential` through the named gate. Every
predecessor must be ready and is executed again in that invocation. A planned
suffix does not block the selected prefix; a planned predecessor does. The
runner preflights all selected case/runner hashes before starting any case,
then rechecks each runner immediately before execution in the pinned native
container. Exact final completion markers and process-group timeout cleanup
remain required. The private five-case admission is not an endpoint or a
substitute for any predecessor.

The no-argument full-qualification command remains fail-closed. Even an
all-ready declaration cannot open it: executing cases alone does not produce
the source/tool/runtime/artifact-bound receipts required by `plan.md` and
`x86-64.md`. The campaign's eight-gate chain is unchanged. This component is
executable prefix infrastructure, not final qualification or promotion.

## Remaining implementation before qualification

- Produce durable ignored per-case and per-prefix execution receipts, including
  logs, actual command/status/timing, dependency order and artifact identities.
  Bind clean committed revision and tracked content before/after execution;
  keep generated results outside tracked source to avoid a self-hash cycle.
- Attest actual pinned tool binaries, musl runtime/specs/headers, Rust toolchain,
  installed runtime and candidate/oracle artifacts. Reject drift or absent
  artifacts when validating a result; a completion marker alone is insufficient.
- Repair the scrubbed execution environment's fixed Rust paths (`/opt/cargo/bin`
  and `/opt/rustup`) before Rust-building cases execute. Preserve the allowlist
  and checkout-local mutable Cargo/temp state.
- Add retained-artifact publication to the same-object ABI harness and its
  temporary-path handling, then qualify an explicitly non-promoting private
  prefix as the first real receipt transaction. Its five-case admission remains
  private, even if every selected case passes.
- Register dependency-ready full-family case manifests and execute their real
  ordered prefixes. All eight current promotion gates are still planned; the
  native `--through compat.abi-differential` check currently rejects that planned
  prerequisite without executing a target case.
- Make final qualification/promotion validation consume current same-revision
  bound receipts for the complete unchanged chain. Do not infer completion from
  `ready`, a private prefix, or historical reports.
