# Qualification declarations and ordered execution prefixes

The v2 `qualification_manifest.json` declares gates as `planned` or `ready`.
Ready means that a finite case manifest and each runner have matching pinned
hashes. It does not mean that a case has run or that its owning family is
complete. A checked-in receipt containing an outcome string and case count is
no longer accepted as completion evidence. The generated projection reports
readiness separately and always leaves completion/promotion false.

`./scripts/dev-x86_64.sh qualification-manifest --private-admission` is the
first receipt transaction. It runs the closed five-case POSIX/ABI admission in
its declared order and writes a fresh ignored transaction below
`.work/x86_64/qualification-receipts/`. Every child has an immutable receipt
with its runner hash, actual command and status, timing, raw stdout/stderr,
and clean revision/content identities before and after it ran. The prefix
receipt binds that ordered roster, the private runner and case-manifest hashes,
the actual allowlisted tools and their version output, the pinned musl runtime,
loader, specs, source/specification manifests and complete header-tree digest.
It checks those source, tool, runtime, log and artifact identities again before
accepting `qualification-manifest --validate-receipt PATH`.

The scrubbed child environment fixes `/opt/cargo/bin` and `/opt/rustup`, while
`CARGO_HOME` and temporary state remain under the mounted checkout
`.work/x86_64/` tree. The same-object ABI leaf receives a receipt-owned
artifact directory. Its builder and comparator use the physical checkout
`TMPDIR`, retain the selected `libc.a`, shared workload object, pinned-musl
reference, freestanding candidate, and the ELF/stream inspection outputs, then
the case receipt seals every retained entry without following symlinks.
The mutable Cargo home must contain no `config` or `config.toml`, so ignored
wrapper, linker, or rustflags injection cannot alter the recorded build. Input
identity covers every resolved directory on the scrubbed `PATH`, the actual
rustup-selected Cargo/Rustc executables and their Rust sysroot, and GCC's
builtin include tree as well as the pinned musl inputs. A prefix timeout first
reaps the active leaf's separately created process group, then its Python
supervisor; that nested cleanup prevents an inherited log pipe from keeping a
failed transaction alive.

This is deliberately a private, non-promoting admission receipt. Its prefix
record fixes `non_promoting: true`, `promotion_ready: false`, and zero completed
promotion gates. It cannot make `compat.abi-differential` ready, replace a
full-family manifest, or turn its final stdout marker into a qualification
claim.

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
- Register dependency-ready full-family case manifests and execute their real
  ordered prefixes. All eight current promotion gates are still planned; the
  native `--through compat.abi-differential` check currently rejects that planned
  prerequisite without executing a target case.
- Make final qualification/promotion validation consume current same-revision
  bound receipts for the complete unchanged chain. Do not infer completion from
  `ready`, a private prefix, or historical reports.
