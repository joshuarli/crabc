# Paired native-shadow C ABI matrix

This harness compares the public local C allocation semantics of two distinct
`crabc-libc` artifacts:

1. the ordinary C-backed mimalloc `libc.so`, captured before feature selection;
2. the nondefault `native-mimalloc-shadow` Rust-backed `libc.so`.

It is a bounded ABI regression harness, not a runtime allocator selector,
general lifecycle claim, or promotion gate. `scripts/dev.sh allocator-shadow`
owns the required order: it builds the ordinary workspace/sysroot, runs
`run.py capture`, builds the selected native libc, and invokes `run.py run`
through the owned-loader test launcher. The capture records the ordinary
artifact and its exact Cargo feature fingerprint before `target/debug/libc.so`
is replaced. The local-matrix run phase independently attests each exported
`free` branch, asks the sealed driver for
`-nodefaultlibs`, and links the selected directory's exact `-l:libc.so` input
plus the owned `libcrabc-builtins.a`. The printed driver plan and permitted lld
trace prove that no injected default `-lc` or sysroot `libc.so` won the link.
The exact-name route is necessary because these test artifacts have no DSO
SONAME: a direct filesystem input would encode its backend path in `DT_NEEDED`.
The runner also rejects an embedded `RPATH`/`RUNPATH` and runs with
`LD_LIBRARY_PATH` containing only that artifact's directory.

The fixture writes a normalized ordered trace rather than pointer values,
usable sizes, or page details. Its completed rows cover local `malloc`,
successful `realloc` growth/shrink, `realloc(NULL, 0)`, `realloc(p, 0)`,
failed `realloc`, and null/ordinary `free` errno preservation. The
two zero-size `realloc` rows are explicit known reds: `realloc(NULL, 0)` is
freeable but non-16-byte-aligned in the ordinary artifact and freeable
16-byte-aligned in the native artifact, while `realloc(p, 0)` reverses that
alignment observation for a distinct freeable replacement. Both artifacts
preserve the fixture's incoming errno in those rows. A completed run records
those differences exactly; it does not call them compatibility passes.
The generated, ignored report is atomically published at
`compat/reports/allocator/shadow-abi-matrix/latest.json`.

Two additional fixtures are named as required source-faithful musl
differentials, rather than as native-only exceptions:

- `tests/fixtures/native_mimalloc_shadow_foreign_realloc_test.c` covers one
  synchronized live-owner foreign `realloc`;
- `tests/fixtures/native_mimalloc_owner_exit_realloc_test.c` covers one
  serialized post-owner-exit `realloc`.

Each case records its exact fixture path and SHA-256, normal successful stdout,
empty stderr, exit status, selected-shadow link shape, and pinned musl 1.2.6
link shape. While its manifest activation is `deferred`, `run.py run` publishes
a failed report instead of treating either row as accepted. Activating a row
hard-fails if its source digest differs, then compiles and runs the exact source
with pinned `musl-gcc` and with the independently attested selected
`native-mimalloc-shadow` artifact. Both executions must produce the recorded
successful status/stdout/stderr byte streams exactly. Thus a candidate-only
refusal witness, a changed fixture, or two matching but wrong outputs cannot be
relabeled as a musl differential. The initial deferred state records that the
source-faithful core and C-fixture siblings have not yet landed; it is not a
pass or a compatibility decision.

The contract intentionally keeps these broader rows blocked rather than
silently treating them as ordinary behavior:

- general foreign-worker free routing outside the selected `realloc` witness;
- general owner-exit/deferred-release routing outside the selected
  post-owner-exit `realloc` witness;
- DSO interposition and static linkage;
- address reuse, usable size, and page-layout observations.

Those cases have separate native-shadow evidence where applicable. The two
selected source-faithful differential rows do not generalize their bounded
synchronization/lifecycle witnesses into a general routing contract or backend
promotion.
