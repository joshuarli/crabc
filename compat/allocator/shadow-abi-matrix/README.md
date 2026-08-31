# Paired native-shadow C ABI matrix

This harness compares the public local C allocation semantics of two distinct
`crabc-libc` artifacts:

1. the ordinary C-backed mimalloc `libc.so`, captured before feature selection;
2. the nondefault `native-mimalloc-shadow` Rust-backed `libc.so`.

It is a bounded ABI regression harness, not a runtime allocator selector or a
promotion gate. `scripts/dev.sh allocator-shadow` owns the required order:
it builds the ordinary workspace/sysroot, runs `run.py capture`, builds the
selected native libc, and invokes `run.py run` through the owned-loader test
launcher. The capture records the ordinary artifact and its exact Cargo feature
fingerprint before `target/debug/libc.so` is replaced. The run phase independently
attests each exported `free` branch, asks the sealed driver for
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

The contract intentionally records these blocked comparison rows rather than
silently treating them as ordinary local behavior:

- foreign-worker free/reallocation;
- owner-exit and post-exit routing;
- DSO interposition and static linkage;
- address reuse, usable size, and page-layout observations.

Those cases have separate native-shadow evidence where applicable. Comparing
them against the C-backed artifact here would either claim a general lifecycle
route that does not exist or turn private allocator choices into an ABI rule.
