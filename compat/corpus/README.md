# Real Alpine package corpus

This is the M8 end-to-end compatibility boundary for crabc's supported modern
runtime profile: Linux AArch64 on Linux kernel versions 5.10 and newer.
`manifest.toml` names exact
Alpine v3.24 AArch64 APK archives, package versions, SHA-256 digests, and the
unmodified package commands that make up tiers A–D. The default is Tier A;
`--tier all` runs the complete progression. Tier A starts with Alpine's real
`coreutils` `/bin/true`, `/bin/echo`, and `/bin/cat`, each of which must retain a
`DT_RELR` dynamic tag. That keeps the loader regression in the real corpus,
rather than only in a synthetic fixture.

The corpus covers only these manifest workloads; it is not a claim that every
musl-linked or glibc-linked package is supported.

The runner stages two disposable roots from the same pinned Alpine image:

* reference: package executable → `/lib/ld-musl-aarch64.so.1` → pinned musl
  1.2.6 `libc.so`;
* candidate: the same package executable → `/lib/ld-musl-aarch64.so.1` →
  crabc `libldso.so`, with `libc.musl-aarch64.so.1` aliased to crabc `libc.so`.

For direct kernel execution in Docker's restricted mount namespace, the runner
copies each package binary byte-for-byte and changes only its PT_INTERP field
to a short absolute path. It then invokes the package binary directly with its
original `argv[0]`; the loader is the ELF interpreter selected by the kernel,
never the program in `argv`. Both roots share the same kernel, image files,
and non-libc DSOs. A single identical `LD_LIBRARY_PATH` value points first at
the staged runtime alias and then at the common non-libc DSO directories; only
the alias bytes are swapped between the sequential reference and candidate
execs. Stdout, stderr, and wait status are compared byte-for-byte, with no
normalization. Reports include the original package-binary digest, package
archive digest/version, runtime loader/libc digests, and kernel release.

Every Tier B–D package has a `stateful = true` manifest case that creates,
reads, transforms, or otherwise mutates deterministic fixture state. These
cases are kept alongside the version/banner probes so package startup and
ordinary state transitions are both visible in the raw comparison report.

## Run

Inside the pinned native Docker image:

```sh
./scripts/dev.sh corpus                 # Tier A (fast gate)
./scripts/dev.sh corpus --tier B
./scripts/dev.sh corpus --tier all      # full A–D corpus
./scripts/dev.sh corpus --case tier-a-true --offline
python3 compat/corpus/tests/test_runner.py
```

The runner downloads only the exact manifest archive URLs and verifies each
digest before extraction. Archives are cached under `compat/corpus/.cache`
(ignored by git); `--offline` requires every selected archive to already be
present. Reports are written atomically to
`compat/reports/corpus/latest.json` and preserve raw stream bytes as hex and
SHA-256 witnesses.

This is intentionally not a glibc test and it does not replace the host
system's loader. A non-AArch64 invocation is an explicit setup error.
