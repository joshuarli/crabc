# Real Alpine package corpus

This is the end-to-end Alpine-package compatibility boundary for crabc's supported modern
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

## Native x86_64 consumer corpus

`manifest-x86_64.toml` is a separate, finite Alpine v3.24 x86_64 APK snapshot
for the existing 34 workloads. It seals the unchanged `manifest.toml` workload
bytes, so all case IDs, argv, setup, stateful cases, and DT_RELR obligations
remain exactly those frozen workloads. It does not transfer an AArch64 result
or claim package-source equivalence. Five unavailable historical x86_64 URLs
are recorded as explicit target-only version deltas: gzip `1.14-r3`, sqlite
`3.53.4-r0`, curl `8.22.0-r0`, openssl `3.5.8-r0`, and
openssh-client-default `10.3_p1-r1`.

The native runner takes a supplied, already-built owned dynamic product. It
does not build a replacement product. Before any private execution it verifies
the signed Alpine index and all 59 exact APK archives using the pinned Alpine
`apk` verifier and keys. It extracts the complete non-libc package closure
without package-manager installation or hooks. The `musl` APK is verified but
not extracted; the candidate and musl roots receive separate sealed loader and
libc bytes at `/lib/ld-musl-x86_64.so.1` and
`/lib/libc.musl-x86_64.so.1`.

The package closure includes third-party application DSOs such as `libgcc_s`
and `libstdc++`; those archives and bytes are shared by both roots. They are
consumer payload, never candidate libc, loader, CRT, compiler input, or an
ambient-image fallback. The runner audits every package ELF executable and
DSO: each interpreter is canonical, every `DT_NEEDED` edge resolves either to
the frozen package `/usr/lib` closure or the exact sealed libc, and a RUNPATH
may name only that declared package library directory. Python's standard
library, file magic database, Git templates, terminfo data, and the pinned
`/etc/alpine-release` fixture are part of the retained payload.

Each private execution root carries the pinned image's sealed `/etc/passwd`
and `/etc/group` bytes and metadata, plus private `/tmp`, `/root`, and a real
`/dev/null` character device (major 1, minor 3). The runner clones only the
ordinary application payload, then stages and checks those base fixtures in
each case/side root; it never copies a device node. No account record, device,
or directory is inherited from the host. Tree seals encode the device kind,
major/minor, and mode as well as regular files and symlinks.

A receipt made before this per-root staging rule is a failed fixture
qualification if its cloned `/dev/null` is a regular file. It remains useful
only as a preliminary diagnostic; it cannot qualify a package outcome.

Every side/case root is retained under a fresh run directory below the
checkout-local `.work` boundary, with pre/post tree seals, product and archive
identities, raw stdout/stderr/status, and the full ELF dependency witness in
its JSON report. The runner seals its own source, the native and shared
workload manifests, and the two process-lifetime helper sources it actually
imports before work starts and rechecks them afterward. It also rechecks the
APK/index bytes, pinned `apk`/key/readelf material, musl source marker, and
supplied product after execution; APK signatures are verified before work, not
repeated during that post-execution identity check. A matched nonzero exit or
timeout is a failure; streams and statuses are never normalized. The chroot
leaf calls the package executable directly through the kernel with the
manifest's original `argv[0]`; it never passes the package program to a
loader argv.

Inside the pinned native Docker environment, after supplying a dynamic product:

```sh
./scripts/dev-x86_64.sh owned-package-corpus \
  --dynamic-sysroot /path/to/dynamic-sysroot \
  --report .work/x86_64/tmp/owned-package-corpus/latest.json
python3 -B compat/corpus/tests/test_runner_x86.py
```

`--work` names the physical parent for this campaign's fresh retained run
directories. It and an explicit `--report` must remain below this checkout's
`.work` directory, cannot cross a symlink or `..`, and an explicit report must
not already exist. The runner always creates `report.json` in its fresh private
run directory and emits that exact path on stderr, including for a candidate
mismatch. `--report` requests an additional identical copy. The oracle seal
binds both the source marker and the actual libc bytes and interpreter alias.
Version 3 records sparse `retention_modes` for the private payload and each
execution root. After native checks finish, only regular-file read bits and
directory read/traverse bits are added for host inspection. Each entry records
the original mode. `tree_sha256(..., retention_modes=...)` verifies that exact
addition and reconstructs the original execution hash; it rejects changed
bytes, other permission changes, absent paths, and symlink/device overrides.
Stateful workloads may have different before/after execution hashes; retained
validation reconstructs the after hash. Newly created evidence parents use
mode 0755; existing parent permissions remain the caller's choice. Fresh run
roots stay private until the native checks and retention step finish.
In quiet mode it separately emits the retained evidence
directory, pass/fail status, and report path. The JSON records the absolute
source mount used for those paths, so a host-side reader can remap the
container receipt deliberately. Omitting `--tier` selects all frozen tiers; an
explicit `--tier B` selects only B, and a tier/case intersection with no
workloads is a setup error.

The dynamic-product catalog's `package-corpus` entry always selects all 34
workloads for each supplied product. Its reader in
`compat/x86_64/owned_loader_corpus_evidence.py` rejects missing or duplicate
cases, changed inputs, mismatched products and incomplete native outcomes
during collection and retained qualification validation. The catalog leaf
has a fresh network namespace with no active interfaces; prepare the pinned
APK cache before running it.

All 34 workloads remain required for completion; a pass on one product or
revision is not evidence for another.

This is one consumer component for the frozen 34 workloads. It does not close
the wider software-corpus, loader-family, performance, or source-build scope.
