# Development setup

This page takes a fresh Linux x86-64 host to a passing check run. Everything
except the host packages below runs in the pinned core image, which the setup
builds reproducibly from `docker/image/sources.lock.json`.

## Bootstrap

On Ubuntu 24.04 x86-64, from a clone:

```sh
scripts/setup-dev
```

The script is idempotent. It installs the host packages, checks the Docker
daemon, builds the pinned core image when it is missing, and fetches the locked
Cargo closure, oracle sources and qualification inputs. It fails with a message
on any other distribution or architecture.

The Docker daemon must be running and reachable by your user, and it must use
the containerd image store (the default for new Docker 29 installs), because
that store gives the loaded image the ID pinned in `compat/x86_64/core_image.py`.

The current toolchain is `nightly-2026-11-09`. The pinned x86 image is
`sha256:b243d937bf906259565a2e3e1b4162a6d1162a5209405995b12a62a9beccd394`;
the native arm image is
`sha256:7b7cd03d19a2e65ea35addb5358bcb849dd935e8cb717581e42233356d40d683`.
The authoritative image IDs are in `compat/x86_64/core_image.py`.

The 2026-11-21 cold-capsule setup and two-build reproduction are historical:
they used x86 image `sha256:c689abaa…`, `nightly-2026-09-15` and source
`b82313a51`. They do not establish reproducibility or setup timings for the
current pair. That cold setup downloaded about 805 MB; on a shared 2026
threadripper host the capsule took 7m50s for `scripts/setup-dev` and 14m35s
through the checks below.

## Host packages

| Package | Consumer |
| --- | --- |
| `docker.io` (Docker 29 or newer) | every build and test runs in the pinned image; `scripts/dev-x86_64.sh image` builds it |
| `python3` (3.12 or newer) | the dispatcher (`scripts/dev-x86_64.sh`), `scripts/test_python.py`, host-side harness modules |
| `git` | the source seal, worktree preparation and pinned oracle checkouts |
| `ca-certificates` | HTTPS fetches of the locked inputs |

Every compiler, linker, Rust toolchain and musl tree comes from the image. On
another distribution, install the same packages and run the remaining steps of
`scripts/setup-dev` by hand.

## Checks

```sh
scripts/lanes/rust-check.sh
python3 compat/x86_64/validate_parity_ledger.py
./scripts/dev-x86_64.sh owned-exit-gate
./scripts/dev-x86_64.sh mimalloc-secure-environment
```

[AGENTS.md](../AGENTS.md#commands) lists the focused commands, and
[docs/lanes.md](lanes.md#check-environments) says which Python modules run on
the host and which in the image. The full qualification candidate
(`./scripts/dev-x86_64.sh qualification-candidate`) takes hours and is the
integration milestone, not a setup check.

## Rust profiles

Use `release` for optimized checks and `dist` for distribution artifacts. To
build the hosted facade together with std from the pinned Rust source:

```sh
scripts/lanes/rust-check.sh sh -ec '
  RUSTFLAGS="-C link-dead-code=no" cargo build --locked -p crabc-rs \
    --profile dist -Z build-std=std -Z build-std-features= \
    --target "$(rustc --print host-tuple)"
'
```

The sealed C sysroot builds its helper objects from the pinned Rust source.
Its static libc keeps separate archive members so applications can override
individual C symbols.

## AArch64

AArch64 runs only natively in arm64 Linux, never emulated or on a macOS bind
mount. On an Apple Silicon Mac, use an OrbStack arm64 Linux VM and keep the
clone on the VM's own disk. Put the work directory (`.work/aarch64`) on an ext4
volume with at least about 40M inodes (for example a loop-mounted image made
with `mkfs.ext4 -i 8192`); btrfs reports zero free inodes, which the harness
rejects. The AArch64 core image is still built from `docker/Dockerfile.aarch64`
and is not reproducible: `./scripts/dev-x86_64.sh image` in the VM builds it,
and the result must match the `AARCH64_CORE_IMAGE_ID` pin in
`compat/x86_64/core_image.py` or be re-pinned. The native musl source oracle is
fetched as described in
[CRAB-8](rfc/CRAB-8-linux-aarch64-feature-completion.md).

## Optional

| Tool | Use | How to get it |
| --- | --- | --- |
| `stuff` CLI with publishing credentials and Tailscale | publishing image inputs after regenerating the lock | [docs/lanes.md](lanes.md#reproducible-core-image) |
| `gh` authenticated to joshuarli/crabc | uploading image inputs to the release mirror | `gh auth login` |
