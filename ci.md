Goal: Implement a complete release path for the already-implemented crabc-owned sysroot:

```text
.github/workflows/sysroot.yml
```

The workflow must build the Linux/AArch64 sysroot, smoke-test the **packaged archive itself**, and publish the exact tested bytes as assets on an immutable GitHub **prerelease**.

This is groundwork for a future `llvm-clang-crabc` repository. Do not implement LLVM, Clang, libc++, compiler-rt, or any C++ functionality here.

## Fixed decisions

Treat these as requirements, not open design questions:

```text
Target:                  Linux/AArch64 little-endian only
Build architecture:     native AArch64 only
CI runner:               ubuntu-24.04-arm
Local development:      Apple Silicon macOS → Docker → Linux/AArch64
Container platform:      linux/arm64
Cross-compilation:       not used
QEMU:                    not used
x86-64:                  out of scope
Release type:            GitHub prerelease
Release identity:        immutable crabc commit snapshot
ABI stability:           no guarantee
API stability:           no guarantee
Header/layout stability: no guarantee
Compatibility promise:  none beyond the smoke tests performed
C++:                     out of scope
```

The sysroot implementation itself is assumed complete. Treat its existing exporter, manifest, layout, CRT objects, libc artifacts, loader, and headers as authoritative.

Do not duplicate sysroot assembly logic in the workflow or a second script.

## Inspect only the relevant repository surface

Before changing anything, inspect:

```text
.github/workflows/ci.yml
scripts/dev.sh
docker/Dockerfile
the existing sysroot exporter and its tests
the sysroot manifest schema
the existing static pthread/TLS harness
the existing Lua adapter-sysroot harness where useful
.gitignore
README.md
AGENTS.md
```

Do not broadly remap the repository or refactor unrelated compatibility machinery.

## Core architectural rule

The workflow must be a thin caller of a local Docker-native release command.

All meaningful build, packaging, extraction, inspection, compilation, linking, and execution logic must run inside the same pinned `linux/arm64` development image used by normal crabc development.

The required local path must be:

```sh
./scripts/dev.sh image
./scripts/dev.sh sysroot-dist
```

This must work from Apple Silicon macOS with Docker Desktop and must be the same path invoked by GitHub Actions.

The macOS host must not need:

```text
Rust
Clang
lld
Python
GNU tar
binutils
an AArch64 SDK
Homebrew packages
```

apart from Docker and the normal repository checkout.

Do not use:

```text
docker buildx
QEMU setup actions
binfmt registration
linux/amd64 containers
nested Docker
CI-only packaging code
host-side macOS compilation
```

## Important macOS/Docker filesystem constraint

Do not package the sysroot directly from the macOS bind-mounted workspace.

Build, stage, normalize, package, extract, and smoke-test it on a Linux filesystem inside the container, such as:

```text
/tmp/crabc-sysroot-*
```

or an existing Linux Docker volume.

Only copy the completed release files into:

```text
/workspace/dist/
```

after packaging and smoke testing have succeeded.

This prevents macOS bind-mount metadata, ownership, permissions, timestamp behavior, or symlink handling from influencing the archive.

Add `/dist/` to `.gitignore` if it is not already ignored.

---

## Deliverables

Implement the smallest coherent set of files needed. The expected shape is:

```text
.github/workflows/sysroot.yml
scripts/dev.sh
scripts/sysroot_dist.py
compat/sysroot-smoke/
├── README.md
├── run.py
├── fixtures/
│   ├── dynamic.c
│   └── module.c
└── tests/
    └── test_runner.py
tests or script tests for deterministic/safe packaging
README.md
.gitignore
```

Follow existing repository placement and naming conventions where they make a clearly better fit. Do not create a general build framework.

Use typed, standard-library-only Python for nontrivial packaging, archive validation, subprocess reporting, and smoke-test orchestration. Keep shell in the workflow and `scripts/dev.sh` limited to straightforward command dispatch.

---

# 1. Add the local `sysroot-dist` command

Extend `scripts/dev.sh` with:

```sh
./scripts/dev.sh sysroot-dist
```

It must:

1. Ensure the pinned `linux/arm64` image exists.

2. Enter the existing native AArch64 development container.

3. Assert inside the container:

   ```text
   uname -s == Linux
   uname -m == aarch64
   ```

4. Obtain the full source commit and commit timestamp from the mounted Git repository.

5. Invoke the existing authoritative sysroot exporter in release mode.

6. Stage its output on an internal Linux filesystem.

7. Validate its existing manifest and required artifacts.

8. Create a deterministic `.tar.xz`.

9. Generate a SHA-256 checksum file.

10. Extract the archive into a new randomly named directory.

11. Smoke-test that extracted copy.

12. Write a structured smoke report.

13. Copy only the final release files to `/workspace/dist`.

14. Exit nonzero on any validation or smoke-test failure.

Also add a focused rerun command if it fits cleanly:

```sh
./scripts/dev.sh sysroot-smoke dist/<archive>.tar.xz
```

It must run inside the same `linux/arm64` image and test the supplied archive rather than rebuilding it.

Do not require any GitHub Actions environment variable for local operation.

---

# 2. Artifact identity and layout

Use a commit-derived snapshot identity, not semantic versioning.

Let:

```text
FULL_SHA  = full 40-character crabc commit
SHORT_SHA = first 12 characters
```

Produce:

```text
dist/
├── crabc-sysroot-aarch64-<SHORT_SHA>.tar.xz
├── crabc-sysroot-aarch64-<SHORT_SHA>.tar.xz.sha256
├── crabc-sysroot-aarch64-<SHORT_SHA>.manifest.json
└── crabc-sysroot-aarch64-<SHORT_SHA>.smoke.json
```

The archive must contain exactly one top-level directory:

```text
crabc-sysroot-aarch64-<SHORT_SHA>/
```

That directory is the sysroot root. A consumer should be able to extract it and pass that top-level directory directly to `--sysroot`.

Preserve the authoritative sysroot layout. Do not redesign it during this work.

The standalone manifest asset must be an exact copy of the manifest included in the archive, or a canonical serialization of precisely the same data if the existing manifest contract requires that.

The smoke report must include at minimum:

```json
{
  "schema": 1,
  "passed": true,
  "target": "aarch64",
  "source_commit": "<full SHA>",
  "archive": {
    "name": "...",
    "sha256": "..."
  },
  "environment": {
    "system": "Linux",
    "machine": "aarch64",
    "compiler": "...",
    "linker": "..."
  },
  "tests": {}
}
```

Record complete subprocess argument arrays, statuses, stdout, stderr, and relevant ELF inspection output in the report. Avoid shell-form command strings as the only command record.

A manifest `schema` version is only a metadata schema version. Do not describe it as an ABI version.

---

# 3. Deterministic packaging

Make the archive deterministic for a given clean commit and pinned container.

Use the source commit timestamp as `SOURCE_DATE_EPOCH`.

Normalize archive metadata:

```text
sorted path order
uid = 0
gid = 0
uname = ""
gname = ""
mtime = SOURCE_DATE_EPOCH
directories = 0755
ordinary data files = 0644
files that genuinely need execute permission = 0755
symlinks preserved as symlinks
```

Do not dereference symlinks while packaging.

The packaging implementation must:

* reject absolute archive member paths;
* reject `..` traversal;
* reject unsupported device nodes, FIFOs, and sockets;
* reject symlinks that escape the sysroot;
* reject hard links unless the existing sysroot contract deliberately requires and validates them;
* preserve only the expected sysroot contents;
* never package Cargo target directories, logs, caches, or the source tree.

Add a deterministic-package test that packages the same fixture tree twice and proves byte-identical archive hashes.

Add negative unit tests for:

```text
../ traversal member
absolute member path
escaping relative symlink
absolute symlink
unexpected special file
manifest/source-commit mismatch
```

Use a safe extraction implementation. Do not call `tar -xf` on an unvalidated archive and assume the archive is trustworthy merely because this repository created it.

---

# 4. Smoke-test the extracted archive, not the staging directory

This is a hard requirement.

The exact `.tar.xz` later uploaded to GitHub must first be:

1. checksummed;
2. safely extracted to a fresh random path;
3. validated structurally;
4. used for all compile/link/run smoke tests.

Do not repack or modify the archive after smoke testing.

The smoke report must name the archive SHA-256 it tested.

## Structural validation

Validate at least:

* one expected top-level directory;
* manifest exists and parses;
* manifest source commit equals the expected crabc commit;
* target architecture is AArch64 little-endian;
* required headers exist;
* dynamic libc exists;
* static libc exists;
* canonical crabc loader exists;
* all startup objects declared by the sysroot contract exist;
* all manifest artifact hashes match;
* symlinks remain inside the extracted sysroot;
* no file unexpectedly points back into `/workspace`, `/tmp`, Cargo output, or the build environment.

Do not invent an ABI-completeness test. This is structural integrity plus executable smoke evidence.

---

# 5. Smoke testing without `llvm-clang-crabc`

Use the native AArch64 Clang and lld already present in the pinned crabc development image solely as disposable build tools.

Do not download or build another compiler.

Do not depend on the hypothetical future `llvm-clang-crabc` repository.

The smoke compiler must be invoked with explicit isolation flags so the test measures the extracted sysroot rather than Alpine’s target runtime.

## Header isolation

Compile with the equivalent of:

```text
--target=aarch64-unknown-linux-musl
-nostdinc
-isystem <extracted-sysroot>/usr/include
-isystem <clang-resource-dir>/include
```

The Clang resource directory is allowed only for compiler builtin headers.

Capture the include trace and fail if an ordinary target header comes from locations such as:

```text
/usr/include
/opt/musl-*
the crabc source checkout
the pre-package staging directory
```

Do not reject the Clang resource include directory.

## Link isolation

Use:

```text
-nostdlib
-fuse-ld=lld
```

Supply by explicit path:

* startup objects from the extracted sysroot;
* crabc dynamic or static libc from the extracted sysroot;
* the manifest-declared dynamic interpreter;
* required compatibility libraries from the extracted sysroot.

Generate and retain an lld link map.

Do not allow the link to select Alpine or pinned-musl:

```text
libc
CRT startup objects
libpthread
libdl
libm
librt
loader
target headers
```

If the disposable compiler genuinely requires a compiler-support object or archive not owned by libc—such as a compiler builtin archive—query and record it explicitly, whitelist only that exact compiler-support input, and prove it is not a host libc or CRT object.

Do not broaden the search path to make a link pass.

## Mandatory smoke programs

### A. Compile-only public-header probe

Compile one C translation unit including representative public headers:

```c
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
```

This must use only the extracted crabc headers plus Clang resource headers.

### B. Dynamic PIE runtime probe

Build a dynamic PIE using the extracted sysroot.

Exercise at least:

* process startup;
* `argc`/`argv`;
* environment access;
* stdio;
* allocation and free;
* `_Thread_local`;
* a pthread;
* `errno`;
* `dlopen`;
* `dlsym`;
* `dlclose`.

Build the loadable module separately as a real shared object. It should export one simple function and may use a constructor to prove normal loader initialization.

The executable must print exactly:

```text
crabc sysroot dynamic smoke ok
```

with:

```text
exit status = 0
stderr = empty
```

### C. Static runtime probe

Build a static executable using the extracted:

```text
crt1.o
crti.o
libc.a
crtn.o
```

and any other startup object explicitly required by the completed sysroot contract.

Reuse the repository’s existing static pthread/TLS fixture where practical instead of inventing a weaker test.

Require:

```text
exit status = 0
expected stdout
empty stderr
```

### D. Other declared link modes

Read the sysroot manifest.

If it declares support for either:

```text
dynamic non-PIE
static PIE
```

the smoke harness must exercise those modes too.

A link mode must not be declared in the manifest without a corresponding smoke test.

## ELF validation

For the dynamic executable and module, retain and validate:

```text
ELF header
program headers
dynamic section
symbol summary
relocation summary
link map
```

Require:

* ELF64;
* little-endian;
* machine AArch64;
* dynamic executable is PIE where intended;
* `PT_INTERP` equals the manifest-declared crabc loader path;
* dynamic dependencies resolve from the extracted sysroot;
* no glibc loader or `libc.so.6`;
* no foreign host libc at runtime.

For the static executable require:

* AArch64 ELF;
* no `PT_INTERP`;
* no `DT_NEEDED`.

Do not identify library ownership solely from a SONAME string. A musl-compatible alias may legitimately resolve to crabc. Prove ownership by resolving it to the extracted sysroot artifact and comparing the expected hash.

## Execute in a scratch root

Do not install crabc’s loader into the development container’s real `/lib`.

Construct a temporary root filesystem from the extracted sysroot:

```text
<scratch-root>/
├── lib/
├── usr/lib/
├── bin/
└── any minimal writable fixture directories
```

Place the test executable under `/bin` and the shared module in an appropriate sysroot library directory.

Run it with `chroot` so its absolute `PT_INTERP` resolves naturally to the packaged crabc loader.

The root must not contain Alpine’s loader or libc.

This proves that the archive contains a usable runtime root rather than succeeding because the development container supplied missing pieces.

---

# 6. Add `.github/workflows/sysroot.yml`

Create a separate manually dispatched workflow.

Do not add this release workload to normal pull-request CI.

The workflow should have approximately this structure:

```yaml
name: Publish AArch64 sysroot

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build-and-smoke:
    runs-on: ubuntu-24.04-arm
    permissions:
      contents: read
    steps:
      # checkout
      # enforce default branch
      # build pinned image
      # run local tests
      # run ./scripts/dev.sh sysroot-dist
      # validate output assets
      # upload exact dist files as a workflow artifact

  publish-prerelease:
    needs: build-and-smoke
    runs-on: ubuntu-24.04
    permissions:
      actions: read
      contents: write
    steps:
      # download the workflow artifact
      # independently verify checksum/report
      # publish immutable GitHub prerelease
```

The publishing job does not compile anything, so it does not need an AArch64 runner. The build and smoke-test job must be native AArch64.

## Workflow requirements

* Permit manual dispatch only.

* Publish only from the repository’s default branch.

* Fail clearly if manually dispatched from another branch or tag.

* Use `ubuntu-24.04-arm` for all build and smoke work.

* Invoke:

  ```sh
  ./scripts/dev.sh image
  ./scripts/dev.sh sysroot-dist
  ```

* Do not reproduce packaging commands inline in YAML.

* Set explicit job timeouts.

* Use least-privilege permissions.

* Give the build job no write permission.

* Give `contents: write` only to the final publication job.

* Pin every GitHub-maintained action to a full commit SHA.

* Add a comment beside each pin naming the corresponding release version.

* Resolve the current compatible action releases at implementation time.

* Use only GitHub-maintained actions for checkout and workflow-artifact transfer.

* Use the runner’s authenticated `gh` CLI for GitHub Release creation rather than adding a third-party release action.

* Set `if-no-files-found: error` on workflow-artifact upload.

* Give the temporary workflow artifact a finite retention period.

* Do not use `continue-on-error` for validation, packaging, checksums, smoke testing, or publication.

Before publication, the release job must independently run:

```sh
sha256sum -c crabc-sysroot-aarch64-*.tar.xz.sha256
```

It must also parse the manifest and smoke JSON and verify:

```text
manifest source commit == GITHUB_SHA
smoke source commit == GITHUB_SHA
smoke passed == true
smoke archive SHA == verified archive SHA
target == AArch64
```

---

# 7. GitHub prerelease policy

Use an immutable full-commit tag:

```text
sysroot-aarch64-<FULL_SHA>
```

Use a human-readable title:

```text
crabc AArch64 sysroot snapshot <SHORT_SHA>
```

Publish these release assets:

```text
crabc-sysroot-aarch64-<SHORT_SHA>.tar.xz
crabc-sysroot-aarch64-<SHORT_SHA>.tar.xz.sha256
crabc-sysroot-aarch64-<SHORT_SHA>.manifest.json
crabc-sysroot-aarch64-<SHORT_SHA>.smoke.json
```

Create the release with:

```text
prerelease = true
target = exact GITHUB_SHA
```

Do not:

```text
create a stable release
mark it latest
use a semantic-version tag
create a moving "nightly" tag
create a moving "latest-sysroot" asset
promise compatibility with another snapshot
overwrite a differing asset for an existing commit tag
```

## Idempotent reruns

If the release tag does not exist, create it.

If the release already exists:

1. download its checksum asset;
2. compare it with the newly built checksum;
3. if identical, report that the exact snapshot is already published and succeed without mutating it;
4. if different, fail loudly.

Do not use `--clobber`.

A different artifact requires a different source commit.

---

# 8. Required prerelease notes

Generate release notes equivalent to:

````markdown
## Experimental Linux/AArch64 sysroot snapshot

This is an unstable prerelease snapshot of the crabc sysroot from commit `<FULL_SHA>`.

It is intended for crabc development, testing, and groundwork for a future `llvm-clang-crabc` toolchain.

There are currently no guarantees concerning:

- ABI stability
- API stability
- header stability
- startup-object layout
- loader behavior across snapshots
- static archive compatibility
- forward or backward compatibility
- suitability as a general-purpose production SDK

Pin the exact commit and verify the accompanying SHA-256 checksum.

The archive was built and smoke-tested natively on Linux/AArch64 inside crabc's pinned Docker development environment. It was tested using the container's disposable Clang/lld installation; it does not contain or depend on a released `llvm-clang-crabc` toolchain.

Local reproduction on Apple Silicon macOS:

```sh
./scripts/dev.sh image
./scripts/dev.sh sysroot-dist
````

````

Do not add stronger compatibility claims elsewhere in the workflow, README, manifest, or release title.

---

# 9. Documentation

Add a focused README section documenting:

```sh
./scripts/dev.sh image
./scripts/dev.sh sysroot-dist
````

State explicitly:

* this runs entirely inside `linux/arm64` Docker;
* it is supported from Apple Silicon macOS;
* the same command is used by GitHub Actions;
* outputs appear under `dist/`;
* the archive is an experimental commit snapshot;
* there are no ABI, API, layout, or cross-version compatibility guarantees;
* the smoke compiler is the pinned container’s Clang/lld, not `llvm-clang-crabc`;
* x86-64 is not built.

Keep this concise. Do not turn the README into a future LLVM toolchain design document.

---

# 10. Testing and implementation discipline

Implement in reviewable increments.

A reasonable sequence is:

1. Add failing unit tests for deterministic and safe archive handling.
2. Implement the packaging helper.
3. Add smoke fixtures and failing harness tests.
4. Implement extracted-archive structural and compiler isolation checks.
5. Implement dynamic/static/chroot smoke execution.
6. Add `sysroot-dist` and optional `sysroot-smoke` dispatch to `scripts/dev.sh`.
7. Run the complete path locally through Docker.
8. Add documentation.
9. Add the GitHub workflow last, as a thin caller of the proven local path.
10. Review permissions, action pins, release immutability, and branch guards.

Do not commit generated `dist/` output.

Run at minimum:

```sh
python3 -m unittest discover -s compat/sysroot-smoke/tests -p 'test_*.py'
```

plus any package-helper unit tests, then:

```sh
./scripts/dev.sh image
./scripts/dev.sh sysroot-dist
```

Afterward, independently verify:

```sh
sha256sum -c dist/*.tar.xz.sha256
tar -tJf dist/*.tar.xz
```

Then rerun the archive smoke command against the resulting archive if a separate command was added.

Run the package operation twice from the same clean commit and prove the archive SHA-256 is identical.

Also run the relevant existing crabc tests affected by any `scripts/dev.sh`, manifest, exporter, or fixture changes.

---

# Non-goals

Do not implement or expand:

```text
llvm-clang-crabc
LLVM
Clang
libc++
libc++abi
compiler-rt distribution
libunwind distribution
C++ smoke tests
x86-64
cross compilation
QEMU
Docker multi-architecture manifests
install scripts
package-manager integration
stable sysroot versioning
ABI comparison between releases
automatic release on every push
stable GitHub releases
OCI image publishing
artifact signing infrastructure
GitHub artifact attestations
```

Do not weaken the existing sysroot contract merely to make packaging pass.

A packaging, isolation, or smoke failure must remain a failure.

---

# Definition of done

The work is complete only when all of the following are true:

1. On Apple Silicon macOS, the user can run:

   ```sh
   ./scripts/dev.sh image
   ./scripts/dev.sh sysroot-dist
   ```

   with Docker as the only required build environment.

2. Every build, package, extract, compile, link, inspect, and runtime operation occurs in native `linux/arm64`.

3. The command produces the four expected files under `dist/`.

4. Two clean runs from the same commit produce the same archive hash.

5. The archive is safely extracted to a randomized path before testing.

6. Public headers compile without ambient target-header leakage.

7. A dynamic PIE links against the extracted crabc sysroot and runs in a scratch chroot through the packaged crabc loader.

8. A separately built shared module loads successfully through `dlopen`.

9. A static pthread/TLS executable links against packaged `libc.a` and runs successfully.

10. Every additional link mode declared by the manifest is exercised.

11. ELF inspection proves AArch64 and the expected dynamic/static contracts.

12. The smoke report records `passed: true` and the exact archive SHA.

13. `.github/workflows/sysroot.yml` uses `ubuntu-24.04-arm` for build and test.

14. The workflow invokes the same `./scripts/dev.sh sysroot-dist` command used locally.

15. The build job has read-only permissions.

16. The publication job alone has `contents: write`.

17. A manual default-branch dispatch creates a commit-derived GitHub prerelease containing the exact smoke-tested assets.

18. A rerun for the same commit is immutable and checksum-idempotent.

19. Release notes clearly disclaim ABI, API, layout, and cross-version guarantees.

20. No x86-64, QEMU, hypothetical LLVM toolchain, or host-side macOS build dependency has been introduced.

