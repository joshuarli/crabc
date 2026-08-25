**crabc should provide the Linux C runtime substrate**: public C headers, libc, dynamic loader, startup objects, static linking support, and a sealed sysroot.

**LLVM should provide the language and compiler stack**: Clang, LLVM, lld, compiler-rt, libunwind, libc++abi, and libc++.

That gives you a complete C/C++ toolchain without turning crabc into a C++ runtime project:

```text
C and POSIX ABI          crabc
ELF dynamic loader       crabc
Application startup      crabc
Compiler builtins        compiler-rt
Linker                    lld
Unwinding                 libunwind
C++ ABI                   libc++abi
C++ standard library      libc++
Compiler frontend         Clang
Optimizer/code generator  LLVM
```

The new repository should not be a mechanical fork with `musl` replaced by `crabc`. The existing `llvm-prebuilt-musl` artifact deliberately does **not** include musl or a target sysroot, and its documented consumer commands still require explicit `--target`, `--sysroot`, C++ header paths, library paths, `-lc++abi`, and `-lunwind`.

`llvm-clang-crabc` should go further: it should be a **complete, relocatable SDK plus a crabc-hosted compiler distribution**, where these work without extra flags:

```sh
clang hello.c -o hello
clang++ hello.cc -o hello-cxx
```

## The hard prerequisite

`llvm-clang-crabc` needs a crabc-owned application sysroot, not a stable crabc ABI release, before it can begin. The old Lua adapter sysroot borrows musl `Scrt1.o`, `crti.o`, and `crtn.o`, plus compiler-provided CRT bookends. That remains valid compatibility evidence, but it cannot support a claim that the LLVM toolchain is completely musl-free.

Therefore, this is a coordinated two-repository project:

1. **crabc must publish an immutable, crabc-owned experimental sysroot prerelease.**
2. **`llvm-clang-crabc` must pin, verify, and consume that exact artifact before adding the LLVM/C++ layers.**

An accepted prerelease is a GitHub prerelease tagged
`sysroot-aarch64-<full-source-commit>` that contains a commit-named archive,
its SHA-256 file, the embedded-manifest copy, and a passing smoke attestation.
The tag, release target commit, manifest `source_commit`, smoke
`source_commit`, and archive digest must all agree. This is an immutable
input boundary, not a promise of ABI, API, header, startup-object, loader, or
static-archive compatibility across snapshots.

That experimental status is sufficient for the LLVM implementation work
because the consumer must lock and validate one snapshot byte-for-byte. A
stable crabc sysroot contract is required only before representing the
combined SDK as a general-purpose stable release; it does not block the
initial LLVM/C++ integration.

Do not implement missing libc, loader, or startup behavior inside `llvm-clang-crabc`. Every such deficiency belongs in crabc with a focused regression.

---

# Fixed architecture

## Scope

| Decision                    | v0 choice                                 |
| --------------------------- | ----------------------------------------- |
| Host platform               | Linux AArch64                             |
| Target platform             | Linux AArch64 little-endian               |
| Build runner                | Native AArch64 only                       |
| Bootstrap environment       | Alpine/musl, build-time only              |
| Final compiler runtime      | crabc                                     |
| Default target ABI triple   | `aarch64-unknown-linux-musl`              |
| Canonical interpreter       | `/lib/ld-crabc-aarch64.so.1`              |
| C runtime                   | crabc                                     |
| C++ standard library        | libc++                                    |
| C++ ABI                     | libc++abi                                 |
| Unwinder                    | libunwind                                 |
| Compiler runtime            | compiler-rt                               |
| Linker                      | lld                                       |
| Final LLVM internal linkage | Static LLVM component libraries           |
| Final LLVM C++ runtime      | Statically linked libc++ stack            |
| User C++ runtime            | Static libc++ stack in v0                 |
| Compression                 | Pinned zlib rebuilt against crabc         |
| x86-64                      | Explicitly deferred                       |
| Sanitizers, OpenMP, LLDB    | Explicitly deferred                       |
| Shared libc++               | Explicitly deferred                       |
| PGO, BOLT, ThinLTO          | Deferred until correctness is established |

## Keep the musl ABI triple initially

Use `aarch64-unknown-linux-musl` as the ABI identity for v0.

crabc deliberately targets a musl-compatible Linux ABI. Keeping the established triple means:

* Autoconf, CMake, Rust build scripts, and LLVM already recognize it.
* Clang already applies the appropriate Linux/musl assumptions.
* Existing source packages do not need to learn a new `crabc` environment name.
* The project avoids a sprawling LLVM Triple, config.sub, CMake, Rust, and dependency ecosystem patch set.

The triple describes ABI conventions; it does not prove that musl code is present.

Do **not** add `aarch64-unknown-linux-crabc` in v0. That can be reconsidered after the toolchain works and there is a concrete semantic difference that cannot be represented by the musl ABI environment.

## Patch the dynamic-loader default cleanly

Pinned Clang’s Linux driver selects `/lib/ld-musl-aarch64.so.1` for an AArch64 musl triple.

Do not solve that with a compatibility symlink named `ld-musl-aarch64.so.1`. The final ELF contract should state crabc directly.

Add one small, upstream-quality LLVM patch introducing a build-time default dynamic-linker override:

```text
CLANG_DEFAULT_DYNAMIC_LINKER=/lib/ld-crabc-aarch64.so.1
```

The patch should:

1. Add a Clang CMake cache variable named `CLANG_DEFAULT_DYNAMIC_LINKER`.
2. Put it into generated Clang configuration.
3. Make `Linux::getDynamicLinker()` return it when nonempty.
4. Add a Clang driver regression test.
5. Leave upstream behavior unchanged when the variable is empty.

This is cleaner than hardcoding a crabc branch into `Linux.cpp`, and the existing musl repository already has a disciplined versioned LLVM patch mechanism that can be carried over.

---

# Runtime ownership boundary

This split must remain explicit:

| Artifact                                                   | Owner       |
| ---------------------------------------------------------- | ----------- |
| `libc.so`                                                  | crabc       |
| `libc.a`                                                   | crabc       |
| `ld-crabc-aarch64.so.1`                                    | crabc       |
| `libm`, `libdl`, `libpthread`, `librt` compatibility names | crabc       |
| Public C/POSIX headers                                     | crabc       |
| `crt1.o`                                                   | crabc       |
| `Scrt1.o`                                                  | crabc       |
| `rcrt1.o`                                                  | crabc       |
| `crti.o`                                                   | crabc       |
| `crtn.o`                                                   | crabc       |
| `clang_rt.crtbegin-aarch64.o`                              | compiler-rt |
| `clang_rt.crtend-aarch64.o`                                | compiler-rt |
| `libclang_rt.builtins-aarch64.a`                           | compiler-rt |
| `_Unwind_*`                                                | libunwind   |
| `__cxa_*`, `__gxx_personality_v0`                          | libc++abi   |
| `std::__1::*`                                              | libc++      |

Compiler-rt can build its own `crtbegin` and `crtend`, and Clang’s GNU/Linux driver already prefers those objects when `--rtlib=compiler-rt` is selected and the objects exist. There is no reason to import GCC’s `crtbegin`, `crtend`, `libgcc`, or `libgcc_s`.

---

# Build graph

The existing repository uses LLVM’s two-stage bootstrap machinery. Its own comments note that a genuine three-stage construction would solve the C++ runtime bootstrap contamination problem. For crabc, implement those stages explicitly rather than trying to force everything through `CLANG_ENABLE_BOOTSTRAP`.

```text
                         BUILD-TIME DOMAIN
                    Alpine/musl AArch64 container
                                 │
                                 ▼
                   bootstrap Clang + lld + tblgen
                    musl-hosted, never packaged
                                 │
          ┌──────────────────────┼───────────────────────┐
          │                      │                       │
          ▼                      ▼                       ▼
  crabc C sysroot       compiler-rt builtins       private static zlib
  headers/libc/CRT       + crtbegin/crtend          built against crabc
          │                      │                       │
          └──────────────┬───────┴───────────────────────┘
                         ▼
                libunwind → libc++abi → libc++
                     built against crabc
                         │
                         ▼
                 final LLVM/Clang/lld build
          bootstrap compiler executes during build,
            final objects and binaries target crabc
                         │
                         ▼
                 FINAL RELEASE ARTIFACT
       clang/lld/llvm-* themselves run through crabc
       clang defaults to the bundled crabc target sysroot
```

This is a **same-CPU cross build**: build and target CPUs are both AArch64, but the build tools execute against musl while final binaries link against crabc. LLVM explicitly supports supplying native build tools such as `llvm-tblgen` and `clang-tblgen` through `LLVM_NATIVE_TOOL_DIR`.

Do not install crabc’s loader into the Alpine builder’s `/lib` during this build. Target executables should remain unexecutable there, making accidental CMake `try_run` or execution of target-built tools fail visibly rather than silently crossing the boundary.

---

# Required crabc sysroot artifact contract

Before LLVM integration, `llvm-clang-crabc` must acquire one pinned crabc
release snapshot. It must consume the release archive rather than invoke a
source-tree export command, inspect Cargo target directories, or infer Rust
artifact naming.

The release assets are named from the pinned full source commit, using its
first 12 lowercase hexadecimal characters as `<short-commit>`:

```text
tag:      sysroot-aarch64-<full-source-commit>
archive:  crabc-sysroot-aarch64-<short-commit>.tar.xz
checksum: crabc-sysroot-aarch64-<short-commit>.tar.xz.sha256
manifest: crabc-sysroot-aarch64-<short-commit>.manifest.json
smoke:    crabc-sysroot-aarch64-<short-commit>.smoke.json
```

After SHA-256 verification and safe extraction, the archive must contain a
conventional, self-contained sysroot:

```text
crabc-sysroot-aarch64-<short-commit>/
├── bin/
│   └── crabc-cc
├── lib/
│   ├── ld-crabc-aarch64.so.1
│   └── ld-musl-aarch64.so.1 -> ld-crabc-aarch64.so.1  # compatibility only
├── share/crabc/
│   ├── manifest.json
│   └── purity.json
└── usr/
    ├── include/
    │   └── all crabc public headers
    └── lib/
        ├── libc.so
        ├── libc.a
        ├── libcrabc-builtins.a
        ├── crt1.o
        ├── Scrt1.o
        ├── rcrt1.o
        ├── crti.o
        ├── crtn.o
        └── compatibility library link names
```

The embedded manifest must use the crabc sysroot schema and include the
following identity and layout fields (the separate manifest release asset must
be byte-for-byte identical to it):

```json
{
  "schema": 1,
  "target": "aarch64-unknown-linux-musl",
  "platform": {
    "os": "linux",
    "architecture": "aarch64",
    "endianness": "little",
    "kernel_minimum": "5.10"
  },
  "canonical_interpreter": "/lib/ld-crabc-aarch64.so.1",
  "source_commit": "<full-source-commit>",
  "artifacts": {
    "libc": {
      "path": "usr/lib/libc.a",
      "sha256": "<sha256>"
    }
  }
}
```

The consumer lock must record the crabc repository, full source commit, release
tag, archive filename, and SHA-256 digests of all four release assets. It must
verify the release is a prerelease targeted at that full commit, verify the
checksum file against the archive, and verify that the manifest and smoke
attestation bind the same source commit and archive hash. The extracted
sysroot is a public crabc product, although this experimental snapshot has no
cross-snapshot compatibility guarantee.

Its gate must prove:

```sh
clang hello.c                  # dynamic PIE
clang -no-pie hello.c
clang -static hello.c
clang -static-pie hello.c
```

using explicit bootstrap-driver arguments during crabc testing, with:

* constructors and destructors;
* TLS;
* `argc`, `argv`, environment, and auxiliary vector handling;
* stack protector initialization;
* pthread startup;
* static relocation;
* exact interpreter selection;
* no musl headers, startup objects, archives, or mapped runtime.

The existing Lua source-build gate must then be rerun using this owned sysroot instead of the adapter CRT bridge.

---

# Final package layout

Keep host-side LLVM libraries and target-side SDK libraries physically separated even though both use AArch64/crabc:

```text
clang+llvm-23.1.0-rc2-aarch64-linux-crabc/
├── bin/
│   ├── clang
│   ├── clang++
│   ├── clang-23
│   ├── lld
│   ├── ld.lld
│   ├── llvm-ar
│   ├── llvm-nm
│   ├── llvm-objcopy
│   ├── llvm-objdump
│   ├── llvm-ranlib
│   ├── llvm-readelf
│   ├── llvm-readobj
│   ├── llvm-size
│   ├── llvm-strings
│   ├── llvm-strip
│   ├── llvm-symbolizer
│   ├── clang.cfg
│   ├── clang++.cfg
│   └── aarch64-unknown-linux-musl.cfg
├── include/
│   └── clang-c/
├── lib/
│   ├── libclang.so
│   ├── libLTO.so
│   └── clang/23/
│       ├── include/
│       └── lib/linux/
│           ├── libclang_rt.builtins-aarch64.a
│           ├── clang_rt.crtbegin-aarch64.o
│           └── clang_rt.crtend-aarch64.o
├── sysroot/
│   ├── lib/
│   │   ├── ld-crabc-aarch64.so.1
│   │   ├── libc.so
│   │   └── compatibility link names
│   └── usr/
│       ├── include/
│       │   ├── crabc C headers
│       │   └── c++/v1/
│       └── lib/
│           ├── libc.a
│           ├── crt1.o
│           ├── Scrt1.o
│           ├── rcrt1.o
│           ├── crti.o
│           ├── crtn.o
│           ├── libc++.a
│           ├── libc++abi.a
│           └── libunwind.a
└── share/llvm-clang-crabc/
    ├── manifest.json
    ├── source-lock.json
    ├── build-command.txt
    ├── elf-policy.json
    └── licenses/
```

The package’s root `lib/` is for libraries used by the compiler distribution. Target runtime libraries belong under `sysroot/`. Never allow CMake or Clang to find target libraries merely because both happen to be under one prefix.

## Relocatable driver configuration

Use Clang configuration files for SDK-relative paths. Clang supports the `<CFGDIR>` token specifically so SDK configuration can remain portable relative to the configuration file. ([Clang][1])

`bin/aarch64-unknown-linux-musl.cfg`:

```text
--sysroot=<CFGDIR>/../sysroot
-B<CFGDIR>/../sysroot/usr/lib
-L<CFGDIR>/../sysroot/usr/lib
-L<CFGDIR>/../sysroot/lib
```

`bin/clang.cfg`:

```text
-fuse-ld=lld
-rtlib=compiler-rt
-unwindlib=libunwind
```

`bin/clang++.cfg`:

```text
-fuse-ld=lld
-rtlib=compiler-rt
-unwindlib=libunwind
-stdlib=libc++
-cxx-isystem <CFGDIR>/../sysroot/usr/include/c++/v1
```

Also compile these defaults into Clang:

```text
CLANG_DEFAULT_LINKER=lld
CLANG_DEFAULT_RTLIB=compiler-rt
CLANG_DEFAULT_UNWINDLIB=libunwind
CLANG_DEFAULT_CXX_STDLIB=libc++
CLANG_DEFAULT_PIE_ON_LINUX=ON
CLANG_DEFAULT_DYNAMIC_LINKER=/lib/ld-crabc-aarch64.so.1
```

The config files should establish paths; compiled defaults should establish policy.

---

# C++ runtime configuration

Build the runtime stack in dependency order:

```text
compiler-rt builtins
        ↓
libunwind
        ↓
libc++abi
        ↓
libc++
```

LLVM documents `LLVM_ENABLE_RUNTIMES` as the correct mechanism for building compiler runtimes with the just-built compiler while preserving builtins ordering. ([GitHub][2])

Use these important runtime settings:

```text
LIBUNWIND_ENABLE_SHARED=OFF
LIBUNWIND_ENABLE_STATIC=ON
LIBUNWIND_USE_COMPILER_RT=ON

LIBCXXABI_ENABLE_SHARED=OFF
LIBCXXABI_ENABLE_STATIC=ON
LIBCXXABI_USE_LLVM_UNWINDER=ON
LIBCXXABI_ENABLE_STATIC_UNWINDER=ON
LIBCXXABI_USE_COMPILER_RT=ON

LIBCXX_ENABLE_SHARED=OFF
LIBCXX_ENABLE_STATIC=ON
LIBCXX_USE_COMPILER_RT=ON
LIBCXX_CXX_ABI=libcxxabi
LIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON
LIBCXX_STATICALLY_LINK_ABI_IN_STATIC_LIBRARY=ON
LIBCXX_HAS_MUSL_LIBC=ON
LIBCXX_HAS_PTHREAD_API=ON
```

Pinned libc++ supports folding the static ABI library into `libc++.a`, while libc++abi supports statically linking the LLVM unwinder. Use those options so a normal `clang++` link needs only the driver’s ordinary `-lc++` behavior rather than exposed `-lc++abi -lunwind` consumer flags.  ([GitHub][3])

Keep these features enabled:

```text
exceptions
RTTI
threads
filesystem
localization
wide characters
Unicode
random_device
monotonic clocks
```

Do not disable standard C++ facilities merely to get the build green. When a facility exposes a crabc gap, add a focused crabc regression and repair the runtime.

The accepted locale contract can remain C/C.UTF-8. Full locale databases are not required, but `std::locale::classic()`, wide-character operations, and UTF-8 behavior must work.

---

# Repository structure

Use a typed, standard-library-only Python orchestrator rather than cloning the current large shell runner:

```text
llvm-clang-crabc/
├── AGENTS.md
├── README.md
├── Makefile
├── versions.toml
├── toolchain/
│   ├── __init__.py
│   ├── cli.py
│   ├── model.py
│   ├── command.py
│   ├── fetch.py
│   ├── patches.py
│   ├── stages.py
│   ├── crabc.py
│   ├── cmake.py
│   ├── elf.py
│   ├── symbols.py
│   ├── package.py
│   └── manifest.py
├── cmake/
│   ├── bootstrap.cmake
│   ├── aarch64-crabc-toolchain.cmake.in
│   ├── compiler-rt-crabc.cmake
│   ├── runtimes-crabc.cmake
│   └── final-crabc.cmake
├── configs/
│   ├── clang.cfg.in
│   ├── clang++.cfg.in
│   └── aarch64-unknown-linux-musl.cfg.in
├── docker/
│   ├── aarch64-builder.Dockerfile
│   └── scratch-rootfs.Dockerfile
├── patches/
│   └── llvm/
│       ├── series.toml
│       └── 0001-clang-default-dynamic-linker.patch
├── tests/
│   ├── unit/
│   ├── policy/
│   ├── smoke/
│   │   ├── c/
│   │   └── cxx/
│   └── real/
│       ├── lua.py
│       └── ninja.py
├── docs/
│   ├── DESIGN.md
│   ├── BUILD.md
│   ├── COMPATIBILITY.md
│   ├── RELEASE.md
│   └── FAILURE-TRIAGE.md
└── .github/workflows/
    ├── build-aarch64.yml
    └── release.yml
```

The `Makefile` should contain aliases only:

```make
doctor:
	python3 -m toolchain.cli doctor

bootstrap:
	python3 -m toolchain.cli bootstrap

sysroot:
	python3 -m toolchain.cli sysroot

runtimes:
	python3 -m toolchain.cli runtimes

final:
	python3 -m toolchain.cli final

validate:
	python3 -m toolchain.cli validate

package:
	python3 -m toolchain.cli package

all:
	python3 -m toolchain.cli all
```

Every stage must:

* print its complete subprocess command;
* write a dedicated log under `out/logs/`;
* record its environment and inputs;
* write a stage stamp containing a hash of all meaningful inputs;
* refuse stale stamps whose inputs changed;
* support `--clean-stage`;
* support `--offline` after sources are fetched;
* reject undeclared host include and library paths.

---

# Coding-agent implementation plan

## PR 0 — Establish the repository contract

Create:

```text
README.md
AGENTS.md
docs/DESIGN.md
versions.toml
Makefile
toolchain/{cli,model,command}.py
tests/unit/
```

Pin the exact LLVM release and patch set used by the current `~/d/laputa-systems/llvm-prebuilt-musl` repository for the first proof. Do not combine a libc replacement with an LLVM version upgrade.

`versions.toml` should pin:

```toml
[target]
architecture = "aarch64"
triple = "aarch64-unknown-linux-musl"
interpreter = "/lib/ld-crabc-aarch64.so.1"

[llvm]
version = "23.1.0-rc2"
source_sha256 = "..."
git_revision = "..."

[crabc]
repository = "https://github.com/joshuarli/crabc"
revision = "<full commit>"

[crabc.sysroot]
release_tag = "sysroot-aarch64-<full commit>"
archive = "crabc-sysroot-aarch64-<short commit>.tar.xz"
archive_sha256 = "<sha256>"
manifest_sha256 = "<sha256>"
smoke_sha256 = "<sha256>"

[zlib]
version = "<pinned version>"
source_sha256 = "..."

[builder]
image = "alpine:<pinned>"
image_digest = "sha256:..."
```

First tests:

* malformed lock file fails;
* abbreviated Git revisions fail;
* missing SHA-256 fails;
* unsupported architecture fails;
* interpreter not equal to the canonical crabc path fails.

Commit this independently before any build implementation.

## PR 1 — Port source acquisition and the native bootstrap

Port only the reusable mechanisms from `llvm-prebuilt-musl`:

* source download and checksum verification;
* idempotent patch application;
* native AArch64 Docker build;
* native host-tool build;
* curated LLVM project selection;
* explicit link-job limits;
* static/private zlib policy where applicable.

Build a musl-hosted bootstrap containing:

```text
clang
clang++
lld
ld.lld
llvm-tblgen
clang-tblgen
llvm-config
llvm-nm
llvm-readelf
llvm-readobj
llvm-ar
```

The bootstrap is an internal artifact under `out/bootstrap/`. It must never be copied into the release tree.

The existing repository already isolates native host tools for LLVM’s build graph; preserve that principle rather than relying on whichever `llvm-tblgen` happens to be in `PATH`.

Gate:

```sh
python3 -m toolchain.cli bootstrap
out/bootstrap/bin/clang --version
out/bootstrap/bin/ld.lld --version
```

Then assert that no file from `out/bootstrap/` appears in a package manifest.

## PR 2 — Pin the crabc-owned sysroot prerelease

The crabc prerequisite is its immutable experimental prerelease, not a stable
ABI release or a source-tree `--output` command. Record one accepted snapshot
in `llvm-clang-crabc/versions.toml`, including its full commit, immutable tag,
four release-asset names, and digests.

The verified extracted archive must provide:

* crabc headers;
* `libc.so`;
* `libc.a`;
* canonical loader;
* compatibility link names;
* `crt1.o`;
* `Scrt1.o`;
* `rcrt1.o`;
* `crti.o`;
* `crtn.o`;
* the embedded manifest and accompanying release-asset hashes.

Required tests:

1. Dynamic PIE.
2. Dynamic non-PIE.
3. Static executable.
4. Static PIE.
5. Constructors and destructors.
6. Static and dynamic TLS.
7. Stack protector.
8. Pthreads.
9. DSO loading.
10. Exact loader path.
11. Lua source build with no borrowed musl CRT.

Do not add any C++ runtime to crabc. Do not require a stable crabc ABI/API
claim for this PR; the pinned snapshot is an intentionally narrow, immutable
input to LLVM work.

## PR 3 — Consume and validate the crabc sysroot

Implement:

```text
toolchain/crabc.py
toolchain/manifest.py
toolchain/elf.py
tests/unit/test_crabc_manifest.py
tests/policy/test_sysroot_policy.py
```

The new repository must download the exact release assets named by the lock,
verify them, and safely extract the archive. It must not:

* inspect Cargo target directories;
* invoke a crabc source-tree export command;
* infer loader names;
* synthesize missing startup objects;
* borrow Alpine files;
* copy musl headers;
* follow a host symlink outside the sysroot.

Validate:

* prerelease tag and release target commit equal the locked full commit;
* release-asset names and SHA-256 digests equal the lock;
* checksum file validates the archive;
* manifest and smoke attestation bind the archive to the locked commit;
* manifest schema;
* exact target;
* exact interpreter;
* a passing smoke attestation, including its required link-mode witnesses;
* hashes;
* ELF machine and endianness;
* no absolute symlinks escaping the sysroot;
* no unrecorded files in critical runtime directories.

Copy the validated result into:

```text
out/sdk/sysroot/
```

## PR 4 — Build compiler-rt builtins and CRT bookends

Create `cmake/compiler-rt-crabc.cmake`.

Build compiler-rt as a target runtime using the bootstrap compiler and crabc sysroot:

```text
COMPILER_RT_DEFAULT_TARGET_ONLY=ON
COMPILER_RT_BUILD_BUILTINS=ON
COMPILER_RT_BUILD_CRT=ON
COMPILER_RT_BUILD_SANITIZERS=OFF
COMPILER_RT_BUILD_XRAY=OFF
COMPILER_RT_BUILD_LIBFUZZER=OFF
COMPILER_RT_BUILD_PROFILE=OFF
COMPILER_RT_BUILD_MEMPROF=OFF
COMPILER_RT_BUILD_ORC=OFF
COMPILER_RT_BUILD_GWP_ASAN=OFF
```

Install only:

```text
libclang_rt.builtins-aarch64.a
clang_rt.crtbegin-aarch64.o
clang_rt.crtend-aarch64.o
```

Add tests for:

* 128-bit multiplication and division;
* overflow builtins;
* stack protector;
* `__builtin_*` arithmetic helpers;
* generic AArch64 atomics;
* 16-byte atomic operations;
* constructors and destructors using compiler-rt CRT bookends.

Do not import GCC’s `libatomic`. Prefer compiler-rt’s atomic implementation. If a standalone atomic archive is genuinely required, build it from compiler-rt and make the link behavior explicit.

### Symbol-ownership gate

Generate sorted strong-symbol inventories for:

```text
libc.a
libclang_rt.builtins-aarch64.a
libunwind.a
libc++abi.a
libc++.a
```

Fail on duplicate strong definitions except a tiny reviewed allowlist.

This is especially important because crabc’s Rust static library may otherwise carry compiler-builtins implementations that overlap compiler-rt. The gate must prove which layer owns every runtime namespace rather than relying on archive extraction order.

## PR 5 — Build private zlib against crabc

Do not link the final LLVM tools against Alpine’s `/usr/lib/libz.a`. Although static, it was built against the bootstrap environment and would violate the target provenance boundary.

Build pinned zlib from source using:

```text
bootstrap clang
crabc sysroot
lld
compiler-rt
```

Install its headers and archive into a private build prefix:

```text
out/deps/crabc/
```

Use it only while linking LLVM. It does not need to become a public SDK dependency unless downstream programs are intentionally meant to consume it.

Gate:

* `libz.a` member objects are AArch64;
* source and command provenance are recorded;
* no host include or library path appears in its compile database;
* LLVM’s debug-section compression smoke test works later.

## PR 6 — Build libunwind, libc++abi, and libc++

Create `cmake/runtimes-crabc.cmake`.

Build static-only runtimes against the combined crabc/compiler-rt sysroot.

Tests must cover:

```text
iostream
string/vector
exceptions
nested exceptions
RTTI and dynamic_cast
std::thread
mutex and condition_variable
thread_local destructor
filesystem
aligned new/delete
std::atomic
wide strings
std::locale::classic()
UTF-8 input/output
random_device
steady_clock
```

The first likely failures will expose real crabc gaps in locale, wide-character handling, TLS destructors, pthread behavior, unwinding support, filesystem calls, `dl_iterate_phdr`, or atomics. For each failure:

1. Reduce it to a focused C or ABI test.
2. Add that regression in crabc.
3. Fix crabc.
4. Pin the new crabc commit.
5. Preserve the original C++ witness.

Do not add a compatibility shim in `llvm-clang-crabc`.

## PR 7 — Add the Clang dynamic-linker patch and final build configuration

Add:

```text
patches/llvm/0001-clang-default-dynamic-linker.patch
cmake/aarch64-crabc-toolchain.cmake.in
cmake/final-crabc.cmake
```

The generated CMake toolchain file should set:

```cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   "<bootstrap>/bin/clang")
set(CMAKE_CXX_COMPILER "<bootstrap>/bin/clang++")

set(CMAKE_C_COMPILER_TARGET   aarch64-unknown-linux-musl)
set(CMAKE_CXX_COMPILER_TARGET aarch64-unknown-linux-musl)

set(CMAKE_SYSROOT "<sdk>/sysroot")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_FIND_ROOT_PATH "<sdk>/sysroot;<private-deps>")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

Set LLVM policy:

```text
LLVM_TARGETS_TO_BUILD=AArch64
LLVM_ENABLE_PROJECTS=clang;lld
LLVM_ENABLE_RUNTIMES=
LLVM_DEFAULT_TARGET_TRIPLE=aarch64-unknown-linux-musl
LLVM_TARGET_ARCH=AArch64

LLVM_ENABLE_LLD=ON
LLVM_USE_LINKER=lld

LLVM_ENABLE_LIBCXX=ON
LLVM_STATIC_LINK_CXX_STDLIB=ON

LLVM_BUILD_LLVM_DYLIB=OFF
LLVM_LINK_LLVM_DYLIB=OFF
BUILD_SHARED_LIBS=OFF

LLVM_ENABLE_ZLIB=FORCE_ON
LLVM_ENABLE_ZSTD=OFF
LLVM_ENABLE_TERMINFO=OFF
LLVM_ENABLE_LIBXML2=OFF
LLVM_ENABLE_LIBEDIT=OFF
LLVM_ENABLE_FFI=OFF

LLVM_INCLUDE_TESTS=OFF
LLVM_INCLUDE_DOCS=OFF
LLVM_INCLUDE_EXAMPLES=OFF
LLVM_INCLUDE_BENCHMARKS=OFF

LLVM_NATIVE_TOOL_DIR=<bootstrap>/bin
LLVM_TABLEGEN=<bootstrap>/bin/llvm-tblgen
CLANG_TABLEGEN=<bootstrap>/bin/clang-tblgen

CLANG_DEFAULT_LINKER=lld
CLANG_DEFAULT_CXX_STDLIB=libc++
CLANG_DEFAULT_RTLIB=compiler-rt
CLANG_DEFAULT_UNWINDLIB=libunwind
CLANG_DEFAULT_PIE_ON_LINUX=ON
CLANG_DEFAULT_DYNAMIC_LINKER=/lib/ld-crabc-aarch64.so.1
```

For final executable links, the bootstrap compiler invocation must explicitly provide the canonical crabc interpreter. The final patched compiler will then choose it by default for downstream programs.

Build only a curated distribution. Do not ship every LLVM utility simply because it exists.

## PR 8 — Assemble the zero-configuration SDK

Implement:

```text
toolchain/package.py
configs/*.cfg.in
tests/policy/test_driver_search_paths.py
```

Generate SDK-relative config files using `<CFGDIR>`.

The following must work from a randomly selected extraction directory:

```sh
"$TOOLCHAIN/bin/clang" hello.c -o hello
"$TOOLCHAIN/bin/clang++" hello.cc -o hello-cxx
```

Forbidden consumer flags in acceptance tests:

```text
--target
--sysroot
-I
-isystem
-cxx-isystem
-L
-B
-fuse-ld
-stdlib
-rtlib
-unwindlib
-lc++abi
-lunwind
-Wl,--dynamic-linker
```

Inspect `clang -###` and prove:

* bundled lld is selected;
* bundled crabc headers are selected;
* bundled libc++ headers are selected;
* bundled compiler-rt is selected;
* bundled libc++ is selected;
* bundled crabc startup objects are selected;
* no GCC installation is consulted;
* no `/usr/include` or `/usr/lib` target input is selected.

## PR 9 — Add scratch-rootfs validation

Construct a root filesystem containing only:

```text
/lib/ld-crabc-aarch64.so.1
/lib/libc.so
/opt/llvm-clang-crabc/
/tmp/
/tests/
```

No shell, BusyBox, Alpine package, musl loader, or glibc should exist inside it.

Run directly:

```text
/opt/llvm-clang-crabc/bin/clang --version
/opt/llvm-clang-crabc/bin/ld.lld --version
/opt/llvm-clang-crabc/bin/llvm-ar --version
```

Then compile and execute C and C++ smoke programs inside that root.

For every executable and shared library in the release tree, validate:

* ELF class is 64-bit;
* machine is AArch64;
* interpreter is exactly `/lib/ld-crabc-aarch64.so.1`;
* `DT_NEEDED` matches a tiny manifest-derived allowlist;
* no `libstdc++`;
* no `libgcc_s`;
* no shared `libunwind`;
* no shared `libc++`;
* no `libz.so`;
* no glibc soname;
* no musl soname or loader.

Do not use a naive `grep -R musl`. The package will legitimately contain the musl ABI triple and LLVM itself contains musl-target support. Purity is demonstrated through source provenance, sysroot contents, link maps, archive members, `PT_INTERP`, `DT_NEEDED`, and runtime mappings—not string absence.

## PR 10 — Real-source proof

Add two real consumers.

### Lua

Rebuild the pinned Lua version using the packaged `clang`, not crabc’s development adapter wrapper.

The toolchain invocation must contain no special target or sysroot flags.

Require:

* interpreter;
* shared `liblua`;
* `luac`;
* loadable C module;
* constructors;
* TLS;
* `dlopen`/`dlsym`;
* exact crabc runtime mappings;
* output parity with the existing reference gate.

### Ninja

Build pinned Ninja from source using the packaged `clang++`.

Ninja is an excellent first real C++ witness because it exercises:

* nontrivial C++;
* filesystem behavior;
* processes;
* threading;
* exceptions;
* the C++ standard library;
* a real build workload;
* few external dependencies.

Run Ninja’s tests and then use the built Ninja to compile another smoke project.

After those pass, add a focused libc++ test subset. Do not start by running the entire libc++ matrix; first establish deterministic groups for:

```text
language support
exceptions
threads
filesystem
atomics
localization
strings and containers
```

## PR 11 — Release and reproducibility

Implement deterministic packaging:

* fixed `SOURCE_DATE_EPOCH`;
* sorted archive entries;
* numeric owner/group zero;
* normalized permissions;
* `-ffile-prefix-map` and `-fdebug-prefix-map`;
* no absolute build-tree paths in configuration;
* SHA-256 checksum;
* exact source and patch manifest;
* license bundle;
* complete expanded build command.

Artifact:

```text
clang+llvm-23.1.0-rc2-aarch64-linux-crabc.tar.xz
clang+llvm-23.1.0-rc2-aarch64-linux-crabc.tar.xz.sha256
```

Run two clean builds in the same pinned builder environment and compare package digests. Any nondeterminism must be classified and reduced rather than normalized away without explanation.

---

# CI design

Use native GitHub AArch64 infrastructure, following the existing repository’s native ARM direction. Do not introduce QEMU into the primary build.

Keep the matrix deliberately singular:

```text
OS:       Linux
arch:     AArch64
libc:     crabc final / musl bootstrap
LLVM:     one pinned version
profile:  Release
```

Workflows:

### Pull requests

1. Python unit and policy tests.
2. Source verification and patch dry-run.
3. Native AArch64 bootstrap.
4. Crabc sysroot export.
5. Runtime build.
6. Final LLVM build.
7. Scratch-rootfs validation.
8. Lua and Ninja gates.

### Releases

* full uncached build;
* second reproducibility build;
* randomized extraction-prefix test;
* scratch-rootfs test;
* package and checksums;
* release manifest upload.

Cache keys must include:

```text
LLVM source digest
LLVM patch-series digest
crabc full commit
zlib source digest
builder image digest
CMake cache digest
compiler version
```

A cache hit must never allow a stage built against one crabc revision to survive after the crabc pin changes.

---

# Critical risk register

## 1. Crabc-owned application startup

This is the only absolute blocker. Until crabc supplies all startup objects and proves static, PIE, and static-PIE startup, the project remains an adapter toolchain.

## 2. Rust/compiler-rt symbol collisions

Rust static libraries commonly bring low-level compiler support. A silent collision between crabc’s archive and compiler-rt could make links order-dependent. The symbol-ownership manifest must be a hard gate.

## 3. Exception unwinding through crabc’s loader

C++ exceptions require cooperation among:

* `.eh_frame`;
* compiler-rt CRT initialization;
* libunwind;
* libc++abi;
* `dl_iterate_phdr`;
* TLS;
* thread teardown;
* loader DSO bookkeeping.

Test exceptions before attempting the full LLVM build. A simple successful `iostream` program does not prove C++ ABI viability.

## 4. `thread_local` destructors

`__cxa_thread_atexit_impl`, pthread teardown, DSO lifetime, and loader behavior are a likely integration fault line. Test destructors on both the main thread and created threads.

## 5. AArch64 atomic helpers

Test generic AArch64 rather than only the CI runner’s native CPU. The toolchain must not accidentally depend on an instruction extension present on the runner. Test 16-byte atomics and inspect unresolved `__atomic_*` symbols.

## 6. CMake accidentally executing target binaries

Use a real cross toolchain file, `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY`, and native LLVM tools. Do not make target executables runnable inside the bootstrap container merely to satisfy probes.

## 7. Static C++ runtime across DSO boundaries

For v0, make no claim about throwing C++ exceptions across independently linked shared-library boundaries. The default C++ runtime is static. Dynamic libc++, stable cross-DSO exception identity, and plugin-heavy C++ applications belong in a later milestone.

C shared libraries and `dlopen` remain required.

## 8. Ambient host leakage

The most dangerous false success is an Alpine header, startup object, `libgcc`, `libstdc++`, or static library satisfying a probe. Capture compiler search paths, link maps, and complete commands. Reject undeclared `/usr/include` and `/usr/lib` target inputs.

## 9. Final compiler host installation contract

A crabc-hosted `clang` has an absolute `PT_INTERP`. Merely extracting the tarball on arbitrary glibc or musl Linux will not make it executable. The documented contract must be:

* run it on a crabc system; or
* install the bundled crabc runtime into the host root; or
* use the provided crabc rootfs/container.

The SDK-relative target sysroot can move. The host loader path remains canonical.

---

# Definition of done

The v0 project is complete only when a root filesystem containing no glibc or musl runtime can execute:

```sh
/opt/llvm-clang-crabc/bin/clang --version
/opt/llvm-clang-crabc/bin/clang++ --version
/opt/llvm-clang-crabc/bin/ld.lld --version

/opt/llvm-clang-crabc/bin/clang /tests/hello.c -o /tmp/hello
/tmp/hello

/opt/llvm-clang-crabc/bin/clang++ /tests/hello.cc -o /tmp/hello-cxx
/tmp/hello-cxx
```

And all of these hold:

* final `clang`, `lld`, LLVM utilities, `libclang`, and `libLTO` are linked against crabc;
* generated dynamic programs use `/lib/ld-crabc-aarch64.so.1`;
* the package contains no musl or glibc headers, CRT objects, loader, libc archive, or runtime library;
* target links consume no musl or glibc object;
* compiler-rt supplies compiler builtins and CRT bookends;
* libc++/libc++abi/libunwind supply C++;
* no GCC runtime is present;
* no consumer target/sysroot/include/library flags are required;
* dynamic PIE, non-PIE, static, and static-PIE C work;
* C++ exceptions, RTTI, threads, TLS destructors, filesystem, atomics, and C/UTF-8 locale behavior work;
* Lua and Ninja build and run;
* the artifact is reproducible from pinned inputs;
* the only role musl plays is as the explicitly recorded, non-shipped bootstrap environment and ABI triple name.

That supports a precise, defensible project claim:

> **`llvm-clang-crabc` is a Linux/AArch64 LLVM C/C++ toolchain whose compiler binaries and default-produced programs use the crabc C runtime and loader, with LLVM’s compiler-rt, libunwind, libc++abi, and libc++ completing the toolchain. No glibc or musl runtime, headers, CRT, or target library is shipped or used in target links.**

[1]: https://clang.llvm.org/docs/UsersManual.html "https://clang.llvm.org/docs/UsersManual.html"
[2]: https://github.com/llvm/llvm-project/blob/main/llvm/docs/CMake.md "https://github.com/llvm/llvm-project/blob/main/llvm/docs/CMake.md"
[3]: https://github.com/llvm/llvm-project/blob/main/libcxxabi/CMakeLists.txt "https://github.com/llvm/llvm-project/blob/main/libcxxabi/CMakeLists.txt"
