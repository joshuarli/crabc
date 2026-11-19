# CRAB-8: Linux/AArch64 feature completion on an Apple Silicon host

Status: accepted 2026-11-18 — the owner took every recommendation in D1–D6.
The host is an OrbStack Linux/arm64 VM on the Apple Silicon Mac.
[`plan.md`](../../plan.md) records it as the campaign after F2.

## Summary

Bring Linux/AArch64 to the same feature-complete, correctness-qualified state as
native x86-64. Performance stays deferred. The work runs natively on an Apple
Silicon Mac, inside a Linux/arm64 virtual machine, with Docker in that VM.
Nothing is emulated. The recommendation is to **converge** AArch64 onto the x86
runtime tree rather than extend the older AArch64 composition. Shared Linux
behavior then keeps one owner, and AArch64 adds only an architecture layer.

This campaign comes before the macOS facade backend
([CRAB-7](CRAB-7-macos-libsystem-backend.md)), which remains deferred.

## Current state

The two architectures are separate implementations of different ages:

| | x86-64 (active) | AArch64 (paused) |
| --- | --- | --- |
| libc C ABI | `libc/src/c_abi/x86_64/`: 472 leaf modules, about 110k lines | `libc/src/c_abi.rs` plus `c_abi/aarch64/`: about 24k lines, one composition |
| Evidence | seven-gate correctness chain (`compat/x86_64/`, about 3.1k files) | `COMPATIBILITY.md` from 2026-08-25 at a dirty tree: 1647/1647 musl dynamic symbols exported, behavior proof older and narrower |
| Oracle | `[musl_native]` musl 1.2.6 snapshot `7813e911` | `[musl]` 1.2.6 |
| Allocator | pinned C mimalloc v3.5.0 plus crabc glue | `libmimalloc-sys` 0.1.49 |
| Facade | 125 `crabc-rs` files gated to x86-64 | 13 |

Exporting a symbol is not the same as having proven its behavior. Most of the
x86 feature work from F0–F2 does not exist on AArch64.

A first look at the x86 tree shows the porting hazards are bounded:

- It uses `c_char` (1488 uses; 2 hard-coded `i8` pointers). That matters
  because `char` is unsigned on AArch64.
- Only a few legacy syscalls with no AArch64 number appear: `chown`/`lchown`,
  `fork`, `select` and the x86-only `arch_prctl`, `iopl` and `ioperm`. They map
  to `*at`, `clone` and `pselect6` forms or stay x86-only.
- 124 files contain inline `asm!`, mostly syscall entry. These need an
  architecture layer, not per-file ports.
- 43 files handle x87 80-bit `long double`. On AArch64, `long double` is IEEE
  binary128. That makes it the largest single semantic port: printf and scanf,
  `strtold`, and the `l`-suffixed math functions.

## Host: Apple Silicon running a Linux/arm64 VM

Docker on macOS always runs containers inside a Linux VM, using Apple's
hypervisor. arm64 containers in that VM execute natively. They are not
emulated, so the "never emulate" rule is preserved. Two host properties need
care:

1. **Filesystem semantics.** Bind-mounting the macOS checkout (virtiofs or
   gRPC FUSE over case-insensitive APFS) changes behavior for hard links,
   xattrs, ownership, file locks, `statx` fields, inotify and case-only name
   differences. Filesystem tests would then measure the bridge, not crabc. The
   checkout, `.work/` and every test scratch directory must live on a
   filesystem on the VM's own block device. OrbStack machine roots are btrfs,
   which the owner accepted on 2026-11-18; ext4 is equally valid.
2. **No x86 on the Mac.** Never pass `--platform linux/amd64` there, because
   Rosetta or QEMU would be emulation. The x86 campaign stays on the existing
   x86 Linux host.

**Recommendation:** use a full Linux/arm64 VM with its own disk (Lima or
OrbStack, running Alpine or Debian), install Docker Engine inside it, and clone
the repository inside the VM. The existing scripts then run unchanged, as they
would on any native Linux/arm64 host. Docker Desktop can also work, but only if
the checkout lives in a named volume rather than a bind mount. That makes
editing and git awkward and invites accidental bind mounts.

Before any work, record these host properties: kernel version (at least 5.10),
page size (`getconf PAGESIZE`), CPU count, and disk. Give the VM at least
150 GB of disk; x86 final6 died of disk exhaustion. The VM kernel will probably
use 4 KiB pages, so 16 KiB and 64 KiB page coverage remains a named gap (D6).
VM timer jitter can lengthen timing-sensitive waits. A failure there is still a
failure and needs root-causing, as with CRAB-6.

## Plan

### A0: Owner amendments and host bring-up

- Amend `AGENTS.md`, `docs/scope.md`, `COMPATIBILITY-PROFILE.md` and `plan.md`.
  AArch64 becomes active on a native arm64 host, and the decisions D1–D6
  below are recorded.
- Treat the frozen AArch64 manifests and `COMPATIBILITY.md` as superseded, not
  refreshed. The converged chain produces new evidence. The old evidence stays
  in Git history.
- Bring up the VM, Docker and the checkout. Build an arm64 core image from
  `docker/Dockerfile.x86_64`'s recipe: Alpine, the pinned Rust nightly, a
  `[musl_native]` oracle toolchain built for `aarch64-linux-musl`, binutils,
  gcc and strace. Pin its digest in an AArch64 counterpart of `core_image.py`.
- **Exit:** the arm64 image is pinned, `cargo check -p crabc-core` passes for
  `aarch64-unknown-linux-musl` in it, and the host properties are recorded.

### A1: Build gap inventory (bounded)

- Widen the x86 tree's cfg gates to `target_arch = "aarch64"` on a branch and
  build `libc`, `ldso`, `crt`, `builtins`, `crabc-core`, `crabc-rs` and
  `unwinder` for AArch64.
- Classify every failure into exactly one bucket:
  1. Linux-generic code that is only gated: ungate it.
  2. Legacy syscalls: switch to the `*at`, `clone` or `pselect6` form.
  3. Architecture layer: syscall entry, `asm!`, TLS, signal frames, `setjmp`,
     `fenv`, vDSO names, relocations, CRT startup, unwinder.
  4. ABI types: `stat` layout, `ucontext`, `va_list`, `c_char` signedness.
  5. binary128 `long double`.
- **Exit:** a short committed list that maps each bucket to its owner files.
  It is a dispatch table, not a ledger.

### A2: Architecture layer

Put each architecture fact in one module per concern under `libc/src/arch/`
and the matching `ldso`, `crt` and `unwinder` locations:

- syscall entry and the vDSO (`__kernel_clock_gettime` and friends);
- TLS variant I with the thread pointer in `tpidr_el0`, and the static and
  dynamic TLS layout in `ldso`;
- AArch64 relocations: `R_AARCH64_*`, including TLSDESC;
- signal frames and `ucontext`/`mcontext`, `sigsetjmp`/`longjmp`,
  `makecontext`-class ABI if selected;
- `fenv` through FPCR/FPSR;
- CRT `_start` and the builtins outline-atomics helpers;
- the DWARF unwinder for AArch64.

Port from the existing AArch64 composition where it already owns a fact, with
provenance. Then delete that copy, so nothing is duplicated.

**Exit:** a static and a dynamic hello-world, plus the loader and TLS focused
tests, pass on arm64 against the oracle.

### A3: binary128 `long double`

Port musl's `ld128` paths into the leaves that currently assume x87: formatted
I/O, `strtold`, and the `l` math functions. Record provenance per STYLE.md §55.
This is independent of A2 after A1, so it runs in a parallel lane.

**Exit:** the libc-test math and stdio `long double` cases pass with the same
discrepancy accounting x86 uses.

### A4: Harness generalization and parallel family closure

- Make the native harness architecture-parameterized instead of copying
  `compat/x86_64/` to a new tree. Select image pin, target triple, oracle
  toolchain and architecture ledgers from one architecture argument. Keep the
  x86 behavior bit-identical: every harness edit reruns that module's x86 tests
  on the x86 host.
- Run the families in parallel lanes, as in F1: POSIX runtime, pthread and TLS,
  loader, text/math/locale/stdio, resolver/network, C ABI compatibility,
  headers/layouts, CRT and sysroot, the `crabc-rs` facade, and the Lua and
  package-corpus consumers.
- **Exit:** each family's aggregate passes on arm64 with receipts.

### A5: AArch64 closeout

One fixed clean commit passes the seven-gate correctness candidate on arm64
with `complete: true` and `fresh: true`. Because the source is shared, **the
same commit must also pass the x86 correctness candidate.** Performance stays
deferred on both architectures.

## Sequencing with x86

- Converging edits shared source and therefore changes the x86 product digest.
  **Nothing from this campaign merges to main until x86 F2 (final8) is
  accepted.** A0 host bring-up and A1 inventory can start now on a branch,
  because they need no merge.
- After F2, every merge that touches shared source needs the focused x86 checks
  for that family on the x86 host. A5 needs both candidates.
- x86 F3 (performance) stays unscheduled, consistent with deferring performance.

## Decisions for the owner

- **D1, converge or extend:** converge AArch64 onto the x86 leaf tree plus an
  architecture layer, then delete the old AArch64 composition (recommended).
  The alternative is to keep growing `c_abi.rs` separately, which doubles every
  behavior owner.
- **D2, oracle:** the `[musl_native]` snapshot for both architectures
  (recommended, because it gives one behavioral reference), or keep released
  `[musl]` 1.2.6 for AArch64.
- **D3, allocator:** move AArch64 to the pinned C mimalloc v3.5.0 glue that x86
  uses (recommended). The profile currently says AArch64's backend "stays
  unchanged", and the Rust allocator port stays frozen either way.
- **D4, host:** a Lima or OrbStack Linux VM with its own disk (recommended),
  or Docker Desktop with a named volume. Accepted as OrbStack, whose machine
  root is btrfs on the VM's block device.
- **D5, start:** start A0 and A1 now on a branch, with nothing merged until
  final8 is accepted (recommended). The alternative is to wait for final8
  before starting anything.
- **D6, page size:** accept 4 KiB-only coverage for this campaign and name
  16 KiB and 64 KiB as a gap (recommended), or require a second host.

## Handoff: starting A0 on the Mac

All six recommendations above were accepted on 2026-11-18. This section is the
starting brief for the Apple Silicon session.

### State at handoff

- **Main:** the governing docs (`AGENTS.md`, `docs/scope.md`,
  `COMPATIBILITY-PROFILE.md`, `plan.md`) already record the accepted decisions.
  No AArch64 code has changed yet.
- **x86 host:** it keeps running F2 unattended. The final7 resume runs to
  completion. If it completes, a fresh final8 runs in `.work/wt/f2-fresh-final8`
  at a fixed main SHA, then a musl-vs-crabc perf comparison. `plan.md` Status
  records that chain. Acceptance (F2 closeout step 6) is recorded from the x86
  host afterwards. The Mac session never runs or edits x86 candidates.
- **Merge rule:** until final8 is accepted, nothing that touches the x86
  product source seal merges to main. The seal is `PRODUCT_TREES` and
  `PRODUCT_FILES` in `compat/x86_64/source_seal.py`, and it includes
  `docker/`, so even the arm64 Dockerfile waits on its branch. Docs outside the
  seal may land.

### Host setup (OrbStack)

```sh
orb create alpine crabc                  # arm64 Linux machine
orb -m crabc
# Inside the machine. Install Docker Engine here, not the Mac's OrbStack engine,
# so every mounted path is on the machine's own disk.
git clone https://github.com/joshuarli/crabc ~/crabc   # under ~, never /Users/...
cd ~/crabc && git switch -c lane/a0-aarch64-image
git config receive.denyCurrentBranch updateInstead
stat -f -c %T .                          # ext2/ext3 or btrfs, never virtiofs/fuse
uname -m; uname -r; getconf PAGESIZE; nproc; df -h ~
```

Record the last line's values in the A0 commit. Never pass
`--platform linux/amd64` on the Mac.

The VM holds no GitHub credentials. The Mac reaches the VM clone over
OrbStack's SSH and relays branches to GitHub:

```sh
git remote add a64 crabc@orb:crabc       # on the Mac, in the main checkout
git fetch a64 && git push origin a64/lane/a1-aarch64-inventory:lane/a1-aarch64-inventory
git push a64 HEAD:lane/a1-aarch64-inventory   # Mac edits; updates the VM checkout
```

### A0 tasks, on `lane/a0-aarch64-image`

1. Create `docker/Dockerfile.aarch64` from `docker/Dockerfile.x86_64` with the
   same tool set and pins. Alpine digests there may be platform-specific; use
   the manifest-list digest, or the arm64 one, and record which. Build the
   `[musl_native]` oracle toolchain for `aarch64-linux-musl`, and set
   `RUST_TARGET=aarch64-unknown-linux-musl`.
2. Build the image natively. Pin its ID in an AArch64 counterpart of
   `compat/x86_64/core_image.py`. Take the architecture as a parameter (A4)
   rather than copying the module.
3. Make `scripts/lanes/rust-check.sh` and `prepare-worktree.sh` select that
   image when `uname -m` is `aarch64`, without changing x86 behavior.
4. **Exit check:** `scripts/lanes/rust-check.sh cargo check -q --locked -p crabc-core --target aarch64-unknown-linux-musl`
   passes in the pinned arm64 image.

### A1 tasks, on `lane/a1-aarch64-inventory` from A0

Widen the x86-only cfg gates to AArch64 and build every runtime crate. Commit
the five-bucket dispatch table described in A1 above. Then dispatch A2 and A3
as parallel lanes.

### A1 dispatch table

`lane/a1-aarch64-inventory` points the AArch64 build at the x86 roots: libc
selects `c_abi/x86_64/static_c_abi.rs`, ldso selects `x86_64_initial_graph.rs`,
and the unwinder gate admits AArch64. The old composition (`libc/src/c_abi.rs`,
`ldso/src/loader.rs`) is unreferenced and kept only as a source of facts for A2.
Its frozen Rust `crabc-mimalloc` dependency no longer compiled, so libc's
AArch64-only dependency table is gone (D3).

Results in the pinned arm64 image: `crabc-core`, `crabc-rs`, `builtins` and
`unwinder` check clean. libc fails with 115 errors under
`x86-owned-dynamic-runtime` and ldso with 34. All of those errors come from
inline asm or name resolution. Type errors only appear once bucket 3 compiles,
so buckets 1, 2, 4 and 5 below also draw on a source scan. Paths without a
directory are under `libc/src/c_abi/x86_64/`.

| Bucket | Owner files |
| --- | --- |
| 1. Linux-generic, only gated | `crabc-core/src/{fenv,syscall,time,event,signal,mm,system}.rs` and their `*_x86_64.rs` forks: make the x86 copy the single generic owner, keeping only numbers, entry and registers per architecture. libc needs these x86-only APIs: `time::VdsoClockGettime`, `param::install_initial_sysinfo_ehdr_for_vdso` and the `crabc-core/src/resolver.rs` question-matched exchange. `libc/src/{getopt_exports,network_interface_exports,allocator_mimalloc}.rs` keep AArch64 arms keyed to the old composition. The `crabc-rs` dual-arm cfgs follow `crabc-core`. Most `global_asm!` blocks are `.weak`/`.set` aliases and portable as is. |
| 2. Legacy syscalls | `open`, `unlink`, `poll`, `dup2`, `readlink`, `select`, `rmdir`, `pause`, `mkdir`, `link`, `chown`, `chmod`, `access`, `symlink`, `rename`, `pipe`, `mknod`, `lchown` in `crabc-core/src/{syscall_x86_64,event_x86_64,io}.rs`, `chown`, `lchown`, `descriptor_entry`, `descriptor_io`, `filesystem_access`, `getpass`, `owned_filesystem_mechanisms`, `owned_named_ipc`, `owned_static_stdio`, `pathname_lifecycle`, `readiness_waits`, `stdio_standard`, `syscall`, `temporary_names`, `temporary_objects`, `ttyname_r`; `fork` through `clone` in `pthread_atfork`. Use the generic form on both architectures unless an x86 test compares syscall sequences. |
| 3. Architecture layer | Syscall entry: `syscall`, `pthread_create_join`, `pthread_atfork`, `posix_spawnattr_{init,signal_fields}`, `crabc-core/src/syscall_x86_64.rs`. Thread pointer (`%fs`, TLS variant II): 16 files including `thread_pointer`, `static_tls`, `dynamic_tls`, plus ldso `x86_64_{initial_worker_tls,general_initial_tls_state,runtime_tls_view}.rs`. Register asm: `atomic`, `integer_arithmetic`, `intmax_arithmetic`, `math_fmod`, `byte_scan` (SSE), `fenv`, `fenv_rounding`, `crabc-core/src/fenv_x86_64.rs`. `setjmp`; signal frames in `signal_foundation`, `signal_control`, `owned_syscall_cancel`, `owned_synccall`; vDSO in `clock_gettime` and `crabc-core/src/vdso.rs`. Relocations: ldso `x86_64_{general_relocation,deferred_relocations,initial_graph}.rs`. CRT: `crt/src/x86_64_*.rs` and `crt/build_x86_64*.py`. Unwinder: `unwinder/patches/unwinding-0.2.10-remote-reader.rs` x86 register arms and the x86 triple in `unwinder/build.py`. `arch_prctl` and `io_permissions` are x86-only exports, absent from the AArch64 surface. |
| 4. ABI types | `stat` layout: `stat_compat`, `mktemp`, `ttyname_r`, `filesystem_capacity`, `filesystem_traversal`, `owned_filesystem_mechanisms`. `va_list` (`owned_printf_float` asserts the SysV layout): `owned_printf`, `owned_scanf`, `stdio_format_scan`, `owned_wide_format`, `owned_error_reporting`, `process_exec_variadic`, `owned_syslog`, `descriptor_entry`, `owned_strfmon`. Unsigned `c_char`: `stdio_format_scan`, `owned_printf`, `locale_multibyte`, `owned_static_stdio`, `byte_scan`. `ucontext`/`mcontext`: the signal-frame files in bucket 3. `include/bits/` already carries AArch64 arms; revalidate them against the oracle. |
| 5. binary128 `long double` | Musl translations first: 37 `*_x86_64.S` from 32 `compat/x86_64/generate_*.py`, split by the x86-only `split_musl_objects` in `libc/build.rs`. Each generator takes `--cc`, and musl's C already carries the binary128 paths, so most of this bucket is regenerating those translations with the aarch64 oracle compiler. Then the Rust leaves that assume x87: 55 files reference x87 or binary80, chiefly `math_x87_extended`, `math_long_double_completion`, `math_elementary_long_double`, `float_parse`, `owned_printf`, `owned_scanf`, `stdio_format_scan` and `owned_static_stdio`. builtins needs nothing new: `builtins/build.py` already source-builds `compiler_builtins` for aarch64, which supplies the `*tf3` helpers and outline atomics. |

A2 takes buckets 1 to 4, starting with the `crabc-core` convergence and the
syscall entry, which every other row depends on. Legacy syscalls switch to the
generic form on both architectures. `compat/x86_64/owned_syscall_profile.py`
already treats `open`/`openat` and the stat family as equal, and its other
groups need the same treatment if a switch changes them. A3 takes bucket 5 in
parallel, starting with the musl translations.

The arm64 image can type-check x86 without an x86 host, which covers changes
to shared files. Linking and running still need the x86 host:

```sh
scripts/lanes/rust-check.sh env CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-Ztls-model=initial-exec \
  cargo check --locked -Zbuild-std=core,alloc --target x86_64-unknown-linux-musl \
  -p crabc-libc --features x86-owned-dynamic-runtime
```

Use `-Zbuild-std=std,panic_abort` for `crabc-rs`. The override drops
`link-dead-code`, which breaks a source-built `compiler_builtins`.

### Progress record (2026-11-18)

Integration branch: `crab8/integration` (origin). Lanes branch from it and are
cherry-picked back after review; nothing merges to main before final8.

Done on arm64, each matching the `[musl_native]` oracle's stdout and status:
static, static-PIE and dynamic PIE `hello`, static/static-PIE pthread+TLS,
initial-exec and TLSDESC dynamic TLS from a DSO, and a `dlopen`ed TLSDESC
module with rollback. The pinned libc-test suite through
`compat/x86_64/owned_libc_test.py` passes 427 of 434. The remaining seven are
accounted: `functional/crypt` is out of profile (`compat/crabc-rs/crypt-profile.md`);
`functional/ipc_sem`, `functional/strptime` and `regression/statvfs` produce
output identical to the oracle's in the chroot; `functional/wordexp` is the
upstream-policy difference that `owned-wordexp-upstream-policy.md` already
accounts on x86; `math/pow` and `math/powf` differ only where the oracle
raises extra exception flags that crabc's finite-identity corrections remove.

Structure now shared: `crabc-core` and `crabc-rs` have one module per concern
with per-architecture `syscall`/`fenv` layers; libc uses one
architecture-selected syscall table; every musl translation has a
reproducible `_aarch64.S` from `compat/x86_64/generate_*.py --arch aarch64`;
the TLS layout contract is `libc/src/c_abi/x86_64/aarch64_tls_layout.rs`
(musl's ABI: DTV at TP-8, `canary_at_end` at TP-16); `compat/x86_64/native_arch.py`
selects platform, image, triple, linker, oracle and work directory for the
harness.

Open, in dependency order:
- The seven-gate driver itself: `compat/x86_64/qualification_candidate.py` now
  takes its work root, oracle wrapper and image pin from `native_arch`; its
  product cohort (static preparation, materialized dynamic qualification,
  static/combined sysroot, CRT dynamic startup) is being made to run on arm64.
  On arm64 the ledger rows' `.work/x86_64/` receipt paths map to
  `.work/aarch64/`, and the canonical run is `--work .work/aarch64/feature-complete`.
- Family producers still x86-bound: loader family readers, hardened entry
  probes, `owned-wordexp` (the aarch64 candidate must reproduce the fixed x86
  traces), dynamic Lua (driver `--application-dependency-file`), Rust provider
  regressions, POSIX native aggregate, pthread/text/resolver/C-ABI families and
  ABI evidence.
- Package corpus: `compat/corpus/manifest.toml` pins the 34-case Alpine
  3.24.1 AArch64 corpus by archive SHA-256, and the converged readers now
  stage and validate it on arm64. The 20 cases whose archives are still
  available match pinned musl byte for byte (stdout, stderr, status) through
  the converged dynamic product. Seven pinned archives (curl 8.21.0-r0,
  git 2.54.0-r0, gzip 1.14-r2, openssh-client-default 10.3_p1-r0,
  openssl 3.5.7-r0, python3 3.14.7-r1, sqlite 3.53.2-r0) now return 404 from
  dl-cdn and mirrors for both architectures, because Alpine drops superseded
  builds, and their binaries also need libacl, libmagic, libpcre2 and libzstd,
  which the pinned image lacks. Decided (2026-11-18, owner-delegated): add
  `compat/corpus/manifest-aarch64.toml`, the AArch64 counterpart of
  `manifest-x86_64.toml`. It pins current v3.24 aarch64 direct-package versions
  and their complete solved non-libc closure by SHA-256, with provenance from the
  signed index under a pinned key, and records `native_version_deltas`. The
  workload source `manifest.toml` and the x86 contract stay unchanged.
- x86 link and run of the converged tree on the x86 host (type-checked only
  here).
- Decided (2026-11-18, owner-delegated): binary128 arithmetic stays on the
  owned `compiler_builtins` helpers. libgcc's soft-fp would be an ambient GCC
  runtime input, which the owned-sysroot invariant forbids. The helpers'
  round-to-nearest, no-exception-flag behavior for `long double` arithmetic is
  a recorded known difference from musl+libgcc; libc-test's `long double`
  cases pass with it.

Host workflow: the VM clone is `~/crabc`, reachable from the Mac as git remote
`a64` (`crabc@orb:crabc`) with `receive.denyCurrentBranch updateInstead`.
`scripts/lanes/orb-vm-lane.sh <name> <commit>` creates the paired worktrees,
and `scripts/lanes/orb-vm-run.sh <command...>` mirrors a Mac worktree into its
VM worktree (git HEAD and index follow the Mac commit) and runs the command
there; wrap builds in `scripts/lanes/rust-check.sh`. The pinned musl trees go
in the VM's `~/crabc/.work/aarch64/musl-src/`: the `[musl]` release tarball
(the generators' tree digest) and the `[musl_native]` snapshot (scanf and
float-parse generators), both downloaded from `compat/upstreams.toml` and
SHA-256 checked. `cargo check` does not assemble `global_asm!` text, so
aarch64 acceptance uses `cargo build`. x86 is type-checked from the arm64
image with `scripts/lanes/rust-check.sh env
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=-Ztls-model=initial-exec
cargo check --locked -Zbuild-std=core,alloc --target x86_64-unknown-linux-musl`.

### Don't

- Do not use `scripts/dev.sh` or the old `c_abi.rs` AArch64 suites as
  acceptance evidence. They are superseded, and the old composition is only a
  source for facts A2 moves.
- Do not refresh `COMPATIBILITY.md` or the old AArch64 manifests.
- Do not change `rust-toolchain.toml` or `compat/upstreams.toml` pins.
- Do not do any performance work, and do not start the macOS facade backend
  (CRAB-7).
