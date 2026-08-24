# Fixed mimalloc semantic-port contract

## Purpose and status

`crabc` may replace the C allocator implementation in its production graph
with a provenance-preserving, pure-Rust semantic port of a fixed mature
allocator. This is a narrow compatibility exception to the project rule
against allocator research. It does not authorize a new allocator design.

The initial target is mimalloc v3.5.0, pinned at
`18b08671c9302247bfb682286e6bf3cc1773f801`. Its archive, license, source
mapping register, and update procedure are in
[`crabc-mimalloc/UPSTREAM.md`](../../crabc-mimalloc/UPSTREAM.md).

The current production `libmimalloc-sys` 0.1.49 backend bundles mimalloc
v3.3.2. It remains the default during this work, but it is not the exact
v3.5.0 C oracle: the pinned v3.5.0 archive must be built separately for the
Rust-port differential and performance baseline.

The workspace now contains the `crabc-mimalloc` crate with source-mapped
configuration, arithmetic, types, provenance, atomic operations, size classes,
ordinary and binned caller-owned bitmap views, a live two-level page map,
immutable Linux memory policy, regular/aligned mapping ownership, an in-place
external-arena substrate, a private futex lock boundary, and bounded
nonallocating support kernels. Its allocator-owned random context preserves the
pinned source's original-ChaCha state and output contract through the audited
RustCrypto primitive; OS entropy acquisition and runtime lifecycle wiring
remain unfinished slices. The recursive allocation-free once protocol is
present as a coordination primitive, but no process initialization state
machine is yet claimed.

One private vertical slice now binds a caller-pinned default theap to a
caller-managed external arena and page map. It claims and publishes 64-KiB
small pages, maintains the direct cache and regular/full queues, extends and
collects scalar local free lists, retires fully free pages, unregisters them
before arena release, and rolls back injected commitment, bitmap, and page-map
failures. The quick oracle gate compares 378 address-independent allocation
facts with exact pinned C v3.5.0 across all 62 small-bin transition requests.
This is bounded engine evidence, not an exported allocator: the crate still
has no public operation, libc integration, process/TLS lifecycle, remote free,
medium/large/aligned/reallocation path, thread teardown, fork protocol, or
backend selection. A fixed-capacity `cfg(miri)` mapping model exercises current
VM ownership and page-map transitions without broadening production support;
the pinned toolchain does not currently install Miri itself. No allocator
readiness or promotion claim follows from this slice.

## Scope boundary

The port is Linux/AArch64 little-endian only, with Linux 5.10 as the kernel
floor and support for valid Linux/AArch64 page sizes. It must be `#![no_std]`,
must not depend on `alloc` or libc, and must not compile C or C++ in the
production allocator. No x86-64, RISC-V, macOS, Windows, big-endian,
32-bit, or portability scaffold is in scope.

The port preserves mimalloc v3.5.0's algorithms, data structures, memory
orderings, lifecycle behavior, and valid-program observable behavior until
parity is established. It is not permitted to replace those mechanisms with
more idiomatic but materially different Rust algorithms. Any such divergence
requires all of the following before acceptance:

- a written design note explaining the upstream behavior and the divergence;
- deterministic differential evidence against the exact pinned C source; and
- Linux/AArch64 performance and memory evidence showing that the divergence is
  justified.

The pinned C implementation remains the mandatory source, differential, and
performance oracle after it is removed from the production dependency graph.
Glibc is never an allocator or C-runtime oracle.

### Random-state dependency boundary

Pinned mimalloc `src/random.c` implements a ChaCha20-based PRNG/DRBG for
allocator cookies and secure mode; it is not merely a `getrandom` syscall
adapter. The project-wide cryptography contract therefore forbids translating
that algorithm locally into `crabc-mimalloc`. `crabc-core::rand` may provide
raw Linux entropy, but substituting repeated syscalls or another algorithm
would be an unproved semantic and performance divergence.

The approved dependency is
`chacha20 = "=0.10.1"` with default features disabled and only `legacy` plus
`zeroize` enabled. `zeroize = "=1.9.0"`, also with defaults disabled, is a
direct dependency so the source's temporary key and output-block cleanup use
its compiler-resistant primitive. The selected Linux/AArch64 external graph
is nine packages total:
`chacha20`, `cfg-if`, `cipher`, `block-buffer`, `hybrid-array`, `typenum`,
`crypto-common`, `inout`, and `zeroize`. None has a build script or native
code in that graph; the selected features use neither `std` nor `alloc`, keep
no global state, and allocate no memory. All are MIT-or-Apache-2.0 licensed.
The resolved lockfile also records `cpufeatures` 0.3.0 and `libc` 0.2.189 for
the crate's target-conditional non-AArch64 backend; Cargo does not select
either package in the fixed Linux/AArch64 graph. The structure check fixes the
direct versions and features, while `allocator --quick` traverses Cargo
metadata for `aarch64-unknown-linux-musl` and rejects any selected package,
version, edge, source, build script, or proc macro outside the audited graph.
It therefore still rejects a compiled libc dependency instead of mistaking
lockfile presence for an active allocator edge.

The intended use is `ChaCha20LegacyCore`, instantiated for one 64-byte block
at a time from allocator-owned key/counter/nonce words. That preserves the
pinned source's original-ChaCha 64-bit counter plus 64-bit nonce layout,
low-nonce-word counter rollover, output word ordering, immediate clearing of
consumed words, and split-context behavior without retaining a library RNG
buffer. Entropy acquisition is injected so a strong context never performs a
spurious reinitialization syscall. The pure-Rust generic implementation
introduces no native call boundary and remains eligible for fat LTO; its
AArch64 code size, selected NEON path, and throughput are explicitly
unqualified until measured.

## Ownership and integration boundary

The future production direction is:

```text
crabc-mimalloc -> crabc-core + chacha20 + zeroize
crabc-libc     -> crabc-core + crabc-mimalloc
```

`crabc-mimalloc -> crabc-libc` is forbidden. Raw Linux primitives belong in
`crabc-core` when genuinely needed; the allocator must not duplicate syscall
assembly or depend on public pthread APIs. Its lifecycle integration is direct
with crabc pthread startup, thread teardown, and fork paths.

`crabc-libc` retains the musl/POSIX C allocation ABI: weak and preemptible
symbols, interposition, `errno`, zero-size behavior, alignment, overflow,
reallocation preservation, and aligned-allocation output rules. The engine is
errno-free. `crabc-rs` continues to use ordinary Rust allocation and exposes
no C `malloc`/`free` allocation API.

There is no runtime allocator-selection framework. During validation, the C
implementation may be a build- or test-selected shadow backend; the Rust
implementation becomes the default only in a final isolated promotion change.

## Evidence and promotion

Track two outcomes separately:

1. readiness to back crabc's `malloc` family without changing its C ABI; and
2. parity for every Linux/AArch64-applicable public mimalloc v3.5.0 `mi_*`
   interface and compile-time mode.

Neither outcome follows from basic allocation tests. Promotion requires focused
invariants, layout/configuration probes, upstream-test evidence, deterministic
C differential traces, concurrency-model evidence, fault injection,
process-isolated misuse tests, pthread/TLS/fork and ABI/interposition tests,
and real-program/corpus evidence. It also requires C-vs-Rust throughput,
latency, RSS, virtual-mapping, startup, and allocation-path evidence on the
same Linux/AArch64 measurement contract. See
[`compat/allocator/README.md`](../../compat/allocator/README.md) and
[`docs/design/performance.md`](performance.md).

The current C backend remains the default until every stated correctness,
memory, latency, throughput, ABI, TLS, fork, and real-program gate passes.
