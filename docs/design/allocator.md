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

The bounded metadata prerequisite from `src/subproc.c:19-88` is now also
present. `MetaAllocator` is one process-static, `!Unpin` owner: its internal
operations require `Pin<&'static MetaAllocator>`, validate the current live
AArch64 thread-pointer identity before taking a nonrecursive `PrivateLock`,
then lazily build a direct-OS page map and aligned external arena in their
final static slots before Release-publishing a detached `ExclusiveTheap`.
The ordinary page lifecycle supplies the first and later metadata blocks; no
`alloc`, libc, public pthread API, compiler-TLS root, separate metadata slab,
or mmap-per-block path participates. Its must-use, non-Copy
`MetaAllocation<'owner>` capability records the static owner address, requested
size, and `MemoryId::Malloc` provenance. A future TLD/theap lifecycle owner
must retain and move that capability as a field, never reconstruct it from the
raw pointer. The checkpoint retains the source allocation-under-lock,
unlock-before-copy/free `rezalloc` ordering and serializes cross-thread free,
but it intentionally covers only successful Malloc capabilities: null,
needs-no-free, and non-Malloc arena-release paths, subprocess destruction,
full heap/theap lifecycle, allocator-owned TLS backing, and public ABI routing
remain open.

One private vertical slice now binds a caller-pinned default theap to a
caller-managed external arena and page map. It claims and publishes exact
small, medium, large, and singleton spans, maintains direct and generic
candidate/regular/full queues, extends and collects scalar local free lists,
retires fully free pages, unregisters complete spans before arena release, and
rolls back injected commitment, bitmap, and page-map failures. The quick oracle
gate compares 378 address-independent allocation facts with exact pinned C
v3.5.0 across all 62 small-bin transition requests. A second 51-key exact
differential record covers page-kind selection, checked calloc, ordinary
reallocation, aligned and offset-aligned allocation, usable size, preservation,
and invalid-size failure. Those operations are live in the private lifecycle,
including OS-aligned singleton ownership for power-of-two alignments above
64 KiB and below the 256 MiB metadata limit. Failed terminal unmaps retain one
exact allocation-free owner for later collection or allocation-boundary retry.
For unpinned external arenas, slice release now schedules the pinned default
four-second purge delay before reuse. Forced collection owns the free-bitmap
range while applying the source `purge_decommits=1` non-owning decommit; pinned
backing skips the path, decommit failure restores availability plus immediate
retry state, and only the external owner may unmap the complete mapping.
This is bounded engine evidence, not an exported production allocator: the
crate still has no production public operation, libc integration, process/TLS
lifecycle, integrated remote-free routing, thread teardown, fork protocol, or
backend selection. The present Milestone 5 foundations are intentionally
narrower: exact AArch64 versioned TLS keys, caller-owned per-thread slots, a
lock-serialized global key registry over caller-owned source-sized bitmap
blocks, five private compiler-TLS roots with direct `TPIDR_EL0` identity,
low-bit atomic remote publication and owner collection, and a bounded
one-page abandonment/adoption protocol. That protocol preserves mapped versus
unmapped source classification, publishes the abandoned bitmap before
releasing ownership, restores a failed reader's bit, waits for reader
quiescence before unabandoning, and reassociates a claimed page before remote
collection. It requires queue-detached, address-stable page/arena/theap
metadata and intentionally does not release or reuse the page. A test-only
Loom model executes the live-owner remote-head publication/detach loops and
the abandoned owner-claim/unown races under bounded schedules; deterministic
native regressions cover the bitmap-field quiescence and full one-page
abandonment interleavings. A dedicated pinned-target probe proves that the TLS
roots are hidden `STT_TLS` objects accessed through initial-exec relocations
without `__tls_get_addr`; its negative control proves the pinned compiler
default emits TLSDESC. Rust has no per-static model annotation, so this is a
bounded crate-codegen proof: production integration must apply the same
per-crate setting and audit the final linked static and shared images. These
slices do not provide allocator-owned dynamic TLS backing or the lifetime owner
needed for thread teardown, terminal page release, or metadata reuse while a
remote producer can exist.
A default-off `test-adapter` feature is the sole exception to that public-
operation statement: it provides an allocation-backed, creating-thread-only
context for the standalone prefixed C evidence adapter. Its stable boxed control
owners, root-last publication, exact outstanding-block count, and staged
page-map/arena teardown are test harness machinery, not a production process
singleton or libc integration path. The separate
`compat/allocator/test-adapter` package exports exactly 16 `crabc_test_*`
symbols and no standard allocation or `mi_*` symbols. The full evidence lane
uses it for the existing crabc allocator fixture and 33 reviewed checks from
the hash-pinned upstream `test/test-api.c`; the applied patch and every omission
are checked-in contracts rather than a copied upstream source fork.
A fixed-capacity `cfg(miri)` mapping model exercises current
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

### Concurrency-test dependency boundary

`loom = "=0.7.2"`, with defaults disabled, is the sole allocator
`dev-dependency`. It is enabled only by the empty `loom` test feature and
models the exact `mi_thread_free_t` publication, owner-detach, abandoned
ownership-claim, and abandoned-unown transitions shared with production. The
model substitutes only the atomic head, address-free block links, and a boolean
for bitmap restoration responsibility; the bitmap field algorithm has its own
native quiescence regression. Raw-pointer lifetime, owner-local page mutation,
page identity, TLS, and page release remain outside that proof.

Loom's normal test graph includes its `generator`, `scoped-tls`, `tracing`, and
`tracing-subscriber` support stack. That graph uses `std`, allocation, global
scheduler state, and TLS. `generator` has a build script and a `cc` dependency,
but its external assembly path is PowerPC64-only and does not compile native
code for Linux/AArch64. Cargo metadata traversal continues to admit only normal
production edges from `crabc-mimalloc`, so Loom and its complete graph are absent
from allocator production builds and have no production `no_std`, native-code,
or fat-LTO consequence. `scripts/check_structure.py` pins this test boundary and
rejects any additional allocator dev-dependency.

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
