# `crabc-rs` design

`crabc-rs` is the idiomatic Linux/AArch64 OS/runtime facade over the shared
`crabc-core` implementation. It is not a generated C-wrapper crate. Its
current platform is Linux/AArch64 little-endian with Linux 5.10 as the kernel
baseline; no second `crabc` architecture is planned.

## Boundary

```text
Rust application
       │
   crabc-rs
       │ direct typed Linux operations
   crabc-core
       │
Linux kernel
```

Syscall-like native APIs must not round-trip through the public C ABI or TLS
`errno`. The only permitted runtime-state exception is the append-only,
versioned private `RuntimeV1` bridge owned by libc/ldso; it is used where
loader, thread/TLS, or opt-in stdio state cannot be represented as a direct
kernel operation.

## API rules

- Prefer typed descriptors, paths, flags, errors, resource ownership, and
  explicit buffer initialization over C pointers, sentinels, globals, or
  `errno`.
- A safe API must make invalid ownership/lifetime states unrepresentable. A
  public unsafe API documents exact pointer provenance, alignment, aliasing,
  lifetime, and process-state obligations.
- Process-global mutation (environment, cwd/root, credentials, signals,
  loader state) must expose its coordination boundary rather than hide it.
- `std` integration is welcome; `no_std` remains a supported base. The crate
  does not grow an async runtime, portability framework, process supervisor,
  security-policy layer, or C-varargs imitation.
- Use Rustix only as a pinned API/behavior/source oracle. It is never a
  production dependency.

## Capability accounting

[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml) owns
the exact classification of every measured C capability and native seam. A
group is either verified with evidence, deferred with a concrete contract, or
documented as ABI-only, Rust-subsumed, internal runtime, or the allocator scope
exception. Do not turn a documented C group into a native API merely to raise
a wrapper count.

The active deferred groups and their scope limits are in
[`TODO.md`](../../TODO.md). Completed delivery rationale is preserved in the
[historical `crabc-rs` record](../history/crabc-rs-delivery-plan.md).

## Dependencies and optimization

Normal dependencies must be small, mature, focused, pure Rust where practical,
and compatible with the `no_std`/LTO boundary. Before adding one, document its
primitive, why `core`/`alloc` is insufficient, normal transitive graph,
proc-macros/build scripts/native code, allocation/global state, `no_std`
status, and LTO effect; obtain user approval unless already explicitly given.

No cryptography is hand-written. The C `crypt(3)` compatibility slice uses
RustCrypto `sha-crypt`; its limits and dependency review live in
[`compat/crabc-rs/crypt-profile.md`](../../compat/crabc-rs/crypt-profile.md).

M12 proves a bounded direct native getpid/write route in O3 and fat-LTO lanes.
It does not prove whole-program LTO or optimization inside dynamically loaded
`libc.so`; see [`compat/lto/README.md`](../../compat/lto/README.md).

## Evidence standard

For each selected capability: define the ownership and error contract; add a
focused observable test; compile the narrow no-std/direct-boundary proof where
relevant; run musl/POSIX or a source oracle as appropriate; then update the
ledger and documentation. A new test or source marker alone is not a verified
claim.
