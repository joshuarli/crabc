# Owned `rand` / `srand` C ABI

The native Linux/x86-64 owned runtime supplies only the ISO C `rand` and
`srand` process-global stream. The implementation is
`libc/src/c_abi/x86_64/owned_rand.rs`, selected by
`x86-owned-static-runtime` and inherited by `x86-owned-dynamic-runtime`.
The default selected archive, the AArch64 baseline, and `crabc-rs` remain
unchanged.

This is compatibility state for the C ABI. It does not provide entropy,
cryptographic randomness, PID/fork reseeding, TLS state, cancellation
behavior, `errno` effects, an atfork hook, or a general random-number API.
It does not add the BSD `random` / `srandom` / `initstate` / `setstate` family,
nor does it affect mimalloc's private PRNG.

## Source and dependency provenance

The C behavior maps to musl 1.2.6 release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license
(`COPYRIGHT`). The pinned source archive is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`
(SHA-256), recorded in `compat/upstreams.toml`.

| Source or dependency | Exact identity | Mapping |
| --- | --- | --- |
| musl `src/prng/rand.c` | SHA-256 `83ac507f40f71ce90477290ca255dffb91e4256226616e46fa044ad1b136c24d` | `owned_rand.rs`: initial global state, C-`unsigned` pre-widen seed subtraction, advance, and high 31-bit projection |
| `rand_pcg` | crate `0.10.2`, checksum `caa0f4137e1c0a72f4c651489402276c8e8e1cf081f3b0ba156d2cbeef09e86a`; `Cargo.toml` SHA-256 `7244a51b7bdf719aeecf8a06f6c65913d347bb0800373129ac41ea77cbadf655`; `src/lib.rs` `f50ce36ee49f7836fb24fc7c97dc88c77a46f30150484db5bfcc32726d43860c`; `src/pcg64.rs` `c44078d20150da6f7b0a86d3f976b932e8d0ce61e2d2dee853e6b4bcb5144119` | supplies the complete recurrence through documented `Lcg64Xsh32::from_state`, `advance`, and `state` |
| `rand_core` | crate `0.10.1`, checksum `63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69`; `Cargo.toml` SHA-256 `4ff4becbb9ef65154f4840262f8d0cffa97d97a265b994b9d53f53925bdd3578`; `src/lib.rs` `b4df43985896bf2f38e595f7574c4d7e0df1c562e40c6a92133d9eef1cc01908` | sole normal dependency of `rand_pcg` |

Both dependency crates are Rust 2024, MSRV 1.85, `no_std`, and licensed
MIT OR Apache-2.0. `rand_pcg` has one optional `serde` feature, left off;
`rand_core` has no normal dependency. The target-qualified manifest uses the
exact `=0.10.2` package with `default-features = false`, so the normal graph is
exactly `rand_pcg 0.10.2 -> rand_core 0.10.1`. There are no build scripts,
native code, allocation, serde, default entropy, or default features in this
selected graph.

The Rust adapter deliberately does **not** write the recurrence itself. For a
candidate state it creates `Lcg64Xsh32::from_state(old, 0)`, calls
`advance(1)`, obtains `state()`, and projects `next >> 33`. That leaves the
reviewed dependency as the only recurrence owner. `srand` performs the source
`unsigned` wrapping subtraction before widening: `srand(0)` stores
`0x00000000ffffffff`, rather than an all-ones 64-bit state.

## State contract

`RAND_STATE` is a single `AtomicU64` initialized to zero. `srand` makes a
relaxed store. `rand` advances a dependency-owned candidate then publishes it
with a relaxed compare-exchange loop; only the successful next state supplies
the returned value. This preserves the source's single-threaded and externally
serialized sequences, including the zero-state default and `srand(1)` reset.

Musl's source has plain mutable global state, so concurrent C calls race. This
owner intentionally strengthens that undefined case into serialized successful
transitions. It does not claim to reproduce a musl data-race schedule. Normal
fork copy-on-write keeps the source-shaped parent and child state copies; no
atfork reset occurs.

The selected release profile uses fat LTO and one Rust code-generation unit.
The final archive audit therefore sees the dependency's recurrence inlined into
the fused owned Rust CGU; it does not find a separate foreign archive/member.
`run_owned_rand.sh` saves that actual provider member, `nm`, relocations, and
per-function `objdump` output. It requires exactly one strong `rand` and
`srand` owner, no Rust allocation shim, and no call edge from either provider
function. Unrelated pre-existing owned-runtime allocator references in the
same fused CGU are recorded rather than attributed to this leaf.

## Evidence

The retained paths in this section are rooted at the isolated
`.work/worktrees/owned_rand` checkout in the shared repository. They are not
paths under the integration checkout's `.work/x86_64` directory.

`compat/x86_64/run_owned_rand.sh` compiles one C workload through the installed
dynamic driver, records the installed-header dependency receipt, and links the
unchanged object against pinned musl, static ET_EXEC, static PIE, dynamic PIE
through the kernel and direct interpreter, and dynamic non-PIE through the
kernel and direct interpreter. Source, oracle, and installed C/C++ declaration
witnesses independently check `stdlib.h`, `RAND_MAX`, signatures, and C++ C
linkage. The installed-header workload receipt is separate from those witness
objects.

The musl comparisons cover the initial zero state and `srand(1)`, reseeding,
the seven boundary seeds `0`, `1`, `2`, `0x7fffffff`, `0x80000000`,
`0xfffffffe`, and `0xffffffff`, the `srand(0)` pre-widen edge, a 256-output
stream, and 64 fixed 128-output streams. They also cover `RAND_MAX`, unchanged
`errno`, a constructor before `main`, a serialized cross-thread sequence, and
fork continuation/reseed behavior. The candidate-only 8-worker case verifies
exactly 1024 published transitions without running a musl data race. A dynamic
application DSO consumes the same libc stream as `main`; its separate dynamic
receipt proves the DSO and libc `DT_NEEDED` order and its `/usr/lib` lookup.

The retained first red is
`.work/worktrees/owned_rand/.work/x86_64/preprovider-red`: the same
installed-header object succeeded in pinned musl for core, serialized-worker,
and fork scenarios, while native static ET_EXEC, static PIE, dynamic PIE, and
dynamic non-PIE links each failed with both absent `rand` and `srand` symbols.
`provider-absence.json` records no selected definition in either old product.
This is pre-provider evidence, not a candidate execution result.

The final supplied-product six-mode receipt passed at
`.work/worktrees/owned_rand/.work/x86_64/tmp/owned-rand.a3Q5o8`. It binds static manifest
`f7edf45b7c50fcc6523bb9dd6bcf230ede799752c81009119f83d49d2132235a`
and dynamic manifest
`f91ed65b4183f52de72b5385fc4e3fab309548853639d4c60509d9db5a33a8e1`.
Its `link-identities.json`, raw streams/statuses, compile receipt, header
witnesses, dependency audit, and provider object audit are retained there.

A fresh `--no-default-features` native archive check retained
`.work/worktrees/owned_rand/.work/x86_64/reports/owned-rand-default-ratchet.symbols` with no `rand` or
`srand` definition (archive SHA-256
`7bedc564039cf1baa68aff87576732bfcd64f324eb934211512d31252f39b800`).
That confirms the target-gated dependency and module do not widen the frozen
non-owned selected-static surface.

Using the unchanged signed 59-APK closure (index SHA-256
`1a66c389ffa52b213474fb345577f3cd8716b98249fb5a21cce283d6e2566f2c`),
the focused package replay passed `tier-c-curl`, `tier-c-curl-file`,
`tier-d-git`, and `tier-d-git-init`: each candidate status/stdout/stderr
matched pinned musl. Its report is
`.work/worktrees/owned_rand/.work/x86_64/owned-rand-package-replay/owned-package-corpus-egfs24ii/report.json`
(SHA-256 `b2eb40303c4cb4e0592534f4781a9630ae0055d52a504acff4f5611313b4de83`).
The replay leaves package payload and loader policy unchanged.

Run a fresh native qualification with:

```bash
CRABC_X86_64_WORK_DIR="$PWD/.work/x86_64" \
TMPDIR="$PWD/.work/x86_64/tmp" \
./scripts/dev-x86_64.sh owned-rand
```

The component does not close the broader random C ABI family or promote
native x86-64 support. It does not qualify AArch64, BSD random interfaces,
cryptographic randomness, entropy acquisition, racy musl schedules, or any
consumer that relies on such behavior.
