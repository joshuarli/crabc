# C `crypt(3)` compatibility profile

This is a deliberately bounded compatibility slice. The public `crypt` and
`crypt_r` symbols remain available for ABI/linker compatibility, while the
implemented password-hash formats are SHA-256-crypt (`$5$`) and SHA-512-crypt
(`$6$`). Their complete digest and Modular Crypt Format (MCF) construction
comes from RustCrypto's [`sha-crypt`](https://crates.io/crates/sha-crypt)
crate. The C entry points only enforce bounded input, invoke that dependency,
and copy its dependency-owned MCF string into caller-owned storage. They do
not implement digest rounds, transposition, password-hash encoding, or a
base64 codec locally.

The dependency-backed profile intentionally accepts only canonical
`Base64ShaCrypt` salt strings of one to sixteen characters that decode and
re-encode byte-for-byte. Empty salts, non-canonical salts, settings containing
an additional field, and rounds outside `sha-crypt::Params` are unsupported
and return `*`. The emitted MCF string consequently uses the dependency's
canonical spelling, including an explicit `rounds=5000` field for default
rounds. This is a deliberate semantic limit: exact historical acceptance of
arbitrary short/non-canonical musl salt text would require local MCF/algorithm
adaptation, which is prohibited by the project's no-hand-rolled-cryptography
rule.

DES crypt, BSDI extended DES, MD5-crypt (`$1$`), bcrypt (`$2a$`/`$2y$`), and
the historical `encrypt`/`setkey` family are intentionally limited. The
private `__crypt_*` symbols remain exported where the existing ABI inventory
requires them, but unsupported formats return the conventional `*` marker.
Null output pointers and a null `crypt_r` storage pointer are rejected without
writing, returning null. This is a profile limitation, not a claim of full
historical musl `crypt` parity.

## Dependency decision

`libc/Cargo.toml` uses:

```toml
sha-crypt = { version = "0.6", default-features = false, features = ["alloc", "password-hash"] }
base64ct = { version = "1.8", default-features = false }
```

`sha-crypt` is maintained in the RustCrypto password-hashes repository. The
`password-hash` feature supplies its dependency-owned MCF parser/serializer;
the `alloc` feature is required because the serializer returns an owned MCF
string. The adapter's temporary allocation uses the existing mimalloc-backed
C allocation strategy through its local `GlobalAlloc` bridge. This is not a
new allocator or a public Rust allocation API, and all persistent C output
remains caller-owned.

The direct dependency tree is focused: `sha-crypt`, RustCrypto `sha2`,
`password-hash`, `mcf`, `ctutils`, `cmov`, and `base64ct`, plus their small
support crates (`digest`, `crypto-common`, `block-buffer`, `hybrid-array`,
`typenum`, `cpufeatures`, and `cfg-if`). No dependency enables `std`, a
provider registry, proc macros, a build script, native crypto code, AWS-LC,
OpenSSL, or BoringSSL. `cpufeatures` only observes target SHA-2 CPU support;
no key, password, digest, or other cryptographic state is global. The
dependency source is `no_std`; `alloc` is used solely for the bounded,
dependency-owned MCF result.

## Evidence

- `tests/crypt.rs` runs a musl-compiled fixture through the project dynamic
  linker and checks canonical RustCrypto-backed SHA-256/SHA-512 output,
  explicit and default rounds, empty/non-canonical salt rejection, null
  handling, and unsupported legacy markers.
- `libc/src/crypt_impl.rs` contains no locally implemented digest, block
  cipher, password-hash rounds, transposition, or MCF serialization. Its
  cryptographic operation is the dependency-owned `sha-crypt` call; the
  remaining code is bounded setting validation and C ABI marshaling.
- `compat/crabc-rs/coverage.toml` continues to account for the C symbols as
  ABI machinery; a native `crabc-rs` password-hashing API is intentionally not
  claimed.
