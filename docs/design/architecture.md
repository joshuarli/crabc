# Runtime ownership architecture

`crabc` has seven runtime and evidence layers with deliberately narrow ownership
boundaries. Native Linux/x86-64 is the active target; AArch64 is paused and
preserved.

1. `crabc-core` owns stateless typed Linux kernel and vDSO operations
   (syscalls, thread pointer, vDSO, floating-point state, raw signals). It has
   no process-global runtime owner.
2. `libc` owns the public C ABI: `errno`, `FILE`, pthread and locale state,
   C layouts, compatibility translation, and other libc process state.
3. `ldso` is the one production dynamic linker. It owns ELF loading,
   relocation, symbol scope, loader TLS, and loader process state.
4. `crt` owns Rust-produced application entry/start/end objects and the
   conventional executable lifecycle boundary. `builtins` owns the separate
   Rust `no_std` compiler-helper archive. Neither owns libc or loader process
   state. See [`crt-and-sysroot.md`](crt-and-sysroot.md).
5. `crabc-mimalloc` is the pinned, errno-free allocator engine (see
   [`allocator.md`](allocator.md)). It consumes `crabc-core` and reviewed
   focused cryptographic primitives, but never libc. Before promotion, `libc`
   has one private Rust-only dependency on its no-page process/pthread
   lifecycle control; that boundary owns no C ABI, allocation routing, or
   backend choice. `libc` owns full C ABI adaptation and lifecycle integration
   after promotion. The C backend remains production until then.
6. `crabc-rs` is the idiomatic Rust facade. It consumes `crabc-core` directly
   for typed native operations and never treats the C ABI as its syscall API.
7. `compat`, `tests`, and `libc-test-harness` are executable evidence. They
   validate contracts but are not runtime dependencies.

The normal dependency direction is toward narrower boundaries: `crabc-rs`,
`crabc-mimalloc`, and `libc` may consume `crabc-core`; `libc` may consume the
bounded private lifecycle control in `crabc-mimalloc`, while full allocator
adaptation is a post-promotion boundary; evidence may exercise every
runtime layer before promotion.
`ldso` stays independently bootstrappable because it starts before ordinary
runtime services are available. Neither `crabc-core` nor `crabc-rs` may own
libc or loader singleton state.

The application CRT enters `libc::__libc_start_main` only after bounded
initial-stack parsing. libc establishes early process state, guard, and
initial TLS; it then owns executable preinit, `_init`, init arrays, normal
exit handlers, fini arrays, and `_fini`. `Scrt1.o` identifies its owned
lifecycle with a private mapped ELF note. When that note is present, crabc
ldso passes a private x0 handoff containing the dependency-constructor and
process-finalizer callbacks; the CRT invokes dependencies after executable
preinit. For a conventional CRT, libc instead reaches ldso's existing private
dlsym callback after guard/TLS startup and asks it to run the complete legacy
initial graph before `_init`. Neither path adds a default-visible lifecycle
symbol: the owned loader finalizer is passed only as an address in the x0
handoff and is ELF-hidden. The loader retains dependency/DSO finalizers and
the dynamic loader process finalizer. This gives each lifecycle phase one
owner and prevents constructors from running before libc startup state exists.

The one intentional bridge is `crabc_core::runtime::RuntimeV1`. It is a
versioned, data-only private wire ABI. `libc` exposes the table and `ldso`
registers its loader-owned callbacks, allowing optional Rust facade features
to reach process singleton services without confusing a separately linked
copy of Rust statics for shared process state. It is neither an installed C
interface nor permission to move loader or libc ownership into `crabc-core`.

C ABI adaptation ends in `libc` export modules: C arguments, sentinel values,
layouts, weak/linkage behavior, and TLS `errno` remain there. Typed native
operations begin in `crabc-core` and are shaped by `crabc-rs`; direct native
errors remain values rather than C `errno` side effects.

Within `libc`, `libc/src/lib.rs` is only the crate's target and linkage
composition root. `libc/src/c_abi.rs` owns the shared C layouts, TLS errno,
stdio, pthread, locale, and process runtime state that cannot safely cross a
C ABI boundary as typed native code. Leaf C ABI domains with independent
state are ordinary private modules with explicit imports: syscall adapters,
fenv, DNS expansion, random, select, timer helpers, small compatibility
exports, and linkage-adjacent leaves are representative examples.

`c_abi.rs` is deliberately a lexical C-ABI namespace rather than a second
composition root: its compatibility fragments directly share private layouts,
TLS state, and helper routines. Independently owned C-ABI leaves remain normal
private modules with named imports. Three cohesive lexical families have an
additional, specific rationale: `math_family.rs` keeps musl-derived numerical
ports beside their private bit and floating-environment helpers;
`encoding_tables.rs` is literal iconv data shared by the conversion
implementation; and `c_abi/aarch64/{atomic,memory}.rs` contains
linkage-sensitive AArch64 assembly. These inclusions never cross the public
crate root, which stays a small target and linkage composition boundary.

[`COMPATIBILITY.md`](../../COMPATIBILITY.md) reports generated measurements.
The exact native capability classification lives in
[`compat/crabc-rs/coverage.toml`](../../compat/crabc-rs/coverage.toml), and
harness-local READMEs describe each evidence runner.

## Native x86-64 runtime hardening

The [selected profiles](../../COMPATIBILITY-PROFILE.md#runtime-hardening-profiles)
define observable policy; [plan.md](../../plan.md#runtime-hardening) is the
only implementation sequence. The following ownership and protection
requirements apply to active native x86-64. They do not change the paused
AArch64 CRT specification.

**Build on existing mechanisms.** The x86 loader already rejects textrel
metadata, validates relocation destinations and protects present RELRO.
[`x86_64_rcrt1.rs`](../../crt/src/x86_64_rcrt1.rs) already applies static-PIE
RELRO before entering Rust startup. Owned startup already seeds guards from
kernel `AT_RANDOM` and establishes startup/TLS/secure state before callbacks. The
hardening requirement is to enforce admission consistently and prove these
invariants through product behavior, not to infer missing mechanisms from
another libc's implementation.

| Owner | Required boundary |
| --- | --- |
| Installed sysroot and link specifications | Bind the selected profile to owned CRT/interpreter artifacts and existing build provenance. Require PIE/static PIE for hardened executable outputs, retain compatibility modes, and diagnose mixed owned products. |
| `ldso` | Enforce the same policy at kernel main-image admission, direct entry, initial dependency/preload loading and `dlopen`. Own validated ELF identity, search inputs, mapping, relocation, RELRO, loader TLS and transactional publication. Keep independent bootstrap and the existing private RuntimeV1 boundary. |
| Owned x86 CRT | Validate applicable static-PIE metadata, complete checked bootstrap relocation and protect RELRO before ordinary startup. Validate inherited main-image facts without relying on ordinary libc, allocation, `/proc` or attacker-chosen argument strings. |
| `libc` | Preserve loader-owned dynamic TLS while owning libc guard/entropy, cached secure state, thread startup and lifecycle responsibilities. Validate the loader/CRT handoff; no guest callback may precede its required startup state and completed loader/CRT protections. |
| Existing evidence owners | Extend native loader, CRT, sysroot and pthread fixtures; bind results to the actual product and source revision. Tests observe behavior and failures, not source literals. |

### Admission and protection invariants

1. **Validate the loaded image.** Identify an executable from bounded ELF and
   auxv facts through both entry routes. A nonzero bias is not a PIE proof.
   Do not require section headers or trust a supplied filename as image
   identity. Hardened DSOs need to satisfy the same applicable admission
   rules; they need not originate from crabc's compiler.
2. **Protect pages, not just headers.** Reject `PF_W | PF_X` and load-layout
   conflicts that defeat W^X after rounding at the target's actual page size.
   Audit overlaps and aliases together with the mapping sequence. Loader-owned
   transitions must not create RWX mappings, including zero-fill and relocation
   windows. Validate inherited kernel mappings before guest initialization;
   userspace cannot claim to have prevented the kernel's earlier mappings.
   Check stack policy on main and dependencies and preserve non-executable
   main/worker stacks.
3. **Bound every write.** Check arithmetic, table shape, destination width and
   writable-load containment for all supported relocations, including RELR and
   TLS descriptors. No missing tag may authorize a text relocation. The early
   assembly path has the same obligations without borrowing unavailable Rust,
   TLS, stack-protector or allocator facilities.
4. **Make RELRO effective.** Validate uniqueness, bounds, page rounding and
   mapped-load containment before changing permissions. Required coverage
   includes relocation-only GOT/PLT binding storage; derive its extent from
   validated ABI metadata, not section-name heuristics. Do not make ordinary
   mutable data read-only or accept an empty token RELRO header as proof.
   Check every protection syscall and protect the interpreter as well as main
   and DSOs. Extend the existing
   [static-PIE fixture](../../crt/tests/test_x86_64_static_pie.py) with write-fault
   and malformed-range checks. Ordinary `mprotect` is not immutable sealing.
5. **Keep committed RELRO closed.** Compatibility deferred binding is a real
   later-`dlopen` retry, with an existing permission/write journal in
   [`x86_64_deferred_relocations.rs`](../../ldso/src/x86_64_deferred_relocations.rs).
   Preserve that behavior and its restoration tests. Hardened loads resolve
   required imports eagerly, have no pending deferred entries, and never use
   that retry path to reopen committed RELRO. Weak-symbol semantics remain
   intact. A failed new load still rolls back its own mappings and TLS work.
6. **Share search enforcement.** Apply the profile to every source consumed by
   [`x86_64_library_search.rs`](../../ldso/src/x86_64_library_search.rs), including
   environment, direct-loader options, system configuration, RPATH/RUNPATH,
   dependency/preload names and explicit `dlopen` paths. Validate absolute
   origins without current-directory fallbacks. Secure-execution filtering is
   an additional invariant. Absolute names and `$ORIGIN` do not establish file
   ownership, safe installation permissions or symlink confinement; document
   those trust assumptions without promising a filesystem sandbox.
7. **Fail before publication and callbacks.** Preflight the whole newly admitted
   graph before guest initialization. Preserve graph visibility, handles, TLS
   generations, pending compatibility words and permissions on rejected loads.
   If rollback cannot restore a safe state, terminate. Main startup violations
   terminate before application entry; `dlopen` policy failures use its normal
   error interface. Fault injection and constructor sentinels prove the boundary.

### Kernel and allocator boundaries

The mandatory profile works on Linux 5.10 and governs crabc-owned loading and
startup. Kernel ASLR, unrelated static binaries, other interpreters and later
application mapping syscalls are outside that guarantee. PIE is necessary for
main-image randomization, not proof that a host enabled ASLR. Do not enable a
process-wide JIT restriction implicitly.

MDWE, irreversible mapping sealing and hardware control flow protection require
separately selected future contracts with kernel/CPU/ABI support, threading,
signal, failure and compatibility evidence. In particular, irreversible
sealing must not defeat failed-`dlopen` rollback. They do not raise the baseline
or delay qualification of the core profile by becoming implicit requirements.
The glibc hardening discussion is design input, not a shipped feature claim
or a replacement compatibility oracle.

Allocator hardening remains within the faithful pinned mimalloc port. Audit
source security options, entropy and metadata protection with their pinned-C
controls in existing allocator evidence; do not substitute another allocator,
invent local cryptography, or wait for native-default promotion to harden the
accepted-C runtime.
