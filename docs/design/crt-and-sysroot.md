# Owned application CRT and sysroot

## Contract

`crabc` publishes one installable Linux/AArch64 little-endian application
sysroot. `./scripts/dev.sh sysroot` builds it twice from clean generated
inputs, proves both trees reproducible, then runs the native evidence harness.
The primary installed tree is `target/crabc-sysroot/`:

```text
bin/crabc-cc
lib/ld-crabc-aarch64.so.1
lib/ld-musl-aarch64.so.1       compatibility alias only
usr/include/
usr/lib/{crt1.o,Scrt1.o,rcrt1.o,crti.o,crtn.o}
usr/lib/{libc.so,libc.a,libcrabc-builtins.a}
usr/lib/{libm.so,libdl.so,libpthread.so,librt.so,libutil.so}
share/crabc/{manifest.json,purity.json}
share/crabc/{crt.provenance.json,crt.commands.json}
share/crabc/{libcrabc-builtins.provenance.json,libcrabc-builtins.commands.json}
```

New dynamic executables name `/lib/ld-crabc-aarch64.so.1`. The musl-name
loader alias exists only for compatible existing expectations; it is not the
default interpreter selected by `crabc-cc`.

The relocatable `crabc-cc` wrapper discovers this tree from its own path. It
seals ambient include and library search variables, rejects replacement
`--sysroot`/interpreter inputs, and supports compile/preprocess/assembly,
relocatable, shared, dynamic PIE/non-PIE, static non-PIE, static PIE,
`-nostdlib`, `-nostartfiles`, `-nodefaultlibs`, and `-pthread` modes. Each
final-link proof records the resolved linker trace rather than trusting a
command string.

## Rust-owned components

`crt/` produces the conventional objects with Rust source and a deterministic
direct-rustc builder:

- `crt1.o` owns non-PIE `_start`.
- `Scrt1.o` owns PIE `_start` and preserves the loader finalizer register.
- `rcrt1.o` performs the static-PIE bootstrap relocation path before ordinary
  Rust state, then enters the common startup ABI.
- `crti.o` and `crtn.o` own the AArch64 `.init`/`.fini` split-object contract.

The CRT builder binds every installed object byte hash to its pinned-rustc
producer command and a machine-entry audit. The emitted `_start` disassembly
must preserve the original stack, clear the frame sentinel, align `sp`, avoid
an early return or ordinary call, and (for `rcrt1.o`) avoid pre-relocation
GOT/TLS relocations before its direct post-relocation handoff. The installed
CRT provenance and command records carry those checks rather than treating
the source assembly as sufficient evidence.

`builtins/` produces `libcrabc-builtins.a` from Rust `no_std` helper routines.
It combines the small crabc-owned helper object with only the
`compiler_builtins-*.o` members from a fresh, locked
`-Zbuild-std=core,compiler_builtins` build of pinned rust-src
`compiler_builtins` 0.1.160. This supplies the native AArch64 binary128
`long double` arithmetic, comparison, and conversion family that Clang emits
for ordinary C expressions. The `c` and `mem` features, native build commands,
prebuilt target archives, memory exports, outline-atomic exports, unwind
sections, and closure undefined symbols are rejected. The builders bind the
Rust library lock and the upstream build-script configuration source, record
their exact producer commands, and inspect the emitted objects/archives. No
GCC, compiler-rt C/assembly, or other target compiler-runtime archive is
linked.

The compiler-helper producer uses a sealed Cargo environment, a deterministic
probe lockfile, and `--locked -Zbuild-std=core,compiler_builtins`. Its command
record covers local Rust compilation, the source build, member extraction,
deterministic archiving, and archive-surface checks; the installed provenance
hash-binds that record to `libcrabc-builtins.a`.

## Startup ownership

The startup ABI is musl's six arguments:
`main`, `argc`, `argv`, `init`, `fini`, and `rtld_fini`. `crt1`/`Scrt1`/`rcrt1`
derive the initial vectors with bounded raw-pointer parsing and transfer to
`libc::__libc_start_main`; they do not manufacture long-lived Rust references
to initial stack memory. The six-argument libc entry is non-returning: it
routes `main` through libc's ordinary `exit` lifecycle rather than leaving a
second termination path in the CRT.

Ownership is intentionally split only once:

```text
kernel stack -> CRT entry -> libc early state / guard / initial TLS
             -> executable preinit -> loader dependency constructors
             -> executable _init + init arrays -> main -> exit handlers
             -> executable fini arrays + _fini -> loader DSO finalizers
             -> loader finalizer -> process exit
```

`Scrt1.o` carries a private `CRABC` ELF note rather than importing a lifecycle
helper from libc. crabc ldso recognizes that note and passes an x0 handoff
record containing only the dependency-constructor and process-finalizer
callbacks. The owned CRT invokes dependencies after executable preinit. For a
conventional CRT, libc reaches ldso's already-registered private dlsym
callback after it establishes guard/TLS state; that path runs the legacy
initial graph before `_init`. Therefore no lifecycle helper becomes a
default-visible libc symbol, and a candidate executable still runs unadapted
under musl's ordinary loader. libc runs executable arrays and normal exit work
exactly once; the loader owns dependency graph finalizers and its process
finalizer. `__cxa_atexit` feeds the normal exit-handler chain;
musl-compatible `__cxa_finalize` is an ABI no-op. `_Exit` and `quick_exit`
retain their separate contracts.

The stack guard comes from `AT_RANDOM`, falling back only to a raw early
`getrandom` syscall and failing closed if neither yields secure bytes. No
deterministic canary is installed. The static-PIE bootstrap validates its
actual AArch64 RELA/RELR forms and fails closed on malformed or unsupported
records before entering normal Rust state.

## Purity accounting

`scripts/crabc_sysroot.py` audits four distinct facts:

1. runtime source languages, classifying public headers and application
   fixtures separately from target implementation;
2. Cargo normal/build dependency closure and native-build indicators;
3. resolved final-link inputs and foreign target-runtime locations; and
4. installed archives/ELF objects, including members, defined/undefined
   symbols, sections, notes, program headers, provenance hashes, commands,
   and absolute build-path scans.

The passed `crt_sysroot_pure_rust` field covers the Rust CRT/builtins/sysroot
boundary. `full_runtime_pure_rust` remains explicitly false while libc uses
`libmimalloc-sys`; its status is `blocked_by_native_allocator`, not a hidden
fallback or a relabeled success.

## Evidence

`compat/sysroot/run.py` proves driver semantics, all supported link modes,
ELF type/interpreter/RELRO/NOW/no-executable-stack facts, canonical kernel
execution, startup vectors, ASLR for PIE paths, stack-protector failure,
pthread/TLS behavior, constructor/destructor ordering, `dlopen`/`dlclose`,
static-PIE malformed relocation failure, packed RELR when available, and
`/proc/<pid>/maps` identities. The harness waits for a complete dynamic map
snapshot containing both owned loader and libc, avoiding a loader-only startup
race.

Lua, the static pthread/TLS gate, and controlled-C LTO configuration B consume
this installed sysroot. Their application C sources are allowed caller inputs;
musl remains a behavior or execution oracle only, never a candidate target
link/runtime fallback.
