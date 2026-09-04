# AArch64 owned CRT/sysroot contract — retained reference

The recorded CRT/sysroot deliverable is complete; full target-runtime Rust
purity remains blocked by the C allocator. See the
[design](docs/design/crt-and-sysroot.md) and
[evidence](docs/evidence/crabc-owned-sysroot.md) for that distinction.

AArch64 implementation and qualification are paused. The original instructions
below preserve the deliverable's contract; they are not an active work queue.
The x86 sysroot is part of [`x86-64.md`](x86-64.md), developed alongside native
mimalloc and requalified after backend promotion under [`plan.md`](plan.md).

---

Implement a complete crabc-owned application CRT and sealed Linux/AArch64
sysroot.

Do not stop after writing a design or plan. Implement the design, add the
evidence harness, migrate the existing source-build path, run the relevant
tests, and leave the repository in a coherent completed state.

The result must make this statement technically defensible:

    The target-side crabc runtime—including libc, the dynamic linker,
    allocator, application CRT objects, and required compiler helper
    routines—is implemented in Rust and contains no C or C++ production
    implementation code.

C headers, C ABI fixtures, and C applications compiled against crabc are not
violations of that statement. Host tools such as clang, lld, rustc, Python, and
Docker are also outside that target-runtime claim. The distinction must be
explicit and machine-audited.

The pure-Rust mimalloc implementation is a precondition owned by separate
work. Do not redesign or reimplement the allocator in this task. If the current
checkout temporarily still uses libmimalloc-sys, keep this work compatible with
the allocator boundary and distinguish:

    CRT/sysroot purity
    complete target-runtime purity

The former must become green in this task. The latter becomes green once the
pure-Rust allocator is present. Never hide or relabel a remaining native
dependency.

=======================================================================
1. Governing project constraints
=======================================================================

Read only the targeted repository contracts needed for this work before
editing:

    AGENTS.md
    SCOPE.md
    STYLE.md
    STATUS.md
    docs/design/architecture.md
    docs/design/source-build.md
    docs/evidence/lua-source-build.md
    docs/roadmap/source-build.md
    compat/lua/README.md
    compat/lua/run.py
    scripts/dev.sh
    libc/src/c_abi.rs
    libc/src/init_fini_exports.rs
    libc/build.rs
    ldso/src/aarch64.rs
    ldso/src/loader.rs
    ldso/build.rs
    tests/static_hello.rs
    compat/static-pthread-tls/

Also inspect every current reference to startup objects or foreign compiler
runtime inputs:

    rg -n \
      'crt1|Scrt1|rcrt1|crti|crtn|crtbegin|crtend|-lgcc|-lgcc_s|libgcc|compiler-rt|libatomic|libssp|MUSL_ROOT|MUSL_REFERENCE_LIBDIR' \
      .

Do not perform a broad repository rewrite. Preserve the completed compatibility
surface and unrelated dirty work.

The active target remains exactly:

    Linux
    AArch64
    little-endian
    kernel >= 5.10

Do not add:

    x86_64
    RISC-V
    32-bit support
    big-endian support
    non-Linux support
    generic architecture traits
    a general toolchain framework
    C++ runtime support
    libstdc++ or libc++
    exception/unwind-runtime support
    sanitizers
    CPython source-build work
    package-management machinery

Musl 1.2.6 remains the behavioral and ABI oracle. Glibc is not an oracle or
fallback.

The supported development path remains Apple Silicon macOS -> Docker ->
native Linux/AArch64. Use scripts/dev.sh as the public command dispatcher.

Do not create durable code, test, or document names based on chronological
milestones or phases. The phases below are implementation workflow only.

=======================================================================
2. Definition of completion
=======================================================================

Produce an installable, relocatable sysroot with a layout equivalent to:

    target/crabc-sysroot/
      bin/
        crabc-cc
      lib/
        ld-crabc-aarch64.so.1
        ld-musl-aarch64.so.1       optional compatibility alias
      usr/
        include/
          ... crabc public headers ...
        lib/
          crt1.o
          Scrt1.o
          rcrt1.o
          crti.o
          crtn.o
          libc.so
          libc.a
          libcrabc-builtins.a
          libm.so
          libdl.so
          libpthread.so
          librt.so
          libutil.so
          ... deliberate ABI aliases only ...
      share/crabc/
        manifest.json
        purity.json

The exact internal staging path may differ, but the installed target layout and
semantics must be conventional and documented.

The canonical dynamic interpreter path must be:

    /lib/ld-crabc-aarch64.so.1

The sysroot may install a compatibility alias named:

    /lib/ld-musl-aarch64.so.1

but new crabc-linked programs must identify crabc through the canonical
interpreter unless a test explicitly requests the musl-compatible alias.

The completed wrapper must support at least:

    compile-only
    preprocessing
    assembly output
    relocatable linking
    shared libraries
    dynamic PIE executables
    dynamic non-PIE executables
    static non-PIE executables
    static PIE executables
    -nostdlib
    -nostartfiles
    -nodefaultlibs
    -pthread
    -static
    -static-pie
    -pie
    -no-pie
    -shared
    -r

The task is not complete if -static-pie is silently mapped to ordinary static
linking or reported as supported without a functioning rcrt1.o path.

After completion, these commands should be canonical:

    ./scripts/dev.sh sysroot
    ./scripts/dev.sh lua

The first command must build and test the owned CRT/sysroot. The second must
build pinned Lua through that owned sysroot by default.

Retain the old adapter-sysroot implementation only if it still provides useful
historical/differential evidence. It must remain visibly labeled as a borrowed
musl-CRT adapter and must not be the default or be counted as pure evidence.

=======================================================================
3. Purity definition and accounting
=======================================================================

Implement four separate, explicit purity checks.

3.1 Source purity

All target runtime implementation sources must be Rust:

    libc
    ldso
    allocator
    CRT
    compiler helper/builtins archive

Architecture instructions may appear through Rust facilities such as:

    asm!
    naked_asm!
    global_asm!

Do not add target implementation files with these extensions:

    .c
    .cc
    .cpp
    .cxx
    .S
    .s
    .asm

Public .h files and C fixtures under test/evidence directories are declarations
and consumers, not implementation sources. The checker must classify them
accordingly rather than pretending they do not exist.

3.2 Dependency purity

For the target-runtime dependency graph, reject:

    cc
    cmake
    autotools build helpers
    bindgen-generated native builds
    crates with links = ...
    build scripts invoking a C/C++ compiler
    bundled native archives
    bundled external assembly selected for AArch64
    OpenSSL/AWS-LC/libsodium-style native dependencies
    libgcc
    libgcc_s
    libatomic
    libssp
    compiler-rt native archives

Audit normal and build dependencies independently.

Do not rely only on Cargo package names. Inspect build scripts and selected
target source sets.

3.3 Link-input purity

Every target runtime object consumed by a final link must have recorded
provenance.

Classify each linker input as one of:

    crabc Rust runtime
    application object
    compiler intrinsic header/declaration
    host tool
    rejected foreign target runtime

For a Lua build, Lua’s own .o files are application objects and are allowed.
Musl/GCC/compiler-rt startup or runtime objects are not.

Reject target runtime inputs from paths such as:

    /opt/musl-*
    Alpine /usr/lib CRT directories
    GCC runtime directories
    compiler-rt native runtime directories
    ambient host sysroots

Use actual linker traces and resolved paths, not substring guesses alone.

3.4 Artifact purity

For every installed archive and ELF object:

    enumerate archive members
    inspect defined and undefined symbols
    inspect ELF headers and sections
    inspect notes and program headers
    retain SHA-256 provenance
    scan for absolute build paths
    record the exact command that produced it

A compiler identification string in .comment is not by itself contamination.
Provenance is the source of truth.

The generated purity report should have explicit fields equivalent to:

    crt_owned
    startup_objects
    runtime_source_languages
    external_native_source_inputs
    foreign_target_runtime_inputs
    compiler_runtime_inputs
    musl_target_inputs
    gcc_target_inputs
    absolute_build_paths
    reproducible
    full_runtime_pure_rust

Do not reduce this to a GitHub language-percentage claim.

=======================================================================
4. Add a dedicated Rust-owned CRT component
=======================================================================

Create a focused workspace component under a durable name such as:

    crt/
    package name: crabc-crt

It must own the source and deterministic production of:

    crt1.o
    Scrt1.o
    rcrt1.o
    crti.o
    crtn.o

Cargo does not need to pretend that these are an ordinary reusable Rust
library. A small typed stdlib-only Python builder may invoke the pinned rustc
directly with --emit=obj where that produces a clearer contract than abusing a
build script.

Requirements for the builder:

    use the repository-pinned nightly toolchain
    target aarch64-unknown-linux-musl
    panic=abort
    no unwinding
    no allocation
    no std
    deterministic output names
    deterministic/remapped source paths
    no ambient target linker inputs
    retain exact rustc command lines
    fail if any expected object is absent
    fail if an object unexpectedly contains Rust metadata-only output
    inspect every produced ELF relocatable object

Do not write generated CRT objects into the source tree.

4.1 crt1.o

crt1.o must implement conventional non-PIE application startup.

The AArch64 entry point must:

    own the global _start symbol
    begin from the kernel-provided initial stack
    clear x29 and x30 as the bottom-frame sentinel
    preserve the original initial stack pointer
    align SP to the required 16-byte AArch64 boundary
    perform no allocation
    access no TLS
    avoid relocated global state before relocation is available
    transfer to a small Rust startup routine
    never return

The Rust startup routine must safely and explicitly derive:

    argc
    argv
    envp
    auxv

Do not manufacture long-lived Rust references over arbitrary startup memory.
Use raw pointers and bounded parsing until invariants are established.

It must call crabc’s exact application-start ABI and terminate through libc if
that function unexpectedly returns.

4.2 Scrt1.o

Scrt1.o must provide the PIE startup variant.

It must be genuinely position independent. Do not simply copy crt1.o under a
different name without proving its relocation model and resulting executable
type.

Verify:

    ET_DYN output for PIE executables
    correct PT_INTERP
    no text relocations
    ASLR changes the executable base across launches
    startup remains correct with RELRO/NOW
    argc/argv/envp/auxv remain correct

4.3 rcrt1.o

Implement static PIE startup as a real supported mode.

Before ordinary Rust code or relocated globals are touched, rcrt1.o must
perform the minimum required self-relocation for the relocation forms emitted
by the pinned clang/lld AArch64 toolchain.

Requirements:

    position-independent pre-relocation execution
    no allocator
    no TLS
    no ordinary GOT-dependent Rust code before relocation
    checked parsing of the relevant dynamic/program-header data
    support the actual AArch64 RELA/RELR forms selected by the toolchain
    fail closed on unsupported relocation types
    apply appropriate RELRO protection after relocation
    proceed into the same validated libc startup lifecycle
    produce an ET_DYN executable with no PT_INTERP
    produce no DT_NEEDED runtime dependencies
    demonstrate ASLR

Reuse a narrowly factored existing relocation primitive only when doing so
makes the early-start proof clearer. Do not force the ordinary dynamic loader
and static-PIE bootstrap behind an elaborate generic abstraction.

Add separate fixtures for unpacked relative relocations and packed RELR if the
linker can emit both.

4.4 crti.o and crtn.o

Implement the AArch64 .init/.fini split objects in Rust source using
global_asm! or an equally explicit Rust-hosted mechanism.

They must preserve the conventional link-order contract:

    crti.o
    [intermediate .init/.fini contributions]
    crtn.o

Verify:

    _init and _fini symbol type and visibility
    section names
    AArch64 stack/frame behavior
    link order
    no executable stack
    no unexpected undefined references

Do not add external .S files merely to mirror musl’s source layout.

=======================================================================
5. Correct and harden the libc startup lifecycle
=======================================================================

Audit the current __libc_start_main implementation rather than building a new
CRT around its current assumptions.

The pinned musl 1.2.6 contract is the compatibility oracle. In particular,
resolve the current seven-argument/glibc-shaped declaration against musl’s
six-argument startup ABI.

The public ABI should model musl accurately:

    main
    argc
    argv
    init
    fini
    rtld_fini

Do not retain an unused stack_end argument and call that musl compatibility.
If an existing crabc regression proves that a compatibility shim is required,
isolate and document the shim rather than contaminating the canonical
signature.

Extract startup implementation into a focused module if that makes the
lifecycle and unsafe invariants auditable. Do not perform an unrelated
c_abi.rs decomposition.

The startup lifecycle must have explicit ownership and ordering for:

    initial-stack parsing
    environment publication
    auxiliary-vector publication
    program-name initialization
    page-size and hardware-capability state
    vDSO state
    initial thread/TLS setup
    errno TLS
    allocator readiness
    stack-protector guard
    preinit arrays
    dependency constructors
    executable _init
    executable init arrays
    main
    exit handlers
    executable fini arrays
    executable _fini
    dependency/DSO finalizers
    loader finalization
    process exit

Do not let both ldso and libc run the same executable constructors or
destructors. Write down the ownership contract and prove exactly-once behavior
with tests.

5.1 Early-start constraints

Before TLS and the stack guard are initialized:

    do not allocate
    do not access thread-local Rust or C state
    do not call code compiled under assumptions that require initialized TLS
    do not call ordinary formatting/panic machinery
    do not expose fake references to startup memory

Use an explicit noinline/stage boundary and a real compiler barrier where
needed so LLVM cannot hoist TLS- or stack-protector-dependent application work
ahead of initialization.

5.2 Constructors

Support and test:

    .preinit_array for the main executable
    legacy _init
    .init_array
    constructor priorities
    constructors accessing TLS
    constructors allocating memory
    shared-library dependency ordering
    dlopen constructors
    no duplicate constructor calls

Derive exact ordering from pinned musl and ELF behavior, then encode it in
tests. Do not infer it from current crabc behavior if current behavior differs.

5.3 Destructors and exit

The current exit path must be audited for missing executable/DSO finalization.

Normal return from main must be equivalent to:

    exit(main(...))

Do not call _fini immediately after main and bypass the ordinary exit path.

Support and test:

    atexit LIFO behavior
    __cxa_atexit and __cxa_finalize where already in the supported ABI
    fini-array reverse ordering
    legacy _fini
    DSO destructor ordering
    dlclose behavior
    exactly-once process finalization
    _Exit bypassing normal finalizers
    quick_exit retaining its separate contract

5.4 TLS

Prove both static and dynamic application startup for:

    main-thread TLS
    TLS accessed from a constructor
    pthread-created TLS
    initial-exec/local-exec models where supported
    DSO TLS
    dlopen TLS
    errno before and after thread creation

Do not make the CRT depend on pthread initialization before libc has
established the initial thread.

5.5 Stack protector

Remove deterministic fallback canaries.

Initialize the AArch64 stack guard before any protected application function or
constructor can execute.

Use:

    AT_RANDOM

as the normal source. If it is unavailable, use the raw getrandom syscall
without allocating or depending on initialized TLS. If secure randomness still
cannot be obtained, fail closed rather than installing a public constant.

Match the actual AArch64 guard-access model selected by the compiler and
wrapper. Do not assume global versus TLS guard behavior without inspecting
generated assembly.

Add tests that:

    inspect generated guard access
    run a protected normal program
    deliberately smash a stack buffer
    observe __stack_chk_fail termination
    verify the guard is nonzero and differs across execs
    exercise a protected constructor

=======================================================================
6. Eliminate GCC/compiler-rt target runtime inputs
=======================================================================

The current adapter copies crtbeginS.o/crtendS.o and links -lgcc. The completed
sysroot must not.

First inventory the pinned compiler’s actual behavior using:

    clang -###
    clang -v
    ld.lld --trace
    llvm-readelf
    llvm-nm
    llvm-ar

Test representative C programs at O0, O2, and O3, including:

    ordinary integer arithmetic
    signed and unsigned 128-bit arithmetic
    float/double conversion
    long-double/binary128 operations in the supported ABI
    complex arithmetic already supported by crabc
    overflow builtins
    atomics
    stack protector
    PIE
    static PIE

6.1 crtbegin/crtend

Do not copy GCC’s crtbegin*.o or crtend*.o.

For the supported C-only sysroot, first prove that ordinary C constructor and
destructor semantics work through:

    crti/crtn
    linker-provided array boundaries
    libc/ldso lifecycle handling

without compiler-owned crtbegin/crtend objects.

C++ exceptions, C++ static object runtime support, and unwind registration are
not part of this task.

If the C ABI still demonstrably requires a small begin/end object for a
supported C behavior, implement the minimum crabc-owned equivalent in Rust
source and prove every symbol it provides. Do not cargo-cult the GCC objects.

6.2 Pure-Rust compiler helpers

Install a target helper archive:

    libcrabc-builtins.a

It must satisfy compiler-generated helper references without consuming:

    libgcc.a
    libgcc_s.so
    libatomic
    compiler-rt C/assembly objects

Prefer a source-built Rust compiler_builtins implementation from the pinned
Rust toolchain, with all C/native-source features disabled.

The dependency/use of compiler_builtins is approved for this task only under
these constraints:

    source is pinned through the repository Rust toolchain/Cargo lock
    no "c" feature
    no native build
    no target-selected external .S implementation
    memory intrinsics do not conflict with crabc’s memcpy/memmove/memset
    no unwinder
    no panic dependency
    no allocation
    complete archive-member and symbol provenance

Do not use the prebuilt rustup compiler_builtins archive without proving its
source configuration. Prebuilt standard-library artifacts may have been built
with native compiler-rt implementations.

Where necessary, use a strict source-built standard-library lane for:

    core
    alloc
    compiler_builtins

using the pinned rust-src component. Keep that expensive purity build focused
on production/sysroot artifacts; normal edit-time builds do not need to become
unnecessarily slow.

If upstream compiler_builtins cannot directly produce the required C-linkable
archive, build a tiny crabc-owned wrapper/export crate around the required
Rust implementations. Do not respond by falling back to libgcc.

The wrapper should default to code generation that does not require the
AArch64 outline-atomics runtime unless crabc provides and tests those helpers.
Audit the effect of -moutline-atomics/-mno-outline-atomics instead of relying on
a default.

The final linker trace must contain no -lgcc or implicit GCC runtime path.

=======================================================================
7. Build a sealed, relocatable compiler wrapper
=======================================================================

Create one small compiler entry point:

    crabc-cc

Substantial argument handling should be typed stdlib-only Python rather than
shell string manipulation. scripts/dev.sh may remain the small shell
dispatcher.

The wrapper must locate its sysroot relative to its own installed path. Do not
embed the build directory.

It should invoke the pinned/configured clang and lld explicitly. A host-tool
override may be supported through narrowly named environment variables, but
the resolved tool paths and versions must appear in the manifest and evidence.

Use a musl-compatible AArch64 target triple, but override all target runtime
selection explicitly. Do not rely on Clang guessing crabc from the triple.

For compilation, seal target includes with an equivalent policy to:

    -nostdinc
    explicit crabc include directory
    explicit clang resource include directory

The clang resource directory contains compiler intrinsic headers; it is a host
compiler resource, not a target runtime library. Discover it with the compiler
and record it.

Reject or sanitize ambient target-search variables such as:

    CPATH
    C_INCLUDE_PATH
    CPLUS_INCLUDE_PATH
    OBJC_INCLUDE_PATH
    LIBRARY_PATH
    COMPILER_PATH
    GCC_EXEC_PREFIX

Do not permit a user-supplied --sysroot to silently replace the crabc root in
the canonical wrapper.

For links, the wrapper should take explicit ownership of:

    startup object selection
    startup object order
    library search roots
    default libc aliases
    pure-Rust builtins
    dynamic interpreter
    linker selection
    PIE/static/static-PIE mode
    RELRO/NOW/noexecstack defaults
    -nostdlib/-nostartfiles/-nodefaultlibs semantics

Mode behavior:

    compile/preprocess/assemble-only:
        no link inputs

    -r:
        no application CRT
        no default runtime libraries

    -shared:
        no crt1/Scrt1/rcrt1
        include only the init/fini support actually required
        no PT_INTERP

    default dynamic PIE:
        Scrt1.o

    -no-pie dynamic executable:
        crt1.o

    -static non-PIE:
        crt1.o
        no PT_INTERP
        no DT_NEEDED

    -static-pie:
        rcrt1.o
        no PT_INTERP
        no DT_NEEDED

    -nostartfiles:
        omit startup/end objects while preserving default libraries unless
        another option disables them

    -nodefaultlibs:
        retain startup objects but omit default libc/builtins

    -nostdlib:
        omit both startup objects and default libraries

Do not inject a development-tree RPATH into normal output.

Provide focused introspection commands such as:

    crabc-cc --print-sysroot
    crabc-cc --crabc-print-manifest
    crabc-cc --crabc-print-link-plan

The ordinary clang -### behavior must also remain usable.

=======================================================================
8. Canonical interpreter testing
=======================================================================

Do not encode a temporary sysroot path into PT_INTERP as the final design.

New dynamic executables must contain exactly:

    /lib/ld-crabc-aarch64.so.1

The Docker test environment is disposable. The sysroot harness may stage the
loader at that unique canonical path inside the test container before
execution and remove it afterward. It must never mutate the macOS host or rely
on a preinstalled crabc loader.

Verify with the kernel’s normal exec path, not only by invoking the loader
manually.

Record:

    PT_INTERP
    DT_NEEDED entries
    loader path
    library search path
    /proc/self/maps
    executable and DSO hashes
    actual loaded libc/loader identities

Invoking pinned musl’s loader manually remains acceptable for differential
oracle runs, but it does not prove crabc’s PT_INTERP path.

=======================================================================
9. Add a focused CRT/sysroot evidence harness
=======================================================================

Add a focused harness under a durable path such as:

    compat/sysroot/
      README.md
      manifest.toml
      run.py
      fixtures/
      tests/

Reuse the existing evidence conventions:

    typed stdlib-only Python
    no shell=True
    raw stdout/stderr capture
    command arrays
    timeout handling
    atomic JSON writes
    SHA-256 artifact records
    native Linux/AArch64 requirement
    human-readable failure taxonomy
    ignored generated report under compat/reports/

Do not create a second generic compatibility framework.

The canonical report should be:

    compat/reports/sysroot/latest.json

9.1 Required executable modes

Build and run distinct fixtures for:

    dynamic PIE
    dynamic non-PIE
    static non-PIE
    static PIE
    shared DSO
    relocatable object link

For each, verify ELF type, headers, interpreter, dynamic dependencies,
relocations, executable-stack state, RELRO, and runtime behavior.

9.2 Initial-process contract

Test:

    argc
    every argv entry
    argv[argc] == NULL
    envp
    auxv termination
    AT_PAGESZ
    AT_PHDR
    AT_PHENT
    AT_PHNUM
    AT_ENTRY
    AT_EXECFN
    AT_RANDOM
    stack alignment
    main return -> process status
    exit
    _Exit

9.3 Initialization/finalization order

Create fixtures that emit a deterministic byte trace for:

    executable preinit
    dependency constructor
    executable _init contribution
    executable constructors with priorities
    main
    atexit handlers
    executable destructors with priorities
    executable _fini contribution
    dependency destructor

Include a dependency graph with at least two DSOs so ordering is not accidental.

Exercise dlopen, dlclose, and reopen separately.

9.4 TLS and threads

Test:

    TLS from main
    TLS from an early constructor
    TLS from a linked DSO
    TLS from a dlopened DSO
    multiple pthreads
    errno isolation
    constructor-time allocation

Run the existing static pthread/TLS regression using crabc’s own CRT rather
than musl startup objects.

9.5 Security/runtime properties

Test:

    stack protector normal path
    stack protector failure path
    ASLR for PIE and static PIE
    no text relocations
    non-executable stack
    RELRO
    NOW binding where selected
    malformed/unsupported static-PIE relocation fails closed

9.6 Driver semantics

Test the exact behavior of:

    -c
    -E
    -S
    -shared
    -r
    -static
    -static-pie
    -pie
    -no-pie
    -nostdlib
    -nostartfiles
    -nodefaultlibs
    -pthread

Use clang -### and the wrapper’s link-plan output as structural evidence.

9.7 Header and library isolation

Run header traces and linker traces.

Fail if compilation or linking consumes ambient target headers or runtime
libraries outside the explicit allowlist.

The allowlist must identify exact resolved paths and artifact hashes.

9.8 Reproducibility

Build the sysroot twice in separate clean temporary directories using a fixed
SOURCE_DATE_EPOCH and path remapping.

Compare:

    every installed regular file hash
    archive member ordering
    manifest
    ELF build-path strings
    wrapper contents

Symlink targets must be relative and remain inside the sysroot.

=======================================================================
10. Promote the existing Lua gate
=======================================================================

Refactor compat/lua/run.py to consume the new sysroot and crabc-cc rather than
maintaining a private bridge implementation.

In the strict/default lane, remove:

    MUSL_ROOT CRT copies
    Scrt1.o copied from musl
    crti.o copied from musl
    crtn.o copied from musl
    crtbeginS.o copied from GCC
    crtendS.o copied from GCC
    -lgcc
    an absolute temporary PT_INTERP

The Lua build must use the installed crabc wrapper exactly as an external
Autoconf/Make-style project would.

Retain and strengthen the existing proofs:

    pinned source archive and hash
    source extraction safety
    crabc-only public headers
    compile and link command records
    Lua interpreter execution
    luac execution
    liblua shared library
    loadable C extension
    io.popen/subprocess behavior
    deterministic failure reporting
    process maps
    ELF dependency inspection

The strict Lua report must state unambiguously:

    no musl headers used
    no musl CRT objects used
    no musl libc used
    no GCC CRT objects used
    no libgcc/compiler-rt target archive used
    crabc canonical interpreter used
    all runtime/startup inputs have provenance

A musl differential run may execute the same application bytes through the
pinned musl loader where compatible. Musl remains an oracle only; it must not
become a link input.

Do not add CPython to this change. The owned Lua source build is the real
source-build promotion gate.

=======================================================================
11. Migrate existing tests and remove false bridge assumptions
=======================================================================

Update every crabc candidate lane that currently uses musl CRT objects.

At minimum inspect and migrate:

    tests/static_hello.rs
    compat/static-pthread-tls/
    compat/lua/
    any source-build/link fixtures found by the initial rg audit

Musl lanes may continue using musl’s own CRT because they are oracle builds.
Crabc candidate lanes must use crabc CRT.

Do not delete useful musl differential evidence.

Remove comments and documentation that describe a musl CRT bridge as the
current production path once the strict path is green. Historical evidence
must remain historically accurate.

=======================================================================
12. Documentation and durable contracts
=======================================================================

Add or update:

    AGENTS.md
        add the CRT/sysroot code and evidence map

    README.md
        document the new sysroot command and concise purity claim

    docs/design/crt-and-sysroot.md
        runtime ownership
        startup state machine
        CRT object roles
        compiler-helper boundary
        wrapper behavior
        unsafe invariants
        canonical interpreter
        installed layout

    docs/design/source-build.md
        replace the active adapter boundary with the owned-sysroot path
        preserve the old adapter as completed historical evidence

    docs/evidence/crabc-owned-sysroot.md
        exact commands
        artifact hashes/report locations
        accepted external host tools
        rejected target inputs
        mode matrix
        Lua result

    docs/roadmap/source-build.md
        mark the owned CRT/sysroot stage complete only after all hard gates pass
        retain CPython as separate future work

    STATUS.md
        route to the completed design/evidence without adding a microtask list

    compat/sysroot/README.md
        harness mechanics and failure taxonomy

Do not hand-edit COMPATIBILITY.md. Regenerate it through the existing dashboard
only if the new report is intentionally represented there.

Do not leave an ephemeral milestone plan as a durable project authority.
Distill any temporary implementation notes into the design/evidence documents
or delete them before completion.

=======================================================================
13. Required implementation workflow
=======================================================================

Work in vertical slices.

Slice 1: baseline and failing evidence

    record current HEAD and tool versions
    run current relevant gates
    add the CRT/sysroot harness skeleton
    add failing tests showing the musl/GCC bridge inputs
    add failing basic crt1/Scrt1 expectations

Slice 2: dynamic and static non-PIE CRT

    implement crt1.o, Scrt1.o, crti.o, crtn.o
    link and run tiny dynamic PIE, dynamic ET_EXEC, and static ET_EXEC programs
    keep the old bridge path available as an oracle until these pass

Slice 3: startup lifecycle

    correct __libc_start_main ABI/lifecycle
    establish constructor/destructor ownership
    harden TLS and stack-guard initialization
    pass ordering, TLS, exit, and stack-protector tests

Slice 4: compiler helper and sealed driver

    inventory implicit inputs
    add pure-Rust builtins
    remove crtbegin/crtend/libgcc
    implement crabc-cc
    pass driver and contamination tests

Slice 5: static PIE

    implement rcrt1.o self-relocation
    pass ET_DYN/no-interpreter/no-dependency/ASLR/RELRO tests

Slice 6: source-build promotion

    migrate Lua to crabc-cc
    migrate existing static candidate lanes
    make the owned sysroot the canonical path

Slice 7: reproducibility, full evidence, and documentation

    run clean double-build comparison
    generate purity report
    update durable documentation
    run the complete acceptance command set

Do not create durable “slice1”, “phase2”, or “m7” names in code or docs.

Add the smallest focused regression before each semantic fix. Keep unsafe
blocks small and document their exact invariants.

Commit each green vertical slice separately with a descriptive purpose-based
message.

Do not push a remote.

=======================================================================
14. Required acceptance commands
=======================================================================

At completion, run at least:

    ./scripts/dev.sh structure
    ./scripts/dev.sh build
    ./scripts/dev.sh test
    ./scripts/dev.sh ldso
    ./scripts/dev.sh static-pthread-tls
    ./scripts/dev.sh sysroot
    ./scripts/dev.sh lua
    ./scripts/dev.sh compat
    ./scripts/dev.sh dashboard

Also run the focused unit tests for the wrapper and evidence parsers directly
inside the pinned container.

The sysroot command must itself cover:

    clean release runtime build
    CRT object build
    pure-Rust builtins build
    sysroot assembly
    wrapper tests
    all executable-mode fixtures
    startup/constructor/TLS/stack-protector fixtures
    ELF audits
    linker-input audit
    process-map audit
    reproducibility comparison
    purity report generation

Do not mark the task complete because “hello world” launches.

=======================================================================
15. Hard completion gates
=======================================================================

All of the following must be true:

1. crt1.o, Scrt1.o, rcrt1.o, crti.o, and crtn.o are produced from Rust source
   owned by crabc.

2. Dynamic PIE, dynamic non-PIE, static non-PIE, and static PIE programs all
   execute correctly through the normal kernel entry path.

3. Constructor, destructor, atexit, TLS, thread, stack-protector, and main-return
   behavior pass focused ordering tests.

4. New dynamic programs contain:

       /lib/ld-crabc-aarch64.so.1

5. Static programs contain no PT_INTERP and no foreign DT_NEEDED entries.

6. Static PIE is genuinely ET_DYN, self-relocating, dependency-free, and
   ASLR-observable.

7. No crabc candidate link consumes musl CRT objects.

8. No crabc candidate link consumes GCC crtbegin/crtend objects.

9. No crabc candidate link consumes libgcc, libgcc_s, libatomic, libssp, or
   compiler-rt native target archives.

10. Required compiler helper symbols come from an audited pure-Rust archive.

11. No target-runtime dependency compiles C, C++, or external assembly.

12. The sysroot wrapper cannot silently fall through to ambient target headers
    or libraries.

13. The sysroot is relocatable and reproducible.

14. Pinned Lua builds and passes the existing execution/extension/subprocess
    gates through the owned sysroot.

15. The report distinguishes application C objects from target runtime
    implementation objects rather than making a misleading “all output is
    Rust” claim.

16. No generated dashboard is edited manually.

17. No old adapter-sysroot result is relabeled as owned-sysroot evidence.

18. All relevant pre-existing crabc tests remain green.

If any hard gate remains red, do not describe the owned sysroot as complete.
Finish all unblocked work, preserve a focused failing regression and exact
evidence for the remaining blocker, and report it plainly.

=======================================================================
16. Final response
=======================================================================

When finished, report:

    concise architecture summary
    files/components added
    startup ABI changes
    constructor/destructor ownership
    compiler-helper strategy
    installed sysroot layout
    canonical interpreter path
    commands run and outcomes
    executable-mode matrix
    Lua source-build result
    exact foreign-input audit result
    reproducibility result
    remaining unsupported modes, if any

Include representative output from:

    clang -###
    linker trace
    llvm-readelf -h -l -d -r
    llvm-nm
    llvm-ar t
    purity report
    /proc/self/maps

Do not claim “100% pure Rust” merely because the repository’s production
sources use .rs extensions. The claim is earned only when source, dependency,
link-input, and final-artifact evidence all agree.
