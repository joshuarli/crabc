# Installed x86 synthetic-loader component

`compat/x86_64/run_owned_loader_synthetic.sh` requires one physical installed
dynamic sysroot.  It never rebuilds a runtime.  `compat/ldso/run_x86.py`
compiles every fixture role once with that product's installed headers, retains
the object digest, and links the same object into a pinned-musl root and an
owned-product root.  The roots, links, command streams, process streams,
source seals, and product seals remain below the emitted evidence directory.

The component executes the 21 frozen `compat/ldso/run.py` workload names.  It
uses kernel interpreter entry first and records the compatibility-alias direct
entry as a second observation.  Ordinary streams must exactly match pinned
musl.  ASLR retains both raw streams and only admits the frozen relation that
both PIE and DSO bases differ across two starts.

`lifecycle` requires the musl-observed `ctor`, `lifecycle=73`, `after-close`,
`reopened=73`, and `dtor` markers, then compares the complete raw stream with
the candidate.  It does not infer a close-to-destructor or reopen-to-
constructor ordering from the marker presence.  This component does not claim
a loader-family qualification.

The installed dynamic driver owns three hash styles through
`--application-hash-style sysv|gnu|both`; the default remains `sysv`.  It also
owns executable-only `--application-rpath PATH`, mutually exclusive with
`--application-runpath PATH`.  The former emits `--disable-new-dtags`; the
latter emits `--enable-new-dtags`.  Both choices and the selected hash style
are sealed into the driver sidecar.  No caller-supplied `-Wl` flag is admitted.

The x86 relocation workload preserves the unchanged frozen
`reloc_consumer.c` imported `R_X86_64_64`, `R_X86_64_GLOB_DAT`, and
`R_X86_64_JUMP_SLOT` roles.  The target-local
`reloc_relative_x86_adapter.c` owns hidden initialized data and a static
initialized pointer; its companion calls both the original consumer and the
adapter, requiring `reloc=42 relative=73`.  Its direct
`R_X86_64_RELATIVE` entry supplies the fourth x86 class.  Current installed
LLD emits that unpacked entry and no `DT_RELR` triple for this adapter; the
runner records and checks that exact compiler form rather than relabeling it
as packed relative relocation.

The report distinguishes a behavior observation from its ELF admission.  A
candidate must match the pinned-musl process stream and produce every frozen
fixture input; otherwise the component remains unqualified.
