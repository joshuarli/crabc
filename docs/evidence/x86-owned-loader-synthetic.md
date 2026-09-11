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

The x86 relocation fixture requires `R_X86_64_RELATIVE`, `R_X86_64_64`,
`R_X86_64_GLOB_DAT`, and `R_X86_64_JUMP_SLOT`.  GNU/SysV hash, `$ORIGIN`/
legacy-RPATH, and legacy init/fini fixture requirements are measured through
the sealed product driver.  A driver surface that cannot produce the frozen
ELF input is retained as a failed case; the runner never calls a host linker
for the candidate to turn that absence into a pass.

The report distinguishes a behavior observation from its ELF admission.  A
candidate may match the pinned-musl process stream while still failing the
case because its sealed link omitted a required hash table, legacy RPATH, or
relocation class.  That distinction keeps the component unqualified until a
new supplied product can produce every frozen fixture input.
