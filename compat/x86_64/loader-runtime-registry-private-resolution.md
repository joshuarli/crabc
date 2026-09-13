# Private loader runtime registry resolution

`loader_runtime_registry_private_resolution` records one narrow native
boundary: the nine unresolved `GLOBAL DEFAULT UND` calls retained by the
selected shared libc are resolved from the selected x86-64 interpreter's
closed `runtime_function` table.  It does not add a libc export, a fallback
provider, or an installed declaration.

The tracked contract is
`loader-runtime-registry-private-resolution.toml`.  Its names map one for one
to `ldso/src/x86_64_runtime_registry.rs:runtime_function`.  The selected
`x86_64-owned-dynamic-runtime` relocation gate in
`ldso/src/x86_64_general_relocation.rs` admits only a zero-addend
`R_X86_64_GLOB_DAT` or `R_X86_64_JUMP_SLOT` relocation against an undefined,
global, default-visible word value (`NOTYPE` or `FUNC`).  The selected product
has the observed `NOTYPE` imports, once in each of `.dynsym` and `.symtab`.
The loader's build provenance and the complete ELF facts bind that source
decision to the supplied shared product and interpreter.

`loader_runtime_registry_evidence.py collect` takes an already prepared
static product, materialized dynamic product, static-preparation receipt,
base inventory and complete ELF-facts report.  It never builds either product.
It captures the existing general-dlfcn workload in both PIE modes, the sealed
100-cell fork workload, and the supplied-product timer reset workload.  The
reader records outer command streams, each linked DSO/executable and its owned
driver receipt, then reopens and rehashes the retained artifacts during
`validate-report`.  It also rechecks the runner's named TBSS, growth,
scope, and applicable failure oracle pairs, plus the timer oracle's stdout,
stderr and status triples and its selected Rust source-test executable/build
captures.  A copied PASS line cannot replace those joins.

The three workload records cover the contract's explicit operation/scenario
roster: six dlfcn operations through the existing 41-module behavior in both
modes, fork prepare/complete through the existing two-mode kernel/direct fork
matrix, and reset through the timer PIE/non-PIE kernel/direct matrix.  Missing
mode, operation, scenario, raw stream, link receipt or supplied-product match
is rejected.  The fork reader remains its own workload-specific 100-cell
receipt; this component only joins it to the same authenticated product.

The collector seals `CRABC_GENERAL_DYNAMIC_DLOPEN_SKIP_SEARCH=1`.  The
unchanged default runner still executes its trailing proc-mount search leaf;
that separate component needs different authority and is recorded as skipped,
not passed, by this dlfcn-only attachment.

## Retained host replay inputs

Fresh reports use
`crabc.x86_64-loader-runtime-registry-private-resolution/v2`.  Their
`replay_inputs` record retains the exact native bytes and original identities
of the selected GCC, LLD, and pinned-musl compiler under `inputs/tools/`, plus
the five fork dependency/preprocessed pairs and both timer dependency, header
trace, and zero-status triples.  Collection compares each original tool again
after the workloads finish; replay verifies the copied bytes, original paths,
and the complete finite preprocessing roster before opening a workload
receipt. It parses rehashed retained ELF64 little-endian bytes for replayed
fork, timer, and dlfcn links instead of executing a host `readelf`. It takes
loader-visible dynamic facts only from `PT_DYNAMIC` whose virtual bytes map
back to its recorded file range through one `PT_LOAD`, and from its uniquely
mapped `DT_STRTAB`/`DT_STRSZ` `PT_LOAD` range; ELF section headers do not
authorize replay metadata. Static PIE keeps the native no-interpreter,
no-`DT_NEEDED`, no-TEXTREL boundary while permitting its self-relocation
dynamic table.

The saved runner argv and `TMPDIR` keep their native `/workspace` spelling.
On a host, the reader maps only that spelling through its one physical
checkout, while it opens retained sidecars through their physical evidence
paths. Fork and timer replay reread the retained preprocessing bytes and use
the sealed original compiler/linker identities to reconstruct exact commands;
the dlfcn reader does the same for every direct-driver receipt. They do not
import the installed compiler helper or invoke GCC, LLD, the pinned musl
compiler, or a host ELF inspector. Link, dependency, raw-stream, product-byte,
and source joins remain exact.

Version 1 reports have no `replay_inputs` field and are deliberately rejected
by this reader.  They remain historical observations; a later host replay
requires a fresh version 2 collection and may not patch a prior receipt.

This is source, import-placement, relocation-admission and finite behavior
evidence.  It does not prove RuntimeV1 worker protocol semantics, CRT startup
structure, general loader qualification, public ABI selection, family
completion, or promotion.
