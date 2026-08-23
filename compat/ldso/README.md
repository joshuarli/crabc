# Synthetic AArch64 ldso differential suite

This is the runtime evidence suite. It compiles the C fixtures once with
the pinned musl 1.2.6 compiler, links equivalent PIEs for the pinned musl
interpreter and crabc's `libldso.so`/`libc.so`, then compares raw exit status,
stdout, and stderr.

It is intentionally distinct from `compat/loader/`: that directory records
source/ELF inventory evidence, whereas this runner executes the mechanisms it
claims to cover. It is also distinct from the later Alpine corpus: all inputs
here are synthetic and deliberately isolate one ELF contract at a time.

## Run

```sh
./scripts/dev.sh ldso
./scripts/dev.sh ldso --case nested-needed
```

The runner requires the native AArch64 development image and a prior workspace
build (the `dev.sh` command supplies that build). It writes the atomic report
to `compat/reports/ldso/latest.json`.

## Initial case: recursive `DT_NEEDED`

`nested-needed` constructs this graph:

```text
main PIE → libnested_mid.so → libnested_leaf.so
```

The middle DSO calls a function defined by the leaf. The runner first verifies
with `readelf -d` that the `DT_NEEDED` edge exists and with `readelf -Wr` that
the call uses `R_AARCH64_JUMP_SLOT`; it then requires pinned musl and crabc to
produce the exact same process result, `nested=42\n`.

This is a regression for recursive graph traversal, not an indirect test of
ordinary libc calls: the two DSOs intentionally need no libc functionality.
The absolute, case-local `DT_RUNPATH` makes library discovery deterministic;
the separate `dso-origin` and `search-path` cases cover `$ORIGIN` and search
precedence.

`nested-dlopen` uses the identical DSO graph through `dlopen`, validates the
middle export through `dlsym`, and closes the handle. Its library directory is
provided only through the test-local `LD_LIBRARY_PATH`, so it isolates runtime
graph traversal from the startup-Pie RUNPATH case.

`search-path` creates three libraries with distinct return values and compares
the pinned-musl result for both a `DT_RUNPATH` and a legacy `DT_RPATH` binary,
with and without a test-local `LD_LIBRARY_PATH`. This verifies actual search
precedence rather than merely checking that the loader parses a tag.

`dso-origin` loads a middle DSO by an explicit relative path. Its own
`DT_RUNPATH=$ORIGIN` must locate a leaf DSO while neither test runtime gets a
library path containing the bundle. This keeps a parent's local search path
and origin separate from the main executable's path.

`initial-tls` starts with a `PT_TLS` DSO in the main executable's
`DT_NEEDED` graph, verifies that program-header evidence, and compares the
initial per-thread values. `dynamic-tls` then covers the separate late-load
case with a thread that predates the DSO.

`dlerror` makes a failed `dlopen` and a failed `dlsym` observable. In each
case it requires a non-null error exactly once, followed by a null result, so
the fixture checks state consumption without treating musl's human-readable
diagnostic text as a separate ABI. The direct C regression also leaves a
failed `dlsym` error unobserved across later successful handle-local `dlsym`,
`dlopen`, and `dlclose` operations: matching musl, callers clear before their
lookup sequence and observe once after it rather than relying on success to
reset error state. It also reuses one mutable character array for `dlerror`,
`dlclose`, then `dlerror` again, proving a handle-local lookup may not use the
C-string address alone as a cache key.

`hash-formats` loads otherwise identical DSOs emitted with `DT_GNU_HASH` and
with legacy `DT_HASH`. It proves the tags remain in the fixture and compares
the two runtime symbol lookups.

`hash-many` emits a DSO with both hash formats and 1,025 default-visible
exports. It resolves its first and last exports through `dlsym`, so a retained
hash-table implementation must keep the dynamic-symbol scope and the high
symbol index correct.

`relro` emits a DSO with `-z relro -z now`, proves its `PT_GNU_RELRO` segment
and relocation shape with `readelf`, and forks a child that attempts to write
a relocated, read-only pointer. Pinned musl must terminate the child by signal;
crabc must provide the same final protection after relocation.

`auxv` proves the rebuilt application stack retains the nonzero `AT_PHDR`,
`AT_PHNUM`, `AT_ENTRY`, `AT_BASE`, and `AT_RANDOM` values needed at startup,
as well as `AT_SYSINFO_EHDR`, the kernel-supplied vDSO ELF base. The fixture
does not model a vDSO as a normal DSO; it verifies that programs can discover
the kernel mapping through the musl public auxiliary-vector contract.

`legacy-lifecycle` emits both legacy `DT_INIT`/`DT_FINI` hooks and compiler
generated init/fini arrays. Pinned musl's `dlopen`/`dlclose` result runs the
arrays while ignoring those legacy hooks; the fixture makes that distinction
observable instead of treating the dynamic tags as proof of execution.

`lookup-scope` loads one `RTLD_LOCAL` and one `RTLD_GLOBAL` DSO. It verifies
that the local export remains reachable through its handle but is absent from
`RTLD_DEFAULT`, while the global export is visible through that default scope.

`visibility` emits one default-visible and one hidden function. It verifies
the dynamic-symbol-table shape before requiring `dlsym` to expose only the
public function and to set a consumable error for the hidden name.

`constructor-order` emits a main PIE with a middle DSO, its transitive leaf,
and an independent sibling. It compares the dependency-first constructor
sequence before the main PIE's own init array runs.

`main-handle` exercises `dlopen(NULL)`, uses that global process handle for a
main-program lookup, and verifies its required successful `dlclose` no-op.

`lifecycle` proves a dynamically loaded DSO has `DT_INIT_ARRAY` and
`DT_FINI_ARRAY`, observes its constructor, closes its handle, and verifies its
destructor when its reference count first reaches zero. Pinned musl retains
that finalized mapping: reopening the same path does not run another
constructor/destructor pair, while the exported function remains callable.
Its raw stdout comparison keeps this lifecycle ordering observable.

`preload` links a startup DSO and supplies an `LD_PRELOAD` DSO exporting the
same function. The reference must select the preload value before the startup
dependency is relocated, and crabc must have the exact same result.

`aslr` runs a PIE and a dynamically loaded DSO in two independent processes,
extracts both `dladdr` load bases, and requires musl and crabc to choose new
bases for both images. The exact addresses are recorded as raw evidence but
are intentionally not compared across runtimes.

`dynamic-tls` creates a pthread before a TLS-bearing DSO is loaded, then uses
the DSO from both threads. `readelf` must show `R_AARCH64_TLSDESC`; the current
thread observes its changed value while the pre-existing worker gets a fresh
TLS image.

The root `tests/tls_growth_regression.rs` direct pinned-musl differential
extends that one-DSO shape to eight optimized TLS DSOs. The worker predates all
loads, must receive every initialized image exactly once, and writes values
that remain isolated from the parent until every handle is closed. It also
keeps the AArch64 TLSDESC register contract observable: an optimized caller
may cache TP in `x1`, which must be refreshed if the resolver migrates the
thread to a larger TLS allocation.

`tests/dynamic_tls_dependency.rs` covers the different one-`dlopen` graph
shape. Its optimized parent DSO has a recorded `DT_NEEDED` edge to an optimized
child TLS DSO; a worker predating the graph must observe both initializers and
write only its own pair of TLS instances. The direct differential proves the
dependency edge with `readelf -d` before comparing both runtime outputs.

`ldso/src/loader.rs` records each image's introduction generation. When
`expand_thread_tls` finds that a thread's recorded capacity and TP placement
already fit every new image, it initializes only those images in place; a
larger image or stronger alignment retains allocation replacement. This keeps
already-written dynamic TLS values intact while avoiding a block swap for each
ordinary late load.

For a late DSO's exact `DT_NEEDED libc.so` edge,
`loaded_initial_libc_by_needed_name` mirrors musl's initial-libc short name and
reuses the initial graph object without reopening it for identity discovery.
Other runtime bare names, `$ORIGIN`, RUNPATH/RPATH, and explicit paths still
use the ordinary inode-identity route.

`relocations` is a two-DSO graph with initialized external data, GOT data, and
a function call. It requires `readelf -Wr` evidence for
`R_AARCH64_RELATIVE`, `R_AARCH64_ABS64`, `R_AARCH64_GLOB_DAT`, and
`R_AARCH64_JUMP_SLOT` before comparing the observable calculation.

`weak-strong` keeps an earlier weak definition and a later strong definition
in the same `DT_NEEDED` graph. It records pinned musl's exact first-definition
lookup result for that concrete scope rather than applying a generic binding
preference that musl does not use there.

## Oracle boundary

Pinned musl 1.2.6 is the runtime oracle. `readelf` only proves fixture shape;
it is not an implementation oracle. The harness does not consult host glibc,
and it removes inherited `LD_LIBRARY_PATH`/`LD_PRELOAD` before the musl run.
