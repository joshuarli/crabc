# Lua owned-sysroot source-build gate

This harness has two deliberately separate source-build lanes for pinned Lua
5.4.8. The established AArch64 lane builds a dynamic graph: a real
`liblua.so.5.4`, dynamically linked `lua`, an upstream-valid private-unit
`luac`, and separate success/failure loadable C extensions. The native x86-64
lane builds complete static ET_EXEC and static-PIE `lua`/`luac` programs from
the same source roster through the installed sealed static driver. Every
candidate compile and link uses `crabc-cc`; resolved linker traces must contain
only installed crabc runtime inputs and explicit Lua application objects or
libraries.

Run it through the architecture-specific Docker entry point:

```bash
./scripts/dev.sh lua
./scripts/dev.sh lua --offline
./scripts/dev-x86_64.sh lua-static-source-build
./scripts/dev-x86_64.sh lua-dynamic-source-build
./scripts/dev-x86_64.sh lua-source-build-admission [--output NEW_DIR]
python3 -m unittest discover -s compat/lua/tests -p 'test_*.py'
```

`run_x86_dynamic_supplied.py` is the separate consumer entry point for an
already sealed dynamic cohort. It takes the frozen cohort checkout and its
`qualification.json`, the exact installed and extracted roots declared by that
receipt, and a physical verified `lua-5.4.8.tar.gz` seed. It first runs the
originating checkout's qualification reader with its matching linked-worktree
Git metadata exposed read-only through explicit `GIT_DIR` and `GIT_WORK_TREE`,
then copies that seed into a new private cache and invokes the existing dynamic
lane twice in offline mode. It never edits the frozen worktree's `.git` file
or invokes the sysroot builder, package tool, extractor, public dynamic
dispatcher, or latest-report publication. Its report records the consumer's
own clean source separately from the product cohort; passing it is a live Lua
source-consumer result, not a transfer of product qualification or support.

The AArch64 command builds `target/crabc-sysroot/` first. The x86 static and
dynamic commands materialize their corresponding sealed sysroots first. Each
x86 dispatcher invocation gets a distinct physical
`.work/x86_64/lua-*-source-build/run-*` root with its own producer logs,
sysroot, source extraction/cache, build state, and authoritative report. The
dynamic dispatcher also packages and extracts its sysroot, then builds the
same complete dynamic graph through both roots and requires exact hashes for
`liblua`, `lua`, `luac`, the success/failure modules, and the missing-symbol
copy. The conventional latest x86 report is atomically replaced only after the
whole invocation passes. Both offline paths require a verified Lua archive
cache entry; neither downloads on a cache miss.

The admission command reads both latest reports as physical receipts. It
requires each authoritative report under `.work/x86_64` to match its published
copy, binds both reports to the current checkout source identity and pinned Lua
archive, revalidates the static and dynamic sysroot manifests, and checks the
dynamic products against their current source seal. The parity ledger calls
this same reader before accepting `consumer.source-build` as
`foundation-verified`. `lua-source-build-admission --output NEW_DIR` also
retains the admission as `NEW_DIR/admission.json`; the qualification gate's
`lua-source-build` publication selects it and passes only while a fresh
admission is identical, so a later lane report, product change, or source
edit invalidates it.

## Ordered qualification case

`qualify_source_build.py` is the only case pinned by
`compat/x86_64/qualification_source_build.json` for the ordered
`consumer.source-build` qualification gate, selected with
`./scripts/dev-x86_64.sh qualification-manifest --through consumer.source-build`
after every predecessor gate is ready. That frozen roster is exactly the
AArch64 `lua` gate: static ET_EXEC and static-PIE `lua`/`luac` with linked
preload modules, and the dynamic `liblua.so.5.4`, `lua`, `luac`, success,
failure, and missing-symbol modules through installed and package-extracted
sysroots, all with source and bytecode workloads compared to fresh pinned-musl
builds. The case adds no workload and substitutes no version probe.

The qualification runner starts cases with a scrubbed environment and
`PYTHONSAFEPATH=1`, so this runner names its own import directories. It fails
before building anything unless the checkout is clean committed source and
every transitive family prerequisite of `consumer.source-build` is
`foundation-verified` in the validated campaign report. It then runs the static
and dynamic dispatchers and the admission reader in order, requires the
admission to bind the same clean source, rechecks that source, and only then
prints its non-promoting marker. A report produced at another revision or
content digest is never admitted.

## Candidate boundary

The dynamic candidate uses the installed public headers, Rust CRT objects,
`libc.so`/`libc.a`, loader, and `libcrabc-builtins.a`. The static candidate
uses only its selected installed `crt1.o` or `rcrt1.o`, `crti.o`, `crtn.o`,
`libc.a`, `libcrabc-builtins.a`, and explicit Lua application objects. Neither
lane copies or accepts musl startup objects, GCC `crtbegin`/`crtend`, `libgcc`,
compiler-rt, `libatomic`, or `libssp` as a candidate input. The runner records
header selection, every static link receipt/map/trace, and ELF facts. The
dynamic lane additionally records candidate `/proc/<pid>/maps` hashes for the
owned loader/libc, `liblua`, and loaded probe extension.

The native dynamic candidate enters a fresh private execution root through its
unchanged canonical `/lib/ld-crabc-x86_64.so.1` kernel interpreter. That root
contains an exact copy of the supplied product, the finite Lua application
payload, and the fixture script; only `/work` may change during a workload.
The `/lib/ld-musl-x86_64.so.1` compatibility alias alone is replaced with the
pinned musl loader required by the separately copied `/bin/sh` fixture used by
`io.popen`. Candidate map evidence is translated through the live
`/proc/<pid>/root` and must identify the copied owned loader/libc and Lua DSOs.

## Musl oracle lanes

Musl 1.2.6 is an execution oracle, not a candidate build or runtime fallback.
The dynamic lane launches the exact candidate executable/application DSOs
under musl's loader with copied musl `libc.so`, with no preload shim. The
crabc-owned CRT uses a private ELF note to select its loader handoff; under
musl it preserves the ordinary direct loader-finalizer ABI and musl's normal
dependency startup.

The x86 lane separately links and launches fresh pinned-musl ET_EXEC `lua` and
`luac` source builds for both owned candidate modes. It never executes a
candidate byte under musl or uses a musl object in a candidate link. The
pinned wrapper's current `-static-pie` route selects `Scrt1.o` and crashes a
tiny independently linked program; that reproducible diagnostic is retained
in the x86 report. It is a wrapper limitation, not a claim that the owned
static-PIE candidate shares ET_EXEC startup: the candidate still has its own
`rcrt1.o`, ET_DYN/relocation, closed-link, source, and bytecode execution
checks.

## Static C-module boundary

The native static lane builds `crabc_probe`, `crabc_fail`, and the small
`static_preload` adapter into each Lua executable. A private copy of upstream
`linit.c` registers their existing `luaopen_*` entry points in
`package.preload`. This proves the same C-module functional and protected
error paths without claiming runtime DSO loading. Dynamic-only DSO map and
missing-symbol cases are explicitly not applicable in static mode. `io.popen`
is not omitted: source and bytecode workloads in every candidate and oracle
arm require it to succeed.

The reports at `compat/reports/lua/latest.json`,
`compat/reports/lua/x86_64-static-latest.json`, and
`compat/reports/lua/x86_64-dynamic-latest.json` compare source and bytecode
streams/status byte-for-byte. The dynamic reports retain non-timing `strace`
diagnostics for normal and controlled-failure module paths. The native dynamic
lane builds a fresh pinned-musl source graph as its oracle; musl artifacts are
never candidate inputs. The fixtures cover dynamic module loading where
applicable, repeated `require`, missing-symbol and init-failure behavior, Lua
C API allocation/buffers, descriptor-relative I/O, stdio, strings/tables/UTF-8,
math, environment/time, and a controlled child/pipe.
