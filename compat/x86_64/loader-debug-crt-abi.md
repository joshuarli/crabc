# Native loader debugger and CRT ABI ownership

The native interpreter owns one debugger rendezvous over its existing
process-lifetime object registry. Shared libc exposes `_dl_debug_addr` as an
eight-byte, GLOBAL, DEFAULT-visible pointer object and `_dl_debug_state` as an
inert WEAK, DEFAULT-visible function. No second object graph, libc-owned
`r_debug`, or application callback is introduced into the loader lock.

`x86_64_debugger.rs::PreparedInitialDebugger` accepts only the libc receiver
already selected by opened-file identity. The selected `_dl_debug_addr` must
be one unversioned GLOBAL/DEFAULT object of size eight in writable storage,
with no overlap with ELF metadata. Main `DT_DEBUG`, if present, must be unique
and writable. The complete relocation preflight rejects RELA, RELR and COPY
writes overlapping either publication slot. `relocate_initial_graph_with_debugger`
then seeds the canonical pointer after ordinary word relocations and before
main COPY relocations. Both libc-handle lookup and an executable COPY receive
the same pointer. Protection and RELRO are applied afterward.

`PreparedInitialRegistry::publish` publishes the actual registry's link-map
head and the interpreter base before any executable or DSO constructor.
`Rendezvous` has the native `<link.h>` layout: version at offset zero, map at
eight, breakpoint at sixteen, state at twenty-four, and loader base at
thirty-two, with a total size of forty bytes. Only the pointer slot is eight
bytes. The initial breakpoint observes version one and RT_CONSISTENT.

Every admitted named `runtime_open` transaction holds the existing graph
lock while `AddNotification` announces RT_ADD. Its guard restores
RT_CONSISTENT on success and failure before releasing that lock. Constructor
callbacks run afterward, so constructor reentry observes a committed graph
and a consistent rendezvous. The breakpoint is the loader's weak `_dl_debug_state` export with
an actual compiler memory boundary; it does not dispatch an interposed
application function. Fork retains the established graph/callback lock
ordering. `dlclose` keeps musl's retained mappings and emits no invented
RT_DELETE or close-time unmapping.

The libc defaults in `init_fini_defaults.rs` are separate from the strong
`crti.o`/`crtn.o` fragments. `_init` and `_fini` remain unversioned WEAK,
DEFAULT-visible functions in the owned static/shared libc products. Direct
calls are inert. CRT and loader lifecycle owners still dispatch the real
initialization/finalization sequence exactly once; a fallback never calls
exit, atexit handlers, or dependency finalizers. The defaults are selected by
the owned-runtime aggregate, leaving the historical default archive ratchet
unchanged.

## Pinned source and structural startup dispositions

The compatibility source is musl 1.2.6, revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT, with release tarball SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.

| Source definition | Native owner |
| --- | --- |
| `ldso/dynlink.c::struct debug`, `_dl_debug_addr`, `dl_debug_state`, `__dls3` debugger publication | `ldso/src/x86_64_debugger.rs`, with the pointer/hook views in `libc/src/c_abi/x86_64/loader_debug_abi.rs` |
| `ldso/dynlink.c::dlopen` RT_ADD/RT_CONSISTENT and retained graph | `x86_64_runtime_registry.rs::runtime_open`, `x86_64_debugger.rs::AddNotification` |
| `src/env/__libc_start_main.c::dummy/_init`, `src/exit/exit.c::dummy/_fini` | `libc/src/c_abi/x86_64/init_fini_defaults.rs` |
| `crt/x86_64/crti.s` and `crtn.s` strong lifecycle fragments | Existing `crt/src/x86_64_crti.rs` and `x86_64_crtn.rs` |

The frozen ledger at `3e100d45c5a0798c2d3862d5e2eef584c610ccf9` classifies
`__dls2b`, `__dls3`, and `_dlstart` under `runtime.loader` as
`internal-runtime`, with no installed application-facing header contract.
Musl's public headers declare none of these spellings. Their presence in the
combined musl libc/loader dynamic symbol table remains an ABI input; it is
not an instruction to reproduce that source's internal stage graph.

The native resolution under `x86-64.md` lines 118 and 676 is explicit:

| Identity | Resolved native structural boundary |
| --- | --- |
| `__dls2b` | Oracle bootstrap/TLS barrier. Musl `__dls2` resolves this name symbolically after self relocation; `__dls2b` installs the early thread pointer and symbolically resolves `__dls3`. Native `_start` self-relocation and `GeneralInitialTlsTransaction` own the real ordering/TLS publication. No ordinary libc or archive callable is selected. |
| `__dls3` | Oracle final startup stage. Musl loads/relocates dependencies, finishes TLS and jumps to `AT_ENTRY`. `x86_64_general_initial_graph.rs::run` and its relocation/TLS/lifecycle owners, with `x86_64_direct_entry.rs`, implement the actual native process-entry boundary. No returning libc state mutator is selected. |
| `_dlstart` | ELF interpreter entry consumer boundary. Musl's Makefile selects this raw-stack assembly entry through `e_entry`. The installed native interpreter selects its existing `_start` and `e_entry`; PT_INTERP and direct execution exercise it. No libc trampoline or ordinary archive provider is selected. |

The frozen AArch64 returning-stage probe
`tests/fixtures/loader_startup_test.c` and libc-address-taking `_dlstart`
probe in `tests/fixtures/loader_debug_exports_test.c` remain preserved
AArch64 implementation evidence. The returning setters deliberately differ
from musl's nonreturning startup stages. Actual native entry, relocation and
TLS ownership evidence supersedes those implementation-specific probes for
these three structural dispositions. This changes no frozen input and waives
none of the debugger or CRT ABI obligations. Root-owned complete native
manifest accounting records these dispositions separately from the monotonic
native dynamic-symbol ratchet.

## Component evidence

Run `compat/x86_64/run_loader_debug_abi.sh collect --output PATH` inside the
pinned native Docker environment, with a physical checkout `.work` TMPDIR and
`CRABC_LOADER_DEBUG_IMAGE_ID=crabc-core-evidence@sha256:...` supplied from the
actual Docker image identity by the invoking dispatcher. The collector
requires clean source, builds one fresh static and one fresh dynamic product,
and checks that source content/revision did not change. It is a component
measurement, not full product qualification or reproducibility evidence.

The fixed matrix includes 68 execution cells. Each workload is compiled once
by the pinned musl compiler and reused unchanged between oracle and candidate
links. The ordinary lifecycle and isolated default/strong-override archive
probes cover static ET_EXEC and static PIE. Debugger, COPY, strong-hook-interposition, weak-default and
lifecycle probes cover shared PIE/non-PIE through both kernel and direct
entry. The COPY objects retain an actual `_dl_debug_addr` R_X86_64_COPY.
The pinned GCC specs always select `Scrt1.o`, so the static lifecycle oracle
explicitly links the installed pinned `crt1.o` or self-relocating `rcrt1.o`,
`crti.o`, `libc.a`, and `crtn.o`. Those inputs are retained; the reader checks
the actual ET_EXEC/ET_DYN and PT_INTERP boundary for every executable.

`loader_debug_abi_trace.c` is a separate static observer. It uses ptrace to
break at the real `r_brk` site, identifies the data provider mapping by opened
file identity, and records initial CONSISTENT and every ADD/CONSISTENT pair.
The strong-hook-interposition executable defines a failing `_dl_debug_state`; its separate definition must never receive loader notifications. Both ordinary and interposed traces must still observe the loader export exactly at `r_brk`. The libc weak view and loader weak definition are distinct functions, not cross-DSO aliases. The same workload checks plugin admission,
failed lookup, constructor reentry, retained close/reopen and ordinary fork.
Trace invocations follow one task; separate ordinary invocations perform the
fork check and call the libc hook directly. Traced runs omit that deliberate
application call, because musl uses the same function for its libc view and
breakpoint. The sequence and graph-growth observations must match pinned
musl in every entry mode.

`loader_debug_abi_evidence.py validate-report PATH` is a read-only host replay.
It checks the fixed execution roster, current source/revision, immutable
artifacts, retained command results, direct ELF metadata, COPY relocations,
archive provider bindings, unchanged workload objects, live installed-product
manifests and raw observer sequences. Focused reader tests live in
`tests/test_loader_debug_abi_evidence.py`; loader publication/transaction tests
live beside their owner in `ldso/src/x86_64_debugger_tests.rs`. All family,
product-promotion and public-support flags remain false.
