# Owned static executable enumeration

The installed static runtime enumerates its own executable through
`dl_iterate_phdr`, including when no private loader record exists. An unwinder
needs those main-image program headers to find the executable's unwind tables;
returning `-1` without invoking its callback prevents even a real Rust
personality and unwind provider from discovering the stack's executable frames.
This is core runtime/C ABI machinery, not a new loader graph or public Rust API.

`libc/src/c_abi/x86_64/static_dl_iterate_phdr.rs::iterate` translates musl
1.2.6 `src/ldso/dl_iterate_phdr.c::static_dl_iterate_phdr` from release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license. The exact
source file has SHA-256
`802a537924c900ff607b65bda465bf66899890b7b0707c0cd55c7b800db20327`.
The translation retains these semantics:

- Collect main-image `AT_PHDR`, `AT_PHENT`, and `AT_PHNUM` from the startup
  auxiliary vector, using the last value for each tag.
- Scan program headers in order: `PT_PHDR` sets load bias from its virtual
  address; `PT_DYNAMIC` sets it from the executable's weak hidden `_DYNAMIC`
  address when defined. With neither, the bias remains zero.
- Invoke the callback once with `/proc/self/exe`, the kernel's program-header
  pointer/count, and zero additions/removals. Return the callback's exact
  result and preserve any errno change made by the callback.
- Report TLS module one and the calling thread's initial-image address when
  the executable has `PT_TLS`; otherwise report zero/null.

The ownership substitutions are explicit. `auxv_observation.rs` supplies only
published main program-header coordinates instead of musl's `libc.auxv`.
`static_tls.rs::current_initial_image` subtracts the already validated
variant-II image distance from the current thread pointer instead of using
musl's `__tls_get_addr({1, 0})` DTV lookup. It neither returns the process-main
thread's TLS to a worker nor creates another TLS layout. Startup already
validates these immutable ELF/TLS inputs. Missing startup publication returns
`-1`; it is not an alternate loader discovery path.

`fixed_graph_dlfcn.rs` keeps the public weak function and selects this body
only with `x86-owned-static-runtime`. Its private fixed-graph build retains the
existing runtime-record/snapshot behavior. The dynamic feature selects
`general_dlfcn.rs` at the target root and does not compile this static body.
The existing null-callback behavior remains unchanged. AArch64 is unchanged.

## Focused evidence

```sh
./scripts/dev-x86_64.sh owned-static-dl-iterate-phdr
```

`run_owned_static_dl_iterate_phdr.sh` compiles the same object for each oracle
and candidate mode, links actual installed ET_EXEC/static-PIE consumers, and
compares them with pinned musl in both modes. The oracle static PIE explicitly
selects pinned musl `rcrt1.o`, since its GCC specs do not select that entry for
`-static-pie`. ELF checks require the expected type and no interpreter.

`owned_static_dl_iterate_phdr_probe.c` verifies main-image header coordinates,
load bias, code containment, name, counters, callback ABI size and results
`0`, `73`, and `-29`, errno at entry/after callback, and initialized/zero TLS
bounds plus independent main/worker TLS. `owned_static_dl_iterate_phdr_override.c`
proves a strong application definition still overrides the weak archive
provider; the ordinary consumer also requires a defined `WEAK FUNC` symbol.
The real libc has TLS, so this consumer does not exercise an executable with
no `PT_TLS`.

Before the fix, both musl modes passed and the owned ET_EXEC consumer aborted
at its first callback-result check: the private runtime record was absent.
After the fix, both owned modes and overrides pass. This component does not
alone prove Rust panic cleanup, DSO unwinding, family closure, or promotion.

The private `fixed_graph_dlfcn_runtime.rs` source root also compiles with the
pinned native compiler. Full `ldso-public-dlfcn` replay is blocked at baseline
`a4101799` by an unrelated missing `virtual_range_in_readable_file_load` in
`ldso/src/x86_64_initial_graph.rs:1886`. The focused host static-TLS contract
passes. Two nearby host checks already fail at that baseline: the dispatcher's
closed-roster test captures newly nested command groups, and the auxv source
check rejects `malloc` inside the existing `native-mimalloc-shadow` cfg name.
Both failures were reproduced with tracked source reads from the baseline;
this component does not broaden into repairing those checks or loader code.
