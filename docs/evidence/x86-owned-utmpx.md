# Owned fixed-profile utmpx compatibility

The native owned runtime has a private complete `utmpx.c` compatibility leaf in
`libc/src/c_abi/x86_64/owned_utmpx.rs`. It is selected only when the x86 root
registers that module under `x86-owned-static-runtime`; the owned dynamic
product inherits the same owner. This is C ABI compatibility machinery for
musl's deliberately inert utmpx profile. It does not open files, retain a
cursor, own records, allocate memory, or import the paused AArch64 database
implementation.

## Source and ownership

The semantic source is MIT-licensed musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. The exact
`src/legacy/utmpx.c` source SHA-256 is
`3138ac427b05fc86177bf80e5e62a3b84b5d1e14daba1e6b935edc3b9839ce56`.
`compat/upstreams.toml` owns the release pin and musl's upstream `COPYRIGHT`
owns the MIT license provenance.

| Musl source | Owned Rust target |
| --- | --- |
| `src/legacy/utmpx.c::endutxent` | `owned_utmpx::endutxent` |
| `src/legacy/utmpx.c::setutxent` | `owned_utmpx::setutxent` |
| `src/legacy/utmpx.c::getutxent` | `owned_utmpx::getutxent` |
| `src/legacy/utmpx.c::getutxid` | `owned_utmpx::getutxid` |
| `src/legacy/utmpx.c::getutxline` | `owned_utmpx::getutxline` |
| `src/legacy/utmpx.c::pututxline` | `owned_utmpx::pututxline` |
| `src/legacy/utmpx.c::updwtmpx` | `owned_utmpx::updwtmpx` |
| `src/legacy/utmpx.c::weak_alias(..., endutent)` | assembler alias of `endutxent` |
| `src/legacy/utmpx.c::weak_alias(..., setutent)` | assembler alias of `setutxent` |
| `src/legacy/utmpx.c::weak_alias(..., getutent)` | assembler alias of `getutxent` |
| `src/legacy/utmpx.c::weak_alias(..., getutid)` | assembler alias of `getutxid` |
| `src/legacy/utmpx.c::weak_alias(..., getutline)` | assembler alias of `getutxline` |
| `src/legacy/utmpx.c::weak_alias(..., pututline)` | assembler alias of `pututxline` |
| `src/legacy/utmpx.c::weak_alias(..., updwtmp)` | assembler alias of `updwtmpx` |
| `src/legacy/utmpx.c::weak_alias(__utmpxname, utmpname)` | weak provider alias |
| `src/legacy/utmpx.c::weak_alias(__utmpxname, utmpxname)` | assembler alias of `utmpname` |

The seven strong entries are inert: cursor controls and `updwtmpx` return
without work, while the four record operations return a null `struct utmpx *`.
All pointer arguments are ignored, including null and unreadable values, so
these entries leave errno and caller records unchanged. The seven traditional
utmp names and both database-name names are weak ELF aliases with the same
addresses as their musl providers. `utmpname` and `utmpxname` return `-1` and
set errno to `ENOTSUP`; their ignored path is never read. The source's internal
`__utmpxname` is not exported.

## Focused evidence

`compat/x86_64/run_owned_utmpx.sh [--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`
is the focused runner. It rejects empty or ambiguous product arguments before
creating evidence, validates every supplied or freshly built product payload,
and compiles C11 and C++17 witnesses against both pinned musl headers and the
installed project headers. The witnesses use typed pointers for all seven
strong and nine weak declarations and retain unmangled C linkage.

The runner compiles `owned_utmpx_probe.c` exactly once through the installed
dynamic driver. An installed-header dependency audit records the driver,
manifest, source, object, and every header dependency. The unchanged object is
linked against the pinned static musl oracle and each selected owned product:
static and static-PIE when a static product is available, and dynamic PIE and
non-PIE through both kernel dispatch and the direct loader. Dynamic-only input
therefore reports only its supplied dynamic modes. Every owned link carries a
sealed receipt validated before execution, and raw stdout, stderr, and process
status are retained alongside the exact symbol multiplicity checks for the
archive, shared library, and final executables.

The probe checks same-address identity for all nine weak aliases. It calls each
strong and weak spelling with ordinary, null, and protected ignored inputs,
checks byte-for-byte preservation of caller records and errno, verifies both
name entries return `-1` with `ENOTSUP`, and retains the observed musl
`pututxline` call with errno initially zero. Every candidate stream must match
the pinned musl stream. The original preimplementation RED remains recorded at
`.work/x86_64/tmp/owned-utmpx.DSceUc`, where the installed-header workload
failed to link on the six original utmpx names; the expanded source-file slice
also covers the remaining aliases captured by the final provider checks.

`compat/x86_64/tests/test_owned_utmpx.py` covers argument ambiguity, product
containment, and the physical evidence-directory boundary without building a
product. This evidence does not claim a utmp database, login accounting,
runtime-family closure, or public x86 support.
