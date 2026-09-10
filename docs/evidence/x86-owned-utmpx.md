# Owned fixed-profile utmpx stubs

The native owned runtime has a private six-entry utmpx compatibility leaf in
`libc/src/c_abi/x86_64/owned_utmpx.rs`. It is selected only when the x86 root
registers that module under `x86-owned-static-runtime`; the owned dynamic
product inherits the same owner. This is C ABI compatibility machinery for
musl's deliberately inert utmpx profile. It does not open files, retain a
cursor, own records, allocate memory, publish errno, or import the paused
AArch64 database implementation.

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
| `src/legacy/utmpx.c::getutxent` | `owned_utmpx::getutxent` |
| `src/legacy/utmpx.c::getutxid` | `owned_utmpx::getutxid` |
| `src/legacy/utmpx.c::getutxline` | `owned_utmpx::getutxline` |
| `src/legacy/utmpx.c::pututxline` | `owned_utmpx::pututxline` |
| `src/legacy/utmpx.c::setutxent` | `owned_utmpx::setutxent` |

The two cursor controls are empty functions. `getutxent`, `getutxid`,
`getutxline`, and `pututxline` return a null `struct utmpx *`. Query and
record pointers are intentionally ignored, and all six entries leave the
caller's errno unchanged. The Rust owner uses an ABI-equivalent opaque pointer
type so it cannot imply a record layout or database state.

The slice deliberately excludes `endutent`, `getutent`, `getutid`,
`getutline`, `pututline`, `setutent`, `updwtmp`, `updwtmpx`, `utmpname`, and
`utmpxname`; those aliases and file/database operations are outside this
bounded owner.

## Focused evidence

`compat/x86_64/run_owned_utmpx.sh [DYNAMIC_SYSROOT]` is the focused runner.
The normal dispatcher registration is owned by the x86 integration root. The
runner first compiles C11 and C++17 witnesses from
`owned_utmpx_header_abi_probe.c` and `owned_utmpx_header_abi_probe.cpp` against
both the pinned musl headers and the installed project header. Their typed
function pointers prove all six declarations and their C++ references retain
unmangled C linkage.

It then compiles `owned_utmpx_probe.c` exactly once through the installed
dynamic driver. That unchanged object links against the pinned static musl
oracle and the owned static, static-PIE, dynamic PIE, and dynamic non-PIE
products. Each dynamic executable runs once through its kernel-selected
interpreter and once through the direct `/lib/ld-crabc-x86_64.so.1` entry, for
six owned executions plus the musl oracle. The runner checks the six-symbol
set as one artifact boundary rather than creating per-symbol gates.

The probe seeds errno with `EDOM`, verifies null results for all four record
operations, verifies that a caller-owned `struct utmpx` remains byte-for-byte
unchanged, and checks that both cursor controls also preserve errno. A second
`pututxline` call starts with errno zero and records musl's deliberately
observed zero result. Every candidate stdout and stderr stream must match
musl. The initial regression is
the same installed-header object failing to link against the unregistered
owned products with six undefined utmpx symbols.

`compat/x86_64/tests/test_owned_utmpx.py` covers the runner's argument and
physical evidence-directory boundaries without building a product. This
evidence proves only the six inert entries; it does not claim a utmp database,
login accounting, broader legacy aliases, runtime-family closure, or public
x86 support.
