# Owned fixed-profile utmpx compatibility

The native owned runtime has a private complete `utmpx.c` compatibility leaf in
`libc/src/c_abi/x86_64/owned_utmpx.rs`. The x86 root selects it under
`x86-owned-static-runtime`; the owned dynamic product inherits the same owner. This is C ABI compatibility machinery for
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
is the focused runner. It rejects empty, ambiguous, or symlinked product
arguments before canonicalization and evidence creation, validates every
supplied or freshly built product payload,
and compiles C11 and C++17 witnesses against both pinned musl headers and the
source project headers. The witnesses use typed pointers for all seven strong
and nine weak declarations and retain unmangled C linkage; the ordinary
workload below is the installed-header proof.

The runner compiles `owned_utmpx_probe.c` exactly once through the installed
dynamic driver. An installed-header dependency audit records the driver,
manifest, source, object, and every header dependency. The unchanged object is
linked against the pinned static musl oracle and each selected owned product:
static and static-PIE when a static product is available, and dynamic PIE and
non-PIE through both kernel dispatch and the direct loader. Dynamic-only input
therefore reports only its supplied dynamic modes. Every owned link carries a
sealed receipt validated before execution, and raw stdout, stderr, and process
status are retained alongside exact provider/alias checks for the archive,
shared library, and static final executables. Dynamic final executables retain
their complete ELF rows and must import all sixteen public names from the
shared library; they do not define those providers themselves.

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

The `owned-utmpx` dispatcher accepts the existing physical static/dynamic
product replay paths. The `utmpx` case is mandatory in every dynamic product
qualification. The owned-static callable roster accounts for all sixteen
public names and the eight explicit same-address alias relationships;
`utmpname` is itself the weak Rust provider for the shared name-rejection body.

## Retained receipt boundary

`compat/x86_64/owned_utmpx_receipt.py` adds a component-only receipt around the
existing runner. It does not select aliases, change the runtime, or turn the
historical RED into qualification. The collector has a deliberately narrow
interface:

```text
python3 -B compat/x86_64/owned_utmpx_receipt.py collect \
  --static-preparation /workspace/.work/.../static/preparation.json \
  --static-product /workspace/.work/.../static \
  --dynamic-product /workspace/.work/.../dynamic \
  --output /workspace/.work/.../owned-utmpx-receipt
```

It is invoked only from the pinned native `/workspace` mount. The image is the
fixed `crabc-core-evidence@sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d`.
`owned_utmpx_current_image_inputs.json` is a finite generated manifest of that image's
runner commands, compiler support programs, musl oracle inputs, Rust compiler,
and LLD. The older image's `owned_utmpx_image_inputs.json` remains frozen.
Collection regenerates the current manifest inside the exact image before
and after the runner; the collector refuses a mismatch. It also refuses a
dirty source revision, same or symlinked product inputs, a static preparation
outside the physical checkout work tree, a pre-existing private evidence leaf,
or a runner that does not execute the full supplied static/static-PIE and
dynamic PIE/non-PIE matrix. The ordinary
`run_owned_utmpx.sh` lifecycle remains unchanged. Collection sets its private
`CRABC_X86_64_RETAIN_UTMPX_COMMANDS=1` switch, which rejects every other value
before evidence creation and uses a fixed private receipt leaf only for this
mode. If that native runner fails, collection preserves only its raw stdout,
stderr, and status as a `native-runner-failure` diagnostic below the fresh
output; it does not create a receipt report or imply replayable evidence.

The receipt copies the exact selected source and runner inputs; the static
preparation plus its before/after whole-source seals; both complete product
trees, manifests, and the dynamic materialization state; command programs and
linker; installed-driver object/dependency record; sealed-link receipts and
sidecars; raw archive/shared/final-executable ELF symbol streams (and the
static-final provider renderings); retained C/C++
header-witness objects and their source-hash input file; and every raw
oracle/candidate process stream. The preparation primary tree must equal the
copied static tree and its full source digest must equal the materialized
dynamic state digest, so static and dynamic products form one exact current
source cohort. Command roles are a closed roster, with reconstructed
installed-driver, musl link, owned static/static-PIE, dynamic PIE/non-PIE,
symbol, sealed-link, and runtime envelopes. In retained mode collection starts
the runner with only its fixed image `PATH`, private `TMPDIR`, and retention
switch; each command child then receives exactly the sealed `PATH`, `TMPDIR`,
switch, `SHLVL=0`, and Bash-resolved program `_` entry. The command/v2 record
contains that full environment, its complete argv, cwd, and resolved program.
The twelve inline Python judges retain their stdin source as physical 0644
files. Host replay admits those bytes only when they match the reader's fixed
per-role digest and size, so repairing a receipt-side stdin identity cannot
authorize a different judge. A report's status, counts, product digests, or
projection cannot substitute for those bytes.

`validate-report RECEIPT/report.json` is public host replay. It executes no
command. It admits only the exact committed collector/source epoch: it reads
the trusted local checkout HEAD without invoking Git, verifies each retained
source blob and mode against both the captured tree and the trusted local
checkout. The collector epoch remains distinct from the selected static/dynamic
product cohort: the static preparation's source revision and whole-source hash
are retained with its before/after seals, and the dynamic materialization state
must name that same whole-source hash. It requires every command record's
program to be the executable
named by its exact argv, and admits that program only when its retained bytes
equal the trusted immutable-image manifest or its copied owned product bytes. It then
rehashes product trees, manifests, materialization state, object/dependency
records, and raw streams; reconstructs every retained
archive/shared/final `readelf` symbol row from the actual ELF or ar bytes;
cross-checks every selected archive/static-final `nm` provider address,
binding, and archive-member domain against those reconstructed rows; uses the
existing bounded retained-link parser on all four copied links; and for the
two static links re-derives every traced object/member from copied product
bytes before joining `main`, `_start`, seven global providers, and nine weak
providers to their fully relocated final ELF bytes. That last finite map and
relocation proof uses the reviewed
`compat/x86_64/owned_static_link_authority.py` revision from commit
`f76844d9fb49465691b88ad4ebb76e1e3b2b04b4` (SHA-256
`2d5143260e9105dd08fd8c2610a741a0c5c5f0791159bb4e4f6f385dcfa8eafe`).
That reviewed helper admits TLS-free static links only when selected inputs and
the final ELF have no TLS geometry to prove, and proves the exact RuntimeV1
weak-descriptor zero-GOT absence form, and joins an undefined hidden target to
its sibling archive-member definition. Those generic static-link authority
checks also prove a selected hidden merged constant's final placement.
They do not add utmpx semantics; the utmpx reader still admits the exact
shared source byte and derives its eight-alias component projection itself.

The same source roster admits the exact
`compat/x86_64/owned_posix_product_evidence.py` mode boundary from commit
`aa8345d3a4f1352284aad11ab1b3b1341b522056` (SHA-256
`b43a58a70bbcb71d33b20c28be9b32fbd5e8b51e6cac7f7cab2ec97b8a9f2c41).
Before any retained link receipt is read, its product validator requires the
raw physical modes for every link input: static `crt1.o`, `rcrt1.o`, `crti.o`,
`crtn.o`, `libc.a`, and `libcrabc-builtins.a` are `0644`; dynamic `crt1.o`,
`Scrt1.o`, `crti.o`, `crtn.o`, `crabc-dynamic-attach.o`, and
`libcrabc-builtins.a` are `0644`, while dynamic `libc.so` is `0755`. These
values come from the collector source policy, not a retained tree or manifest
row that a forged receipt can rewrite. The paired dynamic producer source
explicitly materializes its shared library and attachment object at those
modes before packaging.
The projection explicitly remains component complete only; family completion,
runtime qualification, and public support remain false.
