# Native syscall alias and interposition contract

`run_owned_syscall_alias_contract.sh STATIC_SYSROOT DYNAMIC_SYSROOT` checks the
native x86-64 linkage shape of fourteen musl 1.2.6 syscall-facing C entries.
It is a focused ELF and call-ownership regression, not a new capability,
product qualification, family-completion result, or public x86 support claim.

The source oracle is musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under musl's MIT license:
`src/time/clock_gettime.c`, `clock_nanosleep.c`, `src/unistd/dup3.c`,
`lseek.c`, `src/stat/fstat.c`, `fstatat.c`, `statvfs.c`,
`src/mman/{madvise,mmap,mprotect,munmap}.c`, `src/linux/sysinfo.c`, and
`src/signal/sigaction.c`. The implementation is kept beside the owning native
leaves: `clock_gettime.rs`, `clock_nanosleep.rs`, `descriptor_io.rs`,
`stat_compat.rs`, `filesystem_capacity.rs`, `memory_mapping.rs`,
`system_observation.rs`, and `signal_control.rs`.

Every ordinary spelling below is a `FUNC WEAK DEFAULT` same-definition alias.
The archive body is `FUNC GLOBAL HIDDEN` unless noted; the shared link
localizes it and omits it from `.dynsym`. Pinned musl records `LOCAL DEFAULT`
there, while the Rust link may retain `LOCAL HIDDEN`; the local binding,
dynamic-symbol absence, and identical defining section/value are the stable
boundary. `__statfs` and `__fstatfs` are source-local even in `libc.a`, so
their archive rows are `FUNC LOCAL DEFAULT` and they are not static export
ledger additions.

| Public weak alias | Internal body |
| --- | --- |
| `clock_gettime` | `__clock_gettime` |
| `clock_nanosleep` | `__clock_nanosleep` |
| `dup3` | `__dup3` |
| `fstat` | `__fstat` |
| `fstatat` | `__fstatat` |
| `fstatfs` | `__fstatfs` (local) |
| `lseek` | `__lseek` |
| `madvise` | `__madvise` |
| `mmap` | `__mmap` |
| `mprotect` | `__mprotect` |
| `munmap` | `__munmap` |
| `statfs` | `__statfs` (local) |
| `sysinfo` | `__lsysinfo` |
| `sigaction` | `__sigaction` |

`sigaction.c` also supplies `__libc_sigaction`: it is hidden/global in the
archive and local/non-dynamic in the shared result, with no public alias. Its
outer `__sigaction` body retains validation and selected SIGABRT serialization;
the raw body retains action conversion and the syscall.

## Shared-libc source-call policy

Pinned musl's `configure` adds `--dynamic-list=dynamic.list` to the `libc.so`
link through `LDFLAGS_ALL`; `Makefile` applies those flags only to the shared
libc link. `libc/src/c_abi/x86_64/owned_dynamic.list` is the byte-identical
musl 1.2.6 input (SHA-256
`264ae3bf630a7f6d894a51f91f9acae45b89a5f639537353d03af1a04e9da0f9`).
`scripts/build_x86_64_owned_dynamic_sysroot.py` checks its physical source,
hash, syntax, order, and membership, passes it only to the native `libc.so`
LLD invocation, and records both the selected categories and normalized final
link command in `share/crabc/libc-shared.provenance.json`.

The list has two deliberate categories. Its non-allocation names are public
data that remains interposable for copy relocations. `malloc`, `calloc`,
`realloc`, `free`, `memalign`, `posix_memalign`, `aligned_alloc`, and
`malloc_usable_size` are function exceptions for allocator interposition; they
are not data. The policy does not use `-Bsymbolic` or
`-Bsymbolic-functions`, does not change weak public alias metadata, and does
not apply to the loader, application DSOs, or static archives.

That link policy lets the source keep musl's public spellings in
`__fxstat`, `__fxstatat`, `ftime`, `getloadavg`, `sigignore`, `siginterrupt`,
and `sigset`. The archive paths remain available to a strong application
override. The shared link binds their ordinary libc calls locally. Selected
source callers that actually name `__clock_gettime`, `__lseek`, `__munmap`, or
`__sigaction` remain explicit hidden-body calls; the list never replaces those
ownership choices.

The runner compiles each normal/override probe once through the installed
headers and seals its source and object bytes. Every musl and candidate link
consumes that same object; the final reader rejects source recompilation,
substituted objects, incomplete links, or changed source/object bytes. It
compares pinned-musl static and shared references with owned static
ET_EXEC/static-PIE and owned shared PIE/non-PIE products, using both kernel
and direct-interpreter entry. The
normal probe reaches all fourteen public names. Its strong-override sibling
defines viable Linux implementations for all fourteen public names, so startup
and the selected C allocator can safely use an ordinary spelling before
`main`; counters prove that direct application calls reach those definitions.
For signal callers, the strong-override workload exercises `sigset` with
`SIG_HOLD` and with a viable replacement handler, captures and restores the
prior `SIGUSR1` action and mask, and observes exactly one public `sigaction`
call per branch in static/static-PIE and none in shared PIE/non-PIE. It also
requires the two source calls in `siginterrupt` to reach exactly two static
override calls and no shared override calls.

It distinguishes source and final-link ownership: legacy `__fxstat`,
`__fxstatat`, `ftime`, `getloadavg`, `sigignore`, `siginterrupt`, and both
`sigset` branches name public aliases in source and bind to an application
override from the archive, while the shared link's direct local resolution
reaches the defining libc body. Pinned static caller relocations name `fstat`,
`fstatat`, and `clock_gettime`; pinned shared disassembly directly branches to
local same-address bodies. `statvfs` and `fstatvfs` retain their local statfs bodies;
`sem_timedwait` reaches `__clock_gettime`; `signal` reaches `__sigaction`; and
selected tree search continues through hidden mapping bodies. The reader
rejects a forwarding body that merely shares an archive member and zero
`st_value` with an alias by also requiring the defining section and type.

Before those runtime cases, the runner invokes the pinned LLD from the supplied
product on a two-object PIC fixture. The preserved no-list control has an
`ordinary_local_call` PLT relocation (the focused RED). The checked list
removes that ordinary relocation while retaining `optind` `GLOB_DAT` and
`malloc` `JUMP_SLOT` relocations. The fixture never executes, so it observes
allocator interposition as ELF linkage only. It also rejects a supplied product
whose shared provenance does not bind the selected list and final libc link
command, then rejects a final `libc.so` that still dynamically relocates any
of the seven public-source caller paths.

Run it only in the pinned native image with supplied products below the
checkout's `.work` tree:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" \
  ./compat/x86_64/run_owned_syscall_alias_contract.sh \
  .work/x86_64/syscall-alias-contract/static-product \
  .work/x86_64/syscall-alias-contract/dynamic-product
```

The default static C-ABI export ledger includes these thirteen global-hidden
providers: `__clock_gettime`, `__clock_nanosleep`, `__dup3`, `__fstat`,
`__fstatat`, `__lseek`, `__madvise`, `__mmap`, `__mprotect`, `__munmap`,
`__lsysinfo`, `__sigaction`, and `__libc_sigaction`. The two local statfs
bodies remain outside that global export ledger.

The retained component pair was built at clean runtime revision `3bf0a0cb`.
The earlier harness revision `1494e97c` passes its complete signal-override
checks, but recompiles the oracle sources. Its 45-command receipt is
`.work/worktrees/syscall_alias_contract/.work/x86_64/syscall-alias-contract/sigset-override-proof-1494e97c.json`
relative to the main checkout. The corrected collector passes all 47 commands
with the two unchanged objects across all fourteen links. Parent verification
is retained at
`.work/worktrees/owned_posix_evidence_integration/.work/x86_64/syscall-integration/component-parent-review.json`.
It binds the corrected harness inputs separately from the runtime pair and
does not supply static preparation or product qualification for later source.

## Current component receipt

The historical pair is not selectable evidence: `1494e97c` is the older
45-command source-recompiling harness, while `3bf0a0cb` records the corrected
47-command runner against its then-current runtime pair. Neither establishes a
current selected static preparation, dynamic product, complete ELF facts, or
base inventory.

`owned_syscall_alias_contract_reader.py` supplies that current boundary. Run
`collect` only in the pinned core image, from a clean collector checkout, with
fresh output below its `.work/x86_64` tree. The static product must be the
`products/primary` payload beside the supplied preparation receipt. Full ELF
facts must bind the exact `libc.a` and `libc.so` bytes, and its base-inventory
binding must name the supplied inventory byte-for-byte.

```sh
CRABC_X86_SYSCALL_ALIAS_IMAGE_ID=crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d \
python3 -B compat/x86_64/owned_syscall_alias_contract_reader.py collect \
  --output "$PWD/.work/x86_64/syscall-alias-receipt/current" \
  --static-preparation "$PWD/.work/x86_64/public-data-products/static-a9c51887/preparation.json" \
  --static-product "$PWD/.work/x86_64/public-data-products/static-a9c51887/products/primary" \
  --dynamic-product "$PWD/.work/x86_64/loader-debug-abi/clean-a9c51887/component/dynamic-product" \
  --elf-facts "$PWD/.work/x86_64/native-abi-elf-facts/clean-a9c51887/report.json" \
  --base-inventory "$PWD/.work/x86_64/native-abi-inventory/clean-a9c51887/report.json" \
  --image-id crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d

python3 -B compat/x86_64/owned_syscall_alias_contract_reader.py validate-report \
  --report "$PWD/.work/x86_64/syscall-alias-receipt/current/report.json"
```

The current receipt schema is `crabc.x86_64-owned-syscall-alias-contract/v2`.
Version 1 reports cannot establish this boundary and must be recollected.
Collection retains the fixed 47 command envelopes, including complete argv,
45-second timeout argv, stdin bytes, working directory, scrubbed environment,
status, stdout and stderr. The two native source/ELF checks remain additional
predicates; they do not change the 47-command roster. The reader replays their
full checks, including application override exports, same-definition section
identity, public-call relocation absence, and the exact dynamic-list relocation
types and interposition scope.

`owned_syscall_alias_authority.py` binds observations to bytes outside the JSON
claims. Every symbol row (including archive member, table, index, section and
size) and every RELA row is compared with the retained ELF/archive bytes using
`loader_debug_abi_evidence.Elf`. Every candidate endpoint has an installed-driver link receipt. All four
static/static-PIE contract/override links request `--link-receipt` and retain
its JSON, LLD map and trace. Replay uses `crabc_cc_static`'s exact owned plan,
mode and six-input roster to bind the selected LLD, CRT, `libc.a`, builtins,
correct previously compiled probe object, and exact output bytes. The static
product owner's offline ELF parser requires the selected ET_EXEC/ET_DYN mode,
no interpreter, no `DT_NEEDED`, and no text relocations; a static PIE may have
`PT_DYNAMIC`. Each traced archive member must exist in the retained selected
archive. The map joins `_start`, `main` and every public alias to its actual
CRT/object/archive source, ELF address, size and binding. Mapped function bytes
must match their input bytes outside explicit x86 relocation fields and the
bounded GOT/TLS instruction relaxations emitted by the pinned linkers. Thus
substituting an oracle or dynamic output and resealing its receipt hash cannot
stand in for an owned static link.

The four dynamic final-link receipts bind the selected LLD, full command,
product inputs, correct probe objects, output bytes and link trace. The exact chroot roots contain the selected product
or musl runtime plus the corresponding linked probes and regular input. Host
replay does not execute a compiler, linker, ELF reader, Git, or any other command.

The collector and selected product are distinct source epochs. Deduplicated
loose Git commit/tree/blob objects under `source/git-objects/` authenticate both
complete source trees, including modes, and independently derive the source
content digest used by `owned_posix_static_products.source_identity`. Retained
source leaves must match those trees in bytes, logical placement and mode.
Collector leaves must additionally equal the validator's source-owned collector
files: a newly fabricated but internally consistent Git commit cannot replace
the harness authority. A changed collector requires a fresh component receipt.
Collection checks its clean source before and after execution; selected runtime
leaves must also match the supplied product revision. This allows a repaired
collector to inspect an older supplied product without calling that product
current selected evidence.

`owned-syscall-alias-image-inputs.json` is the finite image input authority. It
records invocation paths, resolved paths, modes, sizes and SHA-256 values for
the runner tools, product compiler/assembler/linker inputs, and pinned musl
wrapper/archive/shared/specs. Regenerate it reproducibly from the exact image:

```sh
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d \
  python3 -B compat/x86_64/owned_syscall_alias_authority.py \
  > .work/x86_64/syscall-image-inputs.json
cmp compat/x86_64/owned-syscall-alias-image-inputs.json \
  .work/x86_64/syscall-image-inputs.json
```

Collection compares this manifest with live inputs before and after use and
retains those inputs. Host replay compares the retained manifest with the
validator's source-owned manifest and verifies every retained tool against it;
mutually consistent report hashes are insufficient. The runner inherits only
`execution_environment` and does not inherit loader, Python, compiler, include,
or library overrides. The image reference remains an execution prerequisite;
this local receipt is retained execution evidence, not a signed remote
attestation or an independent proof of historical process scheduling.

`test_owned_syscall_alias_contract_reader.py` checks each argument of all 47
commands. Set `CRABC_SYSCALL_ALIAS_TEST_RECEIPT` to a freshly collected v2
`report.json` to run the isolated real-artifact round trip and adversarial
receipt mutations, including source/tool resealing, substituted ELF streams,
forged chroot routes, environments, stdin, link receipts, runtime inputs,
coordinated probe/copy mode changes, and a self-consistent invented Git commit.
The static endpoint regressions cover all four provider substitutions, output
hash resealing, changed probe inputs, invented archive members, forged linker
identity, and modified function code with a resealed output hash.
The test copies each receipt under checkout `.work`; it never changes the
original control. These tests explicitly report a skip when no native receipt
has been supplied.

The projection records fourteen aliases, twelve alias-target global-hidden
bodies plus private `__libc_sigaction` (thirteen global-hidden bodies total),
and two source-local statfs bodies. It is derived only after all retained
observations pass. This remains component evidence, never provider selection,
family qualification, runtime qualification, promotion or public support.

A later selector may retain this report's path and SHA-256 with an exact
`selection_projection` match after running `validate-report`. Its only
component discharge is the named fourteen-alias/private-body projection above;
the selector must keep full ELF facts as physical observations and join only
its explicit named artifact roles. This receipt neither constructs identities
from unnamed facts nor discharges the remaining private-body ownership
blockers.
