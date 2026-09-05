# Owned native libc-test aggregate

`run_owned_libc_test.sh DYNAMIC_SYSROOT` executes the finite pinned
[`libc-test`](../upstreams.toml) source graph against one materialized owned
x86-64 dynamic product. It is a private foundation observation: a successful
leaf would establish neither dynamic-product completion nor public support.
The leaf requires a product below the checkout's `.work/` tree and a
root-capable native evidence container because every runtime observation uses
an isolated chroot.

The final `libc-test.json` is published in the leaf directory even when an
input, compile, link, or runtime phase fails. The leaf exits zero only when
all required source-graph phases pass. Its schema is
`crabc.x86_64-owned-libc-test/v1`; `campaign_complete` and `public_support`
remain false in every result.

## Pinned source and finite graph

The runner reads `[libc_test]` from `compat/upstreams.toml`, checks out the
exact detached revision below `.work/x86_64/source-oracles/`, verifies its
clean HEAD and tree, and copies every tracked regular file to its evidence
leaf. It builds the graph from that staged source, with exact count checks:

| Source edge | Count |
| --- | ---: |
| `functional` runtime executable | 74 |
| `math` runtime executable | 199 |
| `regression` runtime executable | 68 |
| `api` compile-only source | 79 |
| Source-defined DSO support object | 4 |
| `common` source, including `runtest` | 10 |
| Total declared units | 434 |

The 29 `src/math/gen/*.c` generator sources are not runtime targets in the
upstream Makefile. `src/musl/pleval.c` is also excluded because its upstream
`.mk` file suppresses the non-public `__pleval` dynamic test. Those exclusions
are retained by name in `inventory.exclusions`; a source-roster change fails
rather than silently changing the campaign.

`src/api/unistd.c` is the sole prepared-source change. The runner surrounds
its `_PC_TIMESTAMP_RESOLUTION` and `_SC_XOPEN_UUCP` probes with their exact
`#ifdef` guards. The staged original and prepared bytes, each replacement, and
its occurrence count are recorded. This makes the upstream API test work with
the installed header profile without defining or inventing either option.

The runner reproduces upstream `options.h` generation from
`src/common/options.h.in` with the installed compiler and headers. Each source
also receives an independent `-H` header trace under `-nostdinc`; traced headers
must come from the installed product, staged source, or this generated header.
A host header is a retained header-translation failure.

## Translation, linking, and runtime sides

Before compilation, the aggregate validates the supplied product's manifest,
every payload hash, and every alias. It copies that complete product into the
evidence leaf and validates the copy against the same complete map. All
compiler, linker, header, and candidate-runtime uses consume only the copied
product. `product.source.before`, `after_copy`, and `after_use`, together with
`product.copied.before` and `after_use`, retain the manifest, full payload map,
and alias map. A mutation cannot switch the product being measured midway.

Every source compiles through the copied installed
`bin/crabc-cc-dynamic`. The aggregate uses only its declared source inputs:
quoted `src/common`, generated API options, `-frounding-math`, `-rdynamic` for
the upstream `dlopen` target, and uncompressed debug information. If an
installed driver lacks one of those required source edges, the runner records
the exact unattempted command as blocked after preserving the header trace; it
does not generate a large set of identical rejected invocations.

`product.compiler` identifies the selected compiler by path and hash;
`product.compiler_helper` and `product.compiler_environment` retain the exact
helper and clean environment used for headers and translation. Each candidate
link is receipt-checked against the copied product manifest:
its direct objects and declared application DSOs are hashed, its runtime input
roster and LLD trace are closed, and ELF interpreter, NEEDED, RELRO and text
relocation properties are retained. The raw side links the **same installed-
driver object bytes** with only pinned musl 1.2.6. It is an oracle link, never
an ambient runtime fallback. `oracle.before` and `oracle.after` use the shared
native-qualification identity checker to bind the pinned compiler wrapper,
specs, source/specification manifests, headers, loader, and libc by path and
hash, and reject a change during the aggregate. ELF observations for both
sides remain in the leaf.

The four source-defined DSO roles come directly from the upstream `.mk` files:
`functional/dlopen_dso`, `functional/tls_align_dso`,
`functional/tls_init_dso`, and `regression/tls_get_new-dtv_dso`. The runner
keeps their initial-link, `dlopen`, `$ORIGIN`, and executable-export topology
with the associated runtime target. `common/runtest` is its own executable;
the upstream `libtest.a` input is exactly the other nine `common` members, so
a test target never acquires a second `main` from the runner.

For every runtime unit, raw musl and candidate each receive a fresh root. The
candidate root comes from the retained copied product; the raw root contains
only pinned musl's loader and `libc.so`. Both receive private `/tmp`,
`/dev/null`, and `/dev/zero` plus the runner, test binary, and declared DSO
payload. Four source-audited exceptions add no broader host topology:
`functional/sem_open`, `functional/pthread_cancel-points`, and
`regression/sem_close-unmap` receive an empty mode-01777 `/dev/shm` for musl's
named-semaphore and shared-memory backing; `regression/tls_get_new-dtv`
receives only `/proc`, `/proc/self`, and
`/proc/self/exe -> /regression/tls_get_new-dtv`. Musl 1.2.6 reads that
kernel-entry link while expanding the target's source-selected `$ORIGIN`
runpath. The runner does not mount `/proc`, emulate any other procfs node, or
share those roots between units. The raw root records the actual copied loader
and libc hashes before it is reclaimed.

The four upstream shell-dependent targets receive a declared control fixture.
It copies the pinned-image BusyBox and the exact pinned-musl oracle loader to `/control/busybox` and
`/control/ld-musl-x86_64.so.1`. A small launcher is translated once through
the installed driver, linked from that same object against candidate and raw
musl separately, and installed as the side-specific `/bin/sh`. The launcher
execves the control loader with BusyBox `sh` and the original arguments. This
keeps the candidate product's `/lib/ld-musl-x86_64.so.1` alias intact; the
control closure is fixture input, never a candidate provider or an extra
libc-test unit.

`functional/spawn` separately receives an `external_echo_fixture`: its source
calls `posix_spawnp("echo", ...)`, so each side gets its own installed-driver
`/bin/echo` launcher. That launcher enters the same pinned BusyBox and musl
control closure with the explicit `echo` applet. Its source, installed-driver
object, header trace, and candidate/raw links are retained independently from
the shell fixture. Neither fixture admits a host executable or changes a
candidate loader alias.

Before and after each execution, the runner writes a retained
`execution/<unit>/<side>.root-payload-{before,after}.json`. Each phase binds
the copied candidate payload and aliases, or the copied raw loader/libc,
along with the declared programs and controls. Its sorted
`filesystem_fixture` roster binds every source-selected directory mode or
literal symlink target before and after execution; fixture-owned directories
reject undeclared children. The runtime record exposes the two phase artifacts
as `root_payload.before` and `root_payload.after`, with `unchanged: true`,
before the private root is reclaimed. No target link or runtime root obtains a
host libc, CRT, loader, header, or general procfs view.

Execution uses upstream `src/common/runtest.c` through its normal Makefile
form, `/runtest -w '' TARGET`: the explicit empty `-w` preserves the empty
`RUN_WRAP` argument, and no `-t` override is supplied, so the source default
is five seconds. It forks, sets the child's `RLIMIT_STACK` to its
source-defined `100 * 1024` bytes, then execs the target. The report records
those source facts under `source_graph.runtest`; changing either value would no
longer test the upstream graph. The host's outer timeout only bounds a stuck
private control process; it is not a runtest timeout. Each side retains command,
environment, exit status, stdout and stderr in
`execution/<unit>/<side>.status.json` before its private root is reclaimed.
The report binds that immutable sidecar and the retained payload phases, so it
never points at the reclaimed root.

The upstream graph selects normal installed dynamic PIE binaries entered by
the kernel through PT_INTERP. It does not select a non-PIE or direct-loader
corpus. The separate 50-case
[owned dynamic-product qualification](dynamic-product-qualification.md) owns
all-entry product coverage; this source graph does not weaken that product
contract.

A common candidate toolchain failure caused by compressed DWARF is retained at
its first real link. Only later candidate links blocked by that same observed
limitation are marked unattempted; raw links and all unrelated observations
continue. Ordinary missing providers and runtime failures remain per-unit
results.

## Reading a result

A unit has independent `header_translation`, `candidate_translation`,
`candidate_link`, `oracle_link`, and `runtime` records. `api` units are
compilation-only by the upstream source graph; helper DSOs and the nine archive
members have the explicitly recorded non-runtime edges. Runtime results compare
raw and candidate exit status, stdout, and stderr byte for byte only after both
sides pass their own prepared root.

The report's counts are a current measurement. A non-passing result names the
failed or blocked boundary and retains its exact command and bytes for the
owner; it does not convert that unit into a skip or a supported capability.

## Source-required execution identity

`regression/pthread_atfork-errno-clobber` sets `RLIMIT_NPROC` to zero and
requires `fork` to fail before checking that atfork callbacks preserve its
error. A root identity bypasses that limit. This one source therefore selects
the fixed nonroot identity in `execution_identity_fixture_for_unit`: UID/GID
65534, no supplementary groups, and zero inheritable, permitted, effective,
and ambient capabilities. Other units declare a null identity fixture. This
is an execution precondition; the source, runner, expected result, and
comparison remain unchanged.

The host-only `owned_libc_test_identity.py` accepts only that unit and has no
caller-selectable identity or target command. Both candidate and oracle use
`/usr/bin/timeout 20 /usr/bin/python3 -B HELPER --root ROOT --receipt RECEIPT
--unit regression/pthread_atfork-errno-clobber`. The helper opens its evidence
and `/proc/self/status` descriptors, enters the disposable root, clears
supplementary groups, and sets all real/effective/saved IDs. It checks the
actual IDs, including filesystem IDs, and capability sets through the
preopened proc descriptor. Its capability bounding set must remain unchanged.
After closing those descriptors it replaces itself with exactly
`/runtest -w '' /regression/pthread_atfork-errno-clobber` in the existing clean
environment. Neither helper nor host Python is copied into the execution root.

Every observed runtime side carries `execution_identity`: null for ordinary
units, or the fixed fixture, helper/Python source and retained artifact hashes,
prepared-source before/after binding, identity receipt, and unchanged producer
parent identity for this source. Control bytes remain in `execution-controls`
so an independent collector can verify them without using its host Python
installation. The helper/Python `source` and `after` artifacts must agree, as
must their retained bytes. Both root-payload phases also declare the exact
`execution_identity_fixture` or null. The child receipt measures the transition
immediately before exec; it makes no claim about identity after target
execution. Existing product, oracle, and root-payload before/after checks
still apply. Missing or invalid identity evidence is a setup failure, even
when a child reports exit zero.

The isolated proof reused the unchanged full-campaign target and `runtest`
binaries: root candidate and musl both failed with `fork succeeded despite
rlimit`; the fixed nonroot identity made both pass with empty stdout/stderr.
The producer's focused native replay also passes on both sides. This evidence
does not rewrite the earlier incomplete aggregate or replace a fresh full
campaign after producer/collector integration. Focused receipt and invocation
regressions live in `test_owned_libc_test_identity.py`.
