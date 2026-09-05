# Proposed owned POSIX runtime family contract

This document defines the remaining evidence needed to promote
`libc.posix-runtime` in `compat/x86_64/parity.toml`. It covers the **entire**
selected family: nine frozen AArch64 semantic capabilities and 149 exact C
spellings. The machine-readable roster is
[`owned-posix-runtime-catalog.toml`](owned-posix-runtime-catalog.toml).

Run `python3 -B compat/x86_64/owned_posix_runtime_catalog.py --check` to
validate the exact frozen spelling roster, required workload bindings, physical
source paths, and all six static and twelve dynamic product cells. This
structural judge does not validate the descriptive evidence references as
executed runtime proof.

It is a proposal and gap report, not a completion record. The ledger remains
`status = "planned"`; no focused runner, selected export, private static leaf,
installed product, or qualified dynamic leaf is reclassified by adding this
document. The frozen AArch64 comparison target remains unchanged.

## Evidence terms

The existing work uses similar words for importantly different facts. This
contract uses them as follows.

| Term | Required fact |
| --- | --- |
| **Private static leaf** | A source module or opt-in archive can compile and has its own focused proof. It does not prove the installed `libc.a`, CRT/startup, allocator, errno/TLS, pthread, loader, or other runtime-state composition. |
| **Installed static** | A public C workload is compiled with installed crabc headers and linked by the owned static driver as both ordinary static `ET_EXEC` and static PIE. |
| **Extracted static** | That workload is built and run from an extracted copy of the packaged static sysroot. It is an additional product result, not a receipt inherited from the original sysroot. |
| **Installed dynamic** | A public C workload runs against the installed shared libc and interpreter as dynamic PIE and dynamic non-PIE, through both normal `PT_INTERP` resolution and direct interpreter entry. |
| **Three-product dynamic result** | The registered dynamic qualification case passed for `installed`, `second`, and `extracted` products. It only covers the case named in `owned_dynamic_qualification.py`. |
| **Header-absent ABI entry** | Installed project headers remain the source of public types, records, and declarations. A frozen ABI spelling deliberately absent from those headers may use an exact local `extern` declaration, source-verified against the installed header types. This admits `__xstat`, `__lxstat`, `__fxstat`, and `__fxstatat`; it does not add declarations to `sys/stat.h`. |

A provider symbol table, a source leaf, a static-only observation, and a
passing dynamic case prove different boundaries. The catalog records each
rather than allowing an installed result to stand in for extraction or a
private leaf to stand in for runtime composition.

## Frozen surface and current binding

The catalog is the proposed coordinator's spelling roster. The frozen ledger
remains authoritative; the catalog copies each capability's exact `symbols`
list from `compat/crabc-rs/coverage.toml`. The following table is a readable
binding and gap summary.

| Frozen capability | Names | Current installed binding | Current gap |
| --- | ---: | --- | --- |
| `filesystem.lchmod-unsupported` | 1 | `owned-posix-filesystem` runs `lchmod` with the other filesystem spellings from one installed-header object through static/static-PIE and dynamic PIE/non-PIE kernel/direct entries. `filesystem-mechanisms` remains its earlier focused case, and `posix-filesystem` registers the dynamic replay for installed, second, and extracted products. | Neither focused case supplies the coordinator's primary/reproduction/extracted static cells or a family receipt. |
| `filesystem.stat-compat` | 4 | `owned-posix-filesystem` supplies the source-verified local `extern` declarations over installed `sys/stat.h` types and runs all four version-insensitive aliases, including dirfd-relative and `AT_SYMLINK_NOFOLLOW` paths, through its installed linkage matrix and registered dynamic replay. | No coordinator-owned six-static/twelve-dynamic receipt binds this group to the family. |
| `filesystem.directory` | 7 | `owned-posix-filesystem` runs every name, including `readdir_r` end storage, `telldir`/`seekdir`, both comparators, `scandir`, and `ftw`/`nftw` callback/cancellation transcripts, through its same-object installed matrix and registered dynamic replay. The older extracted static consumer remains supporting evidence. | The focused result does not provide the coordinator's primary/reproduction/extracted static cells or family receipt. |
| `filesystem.extensions` | 5 | `owned-posix-filesystem` selects and exercises `mktemp`, both temporary-name functions, and both file-handle entries. Its matched transcript retains raw handle return/`errno` values so filesystem support or authority cannot hide a difference. | The default archive boundary remains distinct, and no focused run is the coordinator's complete static/dynamic family receipt. |
| `process.control` | 44 | `owned-process-control` covers the 31 residual exec, priority, group/session, wait, and spawn-attribute names from one installed-header object. `process-trio`, dynamic `fork`, and `spawn`/its seven file actions supply the other 13 names of the exact 44-name composite. The residual case records its stated direct-`execveat` `fexecve` difference rather than calling it generic musl parity. | The composite still needs the coordinator to retain its reused cases across six static and twelve dynamic cells; the bounded composition runner is not a complete control-family receipt. |
| `process.credentials` | 9 | `owned-credentials-profile` runs all nine setters in isolated mapped user-namespace children with raw status/`errno` and real/effective/saved-ID transcripts. It preserves the selected four-alias `-1`/`EOPNOTSUPP` no-mutation profile and caller-coordinated direct setters; `credentials-profile` registers its dynamic replay. | No static reproduction/extraction or full-family aggregate exists, and this evidence does not claim an all-thread credential rendezvous. |
| `process.environment-mutation` | 3 | `owned-environment-lifecycle` covers replacement, removal, clear, allocation failure, direct-`environ`/borrowed-value boundaries, and fork/exec/spawn observations from one object. `owned-posix-composition` additionally covers caller-serialized environment state with signals, `FILE`, syslog, fork, exec, spawn, and cancellation cleanup. | The source's synchronization, signal, fork, direct-`environ`, and borrowed-pointer obligations remain caller boundaries; neither focused runner supplies the coordinator receipt. |
| `process.signal` | 34 | `signal-full` supplies the 23 residual primary spellings through static/static-PIE and dynamic PIE/non-PIE kernel/direct entries, while `owned-posix-signals.toml` names the helper/reporting, wait-cancellation, pthread, and timer cases it reuses. `owned-posix-composition` adds one bounded multi-threaded signal/`FILE`/syslog/fork/exec/spawn scenario. | The exact owner map and bounded composition scenario still need a coordinator receipt across the required cells; they do not complete the signal family. |
| `system.kernel-admin` | 42 | `linux-control` covers 18 names, `syslog` covers five, `system-cancellation` covers `system`, and `kernel-residual` runs the remaining 18 spellings from one installed-driver object. `owned-posix-composition` supplies a bounded logger/`FILE`/signal/fork state scenario. `gethostid.rs` retains its private constant-zero artifact matching musl. | The separate workload receipts and bounded composition scenario are not a 42-name coordinator result. The private `static-c-gethostid` artifact remains evidence under `libc.c-abi-compat`, not a competing provider. |

All seven catalog workload identifiers now have source-bound focused runners:
`posix-filesystem` for `legacy-filesystem`, `process-control` for
`control-residual`, `credentials-profile`, `environment-lifecycle`,
`signal-full`, `kernel-residual`, and `posix-composition` for
`global-state-composition`. Existing `process-trio`, `spawn`,
`signal-helpers`, `linux-control`, `syslog`, `filesystem-mechanisms`, and
`system-cancellation` cases remain named reusable inputs; no new equivalent
fixture replaces their retained objects, receipts, raw streams, or source
identity checks.

`dynamic-product.toml` now declares fifty required dynamic qualification
cases. The focused cases and supplied-product replays are inputs to a new full
dynamic aggregate that still must execute and retain all fifty cases for the
required products. No individual dynamic case, including a three-product
replay, is that aggregate.

The family coordinator itself remains unimplemented. It must combine the
focused and reused inputs into its six static cells and twelve dynamic cells,
with one family receipt. Nothing in these current bindings closes
`libc.posix-runtime`, promotes a product, or changes public x86 support.

### Registered dynamic signal audit

The later `signal-full` case closes the residual spelling workload described in
[`owned-posix-signals.md`](owned-posix-signals.md). Its explicit reuse map keeps
the following original audit as the evidence boundary for existing cases.

All registered `CASES` runners were inspected before recording the signal gap.
The original audit found twelve runners compiling consumers that directly call
frozen signal spellings:
`pthread-signal`, `posix-timers`, `pthread-scheduling`, `signal-helpers`,
`fcntl`, `io-cancellation`, `system-cancellation`, `spawn`, `linux-control`,
`legacy-time`, `process-trio`, and `pty`. A call used only to prepare another
scenario is supporting evidence, not a claim that it proves the called API's
complete contract.

| Cases | Positive signal evidence | Supporting use retained without overclaim |
| --- | --- | --- |
| `signal-helpers` | `__sysv_signal`, `bsd_signal`, `psiginfo`, `psignal`, `sighold`, `sigignore`, `sigrelse`, and `sigset`; it also checks alias binding, action/mask behavior, `raise`, and reporting stream state. | `signal` itself is checked as an alias binding rather than independently exercised as a separate behavior. |
| `io-cancellation` | `sigtimedwait`, `sigwaitinfo`, and `sigwait` under pending, interrupted, and cancellation states, with `sigqueue`, `sigaction`, and signal-set operations supplying checked setup and recovery. | None: the case is the dedicated wait/cancellation proof. |
| `pthread-signal` and `posix-timers` | Worker delivery and timer delivery actively use `sigtimedwait`, `sigaction`, and signal-set operations. | Their signal operations are part of pthread/timer contracts, so they do not establish every C signal API. |
| `spawn`, `system-cancellation`, `legacy-time`, `pthread-scheduling`, `fcntl`, `linux-control`, `process-trio`, and `pty` | Their retained same-object scenarios exercise masks, actions, defaults, waits, or delivery where stated by their owning cases. | These calls do not create a per-spelling signal receipt and are not counted as complete behavior evidence for every callee. |

## Required family coordinator

Add one coordinator for this catalog after the implementation gaps are closed.
It may dispatch existing focused runners, but it must own the finite capability
map, the product matrix, and the family receipt. The coordinator must:

1. Compile each C workload with the selected installed crabc driver and
   its installed project headers, retain that exact object, then link the same
   object to the pinned-musl reference and each candidate product. Independent
   product runs may repeat compilation, but the coordinator must check that
   the compared workload objects have identical bytes. It must
   inspect header dependencies and retain candidate link receipts as the
   existing owned-product runners do. For a frozen ABI spelling deliberately
   absent from an installed header, the workload may provide only the exact
   local `extern` declaration already source-verified against those headers;
   it must not widen a public header to make the test compile.
2. Run the reference and candidate in disposable roots. For each subcase,
   retain and compare raw exit status, stdout, stderr, and errno observations.
   A success-only smoke result, `nm` result, or an independently recompiled
   candidate object is insufficient.
3. Run every workload in two independently built static products as ordinary
   static and static PIE, then from the extracted static package in both modes.
   Static extraction cannot be implied by the current dynamic extraction pass.
4. Reuse the installed, second, and extracted dynamic products. For
   dynamic PIE and non-PIE, run normal kernel interpreter resolution and direct
   installed-interpreter entry. The dynamic receipt must identify every reused
   case by its `owned_dynamic_qualification.py` case name and add the new
   workloads where no case presently exists.
5. Seal source revision, musl identity, installed-artifact identity, workload
   object digest, link receipts, ELF/interpreter inspection, product label,
   raw streams, and fixture-node metadata in the family receipt. Fail when any
   required capability spelling, product, linkage mode, entry mode, or raw
   comparison is absent.

The coordinator must not invoke AArch64 work. It uses the frozen AArch64
harness contracts only as the required shape of native evidence.

## Current workload bindings and required behavior

The catalog's seven workload identifiers now each have a focused source-bound
runner. Their `product_matrix = "all"` contract remains a coordinator
obligation: the runner column records current evidence, while the required
behavior remains the acceptance contract for a family receipt.

| Workload | Current focused runner | Required behavior |
| --- | --- | --- |
| `legacy-filesystem` | `owned-posix-filesystem` | Invoke `lchmod`; all four versioned stat aliases; all directory names; and all extension names. Cover ignored version words, pathname/descriptor forms, callback ordering, allocation/cancellation where source requires it, errno, and authority-bearing file-handle negative paths. |
| `control-residual` | `owned-process-control`; `process-trio`, `fork`, and `spawn` retain the other 13 composite names | Use child processes for every exec alias; cover `nice`, group/session setters, every wait variant, and all spawn-attribute getters/setters, initialization/destruction, invalid values, and rollback. Existing `process-trio` and `spawn` cases remain the implementations for their already covered subcases. |
| `credentials-profile` | `owned-credentials-profile` | In a disposable user namespace, test the selected profile rather than inventing a rendezvous: `seteuid`, `setegid`, `setreuid`, and `setregid` must return `-1`/`EOPNOTSUPP` while real/effective/saved IDs remain unchanged. Exercise `setresuid`, `setresgid`, `setuid`, `setgid`, and `setgroups` as caller-coordinated direct Linux setters, including no-change and rejected inputs, with any other application workers quiesced by the caller. Isolate each mutation in a child namespace process. |
| `environment-lifecycle` | `owned-environment-lifecycle` | Cover replacement, removal, clear, allocation failure, direct `environ` ownership boundaries, and parent/child observations through fork, exec, and spawn. Live workers must obey the source's caller synchronization and borrowed-pointer lifetime obligations; concurrent environment mutation outside that contract is not a valid differential. |
| `signal-full` | `owned-posix-signals` plus named reused cases | Cover all 34 spellings through disposition, masks, pending signals, queueing, waits, alt stack, realtime limits, reporting, and signalfd. Preserve the error ordering and errno checks already modeled by the static consumer and existing helper case. |
| `kernel-residual` | `owned-kernel-residual` alongside `linux-control`, `syslog`, and `system-cancellation` | Cover every selected kernel-admin spelling outside the present `linux-control`, `syslog`, and `system-cancellation` cases. Privileged calls may use a contained negative-path differential where that is musl's observable contract; the test still has to invoke the exact public entry with valid pointer/lifetime conditions. `gethostid` must retain its existing fixed-zero musl mapping and header-visibility contract when it joins the installed workload. |
| `global-state-composition` | `owned-posix-composition` | In a multi-threaded process, establish environment mutation, signal disposition and per-thread masks, a live `FILE` stream, and syslog state; then fork, exec, and spawn. Compare parent, worker, and child results with musl, including state after the child exits and cancellation/lock-sensitive paths. This is the proof that these separate leaves compose under the runtime rather than merely exporting together. |

The credential row is a blocking contract for the governing selected
profile. Closing `process.credentials` requires an installed-product proof of
its four deliberate `EOPNOTSUPP` no-mutation aliases and its caller-coordinated
direct Linux setter behavior. It must not turn that profile into an all-thread
credential-rendezvous contract.

`run_owned_credentials_profile.sh` accepts `[--static-sysroot STATIC_SYSROOT]
[DYNAMIC_SYSROOT]`. Without arguments it builds both disposable products; a
dynamic positional product preserves the dynamic-only replay and does not run a
static pair. Supplying a static product runs its static/static-PIE pair, and if
it is the only argument the runner builds the disposable dynamic product that
compiles the single installed-driver object and runs the dynamic entries.
Supplying both physical checkout `.work` products reuses both and invokes
neither producer. The paths must be nonempty, the static path cannot parse as
an option, and each is canonicalized before the shared product/link validator
checks its manifest and receipt. Every per-scenario stdout retains a sibling
`.status` record for the actual timeout/user-namespace/chroot process result;
candidate process status is compared with its matching musl scenario even when
the alias transcript intentionally differs. This focused replay does not create
a static reproduction/extraction or a family-completion claim.

## Frozen aggregate shape

When the coordinator's focused receipt is complete, run the native successors
of the frozen AArch64 process evidence in the documented order. The relevant
AArch64 contracts are read-only comparison inputs:

- `compat/differential/README.md`: same-object musl differential with raw
  exit, stdout, stderr, and errno evidence;
- `compat/os-test/README.md`: process and signal profiles with retained raw
  results and recorded source exceptions;
- `compat/signal-process/README.md`: fresh signal/process groups covering
  siginfo, nodefer, masks, restart, altstack, thread masks, waits, timers,
  nohang waits, atfork, and fork-worker-exec;
- `compat/pthread-stress/README.md`: repeated same-object process and thread
  behavior with raw streams; and
- `libc-test-harness/README.md`: functional, regression, and API results
  against `libc.so`, categorized without unapproved skips.

The existing `compat.posix-process` private admission receipt is deliberately
insufficient: its five static cases are non-promoting and cannot substitute
for dynamic `os-test`, `signal-process`, pthread-stress, or libc-test-harness
coverage. The completed family coordinator is one prerequisite for that
aggregate, never a replacement for it.

Only after the family receipt and the native aggregate succeed may the ledger
owner consider changing `libc.posix-runtime` from `planned`. That transition
still depends on all of `parity.toml`'s declared prerequisites and leaves the
campaign's broader promotion and public-support predicates unchanged.
