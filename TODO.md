# Active TODO — Linux/AArch64

This is the living, scope-filtered work list for `crabc`. It replaces the
chronological “next” language in [the historical delivery records](docs/history/)
as the planning source. The exact machine-readable capability state remains
[`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml): this document
is its reviewed, human-oriented projection.

Current scope is Linux/AArch64 little-endian with Linux 5.10 as the kernel
baseline. Every item below needs a narrow contract, observable tests,
Linux/AArch64 direct-boundary or ABI evidence where applicable, and musl/POSIX
evidence appropriate to its C behavior. Do not start several broad families
at once.

## Current status

M0–M12 are complete. Current ledger validation records 159 verified native
seams, 16 deferred native capability groups, and 43 documented non-native
boundaries. The current generated dashboard records 1,647/1,647 required musl
dynamic exports, no ABI metadata mismatch, 34/34 measured Alpine corpus cases,
and no current libc-test missing-symbol blocker. These measurements are
evidence, not a claim of complete historical libc breadth.

## Core runtime capability work

| Ledger group | Exact work still left | Do not repeat |
| --- | --- | --- |
| `filesystem.extensions` | Design an authority-safe temporary-file contract for the remaining `mkstemp` family and separate unsafe Linux file-handle operations (`name_to_handle_at`, `open_by_handle_at`). | Existing `mkdtemp`, xattr, allocation-range, and descriptor work. |
| `time.clock-calendar` | Separate local-time conversion, `TZ`/system-zoneinfo discovery, formatting/parsing, and privileged wall-clock adjustment into owned contracts. | UTC calendar operations and M11 caller-supplied POSIX-TZ/TZif offset rules. Do not bundle tzdata. |
| `network.resolver` | Add one caller-owned system resolver state machine: `/etc/resolv.conf`, `/etc/hosts` precedence, A/AAAA/CNAME completion, search domains, retries, and failover. | The configured UDP/TCP transport, malformed-packet handling, and TCP truncation fallback already verified in M11. No NSS, DNSSEC, DoH/DoT, mDNS, or IDNA policy. |
| `network.netdb` | Turn the existing file parsers into owned snapshots/lookups for hosts, services, and protocols as individually specified. | An NSS/plugin abstraction or libc static-buffer APIs. |
| `process.control` | Close the remaining ownership, signal, descriptor, child-lifetime, and `posix_spawn` attribute/action contracts; classify clone/vfork/daemon/nice aliases separately. | Existing prepared exec, fork/wait, and process-group/session observations. |
| `process.credentials` | Implement or explicitly constrain synchronized process-wide credential mutation with musl-compatible cross-thread semantics. | Existing calling-task `setres*` and filesystem-credential operations. |
| `process.environment-mutation` | Design an explicit unsafe, synchronized environment owner for mutation and exec interaction; audit C `setenv`/`unsetenv`/`clearenv` state. | Read-only process observations or a new global registry. |
| `process.signal` | Split the ledger and finish only the unaccounted legacy/async-safety semantics. | M6 typed masks, actions, queueing, waits, alternate stacks, and `signalfd`. |
| `thread.pthread-c11` | Specify robust/process-shared/recursive/error-checking forms, cleanup scopes, cancellation lifecycle, `Send`/`Sync` handle evidence, and shared C/native atfork semantics. | M7 process-private mutex, condition, once, semaphore, rwlock, barrier, and runtime thread/TLS slice. |
| `loader.dlfcn-introspection` | Add an owned image-snapshot/information contract for `dl_iterate_phdr` and `dlinfo`, including reentrancy, callback, and loader-record lifetime rules. | M11 basic owned open/symbol/close. |

### Concrete C-runtime correctness work

- Replace the hard-coded 4 KiB `getpagesize`/`_SC_PAGE_SIZE` behavior with a
  validated `AT_PAGESZ` source. AArch64 must not assume a 4 KiB page size.
- Resolve the success stubs for C `setreuid` and `setregid`: implement the
  required synchronized semantics or record a tested profile limitation. They
  must not silently claim success without the corresponding state transition.

## Useful POSIX/runtime capability work

| Ledger group | Exact work still left | Boundary |
| --- | --- | --- |
| `pattern.regex` | A focused POSIX-equivalent owned compiled-expression API, or an explicit decision to keep it C-only. | No general Rust regex framework by default. |
| `pattern.glob` | Owned byte-preserving result values with explicit current-directory and error policy. | No hidden process-global traversal policy. |
| `ipc` | Select one narrow mechanism at a time from SysV IPC, POSIX named semaphores/message queues, or AIO. | Shared memory and process-private native semaphores already exist; no aggregate IPC framework. |
| `terminal.pty-session` | Owned PTY/session lifecycle for `openpty`/`forkpty`, controlling terminal, `login_tty`, `vhangup`, and `ptsname_r`. | Low-level `/dev/ptmx` and terminal observations are already separate. |
| `users.databases` | Owned `/etc/passwd` and `/etc/group` records plus enumeration; separately classify shadow, utmp/utmpx, mntent, and user-shell families before work. | Conventional files only; no provider/NSS layer. |
| `system.kernel-admin` | Propose and review one authority-bearing mechanism at a time (for example namespaces, capabilities/prctl, inotify, ptrace, or process_vm). | No kernel-administration or security-policy framework. |

## Evidence and maintenance frontiers

These are not hidden feature commitments. Promote one only when it helps a
selected scoped capability.

- Add a focused runtime case for loader self-relocation, the one source-only
  entry in the loader feature inventory.
- Expand static-link evidence beyond the existing static pthread/TLS lifecycle
  case; a full static libc-test matrix remains unmeasured.
- Decide whether exhaustive static-archive ABI comparison and broader
  header-feature/layout probing are worth their cost. The current selected ABI
  probe is green but intentionally not exhaustive.
- Use focused fuzzing/property/failure-path testing for high-value parsers and
  ownership state machines when changing them.
- Benchmark a selected hot facade route against Rustix only when a design or
  regression needs the measurement. Preserve M12’s bounded LTO proof; the
  historical static/build-std linker-plugin lane is optional research, not a
  compatibility blocker.
- Extend POSIX, loader, or real-program evidence only in response to a defined
  contract. Existing selected suites are not claims of full standards or
  arbitrary Alpine DSO-graph coverage.

## Not TODO

The 43 `documented` ledger groups are accounted boundaries, not a hidden
backlog. They include C ABI-only machinery, Rust-subsumed operations, internal
runtime exports, and the mimalloc allocator exception. Their exact rationale
is in [`compat/crabc-rs/coverage.toml`](compat/crabc-rs/coverage.toml).

The following are deliberately outside project scope unless the user changes
it explicitly: x86_64, RISC-V, 32-bit, big-endian, and non-Linux `crabc`;
glibc as an oracle or fallback; allocator research; hand-rolled cryptography;
general locale/charset databases; NSS/plugins; bundled tzdata; gettext;
DNSSEC, DoH, DoT, mDNS, and IDNA policy; async runtimes; process-management
frameworks; security-policy frameworks; and a portability abstraction layer.

## Choosing the next slice

Start with a single ledger row. Write the ownership/state contract and focused
regression first, then implement against Linux 5.10, prove the boundary, and
update the ledger, this TODO, nearby documentation, and the relevant report.
If the work would need a new dependency, perform the dependency review in
[`SCOPE.md`](SCOPE.md) and obtain the required user approval before adding it.
