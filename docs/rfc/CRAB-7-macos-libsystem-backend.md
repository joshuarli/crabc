# CRAB-7: macOS/AArch64 libSystem backend for `crabc-rs`

Status: accepted 2026-11-27. The owner admitted it in parallel with Linux/AArch64
feature completion ([CRAB-8](CRAB-8-linux-aarch64-feature-completion.md)) and
delegated the open questions, which take every recommendation below.

## Decisions

1. Admit now, in parallel with CRAB-8 and the allocator restart, before F3.
2. Hand-written libSystem declarations in `crabc-rs/src/darwin/sys.rs` with
   SDK size and alignment assertions; no `libc` crate.
3. Option (a): set `FD_CLOEXEC` immediately after creation and name the fork
   race in each affected type's docs.
4. `users` and `resolver` are absent on Darwin through D3.
5. macOS 27 or newer, Apple Silicon only (owner decision; supersedes the
   proposed macOS 13).
6. Ported modules are source-compatible across both targets, enforced by
   building the facade's examples for both.

## Summary

[Scope](../scope.md) and the
[compatibility profile](../../COMPATIBILITY-PROFILE.md) reserve a future
"macOS/AArch64 libSystem backend for `crabc-rs`" and give it no further
definition. This RFC proposes that definition. On `aarch64-apple-darwin`,
`crabc-rs` would offer a selected subset of its existing safe API, implemented
over Apple's libSystem through a `darwin` backend chosen at compile time. crabc's
libc, dynamic linker, CRT, builtins, allocator and `crabc-core` are not built for
macOS, and nothing in this RFC changes the Linux product.

The recommendation is a Rust-facade backend only, scoped by module, with its
own oracle and a native macOS test host. The owner needs to decide whether to
admit it at all and, if so, settle the open questions below.

## Motivation

`crabc-rs` exposes OS mechanisms through typed descriptors, paths, flags,
errors and ownership. Programs written against it currently build only for
Linux, because `crabc-rs/src/lib.rs` rejects every other target with
`compile_error!`. Running the same program on a developer's Mac requires
rewriting the calls against `std`, `rustix` or raw `libc`. A backend for the
portable part of the facade would let these programs build and run on macOS
without a portability framework.

## Constraints

- **libSystem is the only stable kernel boundary on macOS.** Apple does not
  support raw `svc` system calls, and syscall numbers and conventions change
  between releases. Go moved to libSystem for this reason. The Linux design of
  direct syscalls through `crabc-core` cannot carry over. Every Darwin
  operation must call a libSystem function.
- **Errors arrive through thread-local `errno`.** libSystem reports failures
  through `__error()`. The [facade boundary rule](../design/crabc-rs.md#boundary)
  forbids round-tripping through TLS `errno`. That rule has to become
  Linux-specific: the Darwin backend reads `errno` immediately after each
  failing call and converts it to a typed error in the same function.
- **Constants differ.** Errno numbers, open flags, `stat` layout, socket
  options, signal numbers and `termios` fields all have different values or
  layouts on Darwin. A facade type that stores a Linux value directly, such as
  a `bitflags` type with Linux bit values, needs per-target constants.
- **Atomic close-on-exec is partial.** Darwin has `O_CLOEXEC`, but not
  `SOCK_CLOEXEC`, `accept4`, `pipe2` or `dup3`. A wrapper that sets
  close-on-exec with `fcntl` after creation can race with a concurrent `fork`
  or `exec`. The facade must not hide this gap behind a fallback (see open
  question 3).
- **Project rules still apply.** [STYLE.md §37](../../STYLE.md) requires
  `#[cfg(target_os = "macos")] mod darwin;` instead of a runtime backend enum
  or table, and §38 keeps platform machinery out of common code. The
  invariants forbid speculative portability layers, a provider/plugin system
  and emulation. Each Darwin item must therefore be a concrete implementation
  of an existing facade API, not a new abstraction for both targets.

## Design

### Boundary

```text
Rust application
       │
   crabc-rs  (common types and API)
       │                         │
 linux backend              darwin backend
 crabc-core → kernel        libSystem (extern "C") → XNU
```

`crabc-core` stays Linux-only. Under `target_os = "macos"`, `crabc-rs` drops
its `crabc-core` dependency and compiles one `darwin` module per facade module
it supports. A facade module either:

- **ports**: the same public type and method signatures, backed by libSystem,
  with any behavioral differences listed in that module's docs; or
- **is absent**: it is not compiled on Darwin, so using it is a compile-time
  error, never a runtime `ENOSYS`.

Shared public types (`Fd`, path types, the error type, flag types) stay in
common code only where their representation really is target-neutral. A type
that holds Linux values gets a per-target constant module, not a translation
table.

### Proposed module classification

| Class | Modules | Darwin notes |
| --- | --- | --- |
| Port, core | `fd`, `io`, `fs` (openat-family, `fstatat`, directories, links, permissions, times), `pipe`, `path`, `buffer`, `collections`, `numeric`, `param` subset | No `statx` (use `fstatat`); there is no `pipe2`, so creating a pipe needs a decision on close-on-exec atomicity |
| Port, process and time | `process` (`posix_spawn`, wait, identity, limits), `signal`, `time` (`clock_gettime`, sleeps), `rand` (`getentropy`) | No `pidfd`, `clone` or `prctl`; `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` covers spawning; the CRAB-2 `Child` ownership contract carries over unchanged |
| Port, networking | `net` (sockets, addresses, messages), `netdb` file snapshots | No `SOCK_CLOEXEC`/`accept4`/`mmsg`; `netdb` snapshots still parse caller bytes or `/etc` files, but `/etc/hosts` is not the authoritative macOS name service |
| Port, terminals | `termios`, `pty` (`posix_openpt`) | Different `termios` layout and control-character indices |
| Port, memory | `mm` subset (`mmap`, `mprotect`, `madvise`, `msync`, `mlock`) | No `mremap` or `memfd` |
| Decide | `users`, `resolver`, `timezone`, `shm`, SysV `ipc` | Accounts come from Open Directory, not `/etc/passwd`; DNS policy belongs to mDNSResponder; see open question 4 |
| Absent | `event` (epoll), `eventfd`, `inotify`, `mount`, `ioctl` Linux requests, POSIX message queues, `fallocate`, `readahead`, `sync_file_range`, `copy_file_range`, `splice`/`tee`, sched affinity | Linux-only mechanisms; macOS has no POSIX message queues. A future kqueue module would be a separate proposal, not an epoll translation |
| Absent | `dl`, `runtime_thread`, `cfile` (features `runtime-loader`, `runtime-thread`, `runtime-stdio`) | These bind crabc's private `RuntimeV1` table in crabc's libc, which does not exist on macOS |

The exact per-group classification belongs in `compat/crabc-rs/coverage.toml`,
which would gain a Darwin status column. That column is only a start: no
module counts as ported until a native behavior test passes on macOS.

### Declarations

The recommendation is to declare libSystem functions, types and constants by
hand in `crabc-rs/src/darwin/sys.rs`, limited to what the ported modules call.
Each struct gets a compile-time size and alignment assertion against the
macOS SDK. The alternative is the `libc` crate: it is mature and already in the
build graph for `rust-std` vendoring, but it adds a large declaration surface
the facade does not need. See open question 2.

### Oracle and testing

- **Oracle:** pinned `rustix` (which supports Apple targets) and Rust `std`
  remain test oracles only, as on Linux. Behavior is checked on a real Mac.
  musl is not the oracle for this backend.
- **Host:** tests run natively on Apple Silicon, using the owner's Mac or a
  dedicated macOS runner. The project rule against emulation applies. Nothing
  runs under Rosetta, a VM or a cross-compiled Linux harness.
- **Tests:** the existing per-module behavior tests in `crabc-rs/tests/` run on
  Darwin wherever their module ports. A Linux-only assertion moves behind
  `cfg(target_os = "linux")` and gets a Darwin counterpart only where the
  behavior genuinely differs.
- The Linux qualification chain, ledgers and receipts are unchanged. The
  Darwin backend never contributes to `capability.accounting` for Linux.

### Phases

1. **D0, scope amendment (docs only):** change the target guard in `AGENTS.md`,
   `docs/scope.md`, the compatibility profile and `crabc-rs/src/lib.rs`'s
   `compile_error!` text. Record the minimum macOS version and the answers to
   the open questions.
2. **D1, compile gate:** `cargo check -p crabc-rs --target aarch64-apple-darwin`
   builds with the core port modules and drops `crabc-core` on Darwin.
   Behavior tests for `fd`, `io`, `fs` and `pipe` pass on a Mac.
3. **D2, process, time and networking:** `process`, `signal`, `time`, `rand`
   and `net`, with ownership and close-on-exec semantics documented per type.
4. **D3, terminals, memory and decided modules:** `termios`, `pty`, `mm`, and
   whatever open question 4 admits.

Each phase is independent of the Linux campaign and changes no Linux product
source. That keeps the Linux product source digest stable, provided the shared
types do not change. If D1 restructures shared types, that is a Linux product
change and needs its own Linux qualification.

## Open questions

1. **Admit it now, later or never?** The current direction defers this until
   F2 is accepted. F3 (performance) is also pending. The question is whether
   D0 comes before, after or in parallel with F3.
2. **Hand-written declarations or the `libc` crate?** The recommendation is
   hand-written declarations with SDK layout assertions, because the surface is
   narrow and auditable.
3. **Non-atomic close-on-exec.** For sockets, pipes and `dup`, should Darwin:
   (a) set `FD_CLOEXEC` immediately afterwards and document the fork race;
   (b) hold a process-wide fork lock, which the facade cannot enforce for
   foreign threads; or (c) remove those constructors on Darwin? The
   recommendation is (a), with the race named in each type's docs, because
   std makes the same trade-off on macOS.
4. **System databases.** Should `users` and `resolver` on Darwin call the
   libSystem lookups (`getpwnam_r`, `getaddrinfo`)? Those go through Open
   Directory and mDNSResponder, which conflicts with the Linux rule of
   conventional files only and no NSS/plugins. The alternative is leaving them
   absent. The recommendation is absent for D1–D3; revisit with a concrete
   consumer.
5. **Minimum macOS version.** The proposal is macOS 13 or newer on Apple
   Silicon only. Intel Macs are out of scope.
6. **Source compatibility.** Does a program that uses only ported modules
   promise to build unchanged on both targets? The recommendation is yes for
   ported modules, enforced by building the facade's examples for both
   targets.

## Non-goals

- crabc libc, ldso, CRT, builtins or the C mimalloc backend on macOS.
- Raw Darwin syscalls or Mach traps that libSystem does not expose.
- A kqueue/epoll abstraction, an async runtime or a portable event loop.
- Intel macOS, iOS or any other Apple target.
- Any change to the Linux qualification chain or its evidence.
