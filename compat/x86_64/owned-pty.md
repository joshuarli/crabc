# Owned PTY and terminal sessions

Installed Linux/x86-64 static and dynamic products provide `posix_openpt`,
`ptsname_r`, `ptsname`, `openpty`, `login_tty`, `forkpty`, `ttyname`, and
`tcgetsid`. These are useful POSIX/runtime terminal mechanisms with C naming
and descriptor-publication contracts. They compose the existing owned open,
close, ioctl, termios, signal-mask, cancellation and atfork boundaries.
The frozen private terminal artifacts and AArch64 remain unchanged; this is
not a process supervisor or a platform/family completion claim.

`libc/src/c_abi/x86_64/owned_pty.rs` translates musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license. The release
archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`,
as pinned in `compat/upstreams.toml`.

| Musl source | Owned functions and retained behavior |
| --- | --- |
| `src/misc/pty.c` | `posix_openpt` and `__ptsname_r`/weak `ptsname_r`; existing `grantpt`/`unlockpt` owners remain separate |
| `src/misc/ptsname.c` | `ptsname`, with a reused 22-byte static buffer and internal naming call |
| `src/unistd/ttyname.c` | `ttyname`, with a reused 32-byte `TTY_NAME_MAX` buffer and the existing `ttyname_r` owner |
| `src/misc/openpty.c` | `openpty`, master/slave allocation and optional settings |
| `src/misc/login_tty.c` | `login_tty`, session/controlling-terminal acquisition and standard descriptor redirection |
| `src/misc/forkpty.c` | `forkpty`, signal/cancellation interval and CLOEXEC child-error pipe |
| `src/termios/tcgetsid.c` | `tcgetsid`, the `TIOCGSID` session observation |

`posix_openpt` opens `/dev/ptmx` with the supplied flags through the owned
cancellation-point open. Only this wrapper maps `ENOSPC` to `EAGAIN`.
`ptsname_r` uses raw `TIOCGPTN` errors as positive return values, without
publishing those errors to errno, then formats `/dev/pts/<number>`. A null
buffer has zero effective capacity; short buffers contain the source's
truncated, NUL-terminated prefix where capacity permits and return `ERANGE`.
Its public ELF entry remains a weak alias of hidden `__ptsname_r`. `ptsname`
calls that internal provider and sets errno on failure. Both static naming
buffers are intentionally reused and unlocked, matching the source; callers
must serialize calls and use of returned pointers.

`openpty` opens its master directly, so master exhaustion remains `ENOSPC`.
That initial open is a cancellation point. The function disables cancellation
after allocating the master, unlocks it, obtains its number, and writes the
name before opening the slave pathname with `O_RDWR|O_NOCTTY`. It preserves
the source pathname algorithm rather than substituting a peer-open ioctl.
Master cleanup follows any unlock, number or slave-open failure. Optional
termios and window-setting errors are deliberately ignored: both descriptor
outputs are still published on success, and an error may remain in errno.
The original cancellation state is restored on every completed path.

`login_tty` calls `setsid`, then `TIOCSCTTY`. Only the ioctl failure stops the
operation. It ignores the results of `setsid` and the three `dup2` calls,
then closes the original descriptor if greater than two, matching musl.
No rollback of a successful session change is invented on later failure.

`forkpty` allocates the pair first, blocks the application signal set and
disables cancellation, then opens a CLOEXEC pipe before the existing `fork`
owner runs its atfork callbacks. In the child it closes the master/read end,
performs `login_tty`, and either writes one errno word and exits 127 or closes
the pipe and restores cancellation then the original mask. The parent closes
the slave/write end and reads the handshake. A received error is reaped and
returned as errno; only a successful parent publishes the master. Source
read/write/wait error handling and operation order remain unchanged. This
slice does not alter thread identity, TLS, cancellation reset, or atfork
ownership; those remain contracts of the existing fork transaction.

Run `./scripts/dev-x86_64.sh owned-pty [DYNAMIC_SYSROOT]`. The optional product
must be a physical checkout `.work` directory. `run_owned_pty.sh` compiles
one ordinary installed-header application object and links that same object
against pinned musl, owned static/static-PIE, and dynamic PIE/non-PIE products.
Both dynamic modes run through kernel and direct interpreter entry. The
`pty` case in `owned_dynamic_qualification.py` applies the same leaf to each
supplied installed, second-build and extracted dynamic product.

The runner owns a disposable chroot with a new devpts instance and read-only
procfs for descriptor-name resolution. Its Docker command receives mount and
chroot capabilities; all sessions and controlling terminals belong to fixture
children in that container, and a trap unmounts both filesystems. It uses no
host PID namespace, host TTY, privileged Docker mode or AArch64 emulation.
The reported evidence directory retains the exact application object, link
receipts, provider ELF binding checks, and paired stdout/stderr files.

Fifteen isolated scenarios cover flags and static/caller-buffer naming;
termios/window application and bidirectional bytes; no controlling-terminal
acquisition by an `openpty` caller that is already a session leader; ignored
optional-setting errors; master, unlock, number and slave-open failures;
standard-descriptor redirection including original descriptors 0, 1 and 2;
ignored `setsid`/`dup2` errors; forkpty atfork/CLOEXEC/mask/cancellation state;
pipe and fork failures; child-login error propagation/reaping; cancellation
before allocation, non-canceling name observation, and pending cancellation
during the disabled forkpty handshake. Error fixtures use contained Linux
5.10 seccomp filters, not runtime fallback code. The initial regression
passed all fourteen original musl scenarios and failed the owned static link
on all eight missing public providers. The additional session-leader case
strengthens the explicit `O_NOCTTY` boundary. No `getpt` alias is added:
the pinned musl PTY source does not export it.

The frozen `libc-ttyname-r` gate independently passes its default-archive
symbol closure and musl/static runtime differential. Its evidence owner now
checks the musl-form `bits/alltypes.h` type dependency instead of a stale
transitive `sys/types.h` include, and accepts the compiler's existing private
syscall2/3/4 leaves as direct callees when they are not inlined. Named syscall
numbers, their instruction bodies, `TIOCGWINSZ`, and the absence of every
excluded public helper remain required. An inlined `isatty` body is judged
inside `ttyname_r` when its separate function is garbage-collected.
