# Private x86 wordexp process adapter

`libc/src/c_abi/x86_64/owned_wordexp_process.rs` is the private Linux/x86-64
process adapter selected by the deterministic word-expansion core and its C
binding in `owned_wordexp.rs`. It binds the core to the selected environment,
locale, spawn, raw-syscall, and C-allocation leaves. It is compiled with
`x86-owned-static-runtime` through the module entry in `static_c_abi.rs` and
exports no C ABI name. Its private API and fixtures do not establish installed
wordexp product or public-platform support.

The engine is the owner of outer expansion syntax, typed undefined-variable
and `WRDE_NOCMD` decisions, IFS field splitting, arithmetic, and the safely
quoted local-assignment prefix. This adapter owns only a call-local environment
snapshot and one opaque command body's child transaction. The complementary
pathname adapter and sole `WordexpResultRecord` transaction are separate private
owners composed by the selected C binding.

## Snapshot boundary

`WordexpEnvironmentSnapshot::capture` takes a mutable fresh
`WordexpContext`. Its unsafe caller obligation is narrow: while capture runs,
the selected `environment::__environ` vector, every pointed-to NUL-terminated
entry, and the active LC_CTYPE selection must remain readable and stable under
the ordinary C environment/locale synchronization rules. A failing capture can
have installed an initial prefix of context variables, so its caller discards
that fresh context on failure. Once it returns, the adapter owns every raw
entry it needs and no longer borrows the parent environment.

The snapshot follows the selected `environment_runtime.rs`/musl `getenv`
first-match rule for valid ASCII shell identifiers:

- The first `NAME=value` entry whose name is `[A-Za-z_][A-Za-z0-9_]*` installs
  a set, exported core variable. `NAME=` remains set-empty; it is never
  confused with an absent name. Later valid duplicates do not replace it.
- An observed `IFS=value` installs both the ordinary exported `IFS` record and
  the core's field-splitting snapshot. If no valid first `IFS` entry exists,
  `set_ifs(None)` preserves the POSIX unset/default distinction.
- Every entry which is not a valid shell assignment, including a missing `=`
  or an invalid/empty name, is copied byte-for-byte with its terminator. These
  entries stay outside the core identifier map and are forwarded to the child;
  they are not silently discarded.
- Capture queries `locale_multibyte::locale_ctype_is_utf8()` once and records
  `WordexpLocaleMode::C` or `WordexpLocaleMode::CUtf8` in the context. It does
  not defer a process-global locale read into later parsing or execution.

The production storage uses only the selected C `realloc`/`free` boundary for
copied bytes, spans, scripts, and pointer vectors. It does not depend on Rust
`alloc`, mutate `environ`, or call `setenv`, `putenv`, `unsetenv`, or
`clearenv`. Every growth calculation checks both element arithmetic and its
resulting byte count against `isize::MAX`, so no allocation can make the
adapter's later pointer offsets unrepresentable.

For each selected command, the child `envp` consists of those copied raw
non-identifier entries followed by the engine's current NUL-separated exported
identifier overlays. Assignment-created locals therefore remain visible to the
child shell through the engine's standalone assignment prefix, while they do
not become child-environment entries or mutate the parent environment. The
engine owns the overlay values; `owned_spawn::spawn_with_outcome` does not
report success until its CLOEXEC handoff makes releasing those borrowed slices
safe.

## One command transaction

`WordexpProcessAdapter` borrows one immutable snapshot. Its caller must have
disabled deferred cancellation until the adapter has closed its pipe and
observed or reaped the child. The selected public `wordexp` wrapper establishes
that whole-call cancellation boundary and retains this precondition.

For each engine-selected command body the adapter:

1. builds one C-allocated script and child `envp`;
2. creates one `pipe2(O_CLOEXEC)` output pipe and one stack-local musl-shaped
   `FdOp` which duplicates the write end onto child stdout;
3. calls `owned_spawn::spawn_with_outcome` once for `/bin/sh -c SCRIPT`;
4. closes its write end, retries `read` and `wait4` after `EINTR`, appends raw
   stdout bytes through `CommandOutput`, closes the read end, then reaps the
   child.

`WRDE_SHOWERR` has already been decided by the selected C ABI binding. When it is
false the script begins `exec 2>/dev/null;`; when true it has no diagnostic
redirection. A shell starts with its inherited `IFS` reset on this platform's
POSIX shell contract, so an exported current IFS is restored as a safely
single-quoted standalone assignment before the core-provided local prefix and
body.

The engine provides an opaque body. Dollar-parenthesis bodies are appended
byte-for-byte. Backtick bodies remain raw source until this boundary, which
removes a backslash only before `$`, backquote, backslash, or physical newline;
when `CommandStyle::Backtick { double_quoted: true }` says the original form
was within double quotes, a backslash before `"` is also removed. This is
POSIX shell quote removal, not a second shell parse, preflight, execution, or
retry. A backslash immediately followed by a physical newline is one line
continuation and therefore removes **both** bytes; it never forwards a newline
to `/bin/sh`. The relevant rules are [Shell Command Language
2.6.3](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_06_03)
and [2.2.3](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_02_03).

Normal child exit status is deliberately ignored after stdout collection. A
`false` command, shell parse diagnostic, or arbitrary stderr text does not
become a typed undefined-variable or syntax result. The engine alone makes
those outer-language decisions.

Pipe, parent-side spawn, read, and wait setup/resource failures return the
engine's typed `NoSpace` and publish the direct kernel/spawn errno. A
child-side `owned_spawn` image failure has already been reaped by that owner;
the adapter closes only its pipe ends, restores the pre-spawn errno, and
returns the selected adapter's existing typed `Syntax` boundary. Output NUL or
append failure closes the read end and kills then reaps the owned child, so a
child that ignores SIGPIPE cannot hold the transaction indefinitely. A
post-read `ECHILD` is successful output completion: `SIGCHLD=SIG_IGN` and
`SA_NOCLDWAIT` discard child status and make the final wait fail that way, while
this engine deliberately does not use an ordinary command status. The selected
`owned_wordexp.rs` control path likewise retries `EINTR` and ignores its final
wait result. The adapter neither signals a potentially recycled PID nor changes
the caller's errno for that completed-output case. This follows POSIX
[`wait`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/wait.html)'s
`ECHILD` rule. Every other partial path closes each owned descriptor once.

## Focused evidence boundary

Run the fake selected-leaf boundary suite through the pinned native dispatcher:

```sh
./scripts/dev-x86_64.sh wordexp-process-adapter
```

`compat/x86_64/owned_wordexp_process_adapter_tests.rs` imports the real core
and adapter but supplies deterministic selected-environment, locale, spawn,
and raw-syscall boundaries. It proves first-match and empty/unset snapshot
behavior, locale capture, non-identifier `envp` retention, current local and
export overlays, apostrophe-safe local prefixes, IFS restoration, exactly-one
spawn, `WRDE_SHOWERR`, ignored nonzero status, quoted/unquoted backtick escape
removal, physical-newline removal, `$()` byte preservation, `EINTR`,
isize-bounded growth without allocation, output/read cleanup, post-EOF
`ECHILD`, and parent/child spawn failure descriptor and errno boundaries. The
backtick cases execute each captured script through the pinned `/bin/sh`, so
the unquoted, double-quoted, and physical-newline results are not asserted from
fake command output alone. A serial native signal control also proves that
stdout EOF followed by `SIGCHLD=SIG_IGN` yields `ECHILD`. Its runner keeps the
test binary under `.work/x86_64/wordexp-process-adapter/`.

The existing `./scripts/dev-x86_64.sh libc-owned-wordexp` static feature gate
also composes this selected process module in the real x86 owned-runtime graph.
Its product-level scope and current direct C validation are reported by
`owned-wordexp.md`; the focused private fixture below remains process-owner
evidence and does not promote this private API into an installed/public ABI.

Run the separate actual-owner fixture through the same dispatcher:

```sh
./scripts/dev-x86_64.sh wordexp-process-private
```

`compat/x86_64/run_owned_wordexp_process_private.sh` first builds an ordinary
sealed owned static sysroot and proves its `libc.a` has no bridge symbol. It
then builds a separate raw `cargo rustc` archive with only
`crabc_owned_wordexp_process_private_test` and its explicit `--check-cfg`,
compiles `owned_wordexp_process_private_probe.c` against the ordinary installed
headers, and directly links that object with the disposable archive plus the
ordinary CRT and bounded builtins through the pinned LLD. No installed header,
normal Cargo feature, or normal-product export names the bridge, and the normal
archive is never replaced. The retained `.work/x86_64/tmp/owned-wordexp-process-private.*`
leaf records the private build, consumer, program headers, stdout/stderr,
marker, leader PID, and hashes.

That C consumer takes the real selected environment snapshot and executes real
`/bin/sh` processes through `owned_spawn`, the pipe/read loop, and wait/kill
cleanup. It proves output final-newline trimming, quoted empty output, ignored
ordinary nonzero command status, current environment updates, local assignment
prefix visibility without export or parent mutation, export overlays, IFS
restoration, backtick quoted/unquoted/physical-newline behavior, quiet versus
shown stderr, exactly-once selected commands, unselected and `WRDE_NOCMD`
zero-command paths, SIGCHLD autoreap completion, and NUL-output kill/reap of a
shell leader which ignores SIGPIPE. It also runs an ordinary no-command
expression in an empty static chroot with no `/bin/sh`, proving only a selected
command requires the shell.

This is a private actual-process proof of the selected process owner, not an
installed C ABI probe, product qualification, or full wordexp closure. The
selected binding composes the pathname adapter and sole C result transaction;
direct C/product validation remains the evidence boundary for installed ABI
claims. The private fixture's earlier measured results remain provenance for
these owner invariants and are not installed-product PASS results.
