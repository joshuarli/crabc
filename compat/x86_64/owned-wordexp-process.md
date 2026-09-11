# Private x86 wordexp process adapter

`libc/src/c_abi/x86_64/owned_wordexp_process.rs` is a private, unselected
Linux/x86-64 adapter between the deterministic word-expansion candidate in
`owned_wordexp_engine.rs` and the already selected environment, locale, spawn,
raw-syscall, and C-allocation leaves. It is compiled only with
`x86-owned-static-runtime` through the private module entry in
`static_c_abi.rs`. It exports no C ABI name, does not select or change
`owned_wordexp.rs`, and does not establish wordexp product or public-platform
support.

The engine is the owner of outer expansion syntax, typed undefined-variable
and `WRDE_NOCMD` decisions, IFS field splitting, arithmetic, and the safely
quoted local-assignment prefix. This adapter owns only a call-local environment
snapshot and one opaque command body's child transaction. The complementary
pathname adapter and any selected C ABI binding remain separate work.

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
observed or reaped the child. The selected public `wordexp` wrapper already
has a whole-call cancellation boundary; a future private binding must retain
that precondition.

For each engine-selected command body the adapter:

1. builds one C-allocated script and child `envp`;
2. creates one `pipe2(O_CLOEXEC)` output pipe and one stack-local musl-shaped
   `FdOp` which duplicates the write end onto child stdout;
3. calls `owned_spawn::spawn_with_outcome` once for `/bin/sh -c SCRIPT`;
4. closes its write end, retries `read` and `wait4` after `EINTR`, appends raw
   stdout bytes through `CommandOutput`, closes the read end, then reaps the
   child.

`WRDE_SHOWERR` has already been decided by the later C ABI binding. When it is
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

## Focused evidence and remaining work

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
also compiles this private module in the real selected x86 owned-runtime graph.
That gate still runs the selected `owned_wordexp.rs` provider, so its relevant
result here is compilation only; it is not process-adapter execution evidence.

This is deliberately not a real `/bin/sh`/`owned_spawn` product execution,
an installed C ABI probe, a selected `wordexp` replacement, or full wordexp
closure. Before selection, a separately linked private consumer must exercise
the actual spawn/path/runtime composition and the bounded shell corpus,
including the retained backtick oracle; the future binding must also compose
the pathname adapter and selected C ABI ownership rules.
