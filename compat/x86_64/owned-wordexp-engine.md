# Private x86 word-expansion engine candidate

This is a private, unselected replacement candidate for the shell-shaped x86
`wordexp` adapter in `libc/src/c_abi/x86_64/owned_wordexp.rs`. It is C ABI
compatibility machinery, not a Rust API, shell implementation, provider
framework, or x86 qualification claim. The selected adapter remains unchanged.

## Contract and provenance

POSIX.1-2024 [`wordexp()`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/wordexp.html)
defines `WRDE_BADVAL` for an undefined shell variable with `WRDE_UNDEF`, and
`WRDE_CMDSUB` when `WRDE_NOCMD` forbids command substitution. The
[Shell Command Language](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html),
particularly sections 2.2.3, 2.6.1, 2.6.2, 2.6.4, and 2.6.5, defines quoting,
tilde and arithmetic expansion, parameter substring patterns, and field
splitting. Its [general-concepts expression rule](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap01.html#tag_18_01_02_01)
imports the relevant ISO C expression semantics, including lazy `&&` and
`||` operands. Its [reserved-word positions](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_04),
[compound-command delimiters](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_09_04),
and [function definition](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_09_05)
rules bound the opaque delimiter scanner. Issue 8 also defines dollar-single-quoted strings.

Musl 1.2.6 release commit `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
`src/misc/wordexp.c` (MIT; SHA-256
`018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8`) remains
the compatibility oracle and source provenance for the selected adapter. This
candidate is a new private design, rather than a source translation. Existing
source RED observations in [owned-wordexp.md](owned-wordexp.md) remain
observations, not equality claims.

`WRDE_UNDEF` is typed only for an attempted expansion that this engine can
identify as an unset parameter. A command body's exit status, stdout, or stderr
remains ordinary subshell behavior. The engine does not parse shell diagnostics
or classify arbitrary child failure as `WRDE_BADVAL`.

## Recognized source and evaluation model

`WordexpSyntax` copies the input and parses only the outer word-expansion
language. Its grammar is intentionally expressed as node kinds rather than a
shell AST:

```text
input       := word *(space-or-tab word)
word        := piece*
piece       := literal | single-quoted | double-quoted | dollar-single-quoted
             | parameter | arithmetic | command | tilde
parameter   := $name | ${#name} | ${name [parameter-operator word]}
arithmetic  := $(( arithmetic-source ))
command     := $(opaque-command-body) | `opaque-command-body`
```

The parser records literal, quoted, parameter, arithmetic, tilde, and opaque
command-body nodes. It uses explicit C-allocated parser stacks for nested
syntax. A command-body delimiter scanner understands quote state, comments,
nested substitutions, pending here-documents, and a finite stack of lexical
command scopes only far enough to retain the exact body span. The scopes track
reserved-word positions and compound delimiters for `case`, `for`, `if`,
`while`, `until`, brace groups, subshells, and every POSIX compound form that
can be a function body. A brace group starts only when `{` or `}` is a whole
lexical token, so `{missing` remains an ordinary command word. Ordinary
arguments and for-list data with those spellings remain data. It does not build
a command execution AST.

An arithmetic node retains a separate `ArithmeticSource` word. Its parameter,
command, quote, and nested arithmetic expansions complete first on the same
heap task stack. The flattened resulting bytes then enter the arithmetic-only
parser. They never re-enter shell-source parsing: for example, command output
`1+2` supplies arithmetic tokens, while output containing `$(...)` is an
arithmetic syntax error and does not cause a second command execution. The
arithmetic AST evaluates `&&`, `||`, `?:`, and assignments lazily after that
source-expansion phase. Therefore a skipped arithmetic assignment remains
unperformed: `V` remains unset after `$((0 && (V=9)))`, as required by the
referenced C `&&` semantics.

A `WRDE_NOCMD` evaluation scans the complete parsed graph before any task,
assignment, or adapter call. It rejects every recognized command node with the
typed command-substitution error. Otherwise each selected opaque body reaches
the command adapter exactly once.

`ExpandedWord` carries ordered byte atoms. Each atom records split eligibility,
pathname-pattern eligibility, quote or escape protection, a zero-width explicit
empty marker, and an expansion origin. Ordered empty markers preserve the
position of `""` around IFS delimiters. In C.UTF-8 mode an IFS character can
only use consecutive eligible bytes from one origin, so adjacent expansions or
quoted/literal boundaries cannot synthesize a delimiter. Nested output is
copied as data and is not reparsed.

## Private interfaces

These are `pub(super)` implementation boundaries for a later sibling C ABI
adapter. They deliberately expose narrow read or write views instead of the
engine's C-allocated vectors, syntax nodes, or atom flags.

| Boundary | Input and output contract |
| --- | --- |
| `WordexpSyntax::parse` | Copies a NUL-free source slice and returns parsed node/span ownership. |
| `WordexpContext` | Holds call-local variable state, export attributes, special-parameter values, IFS, flags, and explicit `WordexpLocaleMode`. `set_initial` distinguishes unset from set-empty. |
| `evaluate_wordexp` | Consumes immutable syntax plus mutable context and deterministic command/path adapters, returning owned result-word views. |
| `WordexpCommandAdapter::execute` | Receives an opaque body, typed `CommandStyle`, a safely quoted local-assignment prefix, current NUL-separated exported entries, and a `CommandOutput` sink. `CommandStyle::Backtick { double_quoted }` retains the outer quote context needed for the POSIX backtick backslash rule; the body bytes themselves stay unchanged. |
| `WordexpPathAdapter::expand_tilde` | Receives a user spelling, the current call-local `HOME` for bare `~`, and a `TildeOutput` sink. A home replacement is marked quoted, so it cannot split or glob. |
| `WordexpPathAdapter::expand_pattern` | Receives `PatternInput` atoms with only pattern eligibility and empty-marker information, then emits copied paths through `PathnameMatches`. |
| `WordexpPathAdapter::remove_parameter_pattern` | Receives an evaluated pattern plus typed `ParameterPatternOperator`, avoiding duplicated private parser tags. |

All growable syntax, parser, evaluator, arithmetic, and output storage crosses
the selected C `malloc`/`realloc`/`free` boundary. Nodes point into the
call-local copied source. Valid nesting has no fixed private depth cap and no
parser or evaluator path uses Rust call-stack recursion.

The later command adapter will invoke `/bin/sh` through `owned_spawn` exactly
once, with no preflight or shadow execution. It receives the byte-exact opaque
body. For a backtick form, it may apply only the normative backslash removal
selected by `CommandStyle::Backtick { double_quoted }` before that one child
invocation; it must not reinterpret the result as shell source itself. It will
receive current exported context values as `envp` overlays. Assignment-created
locals remain unexported and are serialized as safely single-quoted standalone
assignment commands, each followed by a newline before the byte-exact command
body. They are never silently promoted into `envp`, and child assignments never
mutate the parent context.

The later pathname adapter uses `owned_pattern` and copies strings before
`globfree`; named tilde lookup uses `owned_passwd`; environment snapshotting
uses `environment_runtime`. The candidate does not own process creation,
cancellation suppression, pipe/wait cleanup, `wordexp_t` append/reuse/NOSPACE
record ownership, or C status mapping.

## Deterministic policy choices

| Topic | Candidate policy |
| --- | --- |
| Initial variables | The adapter supplies one call-local snapshot of valid shell identifiers, values, and export attributes. The core never reads ambient `environ`. A selected process adapter must also preserve raw non-identifier `envp` entries outside this identifier map. |
| Locale mode | `WordexpLocaleMode::C` is the explicit default and also represents POSIX byte-locale behavior. `CUtf8` is a call-local mode, not a read of process-global locale state. A later adapter must snapshot the selected C or C.UTF-8 LC_CTYPE state into this mode. |
| IFS | Unset means space/tab/newline; set-empty disables splitting; set versus unset shares the ordinary `IFS` variable record so `${IFS:=:}` affects later fields. Only unquoted parameter, command, and arithmetic atoms split. C mode preserves byte delimiters. C.UTF-8 mode scans IFS as UTF-8 character byte sequences and matches a complete sequence only inside one unquoted expansion origin. Direct adjacent expansions cannot synthesize an IFS character. Preserving inner WORD origins through nested `${...:-WORD}` and `${...:+WORD}` is the current narrow candidate interpretation, rather than a specifically adjudicated POSIX/Austin result. Invalid or incomplete UTF-8 in IFS advances as a one-byte delimiter; invalid or incomplete field bytes advance as ordinary one-byte data, so arbitrary input is retained. Only ASCII space, tab, and newline are classified as IFS white space; other Unicode IFS characters are deliberately nonwhite, an implementation-defined choice permitted by POSIX. |
| Empty fields | IFS white-space and nonwhite delimiters follow the section 2.6.5 delimiter rules. A quoted zero-width atom can preserve an otherwise empty field at its original position; an unquoted unset or empty expansion vanishes even with empty IFS. |
| Tilde | Bare `~` receives the current call-local `HOME`; named lookup is delegated. A set-empty `HOME` replaces bare `~` with one explicit empty field. Resolved home bytes are quote-protected from both field splitting and pathname expansion. |
| Special parameters | `wordexp()` leaves their result unspecified. The context supplies finite values; tests use no host positional state. |
| Parameter WORD | The source is parsed once and evaluated only when selected, under distinct parameter-word, assignment-value, or pattern-operand context. Unselected branches have no command, arithmetic, or assignment side effect. Assignment stores the quote-removed operand but emits the assigned result under the enclosing expansion's quote state. The four `#`/`##`/`%`/`%%` operands ignore an enclosing double quote for pattern syntax while retaining quotes written inside the braces; this applies in arithmetic source too. A shared parameter-header scan chooses that delimiter rule before the matching `}`, so an ordinary outer-double-quoted operand retains literal single quotes and removes `\}` only where POSIX makes that brace escape special. |
| Parameter pattern result | The pathname adapter emits removal bytes through `ParameterPatternOutput`. An empty result disappears when its outer parameter expansion is unquoted and becomes one explicit empty field when that expansion is quoted; nonempty output retains normal outer splitting and quote rules. |
| Parameter length | `${#name}` counts bytes in C mode. In C.UTF-8 mode it counts valid UTF-8 scalars; every malformed or incomplete leading byte counts as one character so the operation preserves forward progress on arbitrary stored bytes. |
| Arithmetic | The envelope is recognized before evaluation. Direct parameter, command, and nested arithmetic expansion completes across the full selected envelope before arithmetic parsing; arithmetic AST branches and assignments then short-circuit. An unset bare arithmetic identifier is numeric zero; direct parameter expansion still observes `WRDE_UNDEF`. Octal and hexadecimal literals are accepted. The implementation supports plain and ten compound assignments (`*=`, `/=`, `%=`, `+=`, `-=`, `<<=`, `>>=`, `&=`, `^=`, `|=`). |
| Arithmetic range | Arithmetic uses checked signed 64-bit values. Overflow and divide/modulo by zero are typed errors. Shift counts must be 0 through 63; left shift is checked signed scaling, allowing `0 << 63` and `-1 << 63` when exactly representable while rejecting lost high bits such as `1 << 63`. This is an explicit finite candidate policy where POSIX does not settle every overflow edge. |
| Dollar-single quotes | POSIX.1-2024 Issue 8 dollar-single-quoted literals are parsed and their defined byte escapes decoded. |
| NUL | The private slice API rejects input NUL. A decoded dollar-single or adapter-output NUL is a typed unrepresentable-output error because C result words cannot carry interior NUL. |
| Unspecified breadth | Where no candidate rule and evidence exist, preserve the selected musl adapter. There is no ambient-shell fallback and no status-to-`WRDE_UNDEF` heuristic. |

## Evidence and integration boundary

The focused native suite in `compat/x86_64/owned_wordexp_engine_core_tests.rs`
checks direct/braced/quoted undefined variables; unset versus set-empty;
selected and unselected parameter branches; assignment mutation and child
prefix/export visibility; source scanner progress and line joining; ordered
empty-quote field splitting; quote and pattern preservation; current-HOME
tilde handling; opaque-command delimiters; command exactly-once selection; and
the three-phase arithmetic route, range policy, assignments, and `WRDE_NOCMD`
precheck. It also proves that a raw backtick body reaches the later adapter with
its outer double-quote context intact, including parameter-word and arithmetic
source paths. Locale tests cover default C byte behavior, C.UTF-8 parameter
length, two/three/four-byte IFS delimiters, ASCII/nonwhite delimiter adjacency,
origin and quote boundaries, set-empty/unset IFS, and malformed-byte
progression. Parameter tests inspect each removal operand's pattern atom mask
under enclosing and inner quotes, nested parameters, and arithmetic source;
they also retain the outer-double-quoted delimiter and backslash cases.
Opaque-command tests retain quoted controls, here-documents, a
real `case`, ordinary keyword arguments, for-list data, brace groups,
subshells, all function-body compound forms, empty-case and optional-pattern
boundaries, whole-token brace recognition, and nested case/control paths
without changing raw body bytes. A set-empty `HOME` tilde
case and all four empty parameter-pattern removals have outer-quote regressions.
A 64 KiB-thread regression expands 4,000 nested parameter words, 4,000 nested
arithmetic expansions, and 8,000 arithmetic parentheses while verifying that
parser and evaluator stacks use heap storage.

A retained independent pinned-shell corpus is useful as a comparison, not a
selection gate. Its two observed rows that set `V=9` in a skipped `&&` or `||`
operand are pinned BusyBox behavior that conflicts with the POSIX/C lazy
expression rule above; the retained oracle bytes remain unmodified and the
candidate follows the standard. The candidate has not qualified a C ABI
product, selected allocator, shell fixture, sysroot, POSIX family, or public
x86 support.

Before selection, a separate change must bind these interfaces to
`environment_runtime`, `owned_pattern`, `owned_passwd`, and `owned_spawn`;
preserve raw `envp` entries, C cancellation, pipe/wait cleanup, and result
record semantics; bind the selected LC_CTYPE snapshot to the context; and add
direct C ABI plus musl/POSIX evidence for every claimed behavior.
