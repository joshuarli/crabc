# Owned x86 C word expansion

`wordexp` and `wordfree` belong to the selected `x86-owned-static-runtime`
aggregate. The owned evaluator handles tilde, parameter and arithmetic
expansion, field splitting, pathname expansion, and quote removal. Only a
selected command substitution requires `/bin/sh`. This C ABI facility does
not complete the broader text/process family or public x86 support.

## Ownership and expansion boundaries

`libc/src/c_abi/x86_64/owned_wordexp.rs` owns the two C entry points and their
status/record contract. `owned_wordexp_engine.rs` parses the input once and
holds call-local variable and quote state. Its growable task stacks keep
valid nesting off the Rust call stack. Expanded bytes remain data; they do
not re-enter shell parsing. The selected lexical graph is checked for
`WRDE_NOCMD` before environment snapshotting, result staging, or an adapter
call, including commands contained in an unselected parameter branch.

`owned_wordexp_process.rs` copies the environment and selected CTYPE mode,
then invokes each selected opaque command body once through `owned_spawn`.
Call-local assignments retain their export attributes, and the process
adapter preserves non-identifier environment entries. Child exit status and
diagnostic text never infer an undefined-variable error. The adapter reads
the output pipe, trims trailing newlines, and reaps the child, including its
failure cleanup paths. Ordinary expansion needs no shell executable.

`owned_wordexp_paths.rs` uses `owned_pattern` for quote-aware pathname and
parameter-pattern matching and the reentrant `owned_passwd` boundary for
tilde lookup. It copies borrowed pathname bytes into the result transaction
before releasing the glob owner. All substitutions within one root word
finish before splitting and pathname expansion; that word's final fields
are accepted before evaluation starts the next root word.

`owned_wordexp_results.rs` owns the sole `repr(C)` result record. Fresh calls
read only `we_offs` when `WRDE_DOOFFS` requests it. Append stages a separate
vector while borrowing prior strings; a later semantic error drops only new
storage and preserves the original three fields and allocation addresses.
Success and `WRDE_NOSPACE` publish the accepted prefix without another
allocation. A rejected field is never partially accepted, and no later
command executes after that failure. Even an empty allocation-failure prefix
is releasable. `WRDE_REUSE` first releases the prior result. `wordfree`
releases strings and vector, clears count/vector, retains offsets, and makes
a repeated release inert. A fresh failure other than `WRDE_NOSPACE` does not
promise a new releasable result; an append failure retains the previous one.
The C wrapper disables cancellation until all temporary owners have dropped.

The input, result, environment, locale stability, and prior-record obligations
are documented above the C entry points. Allocation remains in the selected
C domain; this evaluator introduces no production dependency.

## Defined errors and diagnostics

| Private result | Public status |
| --- | --- |
| Resource exhaustion | `WRDE_NOSPACE` |
| Forbidden unquoted character | `WRDE_BADCHAR` |
| Unset selected parameter with `WRDE_UNDEF` | `WRDE_BADVAL` |
| Lexically contained command with `WRDE_NOCMD` | `WRDE_CMDSUB` |
| Malformed syntax, parameter assertion, arithmetic error/overflow, or output NUL | `WRDE_SYNTAX` |

Unset and set-empty values are distinct. A selected default, assignment, or
alternate operand follows its parameter operator before `WRDE_UNDEF` is
applied; an unselected operand has no side effect. A selected `${name:?WORD}`
expands WORD once and then produces a typed parameter assertion. Failure
inside WORD retains its own error type. Arithmetic uses the documented
checked signed-64-bit policy, including C-style short-circuit assignments.
Special-parameter output is unspecified by `wordexp`; the evaluator's finite
values do not claim a portable positional-argument result.

Without `WRDE_SHOWERR`, diagnostics are suppressed. A selected parameter
assertion with that flag writes `wordexp: NAME: MESSAGE` and a newline to
inherited fd 2. An omitted WORD uses `parameter is unset or empty`; an
explicit WORD that expands to empty remains empty. These raw writes avoid
mutating the parent's FILE orientation, buffering, and error indicator, and
do not publish raw write failures to errno. They retry EINTR and partial
writes. A broken pipe follows the calling thread's SIGPIPE disposition; the
previous whole-input shell protocol exposed its child to that signal. This
is a recorded diagnostic-I/O difference, with no additional signal policy.

The detailed grammar, quote/IFS provenance, arithmetic policy, and private
interfaces are specified in [owned-wordexp-engine.md](owned-wordexp-engine.md).
The [process](owned-wordexp-process.md), [pathname](owned-wordexp-paths.md),
[pattern](owned-wordexp-pattern-boundary.md), and
[result](owned-wordexp-results.md) contracts name their direct owners.

## Fixed source observations

Musl 1.2.6 remains the compatibility oracle: release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT license,
`src/misc/wordexp.c` SHA-256
`018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8`.
The owned evaluator is a POSIX implementation, not a semantic port of musl's
whole-input shell protocol. Its historical x86 scanner is retired; the
AArch64 implementation and its frozen evidence remain unchanged.

The governing expansion clauses are [POSIX.1-2024 wordexp](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/wordexp.html)
and the [Shell Command Language](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html).
The same installed-header object preserves these specific source observations:

| Observation | Pinned musl | Owned candidate |
| --- | --- | --- |
| Unterminated quote without SHOWERR | Syntax diagnostic reaches fd 2 | `WRDE_SYNTAX`, empty fd 2 |
| Standard nested/positional parameter syntax under NOCMD | Recorded parameter-brace or positional rejection | Valid expansion without a command |
| Recorded arithmetic-delimiter, continuation and dollar-single marker controls | Creates the prohibited command marker | Rejects before a command starts |
| Initial `#` plus the recorded paired quotes/newlines | Executes the intervening command | Treats `#` literally and returns the exact quoted data without creating a marker |
| Unset parameter with UNDEF | Returns success and no words | `WRDE_BADVAL` |
| Ordinary literal with absent, inaccessible or invalid `/bin/sh` | `WRDE_SYNTAX` | Literal succeeds; a selected command returns `WRDE_SYNTAX` |
| `$((case $A in a) echo x ;; *) echo y ;; esac))` under NOCMD | `WRDE_BADCHAR` after its parenthesis counter reaches zero | The definite arithmetic delimiter mismatch selects the subshell interpretation and returns `WRDE_CMDSUB` |

The last row uses the documented lexical disambiguation heuristic; portable
applications separate `$(` and a following subshell `(` with whitespace.
A direct `$(echo x)` remains `WRDE_CMDSUB` under NOCMD.
Escaped-brace and quoted pattern controls still match the source. No reader
accepts arbitrary candidate failures because a source difference is known.

The untouched upstream `functional/wordexp` unit also contains expectations
that are not universal POSIX wordexp requirements. Its original result is
retained separately from the direct C cases. Special-parameter values are
unspecified, initial `#` may remain literal, and naked unquoted parentheses
require `WRDE_BADCHAR`. Multiple simultaneous errors have no required
[detection order](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html#tag_16_03),
so incomplete substitutions under NOCMD may return `WRDE_SYNTAX`.

Issue 8 quotation rules also preserve one empty field for `${X-$''}` when X
is unset. They leave apostrophes literal in an effectively double-quoted
parameter operand, so `${X=1} $((${X-'}))` can produce `1 1` without evaluating
the skipped default. The same context does not activate dollar-single quotes
in `"${X-$'$(cmd)'y}"`; its command remains subject to NOCMD. In
`${X-"$"{A}B}`, the quoted dollar cannot start nested parameter expansion;
the first unquoted right brace closes the parameter, and the final naked
brace is `WRDE_BADCHAR`. These are specific source-test interpretations,
not permission to waive another candidate outcome or close the raw aggregate.

## Native evidence

`./scripts/dev-x86_64.sh libc-owned-wordexp` exercises the same C object in
pinned-musl static ET_EXEC and owned static ET_EXEC/static-PIE modes. Its raw
source observations are separate from required candidate successes. The
standalone result-allocation witness is
`./scripts/dev-x86_64.sh wordexp-result-private`: only its disposable cfg
archive exports allocation-budget controls; the normal archive must exclude
them. It injects failures only in C result vectors and strings and checks
fresh/append/offset prefixes, sentinels, cleanup, and command suppression.
It does not replace installed-product evidence. The process and pathname
private fixtures separately exercise actual spawn/wait, glob, and passwd
owners. Core tests use deterministic adapters and cannot replace those proofs.
The [C ABI regression contract](owned-wordexp-engine-abi.md) defines the
separate undefined-variable, rollback, diagnostic, signal, and literal cases
included in the installed-product object.

`./scripts/dev-x86_64.sh owned-wordexp` dispatches
`compat/x86_64/run_owned_wordexp.sh` as the separate installed-product
component receipt. The canonical `wordexp` qualification case requires it for
each installed, second-build and extracted dynamic product.  With no arguments it materializes the selected dynamic
and static products, translates the ordinary `owned_wordexp_probe.c` once
through the installed dynamic headers, and links that unchanged object to the
pinned-musl static ET_EXEC oracle, owned static ET_EXEC/static-PIE, and owned
dynamic PIE/non-PIE products.  With a supplied dynamic product it does not
rebuild it; `--static-sysroot` adds the two static modes.  Dynamic PIE and
non-PIE run through both the kernel interpreter and the installed loader's
direct entry, making six product modes when both products are selected.
After validating the report, the runner prints its retained directory with the
catalog's `evidence:` marker, followed by the report path on the final line.

The version-4 receipt uses one finite case registry in
`compat/x86_64/owned_wordexp_evidence.py`. It requires the candidate's exact
positive status and transcript in each declared cell, separately checks the
fixed oracle observation below, and rejects unexpected diagnostic bytes.
The same policy validates the focused static component runner. Each actual
execution retains argv, environment, status, stdout, and stderr. The receipt seals the
installed headers, one workload object, link receipts and ELF validation,
products, compiler/linker inputs, and every declared regular file, alias, and
fixture device in each actual execution root. The source, selected products, fixed compiler/linker
and shell tools, shared pinned-musl qualification inputs, and retained shell
fixture are frozen before compilation and required unchanged after all cells;
the linker is resolved before the first product link. Those roots contain the exact copied product files,
the relevant consumer and oracle, and a copied `/bin/sh` loader closure plus a
private Linux character `/dev/null` (type `char-device`, major `1`, minor `3`,
mode `0666`). The device is sealed by type, device numbers, and mode; it has no
content hash and the evidence reader never opens it. The shell closure is
explicitly an external fixture, not an owned runtime provider or a
shell-semantics claim. In the dynamic roots,
the fixture's pinned-musl `/lib/ld-musl-x86_64.so.1` replaces only the
product's unused compatibility alias of that same name.  The required
`/lib/ld-crabc-x86_64.so.1` entry remains the copied product loader for both
candidate entries; the receipt records this exceptional external alias path
and rejects every other alias change.  Successful and failed
runs remain under `.work/x86_64` for replay.

Run `python3 -B compat/x86_64/owned_wordexp_evidence.py capture-expected-inputs DYNAMIC_SYSROOT` in the pinned native image, adding `--static-sysroot STATIC_SYSROOT` when both product modes are selected. It retains a separate expected native tool/oracle seal; supplied products are validated but never rebuilt. A host replay must provide that independently captured file:
`python3 -B compat/x86_64/owned_wordexp_evidence.py validate --report REPORT
--expected-inputs EXPECTED_INPUTS`. It reconstructs a retained receipt on the
host and requires the fixed
`/workspace` source-mount translation, current source/product/header/object
identities, sealed retained pinned-musl inputs, exact retained link receipts
and ELF observations, and exact execution-tree bytes, modes, aliases, raw
results, and expected transcripts.  This proves only the bounded
installed-product component; it does not qualify a family or public support.

The separate expected-input seal compares the native compiler, linker, oracle
compiler, shell, timeout, chroot, and `ldd` identities with both retained
before/after input maps. It also compares the full pinned-musl oracle identity,
including the qualified loader and static archive. Product drivers remain bound
to the selected product internally. The caller checkout still checks the
oracle wrapper against `docker/x86_64-musl-oracle-gcc`; the fixture's `/bin/sh`
and `/lib/ld-musl-x86_64.so.1` closure remain bound to the sealed shell tool,
actual `ldd` output, and qualified pinned-musl runtime.
