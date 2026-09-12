# Upstream wordexp policy observations

`owned_wordexp_source_policy_probe.c` is one finite public-C companion for
twenty reviewed outcomes in the untouched `libc-test` `functional/wordexp`
unit.  It is installed-product evidence for the selected x86 wordexp
evaluator.  It neither changes the upstream unit nor claims a passing
aggregate, family, or public x86 support.

The ordinary workload includes this source after
`owned_wordexp_engine_probe.c` and calls `wordexp_source_policy_run()`.  The
optional `CRABC_WORDEXP_SOURCE_POLICY_PROBE_MAIN` form includes the engine
helpers itself and exposes the same no-argument execution.  The parent
workload must compile this source once through installed project headers, then
link that unchanged object to fixed musl and each candidate product.

## Observation contract

The probe saves and restores `X`, `UNSET`, `PATH`, and its private marker
variable.  It starts with both `X` and `UNSET` unset.  Its private `PATH`
contains only an executable `cmd` marker: an implementation that evaluates an
otherwise forbidden $(cmd) body creates the marker.  The marker is cleared
before and after every input.  The desired candidate has `effect=0` in every
record.  The marker is a direct command-effect witness; it is not a shell
fallback or a claim about an external shell.

There are exactly twenty stdout records, in table order, with this shape:

```text
owned-wordexp-source-policy: case=NN status=R count=N wordhex=W stderrhex=D effect=E env=V
```

`wordhex` is `-` for zero successful words and for a nonzero status.  Otherwise
it is a comma-separated sequence of `byte-length:lowercase-hex` words; an
empty word is therefore `0:`.  `stderrhex` is `-` only when captured fd 2 is
empty.  The fresh `wordexp_t` record is explicitly zero-initialized for every
call.  Every successful record requires a non-null vector and its null
terminator, including a zero-word result.  Error records never dereference or
free an unspecified non-`NOSPACE` result vector.

`env=0` means that both `X` and `UNSET` remained unset immediately after that
call; `env=1` records a parent-environment mutation.  A successful result with
an unknown vector shape is rendered as an explicit non-hex `wordhex` token
such as `!record`, `!offset`, or `!unterminated`; the fixture does not free
that record and the reader must reject the trace.

A zero process exit means the fixture completed its captures, marker checks,
and environment restoration.  It does not mean the trace satisfies the owned
policy, and the probe never prints `PASS` or a generic source-red verdict.
The retained reader must require all twenty records, exact candidate status,
count, successful word bytes, empty candidate diagnostics, `effect=0`, and
`env=0`.  It separately pins the full fixed-musl trace as an observation.  A
fixed-musl
outcome never waives a candidate mismatch, and an oracle trace must not be
rewritten to make the upstream aggregate pass.

## Candidate policy

All candidate rows require `stderrhex=-`, `effect=0`, and `env=0`.  Error rows require a
fresh zero count and `wordhex=-`; successful rows show the exact encoded word
bytes.

| Case | Exact JSON-style source bytes | Flags | Required candidate observation |
| ---: | --- | --- | --- |
| 01 | `"$#"` | `0` | `0`, `count=0`, `wordhex=-` |
| 02 | `")"` | `0` | `WRDE_BADCHAR`, `count=0` |
| 03 | `"("` | `0` | `WRDE_BADCHAR`, `count=0` |
| 04 | `"$UNSET ) $UNSET"` | `WRDE_UNDEF` | `WRDE_BADCHAR`, `count=0` |
| 05 | `"$UNSET ( $UNSET"` | `WRDE_UNDEF` | `WRDE_BADCHAR`, `count=0` |
| 06 | `"$UNSET $( $UNSET"` | `WRDE_NOCMD \| WRDE_UNDEF` | `WRDE_SYNTAX`, `count=0` |
| 07 | `"$UNSET $(echo $UNSET"` | `WRDE_NOCMD \| WRDE_UNDEF` | `WRDE_SYNTAX`, `count=0` |
| 08 | ``"$UNSET ` $UNSET"`` | `WRDE_NOCMD \| WRDE_UNDEF` | `WRDE_SYNTAX`, `count=0` |
| 09 | ``"#!@$^%&*(_+=<<-0>[{`${"`` | `WRDE_NOCMD` | `WRDE_BADCHAR`, `count=0` |
| 10 | `"#'\necho x\\'"` | `WRDE_NOCMD` | `0`, `count=1`, `wordhex=9:230a6563686f20785c` |
| 11 | ``"a`b"`` | `WRDE_NOCMD` | `WRDE_SYNTAX`, `count=0` |
| 12 | `"${X-\"$\"{A}B}"` | `0` | `WRDE_BADCHAR`, `count=0` |
| 13 | `"${X-$''}"` | `WRDE_NOCMD` | `0`, `count=1`, `wordhex=0:` |
| 14 | `"\"${X-$'$(cmd)'y}\""` | `WRDE_NOCMD` | `WRDE_CMDSUB`, `count=0` |
| 15 | `"$((${X-$'$(cmd)'y}))"` | `WRDE_NOCMD` | `WRDE_CMDSUB`, `count=0` |
| 16 | `"${X=1} $((${X-'}))"` | `WRDE_NOCMD` | `0`, `count=2`, `wordhex=1:31,1:31` |
| 17 | `"$((cmd #(\n)) )"` | `WRDE_NOCMD` | `WRDE_BADCHAR`, `count=0` |
| 18 | `"$((cmd #(\n))\n)"` | `WRDE_NOCMD` | `WRDE_BADCHAR`, `count=0` |
| 19 | `"x \\\n\\\n#);"` | `WRDE_NOCMD` | `WRDE_BADCHAR`, `count=0` |
| 20 | `"$((1 + #x))\n1))"` | `WRDE_NOCMD` | `WRDE_BADCHAR`, `count=0` |

Case 01 selects the owned finite treatment for an unspecified special
parameter.  Cases 02--05 retain unquoted-parenthesis errors.  Cases 06--08
retain malformed input as syntax even when a lexical `WRDE_NOCMD` command
marker is also present; POSIX does not require an error-detection order for
multiple errors.  Cases 09--12 retain the selected literal-initial-`#`,
naked-brace, and unclosed-backquote boundaries.

Case 10 has the literal bytes `#`, newline, `echo x`, and backslash.  Case 13
retains the one empty field introduced by the selected dollar-single-quoted
default.  In cases 14 and 15 apostrophes are literal in their effective
double-quoted and arithmetic contexts, respectively, so their command marker
remains subject to `WRDE_NOCMD`.  Case 16 checks the call-local assignment
path: its default containing the apostrophe is unselected, and the two output
words are both `1`.

Cases 17 and 18 use the documented arithmetic-versus-command-substitution
heuristic.  After the comment consumes `#(`, their definite extra outer close
leaves a naked close outside the locally reconsidered body and therefore
retains `WRDE_BADCHAR`.  Cases 19 and 20 retain the same unquoted closing and
comment-sensitive lexical boundary after physical backslash-newline joining.

## Source and standards basis

The source spellings were checked against the retained raw result from the
unchanged source unit,
`.work/x86_64/wordexp-selection-review/upstream-functional-96a4a847.log`.
That log is byte-spelling evidence only.  It does not turn any failed upstream
case into an aggregate waiver.

The policy is bounded by the POSIX `wordexp` interface, the
[Shell Command Language](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html),
the [XSH 2.3 error-ordering rules](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html#tag_16_03),
and [XRAT C.2.6.3](https://pubs.opengroup.org/onlinepubs/9799919799/xrat/V4_xcu_chap01.html)
for the arithmetic ambiguity heuristic.  The direct interface reference is
[POSIX `wordexp`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/wordexp.html).
These sources constrain the twenty named outcomes; they do not authorize a
generic shell fallback, a glibc comparison, or an unbounded exception list.
