# X86 wordexp engine C ABI regressions

`compat/x86_64/owned_wordexp_engine_probe.c` is a direct C-ABI regression
fixture for the selected Linux/x86-64 word-expansion provider. It adds no
installed declaration and does not qualify x86 support. The selected
`libc/src/c_abi/x86_64/owned_wordexp.rs` is the product boundary binding the
engine, process/path adapters, and `owned_wordexp_results.rs` transaction owner.

The source is included by the one-object product probe or built with
`CRABC_WORDEXP_ENGINE_PROBE_MAIN`, which supplies a standalone `main` taking
one selector. Its helpers all begin with `wordexp_engine_`; its static
assertions require little-endian Linux/x86-64 LP64 `wordexp_t`.

## Selector contract

Every selector writes one standard-output result line:

```text
owned-wordexp-engine-NAME: PASS
owned-wordexp-engine-NAME: SOURCE-RED REASON
owned-wordexp-engine-NAME: FAIL STEP
```

`SOURCE-RED` records one exact retained source shape. It is never an
alternative selected-candidate pass. A receipt must require `PASS` for the
candidate and reserve `SOURCE-RED` for the old provider or pinned-musl
control; all other shapes are `FAIL`.

| Selector | Direct C ABI invariant |
| --- | --- |
| `--engine-literals` | Unrecognized dollar spellings inside double quotes remain literal exactly once; a selected unquoted parameter default expands a leading tilde through the current HOME; removable line joins between paired opening or closing parentheses retain arithmetic. These cases agree with pinned musl. |
| `--engine-undef` | Direct unset expansion with `WRDE_UNDEF` returns `WRDE_BADVAL`; set-empty succeeds as one empty word; skipped/default/assignment parameter branches have their typed lazy behavior. |
| `--engine-append-rollback` | An offset-two append followed by undefined-variable and generic parameter errors retains vector address, count, offsets, leading nulls, sentinel, and original bytes. |
| `--engine-reuse-offsets` | `WRDE_REUSE | WRDE_DOOFFS` retains three leading offsets through release and replacement. |
| `--engine-parameter-word` | A selected parameter-error word runs its marker command once before `WRDE_SYNTAX`; an unselected branch skips it. `WRDE_NOCMD` returns `WRDE_CMDSUB` for both syntactic command forms without a marker. |
| `--engine-diagnostics` | Quiet selected errors write no diagnostic. `WRDE_SHOWERR` emits raw fd-2 `wordexp: NAME: MESSAGE\n` output, distinguishing the omitted default body from an explicit-empty body, without changing parent `ferror(stderr)`. |
| `--engine-sigpipe` | A child with default `SIGPIPE` and a broken fd 2 dies by `SIGPIPE`; ignored-`SIGPIPE` returns `WRDE_SYNTAX` with an unchanged append record and restores the complete prior action. |

Each checked release sets `errno = E2BIG`, calls `wordfree`, and requires
that errno to remain unchanged while count/vector clear and offsets survive.
Cleanup frees only a still-live vector, avoiding a second release of a cleared
record.

The exact pinned-musl control output is:

```text
--engine-undef            SOURCE-RED wrde-undef-untyped
--engine-append-rollback  SOURCE-RED wrde-undef-untyped
--engine-reuse-offsets    PASS
--engine-parameter-word   SOURCE-RED nocmd-parameter-word-badchar
--engine-diagnostics      SOURCE-RED quiet-shell-diagnostic
--engine-sigpipe          SOURCE-RED shell-child-no-raw-sigpipe
```

The undefined append source result must expose precisely the offset-two
three-word record `old-one old-two new-root`. The NOCMD source result requires
both branches to return `WRDE_BADCHAR`, retain `errno`, leave an empty
releasable record, and leave no marker. The quiet source result requires the
exact pinned shell line for the fixture name. The broken-fd source result
requires child exit sentinel 122 plus the ignored-signal rollback result.
These narrow checks prevent arbitrary candidate failures being renamed as
source observations.

## Private result allocation control

`libc/src/c_abi/x86_64/owned_wordexp_result_failure.rs` has one private
interface for the selected C binding:

```rust
pub(super) fn allocator() -> super::owned_wordexp_results::WordexpResultAllocator
```

The module is absent without
`crabc_owned_wordexp_result_private_test`. Under that cfg only, it exports
`__crabc_test_wordexp_result_budget(size_t)` and
`__crabc_test_wordexp_result_unlimited(void)`; normal archives export neither
symbol.

The hook is an allocator handle, never C allocation-symbol interposition. Its
vector/string requests reach the real selected `malloc` or `realloc`; its
frees always reach the real selected `free`. A finite budget permits its
number of result allocation requests, then forces the next allocation or
reallocation to null. Forced reallocation does not invoke real `realloc`, so
the old allocation stays live. The controls allocate nothing and do not set
errno. They are unsafe because the fixture must serialize this process-global
test state with every active result transaction. Unlimited is the default.

With `CRABC_WORDEXP_RESULT_PRIVATE_TEST`,
`--engine-result-failure` sweeps bounded budgets without assuming a stable
allocation count. It checks fresh words, an offset-two zero-word record,
thirteen-word vector growth, and offset-three append. Each accepted prefix
must have leading nulls, exact words, a final sentinel, retained offsets, and
a successful release while the finite budget remains active. A command case
finds a one-word `WRDE_NOSPACE` prefix of `one two $(...)` and requires its
marker absent; a complete success must create one marker byte. Thus failure
before the second word prevents later command execution.

The `wordexp-result-private` runner proves normal-symbol
absence, then links a separate cfg-only archive with this standalone fixture
and runs that selector under an absolute mode-0700 `TMPDIR`. It is private
component evidence, not installed-product qualification.

## Containment and checks

The fixture saves/restores each environment variable it changes. It creates
markers with `mkdtemp` below an absolute `TMPDIR` and passes their path only
through a quoted environment expansion. Stderr capture operates on fd 2 and
does not use or reorient the caller's `FILE`; the only signal mutation is
restored before return.

Pinned native C compilation of both normal and private selector surfaces writes
only under `.work/x86_64/`. The ordinary pinned-musl run above is a source
control. Neither compilation nor this component's isolated hook harness
establishes candidate execution. The installed-product receipt and private
allocation runner separately validate their declared runtime boundaries.
