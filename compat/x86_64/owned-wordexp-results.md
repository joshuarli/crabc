# Private x86 `wordexp_t` result transaction

`libc/src/c_abi/x86_64/owned_wordexp_results.rs` is the sole private owner for
the C result record selected by the x86 `wordexp` binding in
`libc/src/c_abi/x86_64/owned_wordexp.rs`. It exports no C symbol. Its private
API and focused fixtures document result invariants but do not by themselves
establish installed-product or public-platform support.

The result boundary is C ABI compatibility machinery. It owns only C-string
and vector lifetime after a deterministic engine has produced result bytes;
it does not parse shell source, evaluate an expression, start a child, map C
flags, suppress cancellation, or select a provider.

## Result-record contract

POSIX.1-2024 [`wordexp()`](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/wordexp.html)
requires an allocation-space failure to leave completed words available to the
caller, while an `WRDE_APPEND` call that returns a different error retains the
prior result record. The selected C binding classifies the engine outcome and has
two explicit choices:

- after success or `WRDE_NOSPACE`, call
  `WordexpResultTransaction::commit_completed()` to publish the completed
  prefix without another allocation;
- after every other error, drop the transaction. Drop frees only new C strings
  and the private staging vector, leaving an append record's vector pointer,
  count, offsets, and original strings exact.

An append transaction allocates a separate vector from the start. It copies
leading null offsets and old string *pointers*, never reallocates the old
vector, and retains the original vector until commit. Commit replaces the
record first and frees only the old vector; the old strings have become part
of the new vector. This is the condition that makes a late
`UndefinedVariable`, syntax, command, arithmetic, or output error safe to
roll back.

The selected musl 1.2.6 source remains the compatibility oracle for the
selected provider: release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`,
`src/misc/wordexp.c::{do_wordexp,wordexp,wordfree}` (MIT; SHA-256
`018c97c999cb60966a0376b71f2c8c187179ef31cf5ddde47b959e8f440e08f8`). This
new transaction is a private ownership design, not a source translation. It
retains the source `SIZE_MAX / sizeof(void *) / 4` maximum-offset guard and
adds checked `isize::MAX` bounds for every vector allocation and pointer
index.

`WordexpResultMode` and `WordexpResultOffsets` carry fresh/append and offset
ownership explicitly. The selected C binding supplies `Leading(we_offs)` only for
`WRDE_DOOFFS`, and `None` otherwise. Its `WRDE_APPEND` policy must preserve
that flag form across calls; a record does not retain a separate `DOOFFS` bit
when the count is zero. `WRDE_REUSE` remains a binding decision: the selected C
adapter releases its old record before beginning a fresh transaction.

Fresh setup failure writes `{ word_count: 0, words: NULL, offsets }`, so its
`WRDE_NOSPACE` result is releasable. Append setup failure does not alter the
old record. A fresh zero-word success still owns an allocated vector with its
leading null offsets and final sentinel. `release_wordexp_result_record()` is
the private `wordfree` helper for successful and partial-prefix records; it
frees every published C string and vector, then clears only `words` and
`word_count`. This deliberately matches selected `wordfree`: `offsets`
survives both a non-null-vector release and a null-vector fresh `NoSpace`
record, so a later `WRDE_REUSE | WRDE_DOOFFS` call retains the caller's
`we_offs`; a second release remains inert.

## Linear result input and unsafe boundary

`append_word_bytes(byte_len, bytes)` consumes the deterministic engine's linear
`ExpandedResultWord::bytes()` iterator once. It reserves a pointer slot plus
sentinel, allocates one exact NUL-terminated C string, validates that the
iterator yields exactly `byte_len` non-NUL bytes, and only then accepts that
word into the staging vector. Short, long, or NUL-containing streams free the
new string without accepting it. This avoids the former repeated
indexed-byte scan that would copy atom-backed words in quadratic time.

`WordexpResultTransaction::begin()` is unsafe because it takes a raw C record.
For `Fresh`, the selected C binding passes the offset value separately; the component
does not read `we_wordc` or `we_wordv`, which a C caller need not initialize.
For `Append`, the record, its vector, and all original strings must be live,
exclusively owned, and allocated by the same `WordexpResultAllocator` domain.
`WordexpResultAllocator::new()` requires C `malloc`/`realloc`/`free` failure
semantics, including preserving a live allocation when `realloc` returns
null. `commit_completed()` is unsafe because its caller alone knows whether
the final engine status is success/`WRDE_NOSPACE`; all other statuses must use
Drop. It is otherwise infallible: the total count is checked with each word
acceptance, and publication performs no allocation. The private release helper
has the corresponding valid-record and matching-allocator obligations.

## Focused evidence

`compat/x86_64/owned_wordexp_results_core_tests.rs` is a standalone
`rustc --test` root that imports only this owner. It injects tracking allocator
function pointers and never defines a C allocator symbol, so Rust's standard
test allocator is not interposed. The suite covers:

- initial vector, later string, and later vector-growth failures;
- fresh zero-word allocation; offset leading nulls; append pointer transfer;
- `WRDE_NOSPACE` prefix commit without another allocation;
- exact append rollback after a simulated late undefined-variable error;
- malformed linear byte streams, sentinels, original/new string lifetimes,
  `wordfree` release, no leaks, and no double frees;
- every allocation-failure position in a bounded two-word transaction; and
- the retained musl maximum-offset guard before any allocator request.

The focused check is run only in the pinned native image:

```bash
docker run --rm --init --platform linux/amd64 --workdir /workspace \
  --env TMPDIR=/workspace/.work/x86_64/tmp \
  --volume "$PWD:/workspace" \
  --volume "$PWD/.work/x86_64:/workspace/.work/x86_64" \
  crabc-core-evidence:x86_64 bash -lc \
  'mkdir -p /workspace/.work/x86_64/tmp /workspace/.work/x86_64/owned-wordexp-results-core &&
   rustc --edition=2021 --test compat/x86_64/owned_wordexp_results_core_tests.rs \
     -o .work/x86_64/owned-wordexp-results-core/tests &&
   .work/x86_64/owned-wordexp-results-core/tests --test-threads=1'
```

The real invocation binds both `TMPDIR` and the executable output below this
worktree's `.work/x86_64/` directory. It is focused component evidence for the
sole result transaction. The selected C binding already supplies the engine
sink, C status mapping, REUSE policy, cancellation envelope, and process/path
owners; this private check still does not establish installed C ABI/public
promotion or family/platform completion. Direct C/product POSIX/musl evidence
remains the separate validation boundary. Earlier focused results are retained
as provenance for these transaction invariants, not installed-product PASS
results.
