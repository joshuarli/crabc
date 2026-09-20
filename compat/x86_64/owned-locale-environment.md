# Owned locale environment selection

An empty locale name selects a locale from the process environment. This is
C ABI compatibility machinery within the existing `C`, `POSIX`, and
`C.UTF-8` profile, not a request for a general locale database.

`locale_multibyte::environment_locale_mode` follows pinned musl 1.2.6
`src/locale/locale_map.c`: the first nonempty value in `LC_ALL`, the category's
variable, and `LANG` wins; if none exists, use `C.UTF-8`. Each selected category
must resolve to a supported name. Only CTYPE has different built-in data.
`setlocale` validates all selected categories before publishing global state.
A failure leaves the previous state intact. Returned mixed-category strings
keep the existing serialization and lifetime rules.

`locale_objects::newlocale` follows `src/locale/newlocale.c` for category
selection: masked categories use the supplied name, unmasked categories
inherit a supplied base, and a null base resolves unmasked categories from the
environment. A zero mask does not dereference the name. These built-in objects
remain immutable and allocation-free; failure reports `ENOENT` and preserves
the base. A per-thread `uselocale` selection remains independent of global
changes. Concurrent environment mutation is outside the borrowed `getenv`
contract.

The composition is gated by `x86-owned-static-runtime` (also selected by the
owned dynamic runtime). Default freestanding locale artifacts retain their
environment-free contract and empty-name rejection. Unsupported names still
fail under the project profile, unlike musl's general arbitrary-name map.

`libc_locale_environment_probe.c` tests supported-name precedence, empty
variable fallback, the default UTF-8 selection, category masks, inherited and
null bases, zero-mask name handling, and global/thread-object independence.
Its optional `profile` scenario checks transactional rejection of an
unsupported environment name separately from musl differential behavior.
The `object` scenario isolates `newlocale` from the earlier `setlocale`
regression. Native reports must keep those scenarios distinct.

Initial same-installed-object development regressions against frozen
`26dfb153` products passed pinned musl and failed the candidate at status 10
(`setlocale`) and status 20 (`newlocale`). These receipts are retained in the
parent checkout under `.work/x86_64/locale-environment-regression/`; the
regressions do not qualify the frozen products or complete `locale.core`.

`owned_locale_probe.c` includes these assertions in the one installed-header
object used by `run_owned_locale.sh`. The v3 reader seals the shared source,
requires its exact compiler include trace, and admits no other checkout source
as a header origin. It runs common behavior against musl and requires a
separate candidate-only profile transcript in all six product modes.
