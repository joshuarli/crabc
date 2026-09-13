# Native public-data declaration contract

`native_data_declarations.py` accounts for the selected native x86 public-data
header surface.  It is a narrow declaration adapter for the 33 selected object
contracts: 19 installed variables, the `h_errno` accessor macro, and 13
ABI-only spellings.  The reviewed rules live in
`compat/x86_64/native_data_declarations.toml`.

The adapter consumes the envelope already returned by
`header_declaration_inventory.validate_report` and the exact selected
`object_contracts` supplied by native ABI selection.  Its public functions are:

```python
load_contract(path=CONTRACT_PATH) -> dict[str, Any]
validate_selected_object_contracts(selected_objects, contract=None) -> list[dict[str, Any]]
account_declarations(header_report_envelope, selected_objects, *, contract=None) -> dict[str, Any]
```

It does not run a compiler or replay raw compiler artifacts.  The caller must
first use the declaration inventory's public retained-input replay.  This
adapter then requires the complete report envelope and recomputes its finite
job roster, collection counts, summary, and status from the retained raw-derived
rows.  That rejects a selected-row projection or an internally inconsistent
report, while the declaration inventory remains the owner of raw-byte and
retained-input authentication.  `matches_retained = true` requires an empty
current-source difference list.  A historical report with a nonempty difference
list can be accounted for, but its result is marked
`historical-source-drift-with-explicit-boundaries` instead of presenting it as
same-source evidence.

`contract=` is accepted only when it is exactly the normalized result of this
module's reviewed TOML.  It is a convenience for a caller that already loaded
the canonical contract, never an alternate type, site, or profile policy.

## Rules being checked

For each installed variable, the TOML records its physical owning installed
header, direct profile set, candidate and pinned-musl source locations, exact
Clang `qual_type`, the pinned compiler observation that no separate desugared
type was emitted, external declaration/storage/TLS observations, unmangled
linker spelling, and C++ `extern "C"` context.  Candidate and pinned-reference
rows must each meet these source-derived rules.  Every selected physical
occurrence is checked against its owning site, including transitive includes;
the direct owner-header roster remains separately required and cannot be
replaced by a transitive row.  The output retains direct, selected-physical,
and selected-transitive counts rather than silently treating the latter as
unexamined coverage.

The three stream objects illustrate why type spelling is retained exactly:
`stdin`, `stdout`, and `stderr` are `FILE *const`.  Their pointer objects are
const in an application declaration while their pointed-to `FILE` targets are
mutable; `source_mutable = true` does not erase the `const` pointer qualifier.
`_ns_flagdata` remains an incomplete `const struct _ns_flagdata[]` declaration.
The selected provider's 16-entry extent belongs to separate provider/layout
evidence and is never inferred here.

`h_errno` is deliberately distinct from a header object declaration.  The
adapter requires the direct `netdb.h` object-like macro, its exact
`(*__h_errno_location())` expansion, and the four actual visible profiles.  It
requires zero `VarDecl` occurrences named `h_errno`, then separately checks
every selected physical accessor declaration's C/C++ spelling, no-desugaring
observation, and linker name.  Clang JSON reports that accessor's
storage/linkage status as `unresolved-from-json` because its source spelling
has no explicit `extern`; the adapter retains that unknown instead of upgrading
it from a mangled-name heuristic.

The 13 ABI-only spellings must have no declaration or macro occurrence in the
finite candidate or pinned-reference header/profile roster.  Their ELF
provider, type layout, aliases, lifecycle, and runtime behavior remain outside
this adapter.

`cxx17-strict` is a C++ language profile.  In the pinned compiler environment
it exposes the GNU feature surface, so direct visibility follows the retained
profile result rather than treating the label as an invented strict-macro
state.

## Boundaries and evidence

A successful `selected_data_declaration_status` proves only this selected
header-declaration agreement.  The result explicitly leaves provider selection,
object/record layout, runtime behavior, family completion, and public support
unclaimed.

Development checked the retained full declaration receipt at
`native_abi_selection_manifest/.work/x86_64/header-declaration-inventory/full-d8e03de0/report.json`
(SHA-256 `dac12db499d4938aa12cc3ece02e0aa42c46aa25e17604ca01af74064fb8f1ab`)
with one post-repair account pass, recorded under this worktree's
`.work/x86_64/native-public-data-declarations/repair-0f605b56/full-receipt-account-r4/`.
That receipt binds the report hash and the adapter, reviewed TOML, selected
object-contract, and source revision identities before and after accounting.
The source-oracle excerpts under `source-contract/` compare the relevant installed
headers with pinned musl 1.2.6 using
`crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d`.
Those files are development evidence, not an input dependency of the adapter.

Run the focused contract test with:

```sh
python3 -B compat/x86_64/tests/test_native_data_declarations.py
```
