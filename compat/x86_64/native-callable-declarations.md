# Native callable declaration-form account

`native_callable_declarations.py` accounts for the selected native x86 C
callable declarations after one public replay of the retained
`header_declaration_inventory` receipt.  The small reviewed contract is
`native_callable_declarations.toml`.

The selection reader first validates the existing checked
`header_abi_matrix` report and the checked callable-disposition partition.  It
then passes a compact matrix projection, the exact selected provider names,
the exact deferred records, and feature ABI-only records to this adapter.  The
adapter does not invoke a compiler, reread retained compiler artifacts, parse
header text, select a provider, or infer a language-linkage result.

For every selected raw `FunctionDecl`, the account retains its original
occurrence index, input header and profile, physical declaration source,
compiler `qual_type`, optional desugared-type observation, mangled-name
observation, storage/definition/TLS observations, and unresolved linkage state.
Comparable rows require an exact multiplicity-preserving multiset of
`qual_type|mangled=<spelling>` under the same `(input_header, profile, name)`.
This compares spelling; it does not use an unmangled name as a C-linkage proof.

The one native extension is the existing exact `tgkill` contract.  It retains
all four visible profiles through each of its seven direct include roots, has
the fixed `int (int, int, int)` spelling and `tgkill` linker observation, has
no pinned-reference declaration, and remains a native extension rather than a
musl-equivalence claim.  Candidate project-only rows and the existing
oracle-not-applicable row remain separately categorized instead of acquiring a
synthetic reference match.

The existing disposition remains the authority for names.  Deferred names
remain deferred even when their raw declarations are observable.  In
particular, macro evidence cannot make `alloca` a callable provider, and the
consumer-supplied `seqbuf_dump` remains explicitly raw-declaration-unavailable.
Feature ABI-only names are retained as separate feature accounting and are not
made header requirements by this adapter.

Successful declaration accounting leaves provider selection, archive
extraction, complete language linkage, runtime semantics, family completion,
promotion, and public support open.  A historical header receipt can be
replayed and reported with its source drift, but cannot become same-source
closure evidence.

Run the focused parser/account test in the pinned image:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD:/workspace" -w /workspace \
  crabc-core-evidence:x86_64@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d \
  python3 -B -m unittest compat/x86_64/tests/test_native_callable_declarations.py
```
