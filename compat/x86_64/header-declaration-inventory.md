# Native header declaration occurrences

An installed header can declare an external function, an addressable object,
an inline implementation, or a macro. These have different provider and
consumer requirements. A declaration summary cannot recover those distinctions
after repeated declarations have been collapsed.

`header_declaration_inventory.py` retains compiler observations before that
collapse. It uses the existing `header_abi_matrix.toml` header/profile roster,
`header_callable_inventory.py` compiler commands and source-location helpers,
and `header_abi_matrix.py` compiler process controls. The existing collapsed
ABI matrix keeps its own output contract. The new receipt supplies enumerable
inputs to [native ABI selection](native-abi-selection.md).

## Collection and replay

Collect in the pinned native container through the dispatcher:

```bash
mkdir -p .work/x86_64/header-declaration-inventory
./scripts/dev-x86_64.sh header-declaration-inventory collect \
  --output .work/x86_64/header-declaration-inventory/current \
  --workers 4 --timeout-seconds 120
```

The output directory must be fresh. Compiler jobs use bounded concurrency and
isolated temporary directories under the checkout's `.work/`; raw evidence is
retained for replay. Collection includes the complete finite candidate/reference
header/profile roster and records the existing exact oracle exceptions. It does
not turn an unsuccessful compiler job into an empty successful declaration set.
The container uses a resolved image digest, a read-only source mount, and no
network. No runtime product is built by this command.

Replay the retained receipt on the native host:

```bash
./scripts/dev-x86_64.sh header-declaration-inventory validate-report \
  .work/x86_64/header-declaration-inventory/current/report.json
```

Replay needs neither a compiler execution nor the original container's `/opt`
trees. Original compiler, include, and dependency paths remain observations;
explicit mappings identify their retained physical copies. The reader verifies
those bytes, reconstructs the roster and derived records, and rejects missing,
additional, substituted, or malformed evidence. It compares current selecting
source contracts separately from the retained collector inputs. A valid
historical report keeps those differences visible and cannot establish
same-source selection closure. The CLI prints a compact validation result with
the report identity, retained collection status, and current-source comparison;
it does not repeat the full declaration inventory.

Physical evidence may remain in a preserved sibling worktree under the
canonical checkout's `.work/`. It is not reassigned to the selecting checkout
merely because both use `/workspace` inside their containers. The public reader's
replay result carries the unchanged report and the recomputed current-source
comparison; selection consumes both.

## Observation boundaries

The `crabc.x86_64-header-declaration-inventory/v1` receipt retains:

- Each applicable function and file-scope variable declaration occurrence,
  its direct include/profile, physical declaring header and source span, and
  explicit provenance resolution. An include-stack pathname is not a physical
  declaration source. Local variables in function or method bodies are excluded.
- Spelled and available desugared types, storage/TLS observations, assembler-name
  observations, language-linkage context, initializer information, redeclaration
  relationships, and references to the raw AST. Unknown fields or semantics
  remain explicit.
- Ordered compiler preprocessor definition and undefinition events, including
  repeated or changed definitions, separately from the derived active macro
  view. Macro occurrences are not fabricated variable declarations.
- Raw AST/preprocessor output, commands and outcomes, compiler/tool identities,
  source contracts, pin markers, include dependencies, and collector source
  stability observations needed to replay the result.

Physical collection completeness is independent of semantic interpretation.
Clang JSON does not directly state linkage or definition status for every C++
declaration. A mangled-name prefix is not a linkage classifier. Missing semantic
information stays unresolved; it does not invalidate an otherwise complete raw
collection or create a new public ABI requirement. Selection applies each
unresolved fact to the actual obligation that needs it.

For example, the installed `FILE *const` stream declarations constrain the
pointer as seen by an application. They do not make the pointed-to stream
immutable. `_ns_flagdata` has an incomplete array declaration; the declaration
does not supply its source-selected table extent. `h_errno` is observed through
its header macro, while its separately selected compatibility object still needs
an ABI owner. None of these distinctions can be reconstructed from an ELF object
size alone.

This collector does not select providers, evaluate object or record layout,
prove archive extraction, or execute data/alias/lifecycle workloads.
`header_record_layout_matrix.py` and the selected runtime components retain
those responsibilities. Native ABI selection joins their evidence with these
declarations; this receipt alone does not close an ABI family or promote a
platform.
