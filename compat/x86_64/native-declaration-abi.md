# Native declaration ABI object and layout observations

`native_declaration_abi.py` is the finite native x86 companion for two facts
that the public header declaration inventory intentionally does not establish:
ordinary C/C++ object spelling for a selected callable declaration, and two
small record-layout facts needed by selected public data declarations.  Its
reviewed boundary is `native_declaration_abi.toml`.

The collector first replays exactly one retained
`header_declaration_inventory` envelope and reconstructs the existing checked
callable disposition and checked header matrix.  It does not carry a second
provider-name roster.  The existing disposition remains authoritative for the
selected provider, deferred, and ABI-only partitions.  Each selected raw
`FunctionDecl` has already been bound by
`native_callable_declarations.py` to its exact direct `(tree, input_header,
profile)` job, raw AST artifact, and physical declaring-header dependency.

For every resulting direct C or C++ job, this component generates a source
file containing only the installed direct include and a retained address
reference:

```c
#include <string.h>
static __typeof__(&memcpy) volatile reference __attribute__((used)) = &memcpy;
```

It never writes an `extern` declaration, casts an inferred type, or treats
Clang's raw `mangledName` observation as linkage proof.  The source gives each
probe holder an explicit private assembler spelling and uses data sections, so
its own `.rela.data.<holder>` table identifies the one emitted reference.  The
pinned native compiler emits the object; retained `readelf -sW` and
`readelf -rW` output then establishes one local default-visible eight-byte
`OBJECT` holder, its actual undefined `GLOBAL DEFAULT UND` target, and the
exact `R_X86_64_64` zero-addend relocation at that holder offset. The
relocation's ELF symbol index and spelling must join the same undefined row.

An emitted target equal to the C declaration spelling is retained as an
ordinary reference.  A different C++ target is retained as an
`ordinary-linkage-identity-mismatch`, with both the expected declaration
spelling and the object/relocation target.  This records a real installed
header language-linkage difference; it neither guesses a mangled spelling from
the AST nor turns a finite observation into a C++ compatibility pass.  Missing
or ambiguous holder relocation, malformed/truncated tool table, duplicate job,
or an ambiguous direct raw type/spelling pair fails closed before a result is
accepted.  If a selected declaration is genuinely header-defined or inline,
the retained source `function-body-present` observation is required and the
result records that bounded condition instead of fabricating an undefined
import rule.

The existing native `tgkill(int, int, int)` extension remains candidate-only:
it receives a candidate object job through the reviewed native-extension
matrix route and no invented musl reference job.  `__h_errno_location` is an
ordinary callable declaration in this object witness.  The `h_errno` macro's
per-thread storage, lifecycle, and accessor-to-storage semantics remain the
separate runtime obligation; this collector does not make a storage claim.

The layout projection replays the complete checked 1,337-row
`header_record_layout_matrix` report and exposes only `_ns_flagdata` element
facts from `arpa/nameser.h` and `in6_addr` facts from `netinet/in.h`, across
the existing profile roster.  It deliberately leaves `FILE` and `_IO_FILE`
opaque/incomplete and does not infer the selected `_ns_flagdata` provider's
array extent from an element layout.

## Collection and replay

Collection runs only in the pinned native Docker image, with the resolved image
identity in `CRABC_X86_DECLARATION_ABI_IMAGE_ID`.  The existing header receipt
must be physically retained below this checkout's `.work/x86_64` root: that is
the header reader's public physical-input boundary. A copied historical
receipt is still replayed from its raw inputs; it is not accepted merely from
its JSON hash. The collector records the admitted header-input identity, its
clean collector source seal, current imported-source snapshots, exact commands,
raw stdout/stderr/status, objects, and source files. It binds clang's path,
size, and digest to the replayed public-header compiler snapshot. The current
public-header receipt owns no compiler-resource dependency files, so this
component retains the complete compiler resource tree used by its `-isystem`
argument and the otherwise missing `readelf` executable. If a future header
receipt owns a resource header, that file's retained size and digest are joined
to this resource-tree copy. All output is a fresh direct child of
`.work/x86_64/native-declaration-abi`.

For example, after retaining a source-matching header receipt locally:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e CRABC_X86_DECLARATION_ABI_IMAGE_ID='crabc-core-evidence@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d' \
  -v "$PWD:/workspace" -w /workspace \
  crabc-core-evidence:x86_64@sha256:5990e55b88db10c7dc82bb57b8087be74282ddb0c50f1dc88f05cec63ce95b8d \
  python3 -B compat/x86_64/native_declaration_abi.py --collect \
    --header-report /workspace/.work/x86_64/header-declaration-input/report.json \
    --output /workspace/.work/x86_64/native-declaration-abi/clean-COMMIT
```

The host-side public reader executes no compiler or inspection tool.  It takes
the retained report and an explicit physical mapping for the same header
envelope, replays that envelope once, reconstructs the callable plan and
checked layout projection, rehashes retained source/object files plus this
component's retained resource-tree and `readelf` bytes, reparses the raw
symbol/relocation tables, and rejects any altered command, source, object,
header input, plan, or derived observation. It does not reopen historical
clang, resource-root, or readelf paths on the host:

```sh
python3 -B compat/x86_64/native_declaration_abi.py --validate-report \
  .work/x86_64/native-declaration-abi/clean-COMMIT/report.json \
  --header-report .work/x86_64/header-declaration-input/report.json
```

Both collection and replay report explicit `false` values for callable
declaration ABI completion, runtime semantics, family completion, promotion,
and public support.  This is a private finite observation component; it does
not select an archive/shared provider, prove full C++ language linkage, close
an ABI/family gate, or promote native x86 support.
