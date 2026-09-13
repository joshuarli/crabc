# Native x86-64 compiler-helper archive contract

[`x86_64-helper-contract.toml`](x86_64-helper-contract.toml) is the finite
producer contract for the one-member Rust archive `libcrabc-builtins.a`. It
selects exactly 23 unversioned `FUNC GLOBAL DEFAULT` C entries in each distinct
installed archive placement: `static-builtins` and `dynamic-builtins`. Equal
archive bytes do not merge those placements.

The named definitions live in [`src/lib.rs`](src/lib.rs): `Uint128` is the
`#[repr(C)]` low-word/high-word carrier for the native C `__int128` ABI;
`ComplexDouble` is the two-`f64` C complex return carrier for `__muldc3`; and
the `divmod` and `*oti4` entries require the writable result slots documented
at their definitions. The TOML records every exact source signature and C ABI
role. [`build_x86_64.py`](build_x86_64.py) reads that contract before compiling
and rejects a source-definition or archive-roster drift.

Run the aggregate proof only inside the established pinned native x86 evidence
container, with a fresh checkout-local work directory:

```sh
CRABC_X86_COMPILER_HELPER_IMAGE=crabc-core-evidence@sha256:<pinned-image-id> \
CRABC_COMPILER_HELPER_WORK_DIR=/workspace/.work/x86_64/compiler-helper-aggregate \
  bash /workspace/builtins/run_x86_64_compiler_helper_aggregate.sh
```

The runner builds the candidate archive twice, compiles one freestanding C
object that directly imports every selected helper, and requires an
archive-free link to fail at those exact imports. Its archive-backed ET_EXEC
must have no interpreter, TLS, dynamic dependency, unresolved symbol, ambient
CRT, or foreign compiler-runtime input. It compares the fixed transcript with
a separate pinned-musl C object whose arithmetic, checked-overflow, and bit
operations are reference operations rather than direct helper calls. The two
compiled object identities are retained separately in `report.json`.

[`compiler_helper_evidence.py`](../compat/x86_64/compiler_helper_evidence.py)
seals the runner source before execution, records each actual command and raw
stream, retains the pinned musl compiler-wrapper bytes, and reconstructs the
aggregate receipt on host replay. Replay requires each command's exact argv
and the named archive/object/executable input relation; it does not accept an
unrelated `nm`, `readelf`, or `echo` transcript. It also rereads the retained
archive and candidate ELF on the host, rather than trusting command text for
their roster or ET_EXEC facts. Its
source-only writer/reader fixture is a schema control, not product evidence.

This component does not select the 23 same-named `candidate-shared` rows,
complete a compiler-helper family, qualify a runtime, or promote native public
support. The single observed static ordinary `__popcountdi2` import is attached
only when fresh same-source static/dynamic products, complete ELF facts, and
the existing public-data ordinary-link receipt are supplied. Historical `3e`
products remain historical and must not be relabeled by this contract.

At that supplied-product boundary, an aggregate receipt is optional but
meaningful only when present: the reader first replays it, then requires its
full clean product-source identity and retained archive SHA-256/size to match
both distinct installed archive paths. Without that join, placement extraction
is explicitly partial and makes no aggregate C-ABI claim for either installed
role.
