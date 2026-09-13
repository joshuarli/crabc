# Native x86-64 compiler-helper archive contract

[`x86_64-helper-contract.toml`](x86_64-helper-contract.toml) is the finite
producer contract for the one-member Rust archive `libcrabc-builtins.a`. It
selects exactly 23 unversioned `FUNC GLOBAL DEFAULT` C entries in each distinct
installed archive placement: `static-builtins` and `dynamic-builtins`. Equal
archive bytes do not merge those placements.

The owned dynamic builder also passes that exact archive to the one `libc.so`
link because selected Rust libc leaves can need compiler-generated operations.
`scripts/build_x86_64_owned_dynamic_sysroot.py` uses
`--exclude-libs=libcrabc-builtins.a` only for that shared link. Consequently,
the same 23 definitions remain `FUNC LOCAL DEFAULT` in libc's full `.symtab`
and are absent from libc's `.dynsym`; they are not a shared-libc API. The
archive builder rejects every extra external definition, so this archive-name
rule cannot localize another owner. It does not change either installed archive
or an application/DSO's ordinary dynamic-driver link, which still names the
installed `usr/lib/libcrabc-builtins.a` after `libc.so`.

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
support. The private shared placement is source-owned separately from public
selection and needs a fresh installed-product proof. The single observed static
ordinary `__popcountdi2` import is attached only when fresh same-source
static/dynamic products, complete ELF facts, and the existing public-data
ordinary-link receipt are supplied. Historical `3e` products remain historical
and must not be relabeled by this contract.
The ordinary report seals link receipts relative to the checkout; each driver
receipt names its map and trace relative to its own directory. The helper
reader uses the ordinary reader's identity resolver for the outer receipt,
including its recorded hash and size, before reading the adjacent map and trace.

`shared_libc_archive_policy_from_product` lets the fixed-C producer reader
admit this exact helper archive rule when their inputs share a product. It
joins the source policy and single archive link argument to the authenticated
installed archive and its private libc copy. It grants no exclusion to another
archive and makes no family or public-provider selection.

Run the focused shared-placement proof inside the same pinned native Docker
environment used by the dynamic components. It is directly callable there; it
does not add a dispatcher command:

```sh
CRABC_X86_COMPILER_HELPER_IMAGE=crabc-core-evidence@sha256:<pinned-image-id> \
CRABC_COMPILER_HELPER_SHARED_WORK_DIR=/workspace/.work/x86_64/compiler-helper-shared-placement \
  bash /workspace/builtins/run_x86_64_compiler_helper_shared_placement.sh
```

It builds one private materialized product, validates its installed manifest
before and after execution, validates the installed archive and producer/link
provenance, then checks all 23 libc `.symtab` rows and `.dynsym` absence. The
fixture executable and application DSO are copied only to a separate private
execution root, so the observed installed product remains unchanged. A direct
executable and a helper-using application DSO must each
extract `crabc-builtins.o` from the installed archive under the existing owned
driver. A strong exported `__popcountdi2` in a separate executable cannot
preempt libc's direct allocator bitmap-helper transfer. This is focused product
evidence only; it is not a dynamic qualification or a complete helper family.

To reuse the selected dynamic product of a larger collection, pass its absolute
checkout-local path as the runner's sole argument. The owning product reader
admits it before and after execution, and fixtures still run in a separate
copy. That path omits only `product-build`; it retains every placement,
ordinary-consumer, interposition, source-seal, and product-invariance check.
Output paths inside the supplied physical product are rejected before creating
the evidence directory, so an invalid invocation preserves the sealed input.

At that supplied-product boundary, an aggregate receipt is optional but
meaningful only when present: the reader first replays it, then requires its
full clean product-source identity and retained archive SHA-256/size to match
both distinct installed archive paths. Without that join, placement extraction
is explicitly partial and makes no aggregate C-ABI claim for either installed
role.
