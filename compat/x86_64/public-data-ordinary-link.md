# Public-data ordinary-link evidence

public_data_ordinary_link_evidence.py is the narrow data counterpart to the
selected callable/provider work. It proves ordinary C linking and addressability
for the exact 32 typed object contracts placed in both candidate-static and
candidate-shared by native-abi-selection.toml.

The selection TOML is the authority. The component derives its object names,
ELF type/binding/visibility/size/alignment, source references, and ten named
source aliases from that file. It does not consume the historical ignored
selection audit. A policy update that changes the static/shared selection,
alias roster, or fixed probe ABI-only declarations fails before collection.

_dl_debug_addr is deliberately excluded: it is typed as shared-only and
continues to belong to loader_debug_abi_evidence.py. The component does not
turn an address coincidence into an alias. An alias is checked only when the
typed contract names its target, and only after the two static definition rows
have the same definition-domain section, value, type, and size.

## Inputs and collection

Run the collector in the pinned native environment only:

    ./scripts/dev-x86_64.sh public-data-ordinary-link collect \
      --static-preparation .work/x86_64/.../preparation.json \
      --static-product .work/x86_64/.../products/primary \
      --dynamic-product .work/x86_64/.../dynamic-product \
      --output .work/x86_64/public-data-ordinary-link/RECEIPT

The dispatcher requires a fresh physical output below the producing checkout's
`.work/x86_64/public-data-ordinary-link/` directory. Inputs must also be physical
children of that checkout's `.work/` tree. The
collector requires CRABC_X86_PUBLIC_DATA_IMAGE_ID=crabc-core-evidence@sha256:...
supplied by the dispatcher.

The output cannot be inside the static preparation receipt's parent cohort,
the prepared static product, or the materialized dynamic product. Those trees
are inputs for the whole receipt, including archive extraction and
reproduction files that the static reader consumes. The dispatcher uses the
normal `/workspace/.work` mapping and the default core Cargo volume; this
component records checkout-relative paths and deliberately provides no virtual
work-root mapping for alternate environment values.

Collection first calls owned_posix_static_products.validate_receipt and
owned_dynamic_qualification.product_identity. The provided static product
must be exactly the preparation receipt's primary tree. The static clean
source identity and dynamic materialization source digest must agree. Neither
path invokes a sysroot builder. The static preparation reader uses its existing
contained .work/x86_64/tmp extraction scratch; the dispatcher must make only
that scratch and the fresh output writable.

The fixed public_data_ordinary_link_probe.c takes an address of every selected
object. It uses installed public declarations where they exist. Its explicit
declarations are limited to objects whose typed declaration_kind is abi-only;
the h_errno macro is deliberately undefined only to name its selected backing
object. The policy's source_mutable describes storage mutability. It does not
make a pointer object mutable merely because a public declaration contains a
non-const pointee, and it does not make stdin, stdout, or stderr immutable
merely because their installed declarations are FILE *const.

The collector compiles the one probe object, links it through:

- candidate static and static PIE, each with the static driver's required
  --link-receipt;
- candidate dynamic PIE and dynamic non-PIE;
- pinned-musl static, dynamic PIE, and dynamic non-PIE.

It keeps raw command JSON, stdout, stderr, status, consumer object, executable
ELF headers/symbols/relocations, all four candidate link receipts, and a
captured pinned-musl oracle. The static modes execute directly. The four
dynamic candidate/oracle consumers execute by kernel and direct-interpreter
entry in their contained roots. Every native command starts in an owned process
group; a timeout retains `timed-out:<status>` and terminates that group before
the collector returns. The component seals the installed static/dynamic
drivers, their resolved source compiler and linker, the oracle wrapper,
`/usr/bin/env`, `/usr/bin/readelf`, and both parts of Alpine's `chroot`
multicall contract: the absolute `/usr/sbin/chroot` applet invocation and its
sealed physical `/bin/coreutils` bytes. It uses the applet spelling in every
absolute `chroot` argv rather than depending on `PATH` under `env -i`; calling
the sealed multicall binary directly would lose its argv[0]-selected command.

The static musl link also retains the exact wrapper-selected musl `libc.a`,
`Scrt1.o`, `crti.o`, and `crtn.o` inputs. Its pinned wrapper/specification may
select GCC support objects such as `crtbeginS`, `crtendS`, and `libgcc`; they
remain narrow pinned-oracle toolchain support, not candidate-owned runtime
inputs or a purity claim.

## Retained validation

    ./scripts/dev-x86_64.sh public-data-ordinary-link validate-report \
      .work/x86_64/public-data-ordinary-link/RECEIPT/report.json

Host validation rechecks source/product admission, policy bytes and selected
source paths, every retained raw stream, probe imports, static definitions,
alignment, source-declared aliases, oracle capture, and candidate links.
owned_posix_product_evidence.validate_retained_link maps recorded /workspace
paths through the producing checkout and rehashes products, workload,
executable, receipt, sidecars, and the sealed linker identity. It does not
need the original container linker or a live /workspace.

owned_dynamic_qualification.validate_oracle validates retained oracle bytes,
the wrapper, the pin manifest, and specifications without reading a live /opt.
Replay must still execute from the source checkout that produced the products
because the shared readers bind source-controlled wrapper, dynamic contracts,
and clean source identities.

It also reopens all seven retained oracle/candidate executable files and
checks their recorded ELF64 little-endian x86-64 type and interpreter mode.
The two execution roots have exact non-following tree seals. Candidate root
entries must match the supplied dynamic product plus the two copied consumers;
the oracle root must contain only its retained runtime, libc alias, and copied
consumers. Replay therefore rejects an altered interpreter or consumer even if
the command transcript remains unchanged. Tool and oracle-static snapshots are
made readable before the report is written, so the final retention permission
step cannot invalidate their recorded modes.

This component does not prove object initialization or lifecycle state,
strong-definition override behavior, DSO interposition, COPY relocations, or
header feature/C++ declaration profiles. It is prepared/materialized
ordinary-link evidence only. It does not qualify a runtime, close a family, or
change native public-support status.
