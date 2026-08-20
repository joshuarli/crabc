# Pinned AArch64 musl ABI inventory

This directory records the ABI boundary of the pinned musl 1.2.6 reference on
the `aarch64-unknown-linux-musl` target. The source files are the independently
built reference installed at `/opt/musl-1.2.6` in the native `linux/arm64`
`crabc-dev:aarch64` image. The release tarball is SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.

The machine-readable inventory is under
`compat/abi/musl-1.2.6/aarch64/`:

| File | Meaning | Current records |
| --- | --- | ---: |
| `libc.so.dynamic.tsv` | Defined, externally visible dynamic symbols from `libc.so` | 1,647 |
| `libc.a.static.tsv` | Defined global/weak symbols from every `libc.a` member | 2,004 |
| `headers.tsv` | Installed target headers, interface class, size, line count, and SHA-256 | 217 (183 public + 34 arch-internal) |
| `manifest.json` | Schema, source hashes, counts, and generation provenance | — |

The dynamic manifest has columns `name`, `type`, `binding`, `visibility`,
`size`, `value`, `section_index`, and `version`. It includes `GLOBAL` and
`WEAK` symbols that are defined (not `UND`) and have `DEFAULT` or `PROTECTED`
visibility; `GLOBAL` is the ELF strong binding and `WEAK` is the weak binding.
Local, undefined, hidden, and internal entries are not exported ABI. Symbol
sizes are retained as evidence; they are not a claim that a function's
implementation must have the same code size. Versioned ELF names are
represented by the base name plus a `version` field.

The static manifest is intentionally archive-member based. Its `nm_type` is
the raw GNU `nm` type code, and `archive_member` identifies the `.lo` member
that defines it. Duplicate symbol names are retained because static archive
extraction is member-based; this file therefore has 2,004 records and 1,939
unique names across 1,349 members. “Static public link surface” here means
every externally linkable definition in the archive, including musl internal
definitions needed when composing static programs. It is not a filtered list
of C header declarations, nor does it predict which members a particular link
will extract.

The header manifest is archive-independent. Its `public` records are headers
applications can include directly; its `arch-internal` records are installed
`bits/` headers that public headers include and that define AArch64 ABI layouts
and constants. Every record carries its path relative to the pinned
installation's `include/` directory, byte and newline counts, and the SHA-256
of the exact installed file. This is a file-boundary inventory, not yet a
declaration/type-layout comparison: preprocessor feature choices, macro
expansions, declarations selected by those choices, and ABI-bearing
`sizeof`/`offsetof` values require dedicated probes in later milestones.

## `ld.so` and runtime relationship

The pinned musl installation has `lib/ld-musl-aarch64.so.1` as a symlink to its
`libc.so`; the index records that relationship and the shared-object hash. For
this musl build, the interpreter and libc are therefore not two independent
symbol inventories. A dynamically linked executable's `PT_INTERP` names that
musl path, and musl's loader code is part of the same reference shared object.

Crabc uses a different runtime arrangement: `libldso.so` is supplied as the
executable's `PT_INTERP` replacement and loads/resolves the candidate `libc.so`.
`libldso.so`'s exports, relocation support, TLS behavior, startup behavior, and
the interpreter path are runtime contracts that are not proven by either TSV
file. Conversely, the `libc.a` static surface does not involve `ldso` at all.
Dynamic symbol inventory parity must therefore not be reported as proof that
an unmodified binary runs under crabc.

The separate [`loader-runtime.json`](musl-1.2.6/aarch64/loader-runtime.json)
report records this reference loader relationship plus the ELF program-header,
dynamic-tag, relocation-class, and dynamic-symbol observations obtained from
`readelf`. It is deliberately separate from the libc symbol TSVs: these
observations describe the reference runtime shape, not a claim that `libldso.so`
implements the same behavior.

The current crabc-side feature inventory is
[`loader-features.json`](crabc/aarch64/loader-features.json). Its states are
evidence levels (`source_and_test_target`, `source_only`, `surface_only`, and
`not_evidenced`), not compatibility grades. The generator never executes a
test and never marks a loader feature `verified`; run the focused native
AArch64 loader tests described in [`compat/loader/README.md`](../loader/README.md)
for runtime evidence.

## Reproduce and validate

Build or reuse the pinned native image first:

```sh
./scripts/dev.sh image
```

Generate the checked-in files from the image's pinned reference (the generator
uses only Python plus `readelf`, `nm`, and `ar` from that image):

```sh
docker run --rm --platform linux/arm64 \
  --workdir /workspace \
  --volume "$PWD:/workspace" \
  crabc-dev:aarch64 \
  python3 compat/scripts/generate-aarch64-musl-abi.py
```

Validate that the checked-in files are byte-for-byte reproducible, without
writing the checkout:

```sh
docker run --rm --platform linux/arm64 \
  --workdir /workspace \
  --volume "$PWD:/workspace:ro" \
  crabc-dev:aarch64 \
  python3 compat/scripts/generate-aarch64-musl-abi.py --check
```

The generator rejects a non-AArch64 `libc.so`, a missing archive or include
tree, an installed-header symlink, or an `ld-musl-aarch64.so.1` that does not
resolve to the same `libc.so`. `--check` regenerates in memory, compares all
four expected files, and also rejects unexpected files in the inventory
directory. The commands above were run successfully in the existing native
`arm64/linux` image; the generated counts and source hashes are recorded in
`manifest.json`.

Generate both loader/runtime reports after building the AArch64 workspace:

```sh
./scripts/dev.sh loader-inventory
```

The command writes the two JSON reports and then checks them again without
writing. The candidate report includes the current `libldso.so` and
`ldso/src/lib.rs` hashes, so it is evidence for that build only and must be
regenerated after loader changes.
