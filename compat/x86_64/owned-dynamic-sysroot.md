# Planned x86 owned-dynamic product boundary

`dynamic-product.toml` is the non-promoting contract for the future
Linux/x86-64 dynamic half of `sysroot.owned-artifact`. It makes the dynamic
product obligations finite without treating the private static-only sysroot as
a dynamic runtime.

The checked-in `dynamic-product-state.json` deliberately says
`not-materialized`. Its semantic contract digest is checked by
`dynamic_product_contract.py`; a contract edit cannot silently leave a stale
state record behind. All promotion booleans are false. This seed is therefore
useful planning and integrity evidence, but not native loader, CRT, or sysroot
evidence.

## Planned installed boundary

The target layout is deliberately conventional and target-specific:

```text
<sysroot>/
  bin/crabc-cc-dynamic
  lib/ld-crabc-x86_64.so.1
  lib/ld-musl-x86_64.so.1 -> ld-crabc-x86_64.so.1
  usr/include/
  usr/lib/crt1.o
  usr/lib/Scrt1.o
  usr/lib/crti.o
  usr/lib/crtn.o
  usr/lib/libc.so
  usr/lib/libcrabc-builtins.a
  share/crabc/manifest.json
  share/crabc/dynamic-product-state.json
```

`/lib/ld-crabc-x86_64.so.1` is the canonical interpreter selected for new
dynamic executables. `ld-musl-x86_64.so.1` is a relative compatibility alias
to that exact installed file; it is not an ambient musl loader fallback.

`crabc_cc_dynamic.py` is a sealed driver seed for this layout. It has three
explicit modes:

- `--dynamic-pie`: `ET_DYN`, `Scrt1.o`, and the canonical `PT_INTERP`.
- `--dynamic-non-pie`: `ET_EXEC`, `crt1.o`, and the canonical `PT_INTERP`.
- `--dynamic-shared-object`: `ET_DYN`, no executable CRT, and no `PT_INTERP`.

Every mode names installed `crti.o`, `crtn.o`, `libc.so`, and
`libcrabc-builtins.a` directly. Source translation may use the pinned
development environment, but target headers, CRT, libraries, loader, and link
decisions are installed crabc inputs. The driver rejects ambient include,
library, CRT, compiler-runtime, linker-script, interpreter, and DSO-search
overrides. A caller may name an application DSO only with the explicit
`--application-dso` form, so fixture dependencies remain an auditable input
set rather than a library search accident.

This particular seed is plan-only: it first requires the installed
`share/crabc/dynamic-product-state.json` to be the checked
`not-materialized` receipt for the exact semantic contract digest, then accepts
only `--print-link-plan` with one of the three modes. It never invokes a source
translator or linker. That prevents a copied driver plus placeholder runtime
files from being mistaken for dynamic-product evidence. A materialized product
must replace this seed with a separately validated driver and native suite.

## Product gate still required

The future dynamic suite must use one installed main program, an initially
loaded dependency graph, and a runtime-loaded plugin across both executable
modes. It must prove loader/libc RuntimeV1 handoff, selected graph/search and
relocation behavior, lifecycle ordering, `dl*`, initial-exec and
general-dynamic TLS, DTV growth, DSO-boundary runtime interactions, loader
concurrency/reentrancy, selected fork repair, and clean selected failure
behavior. `dynamic-product.toml` carries the exact 12-obligation list.

Each installed and fixture ELF must be audited for link provenance, headers,
program headers, dynamic entries, relocations, symbol ownership, TLS, stack,
RELRO, interpreter/alias, and `DT_NEEDED`/DSO search paths before execution.
The musl oracle remains a separate pinned-musl process; it can never become a
candidate runtime fallback. Two clean installed builds and one extracted
package must execute the same suite with byte-identical declared regular-file
artifacts.

For the current seed:

```bash
python3 compat/x86_64/dynamic_product_contract.py --check
compat/x86_64/run_owned_dynamic_sysroot.sh --check-contract
```

Both commands validate the planned contract only. Calling
`run_owned_dynamic_sysroot.sh` with no arguments intentionally exits nonzero
and prints `INCOMPLETE`; it must not be registered as a passing campaign gate
until the actual installed product and native suite exist.

## Future integration boundary

When the general loader, dynamic CRT, and shared libc are ready, the
integration owner should extend `scripts/build_x86_64_owned_sysroot.py` to
install the dynamic artifacts, compatibility alias, manifest record, state
receipt, and one unified driver. Then it should replace this seed runner with
the native dynamic product suite and wire its validated result through
`compat/x86_64/parity.toml`, `validate_parity_ledger.py`,
`campaign_report.py`, `campaign_runner.py`, `scripts/dev-x86_64.sh`, and the
central x86 documentation. That change must also update the frozen completion
predicate only after every dynamic prerequisite and product assertion really
passes.
