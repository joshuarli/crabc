# X86 owned-dynamic product boundary

An initial-graph component is materialized by
`scripts/build_x86_64_owned_dynamic_sysroot.py`, with an executing installed
driver (`crabc_cc_owned_dynamic.py`, installed as `bin/crabc-cc-dynamic`) and
native package gate. See [materialized-dynamic-sysroot.md](materialized-dynamic-sysroot.md)
for its exact implementation, evidence and remaining conditions.

`dynamic-product.toml` is the non-promoting contract for the
Linux/x86-64 dynamic half of `sysroot.owned-artifact`. It makes the dynamic
product obligations finite without treating the private static-only sysroot as
a dynamic runtime.

The checked-in `dynamic-product-state.json` says `implemented-unqualified`.
`dynamic_product_contract.py` checks it against the contract; a contract edit
cannot silently leave a stale state record behind. All promotion booleans are
false, and the checked-in state is not execution evidence: qualification needs
a live three-product receipt (`owned_dynamic_qualification.py`).

## Installed boundary

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

`crabc_cc_owned_dynamic.py` is the sealed driver for this layout; the installed
driver has three explicit modes:

- `--dynamic-pie`: `ET_DYN`, `Scrt1.o`, and the canonical `PT_INTERP`.
- `--dynamic-non-pie`: `ET_EXEC`, `crt1.o`, and the canonical `PT_INTERP`.
- `--dynamic-shared-object`: `ET_DYN`, no executable CRT, and no `PT_INTERP`.

Executable links preserve weak dynamic imports with `-z dynamic-undefined-weak`.
The owned CRT handoff retains its weak data symbol and dynamic GOT relocation.
The loader still requires the exact one-slot handoff before relocation.

Every mode names installed `crti.o`, `crtn.o`, `libc.so`, and
`libcrabc-builtins.a` directly. Source translation may use the pinned
development environment, but target headers, CRT, libraries, loader, and link
decisions are installed crabc inputs. The driver rejects ambient include,
library, CRT, compiler-runtime, linker-script, interpreter, and DSO-search
overrides. A caller may name an application DSO only with the explicit
`--application-dso` form, so fixture dependencies remain an auditable input
set rather than a library search accident.

The seed is plan-only: it first requires an installed
`share/crabc/dynamic-product-state.json` carrying the `not-materialized`
status for the exact semantic contract digest, then accepts only
`--print-link-plan` with one of the three modes. It never invokes a source
translator or linker. That prevents a copied driver plus placeholder runtime
files from being mistaken for dynamic-product evidence.

## Product gate

The dynamic suite uses one installed main program, an initially
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

To check the contract without building:

```bash
python3 compat/x86_64/dynamic_product_contract.py --check
compat/x86_64/run_owned_dynamic_sysroot.sh --check-contract
```

Both commands validate the contract only. `run_owned_dynamic_sysroot.sh` with
no arguments runs `run_materialized_dynamic_sysroot.sh`.
