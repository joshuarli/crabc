# Installed loader-family component

`owned_loader_family.py` is a finite, non-promoting evidence coordinator for
native `ldso.dynamic-runtime`. It does not start an application, build a
sysroot, inspect ambient host tools, or turn a private fixture into installed
runtime evidence. It replays an already complete owned-dynamic qualification
and one retained loader inventory for each of the qualification's `installed`,
`second`, and `extracted` products.

The coordinator covers the four capability rows owned by the family:
`runtime.loader`, `runtime.private-facades`, `loader.dlfcn-basic`, and
`loader.dlfcn-introspection`. The exact behavior map is
[`loader-family.toml`](loader-family.toml). It records the §7 process entry,
graph/search/mapping/RELRO, relocation and scope, RuntimeV1/TLS/thread,
lifecycle/finalization, `dl*`, fork/callback/rollback, synthetic-loader, and
real-package-corpus boundaries.

The synthetic catalog row is the current full 21-case roster from
`compat/ldso/run_x86.py`; the package row is the current full 34-case roster
from `compat/corpus/manifest.toml`. The roster parser compares both ordered
lists to their current owners. The qualification reader still validates its
complete current case matrix for every product, so a catalog change cannot
become an unobserved partial selection.

Each `qualification_cases` list is an exact case-ID link through
`owned_dynamic_qualification.CASES`, rather than a claim inferred from a row
name. In particular, the `dlopen-*` cases own runtime general-dynamic TLS,
NOLOAD/NODELETE close/reopen, concurrent construction, and the five
pre-callback rollback observations; `lazy-*` owns deferred GOT/RELRO and lazy
rollback; and `loader-synthetic` owns the remaining frozen selected loader
encodings. New runtime initial-exec TLS remains a recorded rejection
differential, not an unclaimed successful mode.

Prepare a physical fresh directory below this checkout's `.work` with an
immutable request file:

```json
{
  "schema": "crabc.x86_64-owned-loader-family/v1",
  "qualification": ".work/x86_64/dynamic/qualification.json",
  "inventories": {
    "installed": {
      "receipt": ".work/x86_64/inventory/installed.json",
      "oracle_capture": ".work/x86_64/inventory/installed.oracle-capture.json",
      "readelf_capture": ".work/x86_64/inventory/installed.readelf-capture.json"
    },
    "second": { "receipt": "…", "oracle_capture": "…", "readelf_capture": "…" },
    "extracted": { "receipt": "…", "oracle_capture": "…", "readelf_capture": "…" }
  }
}
```

Every request path must be a physical checkout-relative `.work` path. Product
paths are deliberately absent from the request: for each named entry the
coordinator derives the only admissible product root from the selected
qualification's retained `work` directory. It then requires the inventory's
capture to name that exact root and manifest, and to retain the same current
source digest.

The qualification preparation owns an independently copied pinned-musl oracle.
Each inventory's retained `oracle_capture.json` is revalidated by
`owned_loader_inventory` and must contain the same complete oracle identity as
that preparation. Each retained `readelf_capture.json` is revalidated without
executing `readelf`; all three must identify the same sealed tool. This lets a
host replay the receipt without `/opt/musl-1.2.6`, Docker, a candidate run, or
a host readelf binary.

Collect and replay with the target-local commands that the dispatcher can
register:

```bash
python3 -B compat/x86_64/owned_loader_family.py collect --work .work/x86_64/loader-family
python3 -B compat/x86_64/owned_loader_family.py validate --receipt .work/x86_64/loader-family/receipt.json
```

Collection creates only `.work/.../receipt.json` and fails if that name already
exists. The receipt seals request and input identities before and after replay,
the current source digest before and after, the complete prepared oracle, the
common readelf identity, the roster identity, every selected qualification case
receipt, and every inventory input. It invokes the qualification and all three
inventory validators again at the end before writing: a changed reached case
artifact, product payload, package tree, or raw readelf stream therefore fails
even if the enclosing JSON receipt bytes did not change. Validation
reconstructs that value and requires exact JSON equality including scalar
types; non-finite JSON constants are rejected on read.

A successful receipt sets `component_complete=true`, because every required
artifact was replayed. It always retains `family_completion=false`,
`promotion_ready=false`, and `public_support=false`. It neither changes the
family's planned status nor supplies a public x86 support claim.

Dispatcher, parity, catalog, and generated-report registration remain the
integration owner's work. The intended command surface is
`owned-loader-family --work DIR` and `owned-loader-family validate --receipt
PATH`.
