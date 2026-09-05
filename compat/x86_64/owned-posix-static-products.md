# Static products for POSIX family execution

The POSIX catalog requires three static products: `primary`, `reproduction`,
and `extracted`. `owned_posix_static_products.py` prepares those inputs and
records their identities. A preparation receipt contains no runtime results
and cannot close a capability, the POSIX family, or either sysroot family.

Run from a clean committed checkout in the pinned native environment:

```bash
./scripts/dev-x86_64.sh owned-posix-static-products .work/x86_64/posix-static-run
```

The final argument must name a new physical directory under the checkout's
ignored `.work` tree. The dispatcher translates that host path to its
`/workspace` mount. Absolute host paths are also accepted; symlink traversal
and paths outside `.work` are rejected before container execution.

The coordinator invokes `scripts/build_x86_64_owned_sysroot.py` twice, with
distinct output directories and the producer's independent temporary build
trees. It invokes `owned_static_sysroot_package.py create` for each result,
requires identical manifests, installed payloads, and archive bytes, then
uses the package owner's `extract` command to materialize the primary archive.
It uses that same owner's installed-tree checks and bounded extractor during
receipt validation. It does not substitute a producer or an archive parser.

The three physical product paths relative to the run are:

- `products/primary`
- `products/reproduction`
- `products/extracted/crabc-x86_64-owned-static-sysroot`

`preparation.json` has schema
`crabc.x86_64-owned-posix-static-preparation/v1` and status
`prepared-unqualified`. It binds the source revision and actual source content
before and after preparation, all five command vectors, raw exit statuses,
stdout/stderr hashes and sizes, the exact three product labels, manifests,
complete installed trees, and both package archives. Paths are checkout-relative
and must resolve physically within `.work`, so the same receipt can be checked
through the pinned container mount or its host checkout.

Tree identities preserve the package owner's normalization: directories are
`0755`; files are `0755` when any executable bit is set and `0644` otherwise.
Thus irrelevant source permission differences do not falsely invalidate a
correct extraction, while changes to executable state, bytes, file inventory,
or directory inventory do. Producer tool identities and toolchain selection
are copied from the validated installed manifests; provenance files remain
bound as ordinary installed payload. The receipt also hashes
`compat/upstreams.toml` and `rust-toolchain.toml`. It records oracle source pins,
not an observed musl execution: no oracle or consumer runs during preparation.

Validate without rebuilding products:

```bash
python3 -B compat/x86_64/owned_posix_static_products.py validate \
  .work/x86_64/posix-static-run/preparation.json
```

Validation reconstructs the exact receipt from current clean source, logs,
products, and archives. Missing or extra product cells, rewritten fields,
unsuccessful steps, or changed source/artifacts are rejected. Temporary archive
verification remains under the run directory and is removed afterwards.
Failed preparation retains each attempted command and its raw output/status;
it writes no successful preparation receipt. A dirty final source is recorded
in `source-after-error.json` instead of a success seal.

Family execution must separately run both static modes for every workload on
each product and retain its own evidence. This preparation command does not
execute that six-cell matrix or publish a family receipt.
