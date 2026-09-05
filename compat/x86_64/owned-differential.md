# Owned-product differential aggregate

`run_owned_differential.sh` is a supplied-product replay of the frozen C
workloads in `compat/differential/tests/`. It consumes one required installed
dynamic sysroot and, when supplied, one installed static sysroot:

```sh
TMPDIR=/workspace/.work/x86_64/tmp \
bash compat/x86_64/run_owned_differential.sh \
  --static-sysroot /workspace/.work/x86_64/products/static-primary \
  /workspace/.work/x86_64/products/dynamic-installed
```

The runner is executed in the pinned native Linux/x86-64 container with the
contained-root authority used by the other installed-product replays. Its
arguments must be physical checkout `.work` paths. It does not build either
product, fetch an oracle, substitute a host sysroot, or construct a fallback.
The dynamic product is mandatory; omitting `--static-sysroot` skips only the
static/static-PIE portion of the replay.

The aggregate takes its exact source roster from `compat/differential/run.py`'s
`CASES`: `foundational.c`,
`string-memory.c`, `allocator.c`, `fd-filesystem.c`, and `stdio-fdopen.c`.
For each source it creates one unchanged object through the supplied installed
dynamic driver. The retained compile receipt records the installed driver,
helper, selected compiler, source, every installed-header dependency, exact
commands, object, diagnostics, and PIE relocation audit. A dependency audit
uses the same compiler prefix as the installed driver and rejects any header
outside the supplied product. The pinned musl linker links that exact object once for the
reference executable; ambient musl header compilation cannot stand in for this
step.

Each candidate link is checked by `owned_posix_product_evidence.validate_link`
before it runs. A supplied static product is exercised as static/static-PIE.
The dynamic product is exercised as dynamic PIE/non-PIE through kernel and
direct interpreter paths; the direct path invokes `/lib/ld-crabc-x86_64.so.1`.
Every
execution gets a fresh copied disposable root. Dynamic roots first retain an
identity record for the copied runtime product, then retain the copied
executable identity; all roots receive a private writable `/tmp` for the two
filesystem workloads.

The evidence directory preserves full raw status, stdout, stderr, and errno
for the musl reference and every candidate execution. Comparisons are byte
exact for status/stdout/stderr and require exactly one workload errno marker.
The runner stops at the first mismatch and leaves those raw records in place;
it never normalizes, adapts, or rebaselines a source result.

After the final comparison, the runner writes `summary.json`. The summary is a
pass-only index: it requires all five dynamic PIE/non-PIE × kernel/direct
comparisons, with zero status and the retained raw streams for each. When a
static sysroot was supplied, it also requires both static cells for every
source. A reviewer can recompute the complete report without executing a
workload:

```sh
python3 -B compat/x86_64/owned_differential_evidence.py \
  validate-summary --work /workspace/.work/x86_64/tmp/owned-differential.XXXXXX
```

This read-only operation revalidates the frozen sources, installed compiler
and headers, product manifests and sealed links, copied runtime/executable
payloads and post-run disposable roots, then recomputes each raw comparison.
The underlying product receipts intentionally bind physical paths. Review a
copied evidence snapshot by mounting its checkout, products, and evidence at
the recorded paths; relocated receipts are rejected rather than rewritten.

A passing replay is only evidence for these five workloads and supplied
products. It does not qualify a capability family or complete a sysroot. It
does not claim native x86-64 platform support or promotion.
