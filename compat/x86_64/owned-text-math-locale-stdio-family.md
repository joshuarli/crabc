# Immutable text, math, locale, and stdio family inputs

`owned_text_math_locale_stdio_family.py` replays assembled inputs for the
planned `libc.text-math-locale-stdio` x86 family. Its `collect` and `write`
commands read a request below the checkout's `.work/` directory, reconstruct
the current POSIX three-product matrix with `owned_posix_family_execution.py`,
and require the corresponding pthread component receipt. They then give each
declared component input to that component's public reader. They never invoke
a producer, compiler, or native workload.

`assemble` is the narrow runnable hand-off from those existing producers. It
accepts only explicitly named physical reports for all three pairs, plus the
independently captured Wordexp input seals. Before it writes anything it
authenticates the POSIX matrix and pthread receipt, including the matrix's
non-reused `primary`, `reproduction`, and `extracted` product pairs. It uses
the existing `owned_text_locale_numeric_component_receipt.py` public collector
to make that component's aggregate, writes the ordinary request, and invokes
the coordinator's normal public-reader replay before writing `receipt.json`.
It does not discover reports, build a product, execute a workload, or change
the sixteen-capability/false-promotion boundary.

The POSIX matrix's `request` field identifies a retained file; it does not
contain the producer request itself. `_product_pairs` authenticates that file
against the matrix identity before passing its contents to `input_products`.
A changed request fails before product replay.

The fixed roster in `text-math-locale-stdio-family.toml` has the sixteen
capabilities from `compat/x86_64/parity.toml`. Every admitted component must
bind the current product-owner source identity and the same three non-reused
static/dynamic pairs: `primary`, `reproduction`, and `extracted`. Each pair must
supply static ET_EXEC, static PIE, and dynamic PIE/non-PIE through kernel and
direct loader entry, for six static and twelve dynamic aggregate cells. A
component cannot substitute a pair, omit a row or cell, or reuse another pair's
products.

The coordinator snapshots the declared matrix, pthread, component-evidence,
and product roots before reader replay. It snapshots the request, product
receipts, reader sources, roster, and Wordexp expected-input files as exact
files. It rechecks all of them after reader replay and again after constructing
the returned product-tree identities. A changed nested retained object or
payload therefore invalidates collection even when its JSON report was not
rewritten. Snapshots are bounded to those declared evidence/product roots; the
coordinator never scans the checkout-wide `.work/` tree.

## Three-pair collection, assembly, and replay

First create a current same-source POSIX matrix and its matching pthread
receipt using their owning commands:

```sh
./scripts/dev-x86_64.sh owned-posix-family \
  --static-preparation .work/x86_64/static-products/preparation.json \
  --dynamic-qualification .work/x86_64/dynamic-products/qualification.json \
  --output .work/x86_64/posix-family-run
./scripts/dev-x86_64.sh owned-pthread-family \
  --family-execution .work/x86_64/posix-family-run/execution.json \
  --output .work/x86_64/pthread-family-run
```

For each pair named by that matrix, run the existing supplied-product
producers with that pair's static and dynamic product. The commands below are
one pair; repeat them with `primary`, `reproduction`, and `extracted` paths,
and record each printed evidence directory. They are native producer commands,
not a host replay substitute.

```sh
./scripts/dev-x86_64.sh owned-locale --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-numeric-calendar --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-text-locale-numeric-component --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-math-fenv-all-entry --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-wordexp --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-stdio --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-stdio-file-engine --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-regex --static-sysroot "$static" "$dynamic"
./scripts/dev-x86_64.sh owned-calendar-component --static-sysroot "$static" "$dynamic"
```

The associated report files in those printed roots are, in order,
`owned-locale-products.json`, `owned-numeric-calendar-products.json`,
`owned-text-locale-numeric.json`, `owned-math-fenv-all-entry.json`,
`owned-wordexp-products.json`, `owned-stdio-products.json`,
`owned-stdio-file-engine.json`, `owned-regex-products.json`, and
`owned-calendar-products.json`. The calendar command derives its own fresh
TZif input in the observed pinned image (see
[`owned-calendar-component.md`](owned-calendar-component.md)). Wordexp also
requires a distinct expected-input capture for each pair:

```sh
TMPDIR="$PWD/.work/x86_64/tmp" python3 -B compat/x86_64/owned_wordexp_evidence.py capture-expected-inputs \
  --static-sysroot "$static" "$dynamic"
```

Run that capture in the same pinned native container as the producer; it
prints its physical `expected-native-inputs.json` path. Do not reuse a
Wordexp seal from another pair.

With `*_primary`, `*_reproduction`, and `*_extracted` set to the recorded
report paths (and `wordexp_expected_*` set to the three independently captured
seals), assemble the exact input set. This command intentionally names every
physical input; it has no report-directory scan or default path.

```sh
python3 -B compat/x86_64/owned_text_math_locale_stdio_family.py assemble \
  --family-execution .work/x86_64/posix-family-run/execution.json \
  --pthread-family .work/x86_64/pthread-family-run/receipt.json \
  --report locale:primary="$locale_primary" --report locale:reproduction="$locale_reproduction" --report locale:extracted="$locale_extracted" \
  --report numeric:primary="$numeric_primary" --report numeric:reproduction="$numeric_reproduction" --report numeric:extracted="$numeric_extracted" \
  --report text-locale-numeric:primary="$text_primary" --report text-locale-numeric:reproduction="$text_reproduction" --report text-locale-numeric:extracted="$text_extracted" \
  --report math:primary="$math_primary" --report math:reproduction="$math_reproduction" --report math:extracted="$math_extracted" \
  --report wordexp:primary="$wordexp_primary" --report wordexp:reproduction="$wordexp_reproduction" --report wordexp:extracted="$wordexp_extracted" \
  --wordexp-expected-input primary="$wordexp_expected_primary" --wordexp-expected-input reproduction="$wordexp_expected_reproduction" --wordexp-expected-input extracted="$wordexp_expected_extracted" \
  --report stdio:primary="$stdio_primary" --report stdio:reproduction="$stdio_reproduction" --report stdio:extracted="$stdio_extracted" \
  --report stdio-engine:primary="$stdio_engine_primary" --report stdio-engine:reproduction="$stdio_engine_reproduction" --report stdio-engine:extracted="$stdio_engine_extracted" \
  --report regex:primary="$regex_primary" --report regex:reproduction="$regex_reproduction" --report regex:extracted="$regex_extracted" \
  --report calendar:primary="$calendar_primary" --report calendar:reproduction="$calendar_reproduction" --report calendar:extracted="$calendar_extracted" \
  --output .work/x86_64/text-math-locale-stdio-assembly
```

The output directory is fresh and contains the derived
`text-locale-numeric-receipt.json`, the sealed `request.json`, and the normal
non-promoting `receipt.json`. Replay it without native execution:

```sh
python3 -B compat/x86_64/owned_text_math_locale_stdio_family.py validate \
  --receipt .work/x86_64/text-math-locale-stdio-assembly/receipt.json
```

## Behavior ownership and pending inputs

The older `locale`, `numeric`, and `stdio` receipts are required corroborating
inputs with zero credits. They retain useful bounded observations, but their
scope labels do not prove the corresponding complete capabilities.

`owned_text_locale_numeric_component_receipt.py` is the only component allowed
to credit `numeric.parse-float-locale`, `locale.core`,
`text.wide-multibyte`, and `text.iconv`. Its closed rows include float parsing
and aliases, the locale ctype/collation/alias/strfmon behavior, wide-character
and conversion behavior, and UTF-16/32 iconv behavior. Its aggregate receipt
must declare one physical `pair_evidence_roots` directory for each product pair,
and its direct per-pair report must be a child of that root. The coordinator
snapshots and retains each declared root separately from the aggregate receipt
directory. The public validator takes a decoded aggregate mapping. Its rows
carry separate `capability` and `id` fields, and its execution cells live in
each pair record. `_text_locale_numeric_adapter` normalizes these validated
records into the coordinator's capability/row keys and mode names; it does not
require the leaf report's `scope` or top-level `execution_cells` fields on the
aggregate. Input receipt paths are resolved against the supplied checkout.

`owned_stdio_component_receipt.py` retains the independent `fopen64` macro,
header-profile, pointer-equality, and ET_REL import observation. The separate
`owned_stdio_file_engine_receipt.py` is required before any stdio capability
can receive credit. Its closed rows are file backends, process streams, wide
streams, wide formatting, file extensions, printf float behavior, scanf
behavior, and the frozen stdio surface. Its retained objects must reference
every frozen `stdio.path-stream`, `stdio.stream-io`,
`stdio.position-buffering`, and `stdio.format-scan` symbol, and the coordinator
requires the reader's `frozen_surface` result for all four. There is no
fallback from the bounded stdio receipt to those rows.

Math, Wordexp, regex, and calendar retain their own public evidence contracts.
The calendar component requires all five named calendar rows; its malformed
TZif support probe is not a sixth credited row. Its public report records
row/role pairs and the `full-six-mode` execution contract; the calendar reader
reconstructs those six modes before the coordinator normalizes them.
`family_completion`,
`promotion_ready`, and `public_support` remain `false` in every successful
coordinator receipt. The output is not a parity selection, aggregate
qualification, or public-support claim; a same-source complete input set is
still required before later integration may make any such decision.
