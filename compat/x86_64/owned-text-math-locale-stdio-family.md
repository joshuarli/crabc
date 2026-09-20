# Immutable text, math, locale, and stdio family inputs

`owned_text_math_locale_stdio_family.py` is a read-only coordinator for the
planned `libc.text-math-locale-stdio` x86 family. It reads a request below the
checkout's `.work/` directory, reconstructs the current POSIX three-product
matrix with `owned_posix_family_execution.py`, and requires the corresponding
pthread component receipt. It then gives each declared component input to that
component's public reader. The coordinator never invokes a producer, compiler,
or native workload.

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
directory. Until that public reader and its aggregate receipt exist, collection
rejects the request.

`owned_stdio_component_receipt.py` retains the independent `fopen64` macro,
header-profile, pointer-equality, and ET_REL import observation. The separate
`owned_stdio_file_engine_receipt.py` is required before any stdio capability
can receive credit. Its closed rows are file backends, process streams, wide
streams, wide formatting, file extensions, printf float behavior, and scanf
behavior. There is no fallback from the bounded stdio receipt to those rows.

Math, Wordexp, regex, and calendar retain their own public evidence contracts.
The calendar component requires all five named calendar rows; its malformed
TZif support probe is not a sixth credited row. `family_completion`,
`promotion_ready`, and `public_support` remain `false` in every successful
coordinator receipt. The output is not a parity selection, aggregate
qualification, or public-support claim; a same-source complete input set is
still required before later integration may make any such decision.
