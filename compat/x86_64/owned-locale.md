# Installed locale and fixed-UTF component

`run_owned_locale.sh` is a bounded installed-product behavior component for
`locale.core`, `text.wide-multibyte`, and `text.iconv`. It translates one C11
object through the selected dynamic product's installed headers, then links
those unchanged object bytes with pinned musl and the selected owned products.
It is not a private archive fixture.

The object fixes the locale names to `C`, `POSIX`, and `C.UTF-8`. It checks the
selected `setlocale`/`localeconv` and named-locale tokens, then starts two
pthread workers with separate `uselocale` values and preserved independent
`errno` values. The C.UTF-8 worker retains a caller-owned partial UTF-8 state,
an invalid sequence, and a truncated sequence; the C worker retains a high
byte conversion. The same object also checks fixed UTF-8-to-UTF-16LE and
UTF-32BE-to-UTF-8 conversions plus exact input/output-pointer and remaining
byte counts for `EILSEQ`, `EINVAL`, partial progress, and `E2BIG`.

The runner uses one pinned-musl link, static ET_EXEC and static PIE when a
static product is supplied, and dynamic PIE/non-PIE through both kernel and
direct owned-loader entry. Every successful run has exact retained argv,
stdout, stderr, and zero status. It traces the installed headers, seals the
probe, runner, tool roster, selected product manifests and trees before and
after execution, retains the one object identity, validates every product link
receipt, and records/audits each copied dynamic execution payload before and
after its two entries.

`owned_locale_component_receipt.py validate-report --root ROOT --report PATH`
reconstructs that retained report. It rehashes the physical sources, object,
raw command streams, products, manifests, tool roster, link receipts, and
copied payloads; replays the exact argv roster; requires an x86-64 ELF
relocatable installed-header object; and compares each candidate raw transcript
with the retained pinned-musl transcript. Recomputing a report hash after
changing an argv or a candidate transcript therefore does not make the receipt
valid. The report schema is
`crabc.x86_64-owned-locale-products/v2` and records one of two explicit modes:
`full-six-mode` includes static ET_EXEC, static PIE, dynamic PIE kernel/direct,
and dynamic non-PIE kernel/direct; `dynamic-only-four-cell-development` includes
only the four dynamic entries. The reader validates both shapes, while callers
that need a complete component pass `--require-static` and reject the dynamic
development shape. Historical `v1` JSON lacks this reconstructable command,
raw-stream, and link-validation interface and is not admitted by the `v2`
reader.

Run it in the pinned native environment:

```sh
./scripts/dev-x86_64.sh owned-locale \
  --static-sysroot .work/x86_64/static-product \
  .work/x86_64/dynamic-product
```

Its interface is `[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With
both supplied products it never builds a replacement. A supplied dynamic
product alone runs the musl and four dynamic entries and publishes only the
explicit development mode; it is still reconstructable, but cannot satisfy a
complete-component caller. With neither argument it builds disposable products
below checkout-local `.work`. Inputs must be physical directories below that
tree.

The reader is a pinned-native-container interface: invoke it with the checkout
mounted at `/workspace`, as the runner does. It stores checkout-contained tool
paths with that fixed mount spelling while retaining their physical hashes, so
the same report can be reconstructed after a host checkout path changes without
mistaking host path text for a different compiler or driver.

This component deliberately excludes environment-driven locale selection,
arbitrary locale tokens or locale maps, collating and wide-stream behavior,
general Unicode tables, and legacy encodings. Those non-C locale and legacy
encoding boundaries stay outside this pinned-musl equality component. The
receipt is evidence for these three finite components only; it does not close
a locale family, alter a disposition, or claim promotion or public x86
support.
