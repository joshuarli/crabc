# Installed numeric and clock/calendar composition

`./scripts/dev-x86_64.sh owned-numeric-calendar` runs a bounded installed-product behavior
component for `numeric.parse-float-locale` and `time.clock-calendar`. It
translates one C11 object through the selected dynamic product's installed
headers, then links those unchanged object bytes with pinned musl and the
selected owned products. It is not a private archive fixture.

`libc/src/c_abi/x86_64/float_parse.rs` and `float_parse_locale.rs` retain the
pinned musl 1.2.6 narrow, locale-wrapper, and wide conversion sources.
`clock_gettime.rs`, `time_observation.rs`, `owned_timezone.rs`,
`owned_calendar.rs`, `owned_strftime.rs`, and `owned_strptime.rs` retain the
selected clock and civil-time source owners from the same pin.

The numeric half fixes the admitted locale names to `C` and `C.UTF-8`. It
checks exact representable decimal and hexadecimal values, end pointers, stale
`errno` after success, one range error, the selected ignored-locale `strtod_l`
boundary without changing the current thread locale, and narrow
`strtof`/`strtod`/`strtold` with `wcstof`/`wcstod`/`wcstold`. Long double
comparisons are semantic; the object never inspects ABI padding.

The time half observes individually normalized realtime records and
nondecreasing monotonic records without ordering the externally adjustable
realtime calls or recording an exact wall-clock value. It uses only explicit
POSIX `TZ` strings:
`UTC0` checks a leap-year civil-date normalization and a
`strftime`→`strptime`→`mktime` round trip, while a fixed `EST5EDT` rule checks
winter and summer local conversions, offsets, names, and DST flags. It never
sets a clock or reads host zoneinfo files.

The runner retains one pinned-musl static ET_EXEC link using
`-static -fno-pie -no-pie`, static ET_EXEC and static PIE when a static product
is supplied, and dynamic PIE/non-PIE through both kernel and direct owned
loader entry. Every successful run has retained exact argv, stdout, stderr,
and zero status. It traces installed headers, seals the probe, runner, tool
roster, selected manifests and trees before and after execution, keeps the one
object identity, validates every product link receipt, and records/audits each
copied dynamic execution payload before and after both entries.

`owned_numeric_calendar_component_receipt.py validate-report --root ROOT
--report PATH` reconstructs that retained report. It rehashes the physical
sources, object, raw command streams, products, manifests, tool roster, link
receipts, and copied payloads; replays the exact argv roster; requires an
x86-64 ELF relocatable installed-header object; and compares every candidate
raw transcript with the retained pinned-musl transcript. Recomputing a report
hash after changing an argv or a candidate transcript therefore does not make
the receipt valid. The report schema is
`crabc.x86_64-owned-numeric-calendar-products/v2` and records one of two
explicit modes: `full-six-mode` includes static ET_EXEC, static PIE, dynamic
PIE kernel/direct, and dynamic non-PIE kernel/direct;
`dynamic-only-four-cell-development` includes only the four dynamic entries.
The reader validates both shapes, while callers that need a complete component
pass `--require-static` and reject the dynamic development shape. Historical
`v1` JSON lacks this reconstructable command, raw-stream, and link-validation
interface and is not admitted by the `v2` reader.

Run it in the pinned native environment:

```sh
./scripts/dev-x86_64.sh owned-numeric-calendar \
  --static-sysroot .work/x86_64/static-product \
  .work/x86_64/dynamic-product
```

Its interface is `[--static-sysroot STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With
both supplied products it never builds replacements. A supplied dynamic product
alone runs the musl and four dynamic entries and publishes only the explicit
development mode; it is still reconstructable, but cannot satisfy a
complete-component caller. With neither argument it builds disposable products
below checkout-local `.work`. Inputs must be physical directories below that
tree.

The reader is a pinned-native-container interface: invoke it with the checkout
mounted at `/workspace`, as the runner does. It stores checkout-contained tool
paths with that fixed mount spelling while retaining their physical hashes, so
the same report can be reconstructed after a host checkout path changes without
mistaking host path text for a different compiler or driver.

This receipt is evidence for these two finite components only. It does not
close the text/math/locale/stdio family, alter a disposition, claim broad math
or arbitrary locale parity, or claim promotion or public x86 support.
