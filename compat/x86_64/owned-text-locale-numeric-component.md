# Bounded installed text, locale, and numeric component

`run_owned_text_locale_numeric_component.sh` replays a fixed collection of
existing musl-facing C probes through the supplied x86-64 installed headers.
It compiles every role once to an ET_REL object with `crabc-cc-dynamic`, links
the exact resulting normal aggregate and separate alias object to pinned musl,
then links those same bytes through the supplied static, static-PIE, dynamic
PIE, and dynamic non-PIE products. Dynamic PIE and non-PIE each run by the
kernel and directly through `/lib/ld-crabc-x86_64.so.1`.

The source-to-behavior map is finite and is stored in
`owned_text_locale_numeric_component_contract.py` rather than inferred from an
export inventory.

| Capability | Row | Probe role |
| --- | --- | --- |
| `numeric.parse-float-locale` | `float-parse` | `libc_float_parse_probe.c` |
| `locale.core` | `ctype-locators` | `libc_locale_ctype_locators_probe.c` |
| `locale.core` | `narrow-ctype-collation` | `libc_locale_narrow_probe.c` |
| `locale.core` | `object-wide` | `libc_locale_object_wide_probe.c` |
| `locale.core` | `alias-contract` | `locale_alias_contract_probe.c` |
| `locale.core` | `strfmon` | `owned_strfmon_probe.c` |
| `text.wide-multibyte` | `locale-object-wide` | `libc_locale_object_wide_probe.c` |
| `text.wide-multibyte` | `multibyte` | `libc_locale_multibyte_probe.c` |
| `text.wide-multibyte` | `wide-character` | `libc_wide_character_probe.c` |
| `text.wide-multibyte` | `wide-conversion` | `owned_wide_conversion_probe.c` |
| `text.iconv` | `utf16-32-iconv` | `libc_locale_wide_iconv_probe.c` |
| `numeric.parse-float-locale` | `differential-transcript` | `owned_text_locale_differential_probe.c` |
| `locale.core` | `error-strings` | `libc_locale_error_strings_probe.c` |
| `locale.core` | `differential-transcript` | `owned_text_locale_differential_probe.c` |
| `text.wide-multibyte` | `uchar` | `libc_uchar_stateful_probe.c`, `libc_c32rtomb_probe.c` |
| `text.wide-multibyte` | `wcswcs` | `libc_wcswcs_probe.c` |
| `text.wide-multibyte` | `differential-transcript` | `owned_text_locale_differential_probe.c` |
| `text.wide-multibyte` | `wide-stream` | `owned_wide_stream_differential_probe.c` |
| `text.iconv` | `differential-transcript` | `owned_text_locale_differential_probe.c` |

Together the normal roles import every frozen spelling of the four credited
capabilities except musl's 44 `__*` public/private locale alias names, which
only the separate alias workload can observe (see below). The contract test
`test_every_frozen_spelling_is_imported_or_alias_proved` enforces that closure
against `compat/crabc-rs/coverage.toml`.

The two differential transcripts carry no expected values. They serialize the
exact observable result of each call (return value, `errno`, source and output
pointer progress, output bytes, `mbstate_t` initial-state predicates, and locale
handle relations) and write it with `write(2)`, so the byte stdio engine cannot
mask or fabricate an observation. The runner requires those bytes to equal
pinned musl's in every execution cell. `owned_text_locale_differential_probe.c`
covers C and C.UTF-8 single-byte, corpus, byte-wise and pending-state
`mbrtowc`/`mbrlen`/`mbtowc`/`mblen`; `wcrtomb`/`wctomb`/`btowc`/`wctob`;
`mbs[n]rtowcs`/`wcs[n]rtombs`/`mbstowcs`/`wcstombs` at every small capacity;
the UTF-16/32 `uchar.h` entries; full-range wide classification, case mapping
and `wcwidth` as run-length transitions; wide string/memory functions;
collation and case-insensitive comparison; narrow `_l` classification and
the ctype tables; `nl_langinfo[_l]`; `strerror_l`/`__strerror_l`;
`wcsftime`/`wcsftime_l`/`__wcsftime_l`; locale objects with explicit
environment scenarios and a worker thread; every `iconv` pair in the fixed
UTF/ASCII/`WCHAR_T` profile at each output capacity and truncated input; and
wide/narrow numeric parsing with legacy decimal conversion. Inputs whose musl
result is an intentional profile difference (arbitrary locale names, BOM,
UCS-2, and legacy codepage iconv names) or undefined behavior are excluded
and documented at the top of the probe.

`owned_wide_stream_differential_probe.c` observes the thirty FILE-oriented
`text.wide-multibyte` entries through anonymous memfd streams, memory streams,
standard input replaced by a memfd, and standard output reopened with
`freopen(NULL, "w", stdout)` around its stdout-only entries. It is the last
normal stage so no later role sees a stream whose orientation it changed.

The normal driver preserves each probe's semantic checks and adds ordered
`begin`/payload/`ok` frames. It flushes `stdout` before a raw marker and after
a probe because the retained probes intentionally use buffered `printf` and
`puts`; `test_owned_text_locale_numeric_component_driver.py` exercises that
ordering with buffered native fake probes. The receipt also parses the raw
normal and source-specific streams to require every retained stage frame in
order, with no bytes outside those frames.

`locale_alias_contract_probe.c` is deliberately a separate executable. Its
strong application definitions replace selected public aliases, while the
library must retain source-selected private providers. Combining it with the
normal roles would change their imports and invalidate both observations. The
receipt preserves this source-specific intentional oracle difference: the
normal object proves selected unresolved public calls have physical providers
in both `libc.a` and `libc.so`; the alias object proves the selected
public/private alias layout from replayed `readelf` tables.

Three existing macro-gated branches run in a third, separate frozen
`source-specific` candidate-only workload. Its static candidate transcript is
the baseline for its static-PIE and dynamic PIE/non-PIE kernel/direct cells;
it is not linked to Musl and it is not added to the table above. The retained
non-credit rows are `candidate-locale-object-wide-profile` from
`libc_locale_object_wide_probe.c`, `candidate-locale-wide-iconv-profile` from
`libc_locale_wide_iconv_probe.c`, and
`candidate-locale-multibyte-profile` from
`libc_locale_multibyte_probe.c`. Their report field is
`source_specific_evidence`, with `credit: false` for every row, explicit raw
candidate cells, physical link/payload receipts, and the source branch
literals that caused the separation.

The owned-runtime object-wide selector rejects unsupported names and accepts
empty-name environment selection with `LC_ALL=C`. Its private freestanding
counterpart still rejects empty names because it has no environment owner.
The earlier frozen rejection was an unclosed family/parity gap, not a final
profile exclusion. Current environment precedence and default/base behavior
require the separate owned-locale `v3` differential component; this supplement
still has no `locale.core` completion credit. The iconv selector
records the bounded rejection of generic `ISO-8859-1`, `UTF-16`, and
`UCS-2LE` names. It does not alter the UTF-16LE/BE and UTF-32 conversion row
above or claim a general legacy-encoding registry. The multibyte selector
records only the rejection of an `LC_ALL` component list naming a non-profile
locale; musl's component parser over profile names is in the parity rows, and
this row adds no `text.wide-multibyte` credit.

The retained ABI is Linux/x86-64 little-endian LP64: `locale_t` and `iconv_t`
are pointer-sized opaque handles, `wchar_t` is four bytes, `mbstate_t` is eight
bytes with alignment four, and float conversion retains the SysV x87 binary80
long-double ABI. The provider reader re-runs `nm` and `readelf` over the
physical normal ET_REL object and supplied products before accepting retained
symbol text. Link receipts and copied dynamic payload audits bind every six
execution cells to those object bytes and product trees.

`owned_text_locale_numeric_component_receipt.py` validates one report with
`validate-report`. Its aggregate `validate(root, receipt)` consumes primary,
reproduction, and extracted POSIX product pairs. The aggregate's `source`
field is exactly `owned_posix_static_products.source_identity(root)`,
`products` maps each pair to its static and dynamic roots, `rows` is the table
above, and each pair retains the six raw `execution_cells`. The required
`pair_evidence_roots` map identifies the three report directories so a family
coordinator can snapshot their nested raw evidence even when the aggregate
receipt lives elsewhere.

This component does not complete the family, runtime qualification,
promotion, or public x86 support. Its `wide-stream` row observes the wide C
entries of `text.wide-multibyte`; the stream engine itself (buffering,
positioning, locking, and byte/wide orientation for every stream kind) stays
owned and proved by the separate stdio FILE-engine component. The scope also
does not add a general locale database, legacy encoding registry, or general
family claim. The frozen 26df supplied-product run is development evidence
only; source-matched three-pair qualification remains the family coordinator
checkpoint.
