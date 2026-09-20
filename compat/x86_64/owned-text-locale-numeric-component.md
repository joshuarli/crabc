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

| Capability | Row | Existing probe role |
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

The object-wide selector records the frozen supplied candidate's rejection of
an unsupported locale name and an empty locale name. Environment-backed and
empty-name locale behavior is an unclosed family/parity gap: it has no Musl
parity comparison and no `locale.core` completion credit. It is historical
candidate-only evidence, rather than a final owned-runtime boundary. The iconv selector
records the bounded rejection of generic `ISO-8859-1`, `UTF-16`, and
`UCS-2LE` names. It does not alter the UTF-16LE/BE and UTF-32 conversion row
above or claim a general legacy-encoding registry. The multibyte selector
records only the exact mixed `LC_ALL` spelling returned by the candidate; it
does not broaden locale-name parsing or add `text.wide-multibyte` credit.

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

This component does not complete `locale.core`, `text.wide-multibyte`, the
family, runtime qualification, promotion, or public x86 support. In
particular, wide FILE/orientation/formatting behavior belongs to the separate
stdio stream-engine receipt; conversion, strings, classification, width, and
UTF16/32 iconv rows here cannot prove it. The scope also does not add a general locale database, legacy encoding registry, or general family claim. The
frozen 26df supplied-product run is development evidence only; source-matched
three-pair qualification remains the family coordinator checkpoint.
