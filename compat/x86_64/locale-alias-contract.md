# Native locale and time weak-alias contract

`locale_alias_contract.json` records the pinned musl 1.2.6 source/artifact
shape for the selected native x86 locale, classification, collation, and time
entries. It is a private component measurement. It does not complete a locale
family, ABI differential, product qualification, promotion, or public x86
support.

Musl gives the selected public spellings weak linkage so an application can
provide a strong replacement. Its libc implementation calls the selected
strong internal spelling when source behavior needs to stay inside libc. The
native providers preserve that distinction instead of making a Rust wrapper
call back through a public name:

- `locale_narrow.rs` owns the narrow `_l` ctype/case/collation aliases.
- `locale_objects.rs` owns locale-object, `nl_langinfo`, and wide `_l` aliases.
  These internal names remain global/default in the pinned static and shared
  observations, with public weak aliases at the same address. `freelocale` is
  the reverse musl form: its strong public body has the weak same-address
  `__freelocale` spelling.
- `gmtime_r.rs`, `owned_calendar.rs`, and `owned_strftime.rs` own the four
  hidden strong time spellings. The static archive retains the hidden internal
  symbol; `libc.so` exposes only the public weak alias in `.dynsym`. Its full
  `.symtab` retains one local definition at the same section, value, and type
  as that public alias. Musl records those local definitions as `LOCAL DEFAULT`;
  the candidate records them as `LOCAL HIDDEN`, which is a permitted linker
  localization difference and not a dynamic export.
- `owned_calendar.rs` and `owned_strftime.rs` call the Rust locale-object body
  directly, so an executable replacement of `nl_langinfo[_l]` cannot change
  libc's C-locale calendar/formatting path.
- `owned_timezone.rs` retains a direct private Rust timezone refresh body and
  a weak public `tzset`. Musl's `__tzset` is local to its archive member; the
  candidate deliberately does not invent a cross-object `__tzset` or a shared
  dynamic symbol merely to reproduce that unused local spelling.

The default static archive gains the selected locale internals, including
`__freelocale`, and `__gmtime_r` because they are default-static providers. The owned static
feature separately adds `asctime_r`, `localtime_r`, and `strftime_l`, each with
its hidden strong internal spelling. Their feature alias accounting belongs to
the root-owned feature roster; this document is not that roster.

## Focused installed-product proof

Inside the pinned native image, run the source guard and then pass matching
installed static and materialized dynamic products:

```sh
python3 -B compat/x86_64/tests/test_locale_alias_contract.py
TMPDIR="$PWD/.work/x86_64/tmp" \
  compat/x86_64/run_locale_alias_contract.sh \
  --static-sysroot "$PWD/.work/x86_64/PRODUCTS/static" \
  "$PWD/.work/x86_64/PRODUCTS/dynamic"
```

The runner compiles one application object through the installed dynamic
headers. It links that exact object separately to pinned musl and to the owned
static and shared products. The candidate runs static ET_EXEC and static PIE;
the pinned wrapper's established ET_EXEC link supplies the static reference
transcript because its static-PIE specs do not select the installed driver's
self-relocating CRT. Shared PIE and non-PIE pairs each execute by kernel and
explicit-loader entry paths. The retained evidence includes link commands,
input snapshots, statuses, archive, `.dynsym`, and selected full `.symtab`
observations, and the exact contract bytes.

The application provides strong replacements for representative public locale
and time names, including `tzset`. It then verifies the replacements directly
and exercises high-level libc paths that must retain internal providers:
`asctime`, `gmtime`, `localtime`, `strftime`, byte/wide collation, and direct
artifact-observation declarations for the locale internals. Those direct
internal checks create `C`, `POSIX`, and `C.UTF-8` objects, duplicate the UTF-8
object, select and restore it, release valid tokens through both
`freelocale` and `__freelocale`, and verify its `CODESET`, narrow/wide
classification, and collation state. The direct internal declarations are
probe-only artifact observations; installed headers remain the application's
ordinary API source.

The runner rejects a changed alias address, binding, visibility, missing time
internal, unexpected time internal dynamic export, a duplicated `.symtab`/
`.dynsym` interpretation, or an executable that fails to retain the selected
public strong replacements. It intentionally does not claim a general locale
catalog, legacy encodings, timezone-data qualification, or full application
interposition coverage.
