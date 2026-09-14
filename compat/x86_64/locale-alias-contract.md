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

## Retained receipt and host replay

`locale_alias_contract_receipt.py` wraps the existing runner; it does not turn
an older shell transcript into current evidence. `locale-alias-contract-image-inputs.json`
is the finite immutable image-input manifest. It binds the pinned image, musl
1.2.6 archive/shared object/specs/compiler, and every runner or collector tool
by physical path, bytes, and mode. Collection requires a clean Git checkout
including no untracked inputs, captures the complete HEAD/tree Git bytes and
modes, and copies the selected source files both before and after the native
work. Each fresh static and dynamic product is joined to that same source
transaction; the dynamic product additionally retains its producer's source
digest. It then passes one fresh explicit `--receipt-dir` to
`run_locale_alias_contract.sh`. Every captured compile, link, header, normal
static runtime, dynamic kernel/direct runtime, and symbol-observation command
retains its exact argv, `/workspace` working directory, closed `LC_ALL`/`PATH`
environment, `/dev/null` stdin, `/usr/bin/env -i` plus `/usr/bin/timeout`
launcher, stdout, stderr, status, and modes. The normal consumer runner uses
`umask 022`; source, image-tool, installed-product, raw-stream, and linked
consumer mode policies are all checked from retained bytes. The receipt also
retains the compiled object and every linked consumer identity, before/after
input snapshots, and complete static/dynamic product trees including directory
and symlink modes.

The host-side `validate-report` path only reads the receipt. It reconstructs
the fixed 35-command runner roster and its paths, authenticates the retained
complete Git source tree, rechecks selected current source bytes/modes, image
inputs, product manifests/trees, launch context, all runtime comparisons, and
the complete alias observation from the retained `readelf` streams. Collection
repeats the source/image/product/raw-input checks after report construction;
host replay starts no compiler, linker, target executable, shell, or container.

The selected source relation remains deliberately narrow: `locale_narrow.rs`,
`locale_objects.rs`, `gmtime_r.rs`, `owned_calendar.rs`,
`owned_strftime.rs`, `owned_timezone.rs`, and their selected
`static_c_abi.rs` composition are byte-bound. The four time internals retain
the source-specific distinction described above: musl's full table has local
`DEFAULT` definitions while the candidate's has local `HIDDEN` definitions;
neither is accepted as a dynamic export. The receipt also retains the
source-local oracle `tzset`/`__tzset` distinction instead of inferring a
candidate static placement from a symbol's presence.

This receipt still excludes `wcsftime_l`, native ABI selection, a general
locale or timezone implementation, dynamic-authority review, runtime
qualification, family completion, and public-support promotion.
