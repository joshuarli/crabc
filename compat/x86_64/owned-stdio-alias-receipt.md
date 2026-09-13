# Installed FILE alias receipt

`owned_stdio_alias_contract_reader.py` owns a finite supplied-product observation:
42 named weak aliases, their targets (78 identities), three hidden FILE bodies,
and two protected FILE boundary controls. `owned-stdio-alias-receipt.toml` fixes
this roster and its five source-owner groups. The existing byte/wide stream source
owns the runtime; this component adds no implementation or public export.

`fdopen`, `fseeko`, and `ftello` share their named hidden internal bodies. Strong
application definitions remain independent of `fopen`, `fseek`, and `ftell`.
No added alias gains an override rule: the existing three hidden bodies are the
only strong-override control, and `__uflow`/`__overflow` remain the only
protected controls.

The five finite source groups are `owned_static_stdio` (the accepted byte aliases
plus `__getdelim`), `owned_wide_stdio` (the accepted wide aliases),
`owned_stdio_extensions` (eight unlocked and six `_IO_*` aliases, with one
`fpurge` spelling), `stdio_format_scan` (six byte `__isoc99_*` scan aliases), and
`owned_wide_format` (six wide `__isoc99_*` scan aliases). Every group requires
the exact source-local `.weak`/`.set` declaration before its retained selected
source bytes are accepted. Single-character unlocked operations use their
unlocked bodies; block and wide string aliases retain musl's locking behavior.
Cookie callbacks synchronously join a contender to observe the enclosing FILE
lock. The contract probe also calls bounded FILE aliases, `__getdelim`, and byte
and wide ISO-C99 string scans. The protected-symbol probe checks collisions,
libc-handle lookup and real body callability. It does not exercise a
defining-libc internal call under an application override.

The three fixed C sources each produce one retained ordinary object. The same
object feeds every relevant musl/candidate link: two probes through musl static
and candidate static/static-PIE plus dynamic PIE/non-PIE; the protected probe
through musl PIE and candidate PIE/non-PIE. Dynamic programs run at both kernel
and direct-interpreter entry. This gives 13 links and 20 executions. The ordinary
contract probe also calls default `fdopen`, `fseeko`, and `ftello`; the separate
override probe defines those public functions itself.

The native pinned image invokes the existing runner in explicit receipt mode:

```sh
compat/x86_64/run_owned_stdio_alias_contract.sh collect \
  --static-preparation .work/x86_64/INPUT/static/preparation.json \
  --static-product .work/x86_64/INPUT/static/products/primary \
  --dynamic-product .work/x86_64/INPUT/dynamic \
  --historical-facts .work/x86_64/INPUT/historical-facts/report.json \
  --output .work/x86_64/OUTPUT
```

Use the pinned native core image, `LC_ALL=C`, its actual resolved image identity
in `CRABC_X86_PUBLIC_DATA_IMAGE_ID`, root with `SYS_CHROOT`, network disabled,
source/products read-only and a disjoint checkout-local writable output parent
and temporary directory. No ptrace capability is needed. The two-positional
shell path is historical; it does not emit this sealed receipt.

Pure host replay uses the retained tools and supplied payloads, without a
compiler, `/opt`, native execution or product rebuild:

```sh
python3 -B compat/x86_64/owned_stdio_alias_contract_reader.py validate-report \
  --report .work/x86_64/OUTPUT/report.json
```

The report retains the current clean collector identity separately from the
historical product source. The historical preparation is correlated to its
primary payload, source seals and manifest; its package reproduction is not
requalified. The old complete-ELF report is a bound product/source cross-check,
not relabeled as a current-collector inventory replay. Fresh complete readelf
header/section/symbol streams and archive rosters independently observe the four
libc artifacts. Archive occurrence, table and positive executable section are
part of every alias domain; equal values alone do not prove aliases. Local,
hidden, undefined and unsupported raw facts remain in the complete projection.
Each public shared `.dynsym` row must itself define an executable section and
match its `.symtab` body in section, value, type and size. The CLI requires exact
option spellings and one occurrence per option, including `--option=value` forms.

The selected FILE/header source must match its historical source revision, and
collector source, actual tools, probe objects, commands, driver receipts,
execution copies and supplied product bytes are guarded before and after the
run. The public reader reconstructs observations and candidate links. It rejects
changed rosters, versions, bindings, alias domains, hidden dynsym exposure,
command diagnostics, transcripts and copied payloads. It preserves all 21
historical selection reasons as unmeasured until a separately owned selector
attachment; runtime/family/public-support closure stays false.
