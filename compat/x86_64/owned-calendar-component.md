# Installed clock/calendar component receipt

`run_owned_calendar_component.py` and
`owned_calendar_component_receipt.py` make one selected installed x86-64
`time.clock-calendar` component reconstructable. The component is deliberately
finite. Its report has `family_completion`, `promotion_ready`, and
`public_support` set to false; it is an input to a later family coordinator,
not evidence that the whole text/math/locale/stdio family is complete.

## Rows and object roles

The public reader admits exactly these rows through all six installed entry
cells: static ET_EXEC, static PIE, dynamic PIE through kernel and direct
interpreter entry, and dynamic non-PIE through kernel and direct interpreter
entry.

| Receipt row | Installed-header object and retained behavior |
| --- | --- |
| `calendar-posix-tz-format` | The ordinary `owned_calendar_probe.c` object plus `owned_calendar_real_zone_probe.c`: POSIX strings, named New York/Berlin/Lord Howe zones, explicit `/etc/localtime`, local conversion, fold/gap/normalization, extended-format/locale behavior, overflow, concurrent `_r` calls, and fixed named-zone transitions. |
| `calendar-tzif-specification` | `owned_timezone_tzif_probe.c check`, which requires the RFC 9636/POSIX result. Its separate pinned-musl `observe` transcript is retained as the documented six-case oracle defect and never treated as parity. |
| `calendar-strptime` | The ordinary parsing matrix plus the separately classified guard-page and delimiter corrections in `owned_strptime_probe.c`. The pinned-musl guard fault is an oracle defect; it is not converted into a passing differential. |
| `calendar-getdate-global` | `owned_getdate_probe.c` with a private `DATEMSK` root, including `getdate_err`, retained state, cancellation state, and final template cleanup. |
| `calendar-clock-adjustment-safe` | Query-only adjustment, local invalid-input validation, null `settimeofday`, the in-process seccomp-contained nonnull attempts in `owned_legacy_time_probe.c`, and the independent rejected-ID/zero-`timex` `libc_clock_adjtime_probe.c`. |

`calendar-malformed-tzif` is a separate object built from the same calendar
source with `-DCRABC_OWNED_CALENDAR`. It is candidate-only: its successful
private malformed-file branch is required without presenting it as a sixth
capability row. Its ordinary binary record stream must remain byte-identical
to the ordinary calendar object for the same entry cell.

## Sealed real-zone input and clock safety

The core image deliberately has no `tzdata`; it is never changed for this
receipt. The runner does not substitute POSIX strings for real-zone cases.
`prepare-tzif-input` builds test-only TZif inputs from the fixed IANA 2025b
source pair inside the immutable core image, and the component runner accepts
only its physical, manifest-bound output below checkout `.work/`.

The tracked pins are
`https://data.iana.org/time-zones/releases/tzcode2025b.tar.gz` SHA-256
`05f8fedb3525ee70d49c87d3fae78a8a0dbae4fe87aa565c65cda9948ae135ec` and
`https://data.iana.org/time-zones/releases/tzdata2025b.tar.gz` SHA-256
`11810413345fc7805017e27ea9fa4885fd74cd61b2911711ad038f5d28d71474`.
The official detached signatures are retained but explicitly marked
`retained-unverified`: the image has no signature verifier or authenticated
IANA release key. The reader checks URLs, hashes, version, retained signature
identities, `make zic` and fixed `zic` argv, compiler/make/zic identities, and
the exact selected fixture roster before it reads component evidence.

The fixed derivation pins are New York (1744 bytes,
`d7f2206b3a45989fc9ad63d558922532fa7352280d5f87176bf1db79cb1d1fa9`),
Berlin (705 bytes,
`a7fd9932d785d4d690900b834c3563c1810c1cf2e01711bcc0926af6c0767cb7`),
and Lord Howe (692 bytes,
`f368bd25659c0293d02bb79ec7dac7d5b73a92dffafce14b4dd2ffb8ba11aada`).
The preparation command passes the recorded canonical compiler explicitly as
`CC=` to `make`; a rehashed manifest cannot admit a changed derived file.

The input contains only these physical mode-`0644` files. `localtime` is a
byte-identical New York copy, never an ambient image or host file:

- `/usr/share/zoneinfo/America/New_York`
- `/usr/share/zoneinfo/Europe/Berlin`
- `/usr/share/zoneinfo/Australia/Lord_Howe`
- `/etc/localtime`

Every candidate is chrooted into a fresh root, so an ambient host zoneinfo tree
cannot satisfy a real-zone lookup. `owned_calendar_real_zone_probe.c` asserts
New York winter/summer, Berlin winter/summer, Lord Howe January `+11` DST and
July `+10:30` standard time, plus the explicit `/etc/localtime` New York copy.
A separate expected-failure action omits Lord Howe and must emit the fixed
missing-fixture assertion. The reader checks staged and copied fixture bytes
and modes, the supplied dynamic product copy before consumer and fixture
staging, complete before/after root rosters, and expected private-probe
cleanup. The pre-existing 427712-byte ordinary calendar stream remains
historical bounded differential evidence; it does not qualify named-zone
fixture availability or transitions.

`adjustment-query` only supplies a null adjustment or zero `timex`. The two
invalid-input guards are input-validation evidence only. Their Docker launch
adds only `SYS_CHROOT`, never `SYS_TIME`; the retained `/proc/self/status`
control record requires `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb`
all to omit `CAP_SYS_TIME` before a direct shell `exec` launches `chroot` and
the consumer. The control command and its multi-call shell/chroot payloads
are identity-sealed. This is a container-boundary absence proof, not an
unsupported in-process capability-drop claim.
`adjustment-seccomp` is the only nonnull adjustment attempt: its own source
installs `EPERM` seccomp rules for `adjtimex`, `clock_adjtime`, `settimeofday`,
and `clock_settime` before it issues any such attempt. The direct
clock-adjtime object uses only clock ID `-1` and `CLOCK_MONOTONIC` with a
writable zero `timex`. The component neither changes nor claims a host clock.

## Collection and replay

The dispatcher owns collection:

```sh
./scripts/dev-x86_64.sh owned-calendar-component
./scripts/dev-x86_64.sh owned-calendar-component --static-sysroot "$static" "$dynamic"
```

On the host it first retains the fixed IANA archive pair and detached
signatures below `.work/x86_64/calendar-tzif-input-2025b/download/`, fetching
only absent files and refusing archive bytes that differ from the tracked
SHA-256 pins. It then resolves the core image's ID and runs
`run_owned_calendar_component.sh` by that ID with only `SYS_CHROOT` added and
`CRABC_X86_CALENDAR_IMAGE_ID` set to the observed identity. The launcher
builds current static and dynamic products when no pair is supplied, derives a
fresh TZif input with `prepare-tzif-input` in that image, and runs
`run_owned_calendar_component.py`. The receipt reader admits only the pinned
current core image,
`sha256:307d75f06680c631437f9faa5f7c726613fcea6f1875dda8cf368ad4b6da1b3d`;
reports from the retired `sha256:5990e55b…` image remain historical evidence.

The producer itself never builds a product. The report retains source/product
and tool seals before and after (including the launcher), every installed-header
ELF object, exact compile, link, validation, chroot, and capability-boundary
argv, public product-link reconstruction, raw stdout/stderr/status, and root
fixture audits. Reconstruct it after the producer exits with:

```sh
python3 -B compat/x86_64/owned_calendar_component_receipt.py validate-report \
  --root /workspace --report /workspace/.work/x86_64/.../owned-calendar-products.json \
  --require-static
```

The reader requires full six-mode evidence. There is no dynamic-only catalog
admission for this component. A receipt binds a single supplied static/dynamic
pair; a later aggregate must select its own product-pair policy rather than
reuse this development proof as source-matched qualification.
