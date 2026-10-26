# Owned feature-alias component receipt

`owned_feature_alias_receipt.py` collects and replays one fixed native x86-64
component for accepted-C release products. Both installed feature routes must
match their selected static and dynamic producer commands. Its five owner sections cover these six source-selected aliases:

| Owner | Public spelling | Target | Feature proof |
| --- | --- | --- | --- |
| signal | `__sysv_signal`, `bsd_signal` | `signal` | Isolated `x86-signal-legacy-aliases` archive |
| passwd | `endpwent` | `setpwent` | Selected static preparation's `x86-owned-static-runtime` command |
| exec | `execvpe` | `__execvpe` | Isolated `x86-process-exec` archive |
| temporary | `mkostemps` | `__mkostemps` | Selected static preparation's `x86-owned-static-runtime` command |
| netdb | `setnetent` | `sethostent` | Isolated `x86-netdb-setent` archive |

The feature roster supplies each complete `function_alias_requirements`
record. The receipt preserves those records unchanged. Isolated archives use
one shared unfeatured baseline and three retained source-runtime Cargo graphs.
Replay checks the actual Cargo and rustc feature profiles, dependency closure,
source-built runtime members and complete public archive deltas. Unknown or
combined retained profiles fail. The broad owned-runtime route reuses the
selected preparation and sealed producer command. It does not claim an
independent aggregate feature delta or build another aggregate archive.

Each owner compiles its existing behavior probe once through the supplied
installed dynamic driver. Each compile requests the driver's
`--application-dependency-file` output. Replay binds the exact object target,
source and complete installed-header dependency identities. A foreign input,
missing required header or changed dependency file fails.
That object links unchanged against the pinned native musl oracle, installed static and static-PIE products, and installed dynamic PIE
and non-PIE products. Both dynamic executables run through kernel and direct
loader entry. The passwd matrix runs all sixteen existing scenarios. The exec
matrix uses the existing 44-name process-control probe. Its exact expected
output retains the established oracle EBADF and candidate ENOSYS distinction
for the seccomp-blocked `fexecve` observation.

Every owner also runs a strong-override probe through the same modes. Netdb,
exec and temporary owners use their existing override fixtures. Signal and
passwd use `owned_feature_alias_override_probe.c`, which replaces the weak
public spelling while calling the ordinary strong target separately.

The reader validates installed link receipts, copied payloads, complete ELF
symbol facts, executable overrides and exact runtime status and streams.
Copied consumer, runtime-file and directory modes must match their sources.
Alias definitions must share an archive member occurrence, symbol-table
section, executable definition section, address and function size. Hidden
shared targets may be LOCAL. A target's extra dynamic export fails. Source,
selected product trees, preparation and native tools must remain unchanged
between the before and after seals.

Collect against one current clean cohort:

```sh
./scripts/dev-x86_64.sh owned-feature-aliases collect \
  .work/x86_64/feature-alias-proof \
  --static-product .work/x86_64/cohort/static/products/primary \
  --dynamic-product .work/x86_64/cohort/dynamic/product \
  --static-preparation .work/x86_64/cohort/static/preparation.json
```

Replay with `validate-report` and the retained `report.json` path, supplying
the same three inputs. `abi-differential-evidence collect-companions` registers
the directory as `feature_alias_work` and passes those cohort inputs directly.
The ABI selector accepts `--feature-alias-work WORK`, matches the exact receipt
occurrences to its complete ELF facts, and discharges only the six existing
feature-alias receipt reasons. Undefined imports, all placement blockers and
all source requirements remain. Any failed owner rejects the companion.
Family completion, runtime qualification, promotion and public support remain
false. The standalone producer does not run the POSIX aggregate. If a separately
validated POSIX admission already discharged `__sysv_signal`, the selector
checks that prior source, cohort, definition-domain and semantic proof. Its
feature join retains both report provenances and discharges no reason twice.
The other five aliases still require their own exact receipt reasons.
