# Finite native POSIX profile dispositions

The native aggregate distinguishes raw upstream success from qualification
under an existing compatibility profile. Original OS-test and libc-test
sources, reports, counts, exit statuses and diagnostic streams remain intact.
A qualified profile difference is never an upstream pass or an excluded unit.
`owned_posix_native_dispositions.py` owns the complete finite difference set;
`owned_posix_native_observations.py` still validates every source, object,
link, execution root, raw outcome and oracle observation.

Only these four source boundaries may have a profile disposition. OS-test
`basic` has none: owned products apply musl's process-wide credential
setters, so its setter outcomes are exact raw matches.

* OS-test `include/stdatomic/{atomic_flag_clear,atomic_flag_clear_explicit,
  atomic_flag_test_and_set,atomic_flag_test_and_set_explicit,atomic_signal_fence,
  atomic_thread_fence}.out`: the six untouched address-taken source forms retain
  candidate `good` and pinned-musl `undefined` raw observations. This is the
  existing `static-c-atomic-addressable` project extension, whose installed
  companion requires the same product's installed header dependencies, exactly
  six dynamic `libc.so` exports, the existing C and C++ behavior probes, and
  all four owned dynamic entry modes. The C++ probe declares only the six
  `extern "C"` spellings and may not introduce a C++ runtime dependency.
  It does not show musl declaration or export availability, a general
  `stdatomic.h` closure, C11 family closure, or a C ABI policy decision.
* libc-test `functional/crypt`: all 32 active calls in the fixed pinned source
  remain present. Twelve legacy-format calls and sixteen unsupported SHA
  setting calls require an actual nonnull `*` result. Two invalid-bcrypt
  markers and the two supported SHA low-round vectors remain exact upstream
  matches. The original unit therefore retains its 28 exact diagnostics and
  raw failure. No additional failure, missing diagnostic, changed result,
  matched oracle failure, timeout, missing source entry or failed setup can
  acquire this disposition.
* libc-test `functional/strptime`: the untouched fixed source's `/* Glibc */`
  block retains exactly two diagnostics for both candidate and pinned musl,
  both with raw exit status 1 and empty stderr. The `%s` call leaves a zeroed
  `tm` after parsing `683078400`; the `%z` call rejects `-06`. This is a
  source-and-standard qualification of the raw upstream failure, never an
  upstream pass or a general allowance for equal failures. Its prepared source
  must equal `native-strptime-reference/strptime.c` byte-for-byte, and the
  candidate and pinned-musl stdout streams must each equal the exact two
  diagnostics plus `FAIL /functional/strptime [status 1]`. A missing, extra,
  or changed diagnostic, another status, nonempty stderr, timeout, or source
  change fails closed.

  The pinned source is MIT-licensed libc-test revision
  `68edb8bd73dab8147ee54c8bec638f4d2b3cff37`, tree
  `4f7a5373652c6534b0fbafb58fe3fed1489f3b3b`; the local reference and license
  are `compat/x86_64/native-strptime-reference/{strptime.c,COPYRIGHT}`. Both
  calls are in that source's explicit `/* Glibc */` block. POSIX.1-2017 does
  not list `%s` or `%z` in [`strptime`](https://pubs.opengroup.org/onlinepubs/9699919799.2018edition/functions/strptime.html).
  POSIX.1-2024 adds `%s` while leaving any effect on `tm` unspecified, and
  defines `%z` only as ISO 8601 `+hhmm` or `-hhmm`, again with any `tm` effect
  unspecified ([`strptime`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/strptime.html)).
  The retained musl 1.2.6 `src/time/strptime.c` parses `%s` while leaving `tm`
  unchanged and requires four digits after a `%z` sign. The ordinary source
  cases remain checked by the untouched unit and installed numeric/calendar
  component; this disposition establishes no general locale, time, or glibc
  extension closure. It admits no other unit or failure.
* libc-test `functional/wordexp`: both the selected candidate and pinned musl
  retain raw exit status 1, empty process stderr, and their complete original
  source-prefixed diagnostic streams. The checked
  `owned_wordexp_upstream_policy_diagnostics.json` reference fixes the
  untouched `functional/wordexp.c` SHA-256
  `e3e310de1a73bc30273ac5f4711492817a2f26a5750795c9a3f0be42645871c9`,
  all 20 candidate and all 104 musl diagnostics, their order, and the terminal
  `FAIL /functional/wordexp [status 1]` marker. `owned_wordexp_upstream_policy.py`
  rejects any changed source, status, stderr, missing, extra, altered, or
  reordered diagnostic.

  The nested disposition is `posix-policy-qualified` and still records
  `raw_passed: false`; the enclosing libc-test result is only
  `profile-qualified`. It is never a candidate pass or a pinned-musl oracle
  defect. Its public-C companion is described in
  [`owned-wordexp-upstream-policy.md`](owned-wordexp-upstream-policy.md): all
  four dynamic entry modes must retain the exact twenty candidate observations
  and the separately pinned musl observations, including every status, word
  byte, captured diagnostic, command-effect, and `env=0` field.

  Qualification requires both the complete same-product wordexp report and a
  separately captured expected-native-inputs file. The native reader gives the
  latter to the full `owned_wordexp_evidence.validate_report` reconstruction;
  it never derives the expected input from the report being checked. That
  reconstruction binds the current installed-product source/object/header/link
  closure. The accounting reader then requires that report's dynamic root and
  manifest to name this aggregate's installed product and requires all four
  `source-policy` cells. A partial companion, another product, a changed
  expected-input seal, or a successful marker without those raw observations
  fails closed. This boundary does not qualify `functional/random` or any
  unlisted libc-test failure.

The bounded adapter parses decimal rounds and normalizes values below 1000 to
1000 before validating RustCrypto parameters. It rejects excessive or
unparseable round values. Empty salts, extra fields, noncanonical salt text
and overlong salts are distinct restrictions; low rounds are not classified
as unsupported. The fixed reference includes the upstream license and exact
source provenance. Qualification requires the fresh prepared `crypt.c` to
match those reference bytes. The observer is separately generated and never
substitutes for the original test.

`run_owned_crypt_runtime.sh` retains its existing canonical ABI fixture and
adds one independent same-object 32-vector observer. The observer records
actual pointer nullness and output bytes for every vector. Its pinned-musl
process and four owned dynamic entries have separate exact expected outputs,
and each must exit zero with no unexpected diagnostics. The existing ABI
fixture additionally proves canonical SHA-256/SHA-512 default and explicit
rounds, public/private symbol ownership, rejection boundaries, buffer guards,
null behavior and overlapping inputs. `owned_crypt_profile.py` reconstructs
`crypt-profile.json` from physical source/header/object/link/product-copy and
raw execution evidence; a success marker alone is insufficient.

## Corrected scalar math pinned-musl oracle defects

Three libc-test entries have a separate, finite source/oracle-defect result;
they are not compatibility-profile dispositions. `math/fmaf`, `math/fmal`, and
`math/powf` each retain the exact pinned musl 1.2.6 diagnostic stream and exit
status 1 after the owned candidate exits 0 with empty stdout and stderr.
`owned_math_oracle_defects.py` binds the complete pinned libc-test source tree,
each prepared source and diagnostic header hash, the musl provenance, and the
fixed correction implementation, generators, probe, and installed-product
proof sources. It also reconstructs every diagnostic path and byte plus the
terminal `FAIL /math/... [status 1]` marker.

The resulting nested disposition is explicitly
`candidate-passed-oracle-defect`: it records a candidate pass and a pinned-musl
oracle defect, never a candidate limitation or a raw musl pass. A candidate
failure, an oracle pass, matched raw failure, changed/missing/extra diagnostic,
source or header drift, timeout, failed link/root, or any unlisted unit fails
closed. `math/nextafterl` remains an ordinary raw pass; this finite set admits
neither it nor `random` or another unlisted unit.

The native coordinator requires the complete family `execution.json`,
`--crypt-profile RECEIPT`, `--atomic-addressable-profile RECEIPT`,
`--wordexp-profile RECEIPT`, and
`--wordexp-expected-native-inputs EXPECTED` before creating output. All three
installed-product companions consume the identical product. Their raw source,
product, report/expected-input trees, and receipt identities join the
before/after input seals.

The state transition is explicit:

1. An ordinary component has raw success and qualification `passed`.
2. Only OS-test or libc-test may retain raw exit 1 and raw failure while an
   independently reconstructed qualification is `profile-qualified`. The
   three scalar-math entries are separate named candidate-pass/pinned-musl-
   defect records inside the libc-test result; they do not widen that profile.
3. Missing or invalid required companion evidence, a missing or invalid
   source contract, an unexpected raw outcome, or any other failure stops
   execution and retains `incomplete.json`.
4. Only the five fully checked component qualifications can establish
   `native_aggregate_complete`. Family, campaign and public-support flags
   remain false.

Host validation reconstructs these facts without executing a target, compiler,
or Docker. The existing family credentials transcript judge remains a source-owned
Python helper; it never invokes the target. No classification changes the frozen AArch64 baseline or
expands public x86 support.
