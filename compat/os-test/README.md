# Pinned os-test POSIX profile

`run.py` runs the pinned `os-test` revision from `compat/upstreams.toml` in
isolated temporary directories under both pinned musl 1.2.6 and crabc.  It
uses os-test's own `make <suite>-test` targets, so its include, namespace,
feature-macro, compile, and execution rules remain intact.

The selected profile is deliberately offline and deterministic: `include`,
`namespace`, `basic`, `limits`, `io`, `malloc`, and `stdio`.  The upstream UDP
suite contains documented public-network probes, so it is not used here.
Resolver/network and signal/process behavior instead have dedicated local
runners that can control their own loopback fixtures.

The same source is tested twice. The musl run uses the pinned musl headers and
runtime. The crabc run uses the project headers, the crabc dynamic linker, and
`libc.so`; its runtime environment contains only the candidate
`LD_LIBRARY_PATH`.

Runtime suites and the generated `include` matrix compare every `.out` outcome
byte-for-byte with musl, with no filtering of semantic differences. The
generated include matrix contains musl-scoped optional and extension
declarations, so its many non-`good` labels are observations rather than a
single portable success token.

`namespace` is different: its source-defined successful result is exactly
`good`; the runner evaluates crabc against that direct test oracle and records
musl's result as an audit observation. Pinned musl 1.2.6 itself reports
namespace pollution for several probes, so using that incidental result as the
target would make crabc reproduce a known failure. The only non-`good`
namespace outcomes allowed are the three individually named pinned-musl header
skips recorded in the runner. This is a narrow source-oracle rule, not a glibc
fallback; musl remains the runtime compatibility authority.

`basic` includes complex-math probes and is compiled with the native AArch64
ABI, as is every other profile suite. It remains a musl differential suite.
When the pinned musl run emits a basic diagnostic but crabc returns that
case's exact source-defined success outcome, the runner reports a **source
improvement**: it preserves the raw bytes and does not treat the improvement
as a differential regression. This recognition is exact—an absent output,
timeout, or any non-success candidate diagnostic is still a failure. The
report separately counts source diagnostics that crabc shares with musl; it
does not call those tests source-clean, and the `basic` suite is red whenever
that direct source contract fails—even when the candidate bytes happen to
match musl byte-for-byte. That count is an accuracy measurement, not a
replacement compatibility oracle: a candidate result that is
byte-identical to musl remains differential parity unless POSIX/C requires a
different result. In particular, the runner never substitutes host-glibc
semantics for musl's behavior.

Run it in the AArch64 image:

```sh
./scripts/dev.sh os-test
./scripts/dev.sh os-test --suite include
```

The runner atomically writes `compat/reports/os-test/latest.json`.  A missing
suite result, failed make target, timeout, or changed outcome is a failure
unless it matches one of the exact, source-evidenced exceptions recorded in
the report.  Raw runtime streams, statuses, and differences remain present
even when an exception is accepted.  The current manifest contains one
same-status `basic` shared-object link case and three individually named
`process` waitpid cases; it does not provide a broad suite or substring
ignore.

The profile includes `include`, `namespace`, `basic`, `io`, `limits`,
`malloc`, `process`, `pty`, `signal`, and `stdio`. It excludes os-test's UDP
suite because that target uses public routing; the local resolver/network runner
instead uses only a deterministic loopback DNS and socket fixture.
