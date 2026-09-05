# Owned fmtmsg

`libc/src/c_abi/x86_64/owned_fmtmsg.rs` translates musl 1.2.6
`src/misc/fmtmsg.c` from release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. The source SHA-256 is
`27354c57b1827561585a73dbe9f2d7f97cd73563d4043cf2907912c8faaebb6e`.
That file explicitly says “Public domain fmtmsg(); Written by Isaac Dunham,
2014”; this source-specific dedication is separate from the surrounding
musl MIT license. `_strcolcmp` maps to `component_mismatch`; `fmtmsg` maps
to `fmtmsg` and its private `msgverb_mask` parser.

The owned function uses the existing environment, descriptor, `dprintf`, and
pthread cancellation owners. It disables cancellation across console open,
formatting, close, and stderr formatting, then restores the caller's previous
state. As in musl, restoring the enabled state does not itself deliver a
pending deferred request; the next cancellation point does. Initialized owned
runtime threads provide that cancellation state. A foreign thread without the
owned state is rejected with `MM_NOTOK` before either descriptor route, using
the same boundary as owned syslog. No broader foreign-thread contract is added.

`MM_CONSOLE` always renders all components and closes its borrowed-open
console descriptor even when formatting fails. `MM_PRINT` borrows descriptor
2 and honors colon-delimited `MSGVERB`; absent/empty or unknown selections
render all components. Route failures compose as `MM_NOMSG`, `MM_NOCON`, or
`MM_NOTOK`, and console close errors leave the route result unchanged. The
source initializes its severity pointer from the zero-valued `MM_NULLSEV`:
unknown nonzero severity therefore passes null to `%s`, retaining the owned
formatter's musl-compatible `(null)` rendering. Empty strings and null
component pointers remain distinct.

The frozen opt-in selected-static `legacy_misc.rs` piece writer and the
paused shared profile retain their existing contracts. Only owned runtime
products select this owner; no symbol other than the already installed
`fmtmsg` declaration is introduced.

`run_owned_fmtmsg.sh` compiles one installed-driver workload object from
`owned_fmtmsg_probe.c`, performs an installed-header dependency audit, and
links that unchanged object against pinned musl and the selected products.
`compile.json`, `workload.d`, and sealed link receipts retain the compile and
product identities; `owned_posix_product_evidence.validate_link` checks every
link before status/stdout/stderr comparisons. With no arguments the runner
builds static/static-PIE and dynamic PIE/non-PIE products and runs dynamic
programs by kernel and direct-loader entry. `--static-sysroot` plus a dynamic
product replays all six forms using supplied products; a supplied dynamic
product alone supports dynamic-only replay. Supplied products are validated
and neither producer runs when both products are supplied.

The probe checks all five components, component-order independence, repeated
and trailing selectors, invalid selectors, null/empty strings, every defined
severity plus the source's unknown-severity case, and no-route classification.
Console success ignores `MSGVERB`; missing console, closed stderr and
`/dev/full` console writes cover independent and combined errors. Console success and repeated
errors check descriptor release. The cancellation scenario
fills a FIFO at `/dev/console`, waits until the worker has opened its blocked
writer after disabling cancellation, then requests deferred cancellation.
The worker must finish both outputs and close the console before its next
explicit `pthread_testcancel` invokes cleanup. Cleanup observes the console
fd closed; the main task verifies both complete output byte strings and the
cancelled join result. An already disabled caller's prior state is preserved.
Each scenario runs in a disposable chroot below checkout `.work`; it never
opens the host console or changes the host stderr route.

The initial regression retained the same installed-header object for the
oracle and candidate link: the candidate lacked `fmtmsg`, while pinned musl
passed all three scenarios. The semantic probe is the regression, and
`tests/test_owned_fmtmsg.py` covers replay parser and evidence containment.

The focused installed run passed all three scenarios against musl in all six
owned execution forms. Its workload SHA-256 is
`090580e91cd8e3193d7e30a16e317202a5d5b16885f1efcba264e47c7499bf61`, identical
to the initial missing-symbol regression object. The separate replay/containment
suite passed three tests. This proves the named `fmtmsg` boundary, not an
unrelated campaign or public-support promotion.
