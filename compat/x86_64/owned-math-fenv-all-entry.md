# Owned math/fenv all-entry component

`run_owned_math_fenv_all_entry.sh` composes four already selected native C ABI
surfaces into one installed-product component: the exact 35
`math.elementary-long-double` entries, 15 `math.elementary-fenv-sensitive`
entries, 90 `math.special` entries, and 66 `math.complex` entries. The closed
206-name roster is loaded from `compat/crabc-rs/coverage.toml` and the existing
complex baseline by `owned_math_fenv_all_entry_contract.py`. It includes
`sqrtl` and `csqrt*`; scalar `sqrt` and `sqrtf` remain with their separate
fenv probe.

The component reuses the existing long-double, fenv, `fdim`, decimal-exponent,
special, and complex C observations. `libc_math_abi_boundary_probe.c` adds the
operands and machine state those probes do not compare: every one of the 206
entries runs in all four rounding modes on signaling NaNs of each precision
(alone and beside quiet NaNs), on the x87 pseudo-NaN, pseudo-infinity,
unnormal, and pseudo-denormal binary80 encodings, and then on 64
deterministic pseudo-random finite operands per shape. Each record retains the
x87 control word, the x87 status word's exception/stack-fault/TOP fields, the
x87 tag word, the whole MXCSR, errno, and signgam after the call, so a callee
that leaves the x87 stack occupied, changes precision or rounding control,
raises a flag in the other unit, or writes errno differs from pinned musl
even when its result matches. The two decimal producers own their
record pointers and byte extents; `owned_math_fenv_all_entry_driver.c` calls an
accessor, retains its returned extent, and then emits that exact byte range.
Before every probe,
the driver sets FE_UPWARD with exactly FE_DIVBYZERO and FE_INEXACT; each ordered
stage records a zero status and that caller environment both before and after
the probe. `validate_owned_math_fenv_all_entry.py` requires the fixed stage
order, body sizes, zero statuses, and caller restoration.

Without a supplied pair, `./scripts/dev-x86_64.sh owned-math-fenv-all-entry`
first builds current static and dynamic products inside its evidence
directory, so the single command runs all six entry modes against the
checkout's own source. The runner translates all eleven object roles through
the dynamic driver, combines their ET_REL objects, and requires every selected import to be
defined by the supplied dynamic provider. When a static product is supplied it
also requires every selected archive definition. Its retained header trace
uses the fixed-image compiler selected by the sealed helper because the
application driver deliberately rejects `-E`; it replays the driver's clean
environment, installed include root, freestanding flags, admitted role define,
rounding mode, and dynamic-PIE mode. The provider reader checks that exact argv
and rejects every traced header outside the supplied installed include tree.

The same combined object is linked with the pinned musl oracle, supplied
static/static-PIE products, and supplied dynamic PIE/non-PIE products. Dynamic
executables run through both kernel and direct-loader entry in copied product
roots. Every six-mode result must have the same framed raw stream, empty stderr,
and zero status as the pinned musl result. The runner retains command argv,
raw streams, source/product and tool seals, link receipts, payload-copy audits,
provider tool output, and objects under `.work/x86_64`.

`owned_math_fenv_all_entry_receipt.py` is a separate 18-cell adapter for the
primary, reproduction, and extracted product pairs. It first authenticates the
current product-preparation and dynamic-qualification inputs, then reconstructs
all source/product/tool seals, commands, header traces, imports/providers,
public link records and validator stdout, payload audits, and raw oracle
comparisons. After authenticating the fixed retained command shapes, it also
replays only the fixed `/usr/bin/nm` and `/usr/bin/readelf` provider inspections
against the authenticated workload object, installed `libc.so`, and installed
`libc.a`; their raw output must equal the retained provider views. It compares
the eleven role-object bytes across all pairs. A report from a different source
transaction, or a single development product pair, cannot satisfy that
three-pair receipt. Neither the runner nor the adapter completes a math family,
qualifies a general libm, changes promotion state, or claims public support.
