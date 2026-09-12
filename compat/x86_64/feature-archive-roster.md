# Feature-archive callable ownership

`feature_archive_roster.py` gives each native x86 Cargo feature one explicit
archive-provider row in `compat/x86_64/parity.toml`. The existing
`additive_callables` and `replacement_callables` fields account only for
functions declared by installed project headers. They feed the compiler-derived
header inventory and its exclusive provider partition.

## Non-header callable providers

An existing feature row may additionally contain this optional field:

```toml
abi_only_callables = ["archive_function_symbol"]
```

Omit the field when it has no members. When present, it must be a nonempty,
ASCII-sorted, duplicate-free list of C identifier spellings. Each name denotes
a `FUNC` archive provider with `GLOBAL` or `WEAK` binding which deliberately
has no installed header declaration. The field does not encode an expected
binding: its named component runner owns that exact source/ELF requirement. It
is not a substitute for an alias row and must not cause a header or a
static-export-ratchet entry to be added. Data objects do not belong in this
function-only field.

The roster rejects an ABI-only name that is already a candidate header
function, a default-static provider, an additive or replacement callable, a
weak alias name, an ABI-only callable owned by another feature, or a provider
already selected by the feature's dependency baseline. An alias target remains
valid because it is the provider side of a source-shaped weak-alias group
rather than an alias identity itself.

`header_callable_inventory.py` deliberately omits these names from its
candidate declaration count, `callable_provider_partition`, and header
unprovided complement. The selected-provider audit instead records each direct
owner's `abi_only_callables`, exact archive delta, ordinary extraction, and
ELF `FUNC GLOBAL` or `FUNC WEAK` definitions. It separately checks the
ABI-only surface inherited from every selected dependency. A dependent row
therefore does not repeat an ancestor's name in its direct field.

The generic header inventory does not establish a signature for a name without
a declaration. The named feature component runner remains the evidence for its
source shape, ABI signature, and behavior; the selected-provider audit proves
only the archive provider and selection closure.

## Current integration assignments

The canonical ledger assigns each non-header provider to its direct feature:

```toml
# x86-kernel-admin
abi_only_callables = ["arch_prctl"]

# x86-owned-static-runtime
abi_only_callables = ["__xmknod", "__xmknodat", "_fini", "_init"]

# x86-owned-dynamic-runtime
abi_only_callables = ["_dl_debug_state"]
```

`x86-owned-static-runtime` selects `x86-kernel-admin` through its Cargo
dependency graph and inherits `arch_prctl` in its baseline. The kernel feature
in turn inherits `ioperm` and `iopl` from `x86-io-permissions`; their existing
header-callable owner remains that I/O feature. The named component runners
prove the exact `GLOBAL` binding. The three ABI-only functions gain no header
declaration, alias row, or default-static ratchet entry.

The owned-static `_init` and `_fini` defaults and shared-libc `_dl_debug_state`
view are real `WEAK DEFAULT FUNC` definitions. Their component contract in
`loader-debug-crt-abi.md` proves inert direct calls, strong CRT overrides and
the loader's separate notification owner. They are not source aliases. The
eight-byte `_dl_debug_addr` pointer is an `OBJECT`, outside this callable
roster; the same component proves its layout and canonical loader ownership.

After a ledger integration, run the roster/ledger reader, regenerate only the
integration-owned header accounting artifacts when their normal workflow calls
for it, and run:

```sh
./scripts/dev-x86_64.sh header-callable-provider-linkage-audit
```

That audit must retain header-only partition counts while its selected feature
profiles show direct function extractions, their observed GLOBAL/WEAK metadata,
and inherited ABI-only baseline surfaces.
