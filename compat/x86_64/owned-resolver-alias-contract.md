# Owned resolver alias receipt

This component records a current x86-64 product receipt for exactly five
existing identities: `res_mkquery`, `res_send`, and `res_search`, plus private
bodies `__res_mkquery` and `__res_send`. It observes the existing strong public
controls `res_query` and `res_querydomain` so that `res_search` cannot silently
change target or policy.

The component is not a resolver-family qualification, a DNS feature expansion,
a dynamic-loader receipt, or a public-support claim. Its status is
`component-verified` only after a current collector and process-free reader
validate the same selected source, static preparation, static and dynamic
products, complete facts, base inventory, product anchor, source-bound link
input modes, and retained command evidence.

## Source route

Musl 1.2.6 (`9fa28ece75d8a2191de7c5bb53bed224c5947417`) is the C ABI and
behavior oracle. `resolver_runtime.rs` preserves its hidden private
`__res_mkquery`/`__res_send` bodies with public weak same-address aliases, and
its public strong `res_query` with weak same-address `res_search` alias.
`query_response` is the selected owned-product source caller of both private
bodies. `lookup_dns_records` also names `__res_send` in source, but it is only
reachable through `getaddrinfo` when `x86-owned-static-runtime` is disabled;
it is a retained legacy-source observation and not required as a selected
product relocation.

The public probe uses only `<resolv.h>` spellings. It reuses the established
local chroot/loopback fixture for the bounded DNS behavior already selected:
query construction, local `res_send`, `res_querydomain`, `res_search`, and
ordinary resolver-state observations. It does not use ambient host
configuration or external DNS.

The override probe is built three times from normal C source, with a strong
`res_mkquery`, `res_send`, or `res_search` definition. Each selected static and
dynamic link must route a separately compiled public call to that strong
definition. The retained caller relocation is checked before link, and the
dynamic output retains the matching public strong export. The hidden
private body source calls remain separately proved through source and retained
static relocation evidence. `res_query` and `res_querydomain` are never
redefined by this component.

## Exact ELF scope

The complete ELF facts stay intact. The receipt joins only these 19 candidate
rows across seven names:

- static `.symtab`: private bodies are `FUNC GLOBAL HIDDEN`; aliases are
  `FUNC WEAK DEFAULT`; controls are `FUNC GLOBAL DEFAULT`;
- shared `.dynsym`: aliases and controls only, with the same public metadata;
- shared `.symtab`: private bodies are `FUNC LOCAL HIDDEN`, aliases are weak
  default, and controls are global default.

The private bodies must have no non-undefined shared `dynsym` definition.
`res_mkquery`/`__res_mkquery`, `res_send`/`__res_send`, and
`res_search`/`res_query` retain same-definition identity in their respective
static/shared domains. Unrelated and unnamed facts remain observations and are
never converted into logical identities.

## Product and replay boundary

`run_owned_resolver_alias_contract.sh` receives caller-supplied selected static
and dynamic products, static preparation, loader-debug product report, complete
ELF facts, and base inventory. It uses their sealed drivers: `-static` and
`-static-pie` for static modes, and `--dynamic-pie` and `--dynamic-non-pie` for
dynamic modes. It records each source compile, link, execution, raw ELF stream,
map/link receipt, and fixture transcript under one receipt directory.
The two normal static links also replay `owned_static_link_authority.py` over
their sealed map/trace sidecars, the exact selected archive members, the
caller object, and the selected CRT records. That is a finite byte relation for
these links only; it does not infer a dynamic-product provider.

The runner does not reuse the standalone resolver archive's custom `_start` or
its no-allocator/no-dynamic-TLS purity tests. A selected runtime product may
legitimately compose those existing owners. The receipt instead authenticates
its exact manifests, product state, current raw mode policy, selected runtime
product authority, and full facts/inventory cohort.

`owned_resolver_alias_contract_reader.py --validate-report` uses retained bytes
and supplied current paths. It does not invoke a compiler, linker, or ambient
target inspection tool. It rechecks the report after reading its retained
inputs, so an in-place report replacement cannot become accepted evidence.
Collection may use the pinned `/workspace` mount while host replay uses the
checkout path; the reader derives that one source-root translation from the
retained reader path and requires every non-image input, command cwd, argv, and
static link sidecar to preserve the same checkout-relative placement.

## Selection boundary

A later selector change may add
`component-owned-resolver-private-bodies` with owner
`x86-owned-resolver-private-bodies`, static `GLOBAL HIDDEN` and shared `LOCAL
HIDDEN` placement for exactly the two private names. That policy first changes
the seven current reasons into five component receipt requirements. A valid
receipt may then remove only those two private requirements and the three
existing feature-alias requirements. It does not alter the two controls,
resolver-family state, qualification gates, or public-support state.
