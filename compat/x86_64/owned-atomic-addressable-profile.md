# Installed addressable-atomics companion

`run_owned_atomic_addressable_profile.sh` builds a fresh owned dynamic product
unless it receives one checkout-local product path. It then runs
`owned_atomic_addressable_profile.py` in a sibling evidence directory. The
receipt is `atomic-addressable-profile.json`; it can be reconstructed without
executing a target:

```sh
python3 -B compat/x86_64/owned_atomic_addressable_profile.py validate \
  .work/x86_64/tmp/owned-atomic-addressable-profile.XXXXXX/evidence/atomic-addressable-profile.json
```

The companion consumes the existing C and C++ address-taken behavior probes.
The C object uses the sealed installed dynamic driver and records its exact
installed `stdatomic.h`, `features.h`, and `bits/alltypes.h` dependency set.
The C++ object has no C++ headers: it declares six `extern "C"` spellings,
retains those undefined C ABI references, and rejects C++ runtime, exception,
allocation, TLS, and unmapped imports. The sealed installed driver links those
three objects in PIE and non-PIE form; each executable runs through both the
kernel and direct owned-loader entries. Every entry retains its link receipt,
copied product payload, and empty successful raw streams.

This proves the existing `static-c-atomic-addressable` project extension on
one installed product. It retains the original OS-test candidate `good` and
musl `undefined` observations as raw differences. It neither claims that musl
has `<stdatomic.h>` or these exports nor changes the
`retained-pending-c-abi-policy` disposition, header-family coverage, C11
closure, or public support.
