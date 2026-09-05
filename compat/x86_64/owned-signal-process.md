# Owned native signal/process evidence

`run_owned_signal_process.sh` is a bounded native x86-64 owned-product
component for the unchanged frozen workload
`compat/signal-process/tests/signal_process.c`. The source has no architecture
condition or candidate-specific preprocessor spelling. The old
`compat/signal-process/run.py` remains the frozen AArch64 runner contract; this
component translates the same source once through a supplied installed dynamic
driver and its headers, then links that one object to the pinned musl 1.2.6
oracle and to supplied owned products.

The fixed scenario roster is `siginfo`, `nodefer`, `mask-pending`,
`sa-restart`, `altstack`, `thread-mask`, `sigwait`, `timer`, `wait-signal`,
`wait-nohang`, `atfork`, and `fork-worker-exec`. Every oracle, optional static
ET_EXEC/static-PIE, and dynamic PIE/non-PIE kernel/direct invocation gets a
fresh process group. A timeout kills that complete group, so a fixture-owned
worker or child cannot carry state into another scenario. The source does not
read `/proc`; dynamic entries run from a copied disposable product root and do
not mount proc.

The runner accepts only:

```
run_owned_signal_process.sh [--static-sysroot STATIC_SYSROOT] DYNAMIC_SYSROOT
```

Both paths must be physical product directories under this checkout's `.work`
tree. The dynamic product is mandatory and supplies the sole compile driver.
The runner never builds products. `owned_signal_process_evidence.py` records
the source, object, manifest, installed driver, compiler helper, selected
compiler, exact driver and dependency commands, and installed header hashes.
It uses `owned_posix_product_evidence.validate_link` for every static and
dynamic executable receipt. Its final seal rechecks those identities, the
copied dynamic execution payload, oracle compiler/archive/object/binary, and
all raw `.status`, `.stdout`, and `.stderr` files.

There is no documented source difference in this workload. Every retained
candidate triplet must byte-match its musl oracle triplet. A new mismatch must
be reported and classified before it can be admitted as a source-contract
difference.

This component does not promote `compat.posix-process`, any runtime family, the
frozen aggregate POSIX matrix, or public x86-64 support. It is standalone
focused evidence using supplied current products.
