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
The runner never builds products. Before the actual installed-driver compile,
`owned_signal_process_evidence.py` snapshots the source, manifest, driver,
compiler helper, selected compiler, exact driver and dependency commands,
clean compiler environment, and installed header/dependency closure. It
rechecks that snapshot immediately after the one object is created and again at
final sealing. It uses `owned_posix_product_evidence.validate_link` for every
static and dynamic executable receipt. After all dynamic product and consumer
copies complete, before the first dynamic launch, it records their source/copy
identities. It audits that record before execution, after execution,
and during the final seal alongside oracle compiler/archive/object/binary and
all raw `.status`, `.stdout`, and `.stderr` files.

## Replay a retained report

Call `validate_observations` in `owned_signal_process_evidence.py` with these
keyword arguments: `work`, `report_path`, `static_product`,
`dynamic_product_path`, `source`, `object_path`, `compile_audit`, `oracle_cc`,
`oracle_binary`, and `oracle_record`. Set `static_product` to `None` for an
existing four-mode report. Supply the static product for a six-mode report.
The reader rebuilds the v1 record from the current source, products, receipts,
payload copies, and raw observations, then compares the complete JSON object.
Unknown or missing fields fail. The report must remain the same physical file
with the same bytes through the replay.

The replay does not compile, link, execute the target or oracle, or rewrite the
report. It may run binary-metadata tools such as `readelf` inside the pinned
image.

There is no documented source difference in this workload. Every retained
candidate triplet must byte-match its musl oracle triplet. A new mismatch must
be reported and classified before it can be admitted as a source-contract
difference.

This component does not promote `compat.posix-process`, any runtime family, the
frozen aggregate POSIX matrix, or public x86-64 support. It is standalone
focused evidence using supplied current products.
