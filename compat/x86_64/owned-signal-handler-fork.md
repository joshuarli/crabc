# Signal-handler fork differential

`run_owned_signal_handler_fork.sh` compares the installed runtime with pinned
musl using the existing early signal, mask inheritance, failed clone, concurrent
kill/fork, and unchanged libc-test `raise-race.c` workloads. Every execution
retains stdout, stderr, and status before the exact comparison; its timeout
remains 30 seconds. The ordinary static workload also retains the sealed
linker's existing receipt for independent input/output reconstruction.

With no arguments the runner builds current accepted-C static and dynamic
products. A positional dynamic product runs dynamic PIE and non-PIE through
both kernel and direct interpreter entry. Supplying
`--static-sysroot STATIC_SYSROOT DYNAMIC_SYSROOT` additionally runs static and
static-PIE from that installed static product. Before compiling, the supplied
pair must have intact payloads, matching allocator selection, and the current
clean source digest. This selects the caller's products without changing the
backend defaults or platform support status.

The pinned raise-race workload checks its child flag once, before waiting for
100 fork signals. A signal-handler fork after that check can leave a child
waiting forever with an inherited partial counter; no sender exists in that
child. Controlled scheduling of the unchanged native and musl executables
reproduces this timeout: children are in the counter loop, the worker waits
for children, and the main thread waits for the worker. The existing
`native_signal_fork_reaping_probe.c` diagnoses the same window and tests child
identity checks inside the loop without modifying the pinned workload.

This diagnosis cannot qualify an earlier failed full cohort whose live task
state was not captured. Keep its original timeout and raw evidence. A later
isolated pass establishes only that execution and its source-bound inputs;
it does not replace the failed cohort or qualify the complete runtime matrix.
