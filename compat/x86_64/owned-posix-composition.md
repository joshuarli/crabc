# Joint owned POSIX process state

`owned_posix_composition_probe.c` observes environment storage, signal actions
and masks, a live buffered `FILE`, and syslog state in one process with a live
worker. This supplies the `global-state-composition` workload from the proposed
POSIX family catalog. It does not close the family or its product matrix alone.

The selected contracts follow pinned musl 1.2.6 revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, under its MIT license:
`src/process/fork.c` and `posix_spawn.c`, `src/env`, `src/signal`,
`src/stdio/{flockfile,funlockfile,fileno}.c`, and `src/misc/syslog.c`.

The worker finishes its environment reads, installs a distinct signal mask,
logs a message, locks the stream, and reports readiness through a pipe. The
parent then changes its environment and creates fork/exec and spawn children.
Only `execve` and `_exit` execute in the fork child before its fresh image;
there is no unsupported concurrent environment mutation or inherited FILE use.
The fresh images check the expected environment, masks, reset/ignored actions,
and close-on-exec descriptor state. The parent checks its own state after each
child exits.

Cancellation retires the worker at a real pipe-read cancellation point. Its
registered cleanup releases the FILE lock. The parent proves it can acquire
that lock, flush and read the exact buffered text, log again with the preserved
mask, deliver the original signal handler, and remove the environment entry.
The descriptor number is captured before the worker locks the FILE because
musl's `fileno` itself acquires that lock.

Run `./scripts/dev-x86_64.sh owned-posix-composition [--static-sysroot
STATIC_SYSROOT] [DYNAMIC_SYSROOT]`. With no arguments the runner builds both
disposable products. A positional dynamic product preserves the existing
dynamic-only replay and skips static modes. `--static-sysroot` selects a
physical checkout `.work` static product for the static/static-PIE pair; when
it is the only argument, the runner still builds its disposable dynamic product
for the installed-driver object and dynamic runs. Supplying both paths reuses
both sealed products and invokes neither producer. This is a bounded
primary/reproduction/extracted-static replay seam, not a family receipt or a
claim of family closure.

The runner compiles one object with installed project headers and the installed
dynamic driver, then uses that same installed-driver object for pinned musl,
the two static runs, and dynamic PIE/non-PIE through kernel and direct
interpreter entry. The registered `posix-composition` case allows the dynamic
coordinator to replay its supplied installed, second, and extracted products.
Static reproduction/extraction and the family receipt remain coordinator
obligations.

Each run has a disposable chroot with its own `/dev/log`, stream, and captured
wire file. Exit status, stdout, and stderr are retained and compared exactly.
Time-bearing syslog datagrams are checked for identity/payload and archived
unchanged in `.log-wire` files; their timestamps are not compared for equality
across separate processes. The compile record identifies the source, object,
installed driver and manifest, plus a separate dependency-only preprocessing
audit under the same compiler/header policy. No alternate compilation supplies
the linked workload object.

Every candidate link also retains its ELF views and passes
`owned_posix_product_evidence.validate_link`: the current product payload,
exact workload object, owned runtime inputs, output, linker and applicable
map/trace or dynamic manifest receipt must agree before execution. Static
links explicitly request their sealed receipt. These link identities do not
substitute for the later family execution receipt.
