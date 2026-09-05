# Owned Linux control mechanisms

The C runtime forwards Linux accounting, capability, module, fanotify, kernel
log, mount-root, quota, reboot, namespace, swap, tracing and process-memory
operations to the kernel. Linux validates permissions, records and command
arguments. `owned_linux_control.rs` owns the C widths, syscall argument order
and calling-task errno translation, with exact musl 1.2.6 source mappings
above its definitions. These are C mechanisms; they add no Rust facade or
administration policy layer.

Tracing needs one additional ABI translation. Linux PEEK requests write a
word to an output pointer and return a syscall status. The C `ptrace` entry
returns the word, which can itself be `-1` or another negative value. Only
the syscall status goes through errno translation. A successful PEEK preserves
the incoming errno, as musl does. The implementation keeps request-specific
output storage separate from the raw status in `owned_linux_control::ptrace`.

Run `./scripts/dev-x86_64.sh owned-linux-control` for the focused installed
matrix. `run_owned_linux_control.sh` compiles one workload object using the
installed headers, then links it into the pinned musl reference and ordinary
owned static, static-PIE, dynamic PIE and dynamic non-PIE applications. Both
dynamic parents additionally run through direct interpreter entry. Each arm
executes in its own chroot. The dynamic qualification catalog repeats the
workload for both clean products and the extracted package.

`owned_linux_control_probe.c` compares invalid/nonexistent-target calls with
their exact raw Linux errors, then checks capability reads/version queries,
self process-memory transfers, and a traced child. The child proves negative
PEEK data, errno preservation, POKE/PEEK, resume/reap and parent-memory
isolation. Privileged system changes are not executed: the error matrix uses
invalid commands, descriptors, pointers or paths in the private chroot.
Those rows prove syscall/C-errno behavior, not successful system reconfiguration.
No added Docker administration capabilities are required.

The earlier unfinished `x86/reboot-feature-20260904` work remains preserved as
historical source/evidence work. Its isolated feature/export-count runner is
superseded by this owned-product batch. The owned reboot entry follows the
release source's three syscall arguments, retaining both fixed magic words
and the caller's command. It does not change the frozen default archive.

This component leaves the `system.kernel-admin` capability and POSIX family
completion open. The remaining C logging APIs have independent state and
transport behavior and are not supplied by the kernel-log `klogctl` entry.
