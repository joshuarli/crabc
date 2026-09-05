# Owned x86 kernel-residual C APIs

`system.kernel-admin` has 42 frozen C spellings. The installed runtime keeps
that finite map explicit: `owned_linux_control.rs` owns 18 Linux-control
entries (`acct`, `capget`, `capset`, `delete_module`, `fanotify_init`,
`fanotify_mark`, `init_module`, `klogctl`, `pivot_root`,
`process_vm_readv`, `process_vm_writev`, `ptrace`, `quotactl`, `reboot`,
`setns`, `swapoff`, `swapon`, and `unshare`); `owned_syslog.rs` owns
`closelog`, `openlog`, `setlogmask`, `syslog`, and `vsyslog`; and
`owned_stdio_process.rs` owns `system`. This slice qualifies the exact
remaining 18 names:

`__sched_cpucount`, `confstr`, `fpathconf`, `getdtablesize`, `gethostid`,
`membarrier`, `pathconf`, `personality`, `prctl`, `sched_getparam`,
`sched_getscheduler`, `sched_setparam`, `sched_setscheduler`,
`setdomainname`, `sethostname`, `syscall`, `sysconf`, and `ulimit`.

The implementations retain their musl 1.2.6 source maps above the relevant
C ABI definitions. The workload exercises bytewise CPU-mask population;
configuration tables and the `RLIMIT_NOFILE` query; fixed-zero `gethostid`;
the direct Linux `membarrier` branch; `personality`; four-word `prctl` and
six-word `syscall` register forwarding; the scheduler source's intentional
`ENOSYS` result without touching caller output; `RLIMIT_FSIZE` `ulimit`
query/set behavior; and Linux UTS setter argument order. It does not select
musl's old-kernel membarrier fallback, scheduler policy, host identity policy,
or a Rust administration facade.

`owned_system_configuration.rs` is selected only by
`x86-owned-static-runtime`. It preserves the frozen
`system_configuration.rs` module outside that aggregate, then adds musl
`sysconf.c`'s `AT_MINSIGSTKSZ` calculation for `_SC_MINSIGSTKSZ` and
`_SC_SIGSTKSZ`. Linux 5.10 x86 does not emit that auxv tag; upstream kernel
commit `1c33bb0507508af24fd754dd7123bd8e997fab2f` added x86 emission in Linux
5.14. On the baseline, musl's `__getauxval` returns zero and sets `ENOENT`,
then `sysconf.c` clamps the frame size to 1024, adds 1024 bytes of application
working space, and adds the historical `SIGSTKSZ - MINSIGSTKSZ` delta for the
default. The selected observer retains that errno side effect: the clamp is
musl's required missing-auxv behavior, not an added fallback.

Run `./scripts/dev-x86_64.sh owned-kernel-residual` for the focused evidence.
Before the owned configuration selection, the same installed-driver C object
passed the pinned musl reference and failed the candidate only at the
signal-stack `sysconf` selector with `EINVAL`; that isolated regression is
retained as the reason for the aggregate-only configuration module.
`run_owned_kernel_residual.sh` compiles that object once with installed
project headers, links it unchanged to pinned musl and owned static
`ET_EXEC`/static PIE plus dynamic PIE/non-PIE applications, and compares raw
exit status, stdout, and stderr for each selector. Dynamic applications run
through both ordinary `PT_INTERP` entry and direct installed-interpreter
entry; the registered `kernel-residual` dynamic case repeats that matrix for
the installed, second, and extracted products. This is a residual
18-spelling receipt. It does not combine the four separate workload objects
into a 42-spelling `system.kernel-admin` family receipt.

The static links request `--link-receipt` and
`owned_posix_product_evidence.validate_link` verifies their selected CRT,
archives, application object, output, map, trace, linker identity, complete
product manifest, and static ELF boundary. The first successful dynamic audit
records the workload source hash, object hash, product manifest hash, and
physical product root; each later PIE/non-PIE kernel/direct receipt must match
that binding. The shared audit verifies the complete installed product and each
dynamic receipt's resolved inputs, command, trace, output, interpreter, and
`libc.so` dependency.

The UTS fixture first tries a child private UTS namespace. If the pinned
container denies namespace creation or mutation, it emits an explicit raw
negative syscall and public-wrapper errno transcript instead of claiming a
successful host change. Its separate seccomp child requires the Linux UAPI
`SECCOMP_MODE_FILTER == 2` filter to install after `PR_SET_NO_NEW_PRIVS`; an
installation failure fails the selector before either setter runs. Once that
filter is installed, valid hostname/domainname pointers pass through the
public C wrappers and the fixture records their exact raw `-EPERM` and wrapper
`errno` transcripts. No host namespace, privileged container mode, or
invalid-pointer probe is used.

This installed slice is not the POSIX-family coordinator's extracted-static
six-cell receipt and does not establish global FILE/logger/signal/fork
composition, kernel administration policy, family completion, promotion, or
public support.
