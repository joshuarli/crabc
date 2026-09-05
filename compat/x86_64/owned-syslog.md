# Owned x86 C syslog

`libc/src/c_abi/x86_64/owned_syslog.rs` supplies the selected C logger from
musl 1.2.6 `src/misc/syslog.c`. Its source map identifies the five retained
process-global fields, the 32-byte copied identifier, the AF_UNIX `/dev/log`
address, the private `__vsyslog` transaction and its weak `vsyslog` spelling.
The sibling locale, descriptor, socket, printf, cancellation and fork owners
remain the owners of their respective boundaries.

The selected behavior is the source's bounded logging contract: priority mask
query/replacement; copied `openlog` state; lazy or `LOG_NDELAY` datagram
connection; lost-connection retry; UTC `C`-locale header; 1024-byte message
truncation/newline handling; saved-`errno` `%m`; optional `LOG_PERROR` and
`LOG_CONS`; and `closelog` descriptor retirement without discarding the
configured identifier, facility, options, or mask. `fork` takes the private
logger lock after stdio and before timezone state, releases it in the parent,
and resets it in the child. Cancellation is disabled around the lock-holding
paths that can reach descriptor cancellation points. Those paths admit only
the initialized owned main task or a current selected `pthread_create` worker;
their defensive failure path does not provide foreign-task logging.
`setlogmask` has no cancellation transition and retains the source-shaped
private lock plus relaxed atomic mask publication.

Run `./scripts/dev-x86_64.sh owned-syslog` for the focused evidence.
`owned_syslog_probe.c` binds a receiver only after entering a disposable
chroot below `.work`, and uses the chroot's regular `/dev/console` fixture for
the fallback. It links the same C workload into pinned-musl, installed static
ET_EXEC/static-PIE, and installed dynamic PIE/non-PIE products; dynamic
parents additionally use direct interpreter entry. The witness covers main,
worker, fork and deferred-cancellation paths and compares each result with the
pinned-musl oracle. The dynamic qualification catalog repeats its dynamic
matrix for both clean products and the extracted package.

This is not a daemon, logger configuration, queueing, discovery, network
logging, host `/dev` access, general locale support, or public x86 support.
