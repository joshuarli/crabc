# Installed template-file calendar parsing

`getdate` reads the conventional template file named by `DATEMSK` and uses
the installed `strptime` parser to consume the complete input. It exposes
one persistent `struct tm` and the process-global `getdate_err`; callers
serialize this interface and access to those records. It does not infer the
current date or fill unspecified fields. Earlier successful and failed
parses can leave fields used by later calls.

`libc/src/c_abi/x86_64/owned_getdate.rs` translates the complete
`src/time/getdate.c` from MIT-licensed musl 1.2.6, release revision
`9fa28ece75d8a2191de7c5bb53bed224c5947417`, archive SHA-256
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`.
The environment lookup, `rbe` file open, 100-byte `fgets` chunks, complete
parse check, shared record, error selection, close, and cancellation-state
save/restore map directly to that function. As in the source, successful
calls leave `getdate_err` unchanged. Its initial
`pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, ...)` passes the value zero
and therefore enables cancellation; it does not select the cancellation
type. The native implementation preserves that actual operation.

The leaf composes the already selected environment, FILE, cancellation, and
calendar owners. It introduces no independent allocator, timezone parser,
locale policy, or template database. `strptime`'s documented bounded unknown
timezone-name correction also applies when such a template is used.

Inside the pinned native x86 container with `SYS_CHROOT` and a physical
checkout `.work` temporary directory, run:

```sh
bash compat/x86_64/run_owned_getdate.sh
```

The runner builds static and dynamic products, then compiles the probe once
through the installed dynamic driver. The unchanged object links to pinned
musl, static ET_EXEC, static PIE, and dynamic PIE/non-PIE executed through
both kernel and direct-interpreter entry. A supplied dynamic product is an
optional argument for focused four-entry reuse.

The eleven exact observations cover unset/missing/directory/empty templates,
full and partial field updates, rejected suffixes and their retained writes,
multiple templates, a missing final newline, and a template split at the
fixed `fgets` boundary. Every call also verifies restoration of enabled or
disabled cancellation state, and records errno and `getdate_err` separately.
This does not inject allocation failure or pending asynchronous cancellation.
The runner retains source/object hashes and raw output/status records.

This installed component preserves the frozen default archive and paused
AArch64 implementation; full POSIX family qualification remains separate.
