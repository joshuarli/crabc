# Owned native os-test

`run_owned_os_test.sh DYNAMIC_SYSROOT` runs the frozen ten-suite os-test
profile against one already materialized native dynamic product. Its command is
intended for the pinned x86-64 container; the supplied product is mandatory and
the runner never invokes a product producer. The profile is exactly `include`,
`namespace`, `basic`, `io`, `limits`, `malloc`, `process`, `pty`, `signal`, and
`stdio` from os-test revision `5e9456d510612f83b6ec8b1a0c06d6b1303a2512`.
Because that exact profile includes PTY lifecycle cases, its canonical container
entry needs the dispatcher’s scoped `SYS_CHROOT` and `SYS_ADMIN` authority,
unconfined AppArmor and seccomp profiles, and no network. The runner spends
mount authority only for its disposable private devpts instance.

The frozen `basic` and `include` X/Open cases for `setkey` and `encrypt` are
ordinary product observations. `libc/src/c_abi/x86_64/legacy_des_compat.rs`
exports the project’s explicit inert compatibility contract: both calls return
without reading or writing their arguments or changing `errno`. This closes
those call/link observations through the owned runtime’s narrow
`x86-legacy-des-compat` feature without adding DES, a cipher, a PRNG, or a
cryptographic service; the runner continues to report every other source
outcome independently.

Each fresh source copy first runs through pinned musl 1.2.6, then the supplied
dynamic product runs the same target. The runner uses a fixed empty build
environment and preserves os-test's own `CFLAGS`, `CPPFLAGS`, and `LDFLAGS`
defaults, including its ordinary Linux pthread, math, and realtime aliases.
It sets only `EXTRA_LDFLAGS=` because Linux's source profile otherwise injects
unowned gdbm, crypt, and atomic libraries. Musl’s pinned compiler specs select
its headers and mode; the installed product adapter records its own selected
headers and ordinary PIE or explicit shared-object mode. `os-test.json` binds
raw physical Make stdout, stderr, and canonical status records for every
suite/side, derives each exact expected `.out` roster from the frozen source,
and compares outcomes by relative pathname and exact bytes. A source or
runtime difference is a failure; the runner has no inherited exception list.

The source checkout and product must both be physical directories below this
checkout's `.work` boundary. Before either oracle runs, the runner checks the
clean source revision and fixed Git tree, clones a pristine `source-stage`,
records every Git-tracked path with its mode/type/content identity, and removes
write permission from that reconstruction. It similarly records the complete
supplied-product payload roster, including installed modes. Each suite first
receives a compiler and linker product copy that must match that roster
path-for-path and keeps those source-bound modes: dynamic CRT objects and
archives remain `0644`, while `usr/lib/libc.so` remains `0755` for its link
contract. The retained compiler copy is compared to the original roster after
the suite; its integrity comes from that exact snapshot comparison, not from
changing the product's role modes. A separate execution-root copy carries the
runtime controls. Its control shell, source tree, devices, resolver fixtures,
and private devpts mount live outside the product payload; post-execution
product rosters must still match exactly.

`basic/aio/aio_suspend.c` is the one explicit prepared-source exception.  The
runner first verifies its pinned upstream bytes, then replaces only its `main`
with the hash-pinned lifetime-safe derivative from
`owned_os_test_aio_suspend_source.py`.  That derivative retains the original
one-completion assertion after `aio_suspend`, but reaps every submitted request
before its `aiocb`s, shared buffer, or `FILE` can expire.  The exact derivative
is staged separately for musl and the dynamic product; both retained receipts
bind the upstream hash, derivative hash, replacement map, and preparer hash.
Aggregate admission requires this explicit `source_preparation` record.  Earlier
v1 raw reports without it remain historical observations and are not silently
upgraded into the prepared-fixture aggregate.

The runner creates one `owned-os-test.*` directory directly under `TMPDIR`.
Its `os-test.json` contains every Make status record, raw stream artifact,
outcome file, selected-product and staged-source identity, retained adapter
failure, and pre/post payload proof. It binds musl's wrapper, oracle marker,
spec digest, libc, and complete include roster before and after the campaign.
The command exits nonzero when any suite fails. No historic os-test exception
or AArch64 observation is accepted by this native runner.

os-test drives ordinary compiler spellings that deliberately lie outside the
installed dynamic driver's target-input surface. `owned_os_test.py` supplies a
narrow, recorded adapter for its actual Make invocations. It accepts only the
product's installed include directory and maps os-test's `-fPIE`, `-fPIC`,
`-pthread`, `-lm`, `-lpthread`, and `-lrt` defaults to the matching mode or
implicit provider in the selected product. It rejects another include path,
library search path, library, linker injection, or an unfamiliar flag. Every
successful target compilation retains the installed-driver object, its exact
command and streams, exact installed compiler/hash, and a dependency closure
whose headers may reside only in the copied source or selected installed header
tree. The runner independently replays the same source and normalized flags
through that recorded compiler and rejects a byte mismatch.

Each ordinary executable link is validated with
`owned_posix_product_evidence.validate_link` while os-test's own recipe still
has its input object. The retained receipt and link identity therefore bind the
current product, workload, output ELF, interpreter, CRT, libc, builtins, and
link trace. Shared `basic/dlfcn` fixtures retain their source object, output,
and receipt too; they are not treated as executable links.

The copied suite source remains the Make authority. Its target executables are
sealed before a documented execution wrapper replaces only the host copy. The
wrapper enters a private copy of the selected product and invokes its
`/lib/ld-crabc-x86_64.so.1` directly. Pinned-musl BusyBox and its loader live
under `/control` and are invoked explicitly, so they cannot overwrite the
product's loader aliases or make the candidate's loader and `/usr/lib/libc.so`
host-control dependencies. The runtime root also retains a minimal deterministic
`etc/hosts` and `resolv.conf`, target artifacts, and basic device nodes,
including root-local `/dev/tty`. Basic cases additionally receive only the
inputs their frozen sources name: a private devpts `/dev/ptmx`, writable
`/dev/shm`, root uid/gid records in deterministic `passwd` and `group` files,
and one `http/tcp` service record. Its candidate-visible `/bin/sh` is an
attested control fixture: a candidate-linked launcher explicitly execs the
`/control` musl loader and BusyBox while preserving all product loader aliases.
A missing control-plane facility is recorded as an ordinary failing observation;
it cannot become a skip or source edit.
The wrapper preserves os-test’s suite working directory even for nested test
paths. The basic and PTY suites mount `devpts` with `newinstance`, link their
root-local `/dev/ptmx` to that mount, and record both mount and unmount streams
in the evidence. This private fixture prevents host terminal acquisition while
keeping the full source fixture and product runtime beneath the disposable root.

Basic alone also reserves a collision-checked, empty `/proc` directory before
the ordinary execution-root snapshot. After that snapshot, it mounts procfs
only at that root with `/bin/mount -t proc -o nosuid,nodev,noexec proc`, then
uses the pinned control loader and BusyBox inside the chroot to prove the
mounted view reports the container's same `pid:[…]` namespace identity. The
runner records the mount, witness, and `/bin/umount` streams. It unmounts procfs
before any post-run payload roster; an unmount failure makes the suite
incomplete and prevents a walk of the live mount. Every non-basic suite records
no procfs fixture.

`run_owned_os_test_ttyname_proc.sh DYNAMIC_SYSROOT` is the focused native
regression for this execution-root boundary. It uses the exact same supplied
dynamic product as its candidate compiler and runtime, compiles the unchanged
pinned `basic/unistd/ttyname.c` and `basic/unistd/ttyname_r.c` once each through
that product and pinned static musl, then runs both binaries in two otherwise
identical basic roots. The empty unmounted root must give both sides the source
reports `ttyname: ENOENT` and `ttyname_r: ENOENT`; the bounded procfs root must
give both sides status zero with empty streams. It retains every raw status,
stdout, and stderr artifact, source/product/oracle identities, candidate link
receipts, fixture lifecycle, and post-unmount product proof. This is a focused
fixture regression, not a substitute for a fresh ten-suite campaign.

`namespace` is the bounded exception to target translation: os-test asks for
preprocessor output and a host-side analyzer, neither of which is a target
runtime program. The adapter uses the same installed compiler contract as a
PIE target compilation, including `-nostdinc`, installed headers,
freestanding/builtin policy, stack protection, and PIE mode, for `-E` and
`-dM`. It retains successful preprocessed output and its installed-header
dependency closure before Make removes intermediates. The pinned host compiler
is used only for os-test's `CC_FOR_BUILD` analyzer. Both command classes and
their hashes appear in the evidence.
