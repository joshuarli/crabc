# Installed prepared-worker TLS ownership

`prepared_worker_tls_evidence.py` is the owning supplied-product observation
for native pthread worker TLS. Its contract is `prepared-worker-tls.toml`.
The three private libc imports ask the loader to allocate a prepared token,
release that exact live token, and resolve a two-word module/offset index.
They are registry operations, with no same-name loader dynamic export.
The seven frozen `__rc_*` spellings are accounted by named native source
replacements. They do not imply separate allocation or offset-query exports.

The current receipt is `crabc.x86_64-prepared-worker-tls-evidence/v2`.
It requires the active full-dynamic-fork source order and post-fork third
TLS-generation account below; an older v1 receipt lacks those mandatory fields
and cannot be replayed as this observation.

The loader token is four native words: mapping, mapping size, thread pointer,
and allocation ID. The ID distinguishes a live allocation from a stale token
whose address might later be reused. The installed pthread owner initializes
TLS and the thread control before `clone(CLONE_SETTLS)`, publishes its registry
entry and start-ready state before the callback, and releases TLS only after
kernel clear-child-TID, registry withdrawal and cancellation/signal reader
quiescence. Detached workers leave their live stack/TLS intact at exit; a
later create/join operation claims and reaps the retired worker.

`GeneralLoaderLibcTlsRuntimeV1` is the private process-lifetime **initial** TLS
provenance descriptor. The independent current `RuntimeTlsView` at TCB offset
24 publishes a coherent DTV/size generation. Old views and live TLS addresses
remain valid until worker quiescence. The descriptor is not forced into an
installed main object that has no such import. The public facade
`__crabc_runtime_v1` capability gate remains separate. The old initial-worker
foundation notes describe its original fixed graph; the selected owned-runtime
contract and current source define growth and prepared worker ownership here.

## Finite observations

One ordinary C object is compiled once and passed to all four candidate and
three musl executable links. Three additional PIC objects instantiate explicit TLS generations 1, 2,
and 3. The ordinary normal/exit/cancellation cells load generations 1 and 2;
the dynamic fork-worker child alone loads generation 3 after fork. Each
identical object is passed to the owned and musl DSO links. The installed candidate drivers produce their actual retained link
receipts. No supplied product tree receives fixture files.

The five cases are normal callback return, explicit `pthread_exit`, detached
exit followed by reaping, deferred cancellation with a TSD destructor, and
fork from a live worker followed by creation/join of a fresh child worker.
Each runs in six candidate and five musl entry modes (55 cells): candidate
static/static PIE and shared PIE/non-PIE kernel/direct; musl static and shared
PIE/non-PIE kernel/direct. Static links select the real `crt1.o`/`rcrt1.o`
through the owning driver reader; this does not claim an unexecuted musl
static-PIE comparison.

The C boundary verifies initialized TLS, zero TBSS, independent thread
addresses and values, callback/TSD lifetime, and fork ownership. In dynamic
modes, an existing worker observes two later `dlopen` TLS generations while
retaining its old addresses/values. In the fork-worker child, that surviving
worker loads a third generation after fork, retains its first two values and
receives the new one, then a freshly created child worker receives the three
fresh initial images. This makes the post-fork adopted main the target of the
next all-thread TLS growth. A worker created after the ordinary two-generation
case sees fresh initial images too. Static fork-worker cells retain their
existing no-DSO behavior and pass a placeholder third path only. Musl is the
oracle for these common C behaviors. Candidate
checks additionally inspect the source-defined coherent view and use
`mincore` on retained addresses to distinguish live mappings from joined or
reaped mappings. No stale pointer is dereferenced, and no musl allocation
layout or reclamation timing is assumed.

For a full dynamic `fork`, the child first retains its existing minimal
TID/TSD/main-pointer adoption, robust-list registration, and signal-target
repair inside the all-signal/abort/AIO transaction. The paired loader child
completion then re-roots inherited loader ownership before libc clears the
selected-worker registry, task state, and copied registry lock. `_Fork` keeps
its original immediate no-loader transaction; static full `fork` and clone
also complete their registry reset immediately. The source account names
`pthread_atfork.rs`, the active Cargo feature inclusion, and this finite order;
it does not turn `_Fork` into loader-lifecycle evidence.

Seven exact existing loader source tests independently cover initialized
worker materialization, stale/malformed/double-release tokens, abandoned and
malformed view preparation, live readers across publication, preserved TLS
addresses, and pre-FS descriptor reservation rollback. The source root and
production feature predicates are retained; no source-root permissions or
runtime algorithm are changed. The Rust executable and compiler diagnostics
are sealed. Compiler warnings are retained as structured observations;
errors and unparsed diagnostics reject the receipt.

## Collection and replay

Use clean, same-source canonical static preparation, its primary product, a
materialized dynamic product, and the current public ABI inventory/complete
ELF fact receipts. The component does not build products. Its public commands
are:

```sh
python3 -B compat/x86_64/prepared_worker_tls_evidence.py collect \
  --base-inventory "$base/report.json" --elf-report "$facts/report.json" \
  --static-preparation "$static/preparation.json" \
  --static-product "$static/products/primary" --dynamic-product "$dynamic" \
  --output "$fresh_output"
python3 -B compat/x86_64/prepared_worker_tls_evidence.py validate-report \
  --base-inventory "$base/report.json" --elf-report "$facts/report.json" \
  --static-preparation "$static/preparation.json" \
  --static-product "$static/products/primary" --dynamic-product "$dynamic" \
  --report "$fresh_output/report.json"
```

Every path must be physically contained in the checkout's `.work` directory;
output must be fresh and disjoint from product/preparation/inventory/fact
cohorts before any write. Collection runs at `/workspace` in the pinned native
core image with `LC_ALL=C`, `RUSTUP_HOME=/opt/rustup`, and the resolved image
identity in `CRABC_X86_ABI_IMAGE_ID`. Retain the actual outer Docker argv and
streams using the existing launcher. Use native `linux/amd64`, network none,
default root and `SYS_CHROOT`; no ptrace permission is needed. Mount source,
Git metadata and supplied inputs read-only, with only the output parent and
contained temporary/cache locations writable. Preserve `/usr/sbin/chroot`
applet invocation while sealing its physical `/bin/coreutils` bytes. Preserve
the pinned `/opt/cargo/bin/rustup` applet spelling while retaining the
physical `/usr/bin/rustup-init` bytes; this finite image alias does not relax
generic physical-tool admission. The
private oracle interpreter copy is executable 0755; the archived oracle bytes
remain unchanged.

Replay invokes the owning product and complete-ELF readers, reopens all raw
commands and finite output artifacts, reconstructs exact source/product/tool
and one-object joins, checks both private roots and all lifecycle cells, and
rehashes the report/source afterward. It does not run a compiler or a runtime
workload and needs no original `/opt` compiler/oracle files. Existing owning
link readers may inspect retained ELF bytes with `readelf`.

A valid receipt is an unqualified component observation. It does not complete
the pthread family, runtime qualification, public facade gate, platform
promotion or public support. Historical development executions are not
substitutes for a current clean supplied-product receipt.
