# Owned native process creation

The installed Linux/x86-64 products provide strong `clone`, `vfork`, and
`daemon` definitions. These belong to the owned static runtime and its dynamic
composition; they do not extend the frozen private archive or paused AArch64
qualification.

`libc/src/c_abi/x86_64/owned_process_trio.rs` translates fixed musl 1.2.6
(release revision `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT; archive
SHA-256 in `compat/upstreams.toml`). Source-specific mapping:

| Musl source | Owned definition |
| --- | --- |
| `src/linux/clone.c::clone`, `clone_start` | `clone`, `CloneStart`, `clone_start` |
| `src/thread/x86_64/clone.s::__clone` | `__crabc_owned_clone_raw` |
| `src/process/_Fork.c::__post_Fork` | `owned_process_lock` plus `pthread_create_join::clone_child` |
| `src/process/x86_64/vfork.s::vfork` | `vfork` assembly and `__crabc_owned_vfork_result` |
| `src/legacy/daemon.c::daemon` | `daemon` composing the existing full `pthread_atfork::fork` |

The clone wrapper rejects musl's three invalid thread/TLS flags and null
stack before reading optional arguments. Parent ID/pidfd, TLS, and child ID
retain the source's variadic slots. `CLONE_VM` runs the raw callback directly
with musl's restrictive vfork-like execution context. Other clones block all
signals, retain the shared process-creation/abort lock, run child identity
repair, release their own lock copy, and restore the caller mask. Public
atfork callbacks and full fork's loader, stdio, timezone and key-registry
transactions are absent from this minimal path, as in the source. The owned
runtime has no AIO state to repair.

Owned thread representation differs from musl's embedded thread record.
`pthread_create_join::CloneCaller` recovers only the caller's live control
from its reserved FS+32 cancellation pointer. Its own execution pins that
mapping, so no parent worker-list lock or copied registry traversal is
necessary. `clone_child` installs the child's kernel TID, copies only the
caller's TSD values into the separate main table, adopts its TLS identity and
robust list, and forgets the inherited worker list. The copied key metadata
and loader registry retain source-style minimal-clone semantics. This does
not invoke the full fork coordinator or change the private raw clone leaf's
narrower flag contract.

`vfork` removes its return address from the shared stack before syscall 58,
restores it afterwards, and tail-calls errno conversion. It cannot be replaced
by a Rust function retaining a stack frame over the syscall or by `fork`.
`daemon` retains source ordering: optional chdir and short-circuit descriptor
redirection precede the first fork, then setsid precedes the second fork.
Both parent branches use immediate exit; fork errors keep full fork's parent
handler behavior.

Run `./scripts/dev-x86_64.sh owned-process-trio` for the default disposable
matrix. Its underlying runner accepts `[--static-sysroot STATIC_SYSROOT]
[DYNAMIC_SYSROOT]` when a coordinator replays already-built products. It
compiles one installed-driver workload object, then links those exact bytes to
pinned musl, static/static-PIE, and dynamic PIE/non-PIE products, including
normal kernel and direct-interpreter dynamic entry. The harness checks strong
provider binding and retains normal driver link receipts. Its private chroots
contain an actual `/dev/null` device and no foreign runtime. The dynamic
qualification catalog also runs this leaf on its supplied dynamic product.

The installed-header dependency audit retains `workload.d` and `compile.json`
beside that object. It imports the selected product's installed
`crabc_cc_static.py` helper to derive the source translator and clean
environment, then repeats dependency-only preprocessing with the driver's
include policy. The only admitted dependencies are
`owned_process_trio_probe.c` and headers beneath that selected product's
`usr/include`; the recorded driver, manifest, source, object, command, and
dependency hashes bind this audit to the object that the runner links. It does
not substitute a separately compiled object for the installed-driver output.

With no paths, the runner builds both disposable products. A positional
dynamic product preserves the dynamic-only replay and does not build or run a
static product. `--static-sysroot` selects a physical checkout `.work` static
product for the static/static-PIE pair; if it is the only supplied product, the
runner still builds its disposable dynamic product so its installed driver can
make the one shared object and run the dynamic matrix. Supplying both paths
reuses both sealed products and invokes neither producer. Paths must be
nonempty, cannot be parsed as options, and are canonicalized before their
contained checkout `.work` targets are accepted. This is a bounded
static-product replay seam, not a family receipt or a completion claim.

Every static link explicitly requests a sealed receipt. Before any candidate
process runs, `owned_posix_product_evidence.validate_link` validates each
selected link: the complete selected product payload, one workload object, the
output and receipt, selected CRT/runtime inputs, linker trace, ELF form, and
the static no-DSO or dynamic no-foreign-import/application-DSO boundary. It
retains all four identities when static modes are selected, or the two dynamic
identities for the established dynamic-only replay, together with raw
status/stdout/stderr files. For each of the existing `ordinary`, `errors`, and
`redirect` scenarios, those raw artifacts are compared exactly to the
pinned-musl artifacts; this preserves the existing semantic normalization
rather than collapsing an error stream or process exit into the success marker.

The probe covers invalid flags, raw clone failure and mask/lock rollback,
parent/child ID slots, pidfd, successful errno preservation, main and worker
clone with another live parent worker, caller TSD and child thread creation,
nested adopted robust-list preservation, restricted shared-VM callback,
vfork shared-memory suspension and exec, daemon sessions and intermediate
child reaping, directory/descriptor options, missing `/dev/null`, and denied
fork/vfork/clone syscalls. The nested robust regression first passed musl and
failed the owned static product because resetting an already adopted main
lost its linked head; the shared robust helper now preserves that head while
clearing only registration offset and pending state.

This evidence does not claim namespace creation, arbitrary application locks
held across clone/fork, loader mutation racing clone, AIO, or expansion of the
source's restricted `CLONE_VM`/vfork child contract. It adds no new kernel
requirement beyond Linux 5.10.
