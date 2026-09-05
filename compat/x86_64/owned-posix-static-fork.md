# Supplied-static fork workload adapters

`run_owned_posix_static_fork.sh` is a narrow static-only replay adapter for two
existing Linux/x86-64 workloads. It adds no runtime code, fixture behavior, or
dynamic-fork qualification. The caller supplies one already-built owned static
product, and the runner compiles each unchanged source exactly once with that
product's static-PIE source-translation contract.

| Role | Unchanged source | Retained object | Links and ordinary execution |
| --- | --- | --- | --- |
| `atfork-registry` | `compat/x86_64/owned_atfork_registry_probe.c` | `atfork-registry/workload.o` | pinned musl ET_EXEC, supplied static ET_EXEC, supplied static-PIE |
| `static-posix-forkexec` | `compat/x86_64/owned_static_posix_probe.c` | `static-posix-forkexec/workload.o` | pinned musl ET_EXEC, supplied static ET_EXEC, supplied static-PIE |

The atfork workload remains the existing empty-registry, 67 distinct callback
triples plus null triple, child and worker registration, repeated fork, and
denied-fork parent-completion test. The POSIX workload remains its full signal
mask, disposable child-root, environment mutation, fork/`execve` round trip,
wait, and descriptor-pipeline scenario. The adapter supplies no scenario flag
that could narrow either source.

Run it inside the pinned native x86 environment with:

```sh
bash compat/x86_64/run_owned_posix_static_fork.sh \
  --static-sysroot STATIC_SYSROOT
```

`STATIC_SYSROOT` is required, must be a physical directory below the checkout's
`.work/` tree, and is never built by this runner. Before creating evidence, the
runner asks its sealed driver for both static link plans, which verifies the
complete supplied payload. There is no positional dynamic-product argument,
dynamic driver call, or hidden producer path.

For each role, `compile.json` binds the source and object hashes to the
installed headers, the current checkout and installed `crabc_cc_static.py`
identities, the current evidence-helper identity, the helper-selected and
resolved compiler identity, the pinned clean environment, and the exact
static-PIE `-fPIE` compile and `-M -H` audit vectors. Final sealing derives
those vectors again from the current static driver, reparses `headers.d`, and
requires the exact role-specific installed-header closure; it does not accept
a source-only or ambient-header trace. The object hash is rechecked after the
musl link and after each sealed static link. The shared
`owned_posix_product_evidence.validate_link` validator binds each product link
to its static receipt, selected CRT, owned archives, map, trace, final ELF, and
that same object. The header audit repeats preprocessing only; it does not
produce a second workload object.

Every ordinary run uses a fresh retained root at
`<role>/<linkage>/root/workload/consumer`; this lets the POSIX source's own
child root change and self-exec path run without exposing a host path. Before
execution, the runner hashes the original candidate and the copied consumer,
and byte-compares them. Raw files are retained as
`<role>/<musl|static|static-pie>/ordinary.{stdout,stderr,status}` and each
candidate triplet must match the musl triplet exactly. The role `evidence.json`
binds the source, compile receipt, object, sealed-link identities, each copied
consumer, and raw transcripts.

This adapter does not rerun or subsume the dynamic `fork` case, its DSO/TLS and
loader-state coverage, `owned-process-trio`, or a fork-family completion
claim. It is supplied-static evidence for these two established workload
sources only.
