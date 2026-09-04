# Initial-graph worker TLS ownership

The installed dynamic component selects `x86_64-owned-dynamic-runtime` in
ldso. It retains the established arbitrary admitted initial graph, its module
IDs, Variant-II offsets, relocated templates and initial TLS generation. This
does not introduce runtime module growth, DTV replacement or module unloading.
The 72-byte RuntimeV1 and 32-byte OwnedCrtHandoff are unchanged.

`ldso/src/x86_64_initial_graph.rs::materialize_initial_tls` now owns allocation
and template copying without installing FS. Initial startup wraps it with the
existing once-only ARCH_SET_FS; workers receive its TP through CLONE_SETTLS.
The initialized template, zeroed TBSS, DTV slots and module-size table are
identical owners for both paths. The process compiler guard is copied from
FS+40, not generated again. This continues the existing musl 1.2.6 initial-TLS
source provenance (release `9fa28ece75d8a2191de7c5bb53bed224c5947417`, MIT;
`ldso/dynlink.c`, `src/thread/__tls_get_addr.c`).

The additional process-private ownership boundary is a crabc design, not a
claim to translate musl's internal struct pthread allocation scheme:

- `__crabc_x86_64_initial_tls_allocate(output)` returns zero and a 32-byte
  native-layout token, or nonzero without publishing an allocation.
- Token words are exact mapping base, byte length, TP and a nonzero monotonic
  allocation ID. They are opaque outside the linkage adapter.
- `__crabc_x86_64_initial_tls_release(token)` accepts only an exact live token.
  Wrong extents/TP, stale generations and duplicate releases return `-EINVAL`
  without unmapping. ID overflow refuses new allocations rather than wrapping.
- `__crabc_x86_64_resolve_initial_tls(index)` delegates directly to the existing
  loader resolver, allowing shared libc to export the conventional compiler
  `__tls_get_addr` symbol without a second resolver implementation.

`x86_64_initial_worker_tls.rs` places its registry node in a reserved prefix of
the allocation itself. A short atomic lock protects the owned linked list; no
libc allocation or callback is called while held. There is no additional fixed
worker ceiling. These calls are not async-signal-safe. The caller must provide
valid token storage and must prove clear-child-TID plus withdrawal/quiescence
of all TP/DTV readers before release. Registry validation cannot establish that
external lifetime proof. A failed munmap retains registry ownership.

General relocation preflight recognizes only the exact private function names,
undefined strong/default function-or-NOTYPE requests, zero-addend GOT/PLT
relocations. Existing weak/main-only RuntimeV1 and CRT wire checks stay intact.

Native evidence at this component boundary: the general RuntimeV1 source root
with the installed loader feature passes 27 tests, including actual mmap
ownership regressions for wrong span, wrong TP, stale ID and double release,
plus independent over-aligned template/TBSS/DTV copies with unchanged FS;
the unchanged `run_general_dynamic_lifecycle.sh` still passes ordinary PIE,
musl callback ordering, malformed handoffs, entropy guard and one-FS-install
checks. Installed worker and package evidence belongs to the materialized
dynamic sysroot gate; these unit results alone do not complete that product.
