# Technical references

Start with [AGENTS.md](../AGENTS.md) and [plan.md](../plan.md). The plan is the
only active implementation/progress document; these references explain the
boundary being changed and need not be loaded wholesale. The
[compatibility profile](../COMPATIBILITY-PROFILE.md) defines deliberate limits;
[COMPATIBILITY.md](../COMPATIBILITY.md) is generated evidence.

## Architecture and design

| Boundary | Reference |
| --- | --- |
| Layer ownership and private runtime wire format | [Architecture](design/architecture.md) |
| Typed native facade, ownership and safety | [crabc-rs](design/crabc-rs.md) |
| CRT, installed sysroot, sealed driver and target-input purity | [CRT/sysroot](design/crt-and-sysroot.md) |
| Allocator source mapping and implementation context | [Allocator](design/allocator.md), [upstream pin](../crabc-mimalloc/UPSTREAM.md) |
| Explicit dynamic native-shadow ownership and lifecycle | [Dynamic allocator integration](design/x86-dynamic-native-allocator.md) |
| Approved Rust unwinder provider and trust boundary | [Unwinder](design/x86-rust-unwinder-proposal.md) |
| Measurement methodology and cost attribution | [Performance](design/performance.md) |
| Existing owned-sysroot Lua consumer | [Source build](design/source-build.md) |

Implementation context may contain revision-specific observations. The live
code/manifests and current qualified reports establish current behavior;
older measurements never transfer across targets, backends, or revisions.
The plan contains release acceptance and explicitly deferred work.

## Inventories and harnesses

Runtime mappings and promotion live in
[`compat/x86_64/parity.toml`](../compat/x86_64/parity.toml); the
[native harness guide](../compat/x86_64/README.md) owns command options.
Allocator source status lives in
[`port-map.toml`](../compat/allocator/port-map.toml), with commands in the
[allocator harness guide](../compat/allocator/README.md). Native Rust semantic
accounting lives in [`coverage.toml`](../compat/crabc-rs/coverage.toml).

Use the nearest `compat/` README for ABI, loader, corpus, POSIX, Rust std/LTO,
Rustix, or performance work. C runtime and loader guides are in
[`libc/`](../libc/README.md) and [`ldso/`](../ldso/README.md); the pinned external
suite has its [own harness](../libc-test-harness/README.md).

`evidence/` contains scoped technical arguments and observations, not another
queue. Preserve required source provenance and raw generated reports in their
owning locations. Git supplies delivery history; do not maintain prose archives
or append a settlement narrative for each leaf change.
