# Native M2 bitmap component

`m2-bitmaps-x86_64-v3.5.0.fragment.json` is component evidence, not an M2
milestone report. Promotion requires the aggregate gate and the two shared
x86 source-map records to land together. The frozen AArch64 manifest and
qualification status are unchanged.

The boundary is fixed mimalloc 3.5.0 scalar bitmap behavior for the default
Linux/x86-64 profile: 64-bit fields, 512-bit chunks, `MI_OPT_SIMD=0`, and
release `MI_STAT=0`. The fragment pins the field/chunk primitives, complete
ordinary and binned bitmap families, all three scalar visitors, inverse/high
scans and counts, rollback, and their mandatory subprocess statistics calls.
Optional SIMD/debug configurations and full allocator ownership, statistics
ABI/reset/merge/reporting remain separate claims.

`crabc-mimalloc/src/bitmap.rs` preserves source algorithms and atomic orders.
`AbandonedBitmapClaim::Discarded` represents the source callback outcome
`claim=false, keep_set=false`; arena ownership callers continue to restore
rejected pages because a concurrent unabandon writer can be waiting for them.
Checked Rust ranges and lifetime-bound views replace raw asserted C inputs;
they do not invent an alternate bitmap algorithm.

The unconditional `chunk_bins` count transitions and
`pages_unabandon_busy_wait` counter live in `MainSubprocess::bitmap_statistics`.
Its five active bin counters retain signed 64-bit current, peak and positive
total updates in source order; the source `NONE` bin has no update event.
This typed subset is not a `mi_stats_t` byte-layout claim. Binned images retain
a live subprocess owner, while ordinary `clear_once_set` takes the source
subprocess explicitly. Test contexts own a stable subprocess rather than
discarding events through a test observer or process-global fallback.

`m2_bitmaps_x86_64.py::run_evidence(harness, offline=...)` is the native
producer interface. It uses the canonical harness's pins and contained paths,
extracts the fixed archive, builds the direct C fixture with pinned `stats.c`
and Linux primitives, then runs the complete `bitmap::` Rust module. It checks
41 passed tests and compares 132,184 ordered unsigned observations, including
actual words, transition counts, visitor order, conservative maps, bin counters
and uncontended/contended clear-once-set counts. The C fixture supplies only
the fixed scalar `_mi_cpu_stosb_max=0` environment input; bitmap/statistics
algorithms come directly from the archive.

The producer's single Rust execution supplies both the differential and
unit-invariant evidence rows; an aggregate consumer must record this reuse,
not describe two separate runs. The aggregate owns exact clean-revision
attestation and validates the fragment's source-map predicates and bounded
definitions before promoting the component.

Focused Rust invariants additionally exhaust every within-chunk conditional
range with missing start/middle/end bits, exercise concurrent mixed-width
claims and returns across 65 chunks, and preserve a concurrent setter during
stopped clear-range callbacks. Host-only `test_m2_bitmaps_x86_64.py` rejects
missing, duplicate, reordered, malformed and overflowing trace observations.
