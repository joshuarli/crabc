# R1: Full dynamic startup profile and design

## Acceptance and profiles

The matched-LLVM-23 counts from the R0 product are the acceptance baseline:
startup 1.8917, `dlopen_graph` 1.5993, and loader TLS growth 2.5682. Reaching
1.10 needs 41.8% fewer startup instructions and 57.2% fewer TLS-growth
instructions.

The exact timing-launcher chroot profiles had no lost samples. Loader-only
startup samples named self-relocation (8.79%), `lookup_result_at` (6.96%),
`relocate_initial_graph_inner` (5.26%), and `parse_mapped` (2.25%). The lookup
routine accounted for 33.08% of `dlopen_graph` and 22.79% of TLS-growth samples.

To widen the view without accessing the denied timing result files, a second
diagnostic profiled 32 direct chroot launches of the R0 dynamic `/bin/true`
with `instructions:u`, period 1,000, and no symbol filter. Its PT_INTERP is the
R0 `ld-crabc-x86_64.so.1`; the capture had 5,021 samples and no loss. The
`comm=true` report attributed 32.94% of the whole capture to `ld-crabc`, 5.48%
to unknown mappings, 0.20% to the executable, and 0.02% to the vDSO. The report
is diagnostic: it includes launch helpers, is not the counts workload, and
does not separate loader and libc code linked into the same product image.
The three counts rows remain the only acceptance measure.

## Candidate transaction design

Keep the lookup cache local to one immutable relocation transaction, keyed by
requestor, dynsym index, and lookup mode. Validate the requestor record and
bounded name before every cache access. Preserve weak-versus-missing results,
BFS scope, version visibility, symbol extents, TLS, COPY, and lazy binding.

Retain typed operations during full preflight: admitted word writes, COPY
source/destination/length records, and deferred PLT entries. Allocate and
validate the entire plan before writing. Apply initial libraries first and
main last, publish debugger slots after word writes, and run COPY operations
last. Runtime relocation touches only new mappings and publishes lazy entries
after successful preflight. Preserve graph-wide canonical-libc uniqueness,
private-import owner and cardinality rules, exact selector forms, and the
merged-self and foreign-conventional cases.

## Review required before code

The transaction changes have precise semantic obligations, but the widened
profile does not show enough removable non-allocator work to reach either
startup gate. The exact profile identifies resolver and relocation work; the
minimal full-process profile shows no separate CRT/libc DSO contribution, and
cannot attribute source modules within `ld-crabc`. The profile evidence does
not justify implementation under the unchanged gates. Independently review
whether another code path inside `ldso/`, `crt/`, or libc startup has measured
headroom; otherwise stop R1 without code or gate changes.
