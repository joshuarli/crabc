# D16: Reuse relocation work within a transaction

## Evidence

The R0 installed product was profiled in the pinned image through the static
timing launcher and candidate chroot. The `instructions:u` profiles had no lost
samples. On startup, `__crabc_x86_64_self_relocate` accounts for 8.79% of
samples, `lookup_result_at` 6.96%, `relocate_initial_graph_inner` 5.26%, and
`parse_mapped` 2.25%. `lookup_result_at` accounts for 33.08% of `dlopen_graph`
and 22.79% of loader TLS-growth samples. Matched-LLVM counts are the acceptance
evidence: 1.8917, 1.5993, and 2.5682 for those rows. Startup needs 41.8% fewer
candidate instructions to meet 1.10; TLS growth needs 57.2% fewer.

## Design

Use one transaction-local lookup cache keyed by requestor, dynsym index, and
lookup mode. Validate the requestor record and bounded name before each cache
access. Preserve the full `SymbolLookup`, including undefined weak versus
missing strong results. Drop the cache at transaction end; retain the existing
GNU and SysV hash lookup on misses.

During initial-graph and runtime-new preflight, retain an ordered write plan
with admitted target address, width, and resolved value. Runtime deferred PLT
entries remain tagged separately. Apply the plan only after every affected
object passes preflight and plan allocation succeeds. This removes the second
relocation-table walk and repeated address conversion during apply, while
keeping all writes after complete validation. Fold private-import recognition
into that preflight walk; retain exact selector forms and reject malformed or
foreign private imports before any write.

Keep BFS scope order, first-definition binding, version visibility, TLS and
COPY rules, symbol extent checks, RELRO admission, writable-load bounds,
lazy-binding queue behavior, and the no-write-before-preflight invariant.
Existing mappings remain read-only during runtime-new relocation. Keep the
self-relocation validation and application passes intact: its 897 RELR targets
are mandatory writes, and merging those passes would violate the complete
validation-before-write invariant without a bounded retained plan.

## Independent review required

The wider design addresses repeated resolution and relocation-table work, but
the measured startup headroom is not yet demonstrated. Even eliminating the
four named startup functions entirely would remove only 23.3% of samples, less
than the required 41.8%; the proposed changes can only remove part of them.
The evidence therefore does not currently justify code work under the fixed
three-row gate. Review whether another semantics-preserving `ldso` mechanism
has enough measured headroom; otherwise record R1 as infeasible at this gate
and request a new owner direction rather than weakening it.
