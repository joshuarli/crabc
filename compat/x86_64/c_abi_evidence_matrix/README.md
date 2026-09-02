# Routine C ABI matrix fragments

`c_abi_evidence_matrix.toml` owns the matrix-wide target, policy, and reusable
templates. Each direct `families/<family-id>.toml` child owns one routine ABI
family aggregate and its rows. The filename must exactly equal `[family].id`.

`generate_c_abi_evidence_matrix.py` discovers fragments in lexical filename
order, rejects symlinks, duplicates, cross-family rows, and unsupported
top-level fields, then exposes the merged view only through its checked
generated report. The report records the root and every fragment digest.

This is a forward-only ownership boundary. It does not fragment or replace the
canonical x86 parity ledger, exports, dispatcher, generated registries, or
status documentation; those remain integration-owner surfaces.
