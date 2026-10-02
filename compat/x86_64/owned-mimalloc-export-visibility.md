# Owned mimalloc shared-export boundary

`libc/src/c_abi/x86_64/owned_mimalloc_hidden.list` is the exact 424-name
contract for bundled `libmimalloc-sys` 0.1.49/mimalloc v3 definitions that may
remain global in the selected static `libc.a` member but must be local in the
owned `libc.so`. It contains 172 names declared by the bundled upstream
`mimalloc/v3/include/mimalloc.h` and 252 names from its implementation surface.
The installed crabc headers declare none of them. This is a visibility decision
for the selected shared product; it does not claim that the upstream header is
part of crabc's installed C ABI.

`scripts/build_x86_64_owned_dynamic_sysroot.py` verifies the physical list,
its SHA-256 and its sorted 424-member roster, then materializes an `ld.lld`
version script with one `local:` rule per name. The option is passed only to the
owned shared-libc link. The static sysroot builder and its `libc.a` remain
unchanged. Musl's byte-pinned `owned_dynamic.list`, including its eight malloc
interposition exceptions and data exceptions, stays separate from this list.
No prefix/glob visibility policy or archive-wide exclusion is permitted.

`run_libc_mimalloc_export_visibility.sh PRECHANGE_ABI_REPORT PRECHANGE_LIBC_SO`
builds fresh static and dynamic products, checks their source-bound metadata,
and compares their dynsym against the retained pre-change product. The only
allowed shared dynsym removal is the exact contract list. It derives the
baseline's extras from the retained reference/candidate symbol identities and
requires every raw triage record to equal its candidate record, rather than
only sharing its identity; any independent extra present on both sides remains
present. The ae0fcc22 pair
measured 475 extras before and 51 after this change, but those counts are a
historical measurement rather than the 424-name visibility policy. The runner
records the actual before/after counts for its supplied matched pair. It also
reads complete `--syms --wide` tables. It rejects a dynsym row for
any contract name, requires its one shared definition to be `LOCAL`, and
matches its raw spelling, version, kind, and object/TLS size to the sole
selected static allocator member. The complete shared table may localize only
the exact roster; surviving visible entries retain their ELF metadata and
OBJECT/TLS size. The evidence records the collector source identity and the
dynamic product's source state separately. Both fresh installed products must
match the collector source and the explicitly selected accepted-C backend; a
historical comparison product cannot substitute for either fresh product. It then reuses the owned C
allocation-interposition and mimalloc startup/errno lifecycle components with
the fresh dynamic product.

`run_libc_mimalloc_export_visibility.sh --native-shadow` builds the selected
Rust allocator products from one sealed source state. Its reader checks both
installed manifests, the static archive's selected members and weak C ABI
allocator entry points, and the dynamic product's source state, link inputs,
public allocator bindings, absent bundled-C definitions, and local process
finalizer. The C-only 424-name version script must be absent from this shared
link. This path does not compare a historical C product because the native
backend has no bundled C allocator member. Its `ar`, `nm`, and `readelf`
executables are bound to the core image and exact bytes in
`owned_mimalloc_export_visibility_image_inputs.json`; changed tool bytes,
backend selection, link policy, or product provenance fail the receipt.

This is component evidence only. It does not qualify the native runtime,
allocator, product campaign, or public x86 support.

Both backend paths authenticate the same inspection-tool manifest before
building products. The immutable core image is
`sha256:a635e97c4bb5afe33d29ec9607f1c906a5c958c720527a658f1f91035d28466a`.
The restored image's `ar`, `nm` and `readelf` bytes match their existing hashes;
this observation does not transfer reports produced under the previous image.
Run `owned_mimalloc_export_visibility.py --check-image-inputs` inside that image
to authenticate the manifest and tool bytes without reading or building any
runtime product. The command prints the authenticated image and file identities.

The product reader uses the existing installed static payload validator and
dynamic product ownership validator before symbol inspection. Static manifest
and dynamic materialization metadata must select the requested allocator backend
and match the collector source digest. Fresh product payloads, source metadata
and allocator provenance remain distinct from historical comparison evidence.
