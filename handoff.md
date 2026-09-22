# Handoff: finish the documentation consolidation

You are on native Linux/x86-64. Your task is to **finish and verify the
documentation consolidation**, not to implement `plan.md`. Do not start runtime,
allocator, qualification, or promotion work. Delete this file as the last step:
it names retired documents on purpose, so it is excluded from the scans below.

Follow `AGENTS.md` for repository rules. In addition, the user's standing rules:
do not run formatters or linters; do not run pre-commit hooks; add no
dependencies; do not commit or push unless the user asks.

## What the consolidation is

Consolidate the scattered plan/scope/history documents into one active
completion contract (`plan.md`) and one scope/policy entry point (`AGENTS.md`),
with no archive left behind:

- Rewritten: `AGENTS.md` (absorbs the old scope document), `plan.md` (absorbs
  the runtime plan, the allocator plan, and three roadmaps), `README.md`,
  `COMPATIBILITY-PROFILE.md`, `docs/README.md`.
- Deleted: `SCOPE.md`, `x86-64.md`, `native-mimalloc.md`, everything under
  `docs/roadmap/` and `docs/history/`. Past content is still available in Git
  history at `93b21b8336862ed89e7967c3e140877f97feb782`.

Retired document → successor. Use this table for any reference you still find:

| Retired | Successor |
| --- | --- |
| `SCOPE.md` | `AGENTS.md` (policy sections; `#scope-and-authority`, `#dependencies-safety-and-performance`) |
| `x86-64.md` | `plan.md` (`#runtime-completion`, `#final-promotion-and-definition-of-done`) |
| `native-mimalloc.md` | `plan.md` (`#native-allocator-completion` and its subsections) |
| `STATUS.md` (already gone at base) | `plan.md#progress-status` |
| `docs/roadmap/performance-completion.md` | `plan.md#runtime-performance-and-qualification` |
| `docs/roadmap/software-corpus-validation.md`, `docs/roadmap/source-build.md` | `plan.md#deferred-work` |
| `docs/history/*` | Git history at the base commit; no replacement file |

Cite successors by **section name**, never by the old `§N` numbers. The new
documents do not keep the old numbering.

## Starting state (verify before doing anything)

The previous session did the migration in the working tree on top of base
`93b21b83` (65 files: 52 modified, 13 deleted). Confirm you have it:

```sh
test ! -e SCOPE.md && test ! -e x86-64.md && test ! -e native-mimalloc.md \
  && test ! -e docs/history && test ! -e docs/roadmap && echo retired-files-gone
sha256sum compat/crabc-rs/coverage.toml compat/x86_64/parity.toml
# expect 4c774b50acb3aea5cb9a5e6be2af4ac1dfae50e377f3d113d66a9d47375ce875  coverage.toml
# expect ce122067f031e6b75cff20477ec8fb691db404df8b539a23e32be4e623557c17  parity.toml
```

If these do not match, stop and ask the user; do not redo the migration from
scratch.

Already done and verified (in emulated `linux/amd64` Docker on macOS):

- All retired references in code, data, tests, and Markdown were retargeted.
  Source-owner lists had duplicates removed where `plan.md` was already present.
- `compat/crabc-rs/coverage.toml`: only 33 `evidence`/`review_evidence` path
  strings changed. It still has 223 capabilities with the same symbols and
  classifications. The allocator scope-exception evidence is now
  `("AGENTS.md", "docs/evidence/crabc-rs-subsumption.md")`, matching
  `ALLOCATOR_SCOPE_EXCEPTION_EVIDENCE` in `compat/rustix/run.py`. The user
  explicitly approved this reviewed change to the frozen ledger and the re-pin
  of its digest in `compat/x86_64/aarch64_frozen_baseline.json` and
  `compat/x86_64/tests/test_aarch64_parity_inventory.py`. Do not change the
  ledger or its pin again.
- Regenerated with their owning generators (only digest fields changed):
  `header_callable_inventory.json`, `header_callable_disposition.json`,
  `generated/header_callable_visibility_matrix/report.json`,
  `generated/headers_layouts_aggregate/report.json`, and
  `aarch64_parity_inventory.json` (serialized from `build_inventory()` with
  `json.dumps(..., indent=2, sort_keys=True) + "\n"`; it has no `--write` flag).
  Base `93b21b83` had already left the first two stale.
- Deliberate pin updates: `units_sha256` in
  `compat/allocator/x86_64-source-map-v3.5.0.json`, the
  `math-scalar-corrections.md` entry in `PROOF_SOURCES` in
  `compat/x86_64/owned_math_oracle_defects.py`, and `REPORT_SHA256` in
  `compat/x86_64/tests/test_native_abi_headers_layouts_aggregate_attachment.py`.
- Rustix exclusion rationale (io_uring, `rustix::runtime`) moved into
  `docs/design/crabc-rs.md#api-rules`. `compat/rustix/api.toml` points there.
- Emulated results: `test_parity_ledger` 339/339, `validate_parity_ledger`,
  `aarch64_parity_inventory.py`, `header_callable_disposition.py --check`,
  `header_callable_visibility_matrix.py --check`,
  `headers_layouts_aggregate.py --check`, the allocator source-map ratchet and
  its 45 tests, and the aggregate-attachment tests all pass.

## Remaining work

### 1. Re-verify natively through the real dispatchers

The dispatchers refuse non-Linux hosts, so the previous session called the
generators directly. Run the real entry points here:

```sh
./scripts/dev-x86_64.sh image
./scripts/dev-x86_64.sh header-callable-disposition
./scripts/dev-x86_64.sh header-callable-visibility-matrix
./scripts/dev-x86_64.sh headers-layouts-aggregate
compat/allocator/run-x86_64.sh image
compat/allocator/run-x86_64.sh allocator-startup-regular-arena --reader-tests   # includes source-map tests
```

Then run the affected unit suites in the image (`python3 -B -m unittest ...`):
`compat/x86_64/tests/test_parity_ledger.py`,
`compat/x86_64/tests/test_aarch64_parity_inventory.py`,
`compat/x86_64/tests/test_loader_debug_abi_evidence.py`,
`compat/x86_64/tests/test_native_abi_headers_layouts_aggregate_attachment.py`,
`compat/x86_64/tests/test_native_abi_selection_dispatcher.py`,
`compat/x86_64/tests/test_compiler_helper_evidence.py`,
`compat/allocator/tests/test_x86_64_source_map.py`, plus
`python3 compat/x86_64/validate_parity_ledger.py` and
`python3 compat/x86_64/aarch64_parity_inventory.py`.

Rust edits were comment-only (`crabc-mimalloc/src/single_thread.rs`,
`crabc-mimalloc/src/remote_free_loom.rs`, `crabc-rs/src/lib.rs`,
`libc/src/legacy_des_exports.rs`, `libc/src/c_abi/x86_64/legacy_des_compat.rs`)
and were not compiled. Build those crates the way `plan.md#commands-and-evidence`
or the dispatcher does. A plain `cargo check` is enough if it is supported.

If a check fails on something this migration touched, fix the root cause via
its owning generator or source. Never hand-edit a generated report or loosen a
guard.

### 2. Fix the two stale section-number citations

- `compat/allocator/perf-local-aarch64/README.md`: "§19.2 requires a recorded
  native Linux/AArch64 final-performance environment". This was the old
  allocator plan's "Final promotion bands". Point it at
  `plan.md` (Allocator verification and performance) and keep the AArch64
  lane described as paused, or say the requirement is historical.
- `compat/x86_64/owned-loader-family.md` line ~13 ("the §7 process entry") and
  the comment in `compat/x86_64/owned_loader_family.py` line ~47 ("§7's finite
  behavior boundaries"). This was old `x86-64.md` "### 7. `ldso.dynamic-runtime`".
  Use the Loader row in `plan.md` (Families and public ABI).

After editing any file, run the pin scan below. The `.py` file or the doc may be
digest-pinned somewhere.

### 3. Review the new documents against the repository

The new documents were written by an agent without access to a checkout. Check
their factual claims and fix what is wrong. Keep the structure and contracts;
do not add process overhead or new status files.

- `plan.md#progress-status`: every qualified commit ID exists
  (`git cat-file -t`), and each milestone/family state matches the executable
  sources (`./scripts/dev-x86_64.sh campaign-status`, the allocator milestone
  manifests under `compat/allocator/`, and `compat/x86_64/parity.toml`).
- `plan.md#commands-and-evidence` and the `AGENTS.md` code/command map: every
  named command is a real case in `scripts/dev-x86_64.sh`,
  `compat/allocator/run-x86_64.sh`, or `scripts/dev.sh`, and every named path
  exists.
- `plan.md#fixed-contracts`: the frozen numbers (223 capabilities, 26 families,
  source commit `3e100d45…`) match `compat/x86_64/aarch64_frozen_baseline.json`.
  It says to "validate them, never refresh them". Leave that sentence as is: the
  one-time re-pin above was an approved migration, not drift. Mention it in
  the commit message instead.
- `plan.md` states that explicit static and dynamic native-shadow products
  exist in `libc/Cargo.toml`. Confirm this.
- `README.md` and `COMPATIBILITY-PROFILE.md` do not contradict each other or
  `plan.md` about supported platforms (public support is still Linux/AArch64;
  x86 is private until promotion).

Report anything you cannot confirm instead of guessing.

### 4. Optional, bounded: stale wording in retained design notes

Durable design notes were intentionally kept, not rewritten. Only fix sentences
that now misdirect a reader (for example, "the live queue is in …" pointing at
something that no longer owns it). Do not rewrite historical explanation.
Candidates: `docs/design/allocator.md`, `compat/allocator/README.md`,
`compat/x86_64/README.md`.

## Required checks before you finish

Run all three from the repository root. Each must print nothing except the final line.

```sh
# a) No retired references anywhere tracked (this file excluded).
git grep -n -E "native-mimalloc\.md|x86-64\.md|SCOPE\.md|STATUS\.md|docs/roadmap|docs/history|performance-completion\.md|software-corpus-validation\.md|crabc-rs-delivery-plan|runtime-plan\.md|semantic-migration|throughput-reset|project-status-2026|native-mimalloc-aarch64|plan-before-throughput|crab-orchestrate" -- . ':!handoff.md'; echo scan-a-done

# b) No tracked file pins the base-commit sha256 of any file you changed.
git diff --name-only 93b21b8336862ed89e7967c3e140877f97feb782 | while read f; do
  h=$(git show 93b21b8336862ed89e7967c3e140877f97feb782:"$f" 2>/dev/null | sha256sum | cut -c1-64)
  hits=$(git grep -l "$h" -- . ":!$f" 2>/dev/null | tr '\n' ' ')
  [ -n "$hits" ] && echo "$f <- $hits"
done; echo scan-b-done

# c) No broken relative Markdown links or anchors into the rewritten docs.
python3 - <<'EOF'
import os, re, subprocess
def anchors(p):
    out, seen = set(), {}
    for line in open(p, encoding="utf-8"):
        if re.match(r"^#{1,6}\s", line):
            h = re.sub(r"[^\w\s-]", "", re.sub(r"^#{1,6}\s+", "", line).strip().lower())
            s = re.sub(r"\s", "-", h); n = seen.get(s, 0); seen[s] = n + 1
            out.add(s + (f"-{n}" if n else ""))
    return out
for f in subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True).stdout.split():
    if f == "handoff.md" or not os.path.exists(f): continue
    for m in re.finditer(r"\]\(<?([^)\s>#]+)(?:#([^)\s>]+))?", open(f, encoding="utf-8", errors="replace").read()):
        t = m[1]
        if "://" in t or t.startswith("mailto:"): continue
        p = os.path.normpath(os.path.join(os.path.dirname(f), t))
        if not os.path.exists(p): print("missing", f, "->", t)
        elif m[2] and p.endswith(".md") and m[2] not in anchors(p): print("anchor", f, "->", t + "#" + m[2])
print("scan-c-done")
EOF
```

If scan b reports a pin, update it through the pin's owning generator or
reviewed constant. Then repeat scan b until it is clean, because updating a pin
can expose another pin.

## Known failures unrelated to this migration (report, do not fix here)

- `test_aarch64_parity_inventory.test_checked_snapshot_is_source_derived_and_non_promoting`
  expects `selected_static_export_count == 1276`, but the tree has 1275 since
  commit `80d45a17` ("leave Rust personality ownership to std").
- `compat/allocator/tests/test_port_map_pointer_first_post_owner_exit.py`:
  "port map duplicates upstream path: src/theap.c". Also,
  `compat/allocator/ratchet-v3.5.0.json` pins a `port_map_sha256` that did not
  match `port-map.toml` even at the base commit.
- `compat/rustix/tests/test_harness.py` needs the ignored
  `compat/reports/symbols/*aarch64.dynamic.tsv` files. Only the paused AArch64
  pipeline produces them. With only those two inputs stubbed from the ledger's
  embedded symbol lists, all 29 tests and `validate_coverage` passed.

## Out of scope: decisions for the user

- The 0.90× total peak-memory release gate may be infeasible for fully touched
  workloads (see `plan.md#runtime-performance-and-qualification`). This is a
  policy decision for the user, not a documentation fix.
- Any implementation, qualification, allocator-default or public-support
  promotion work from `plan.md`.

## Finish

1. All three scans are clean, and the native checks in step 1 pass or have
   failures you have explained.
2. Delete `handoff.md`.
3. Report to the user: what you ran, what passed or failed (with output), what
   you changed in steps 2–4, and anything in step 3 you could not confirm.
   Suggest one commit for the consolidation plus regenerated artifacts. Its
   message should mention the approved frozen-ledger evidence re-pin
   (`128458dd…` → `4c774b50…`).
