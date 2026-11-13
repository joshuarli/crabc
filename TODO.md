Prefix: CRAB
Next: 6

### CRAB-5 · P2 · Stop text-family assembly re-reading product trees

- **Area:** Qualification harness
- **Where:** compat/x86_64/owned_text_math_locale_stdio_family.py:880-915,1008,1038,1093; the per-component `_report_adapter`/`_*_adapter` readers at :560-862
- **Problem:** Priority assumed; D23 waives cost budgets, but this sets qualification wall time. In the `fb4583ae2` candidate, `text-family assemble` ran over 2.5 hours on one core and had read 864 GB (`rchar`, 90 M read syscalls, about 19 MB/s) while the whole candidate output is about 20 GB, including a 14.7 GB dynamic product. Each component adapter revalidates and snapshots the product pairs, and `_require_snapshots_current` repeats the directory snapshots, so the same trees are hashed dozens of times per run. Every fresh correctness candidate repeats this step.
- **Recommendation:** Measure which calls read the product trees, then validate and snapshot each physical product path once per assembler process and reuse that identity across components and pairs, keeping the final changed-during-collection comparison. Do not drop any check or narrow what is hashed. Prove with the existing text-family tests plus an injected product mutation between components that is still rejected.
- **Fix with:** make-it-fast
- **Effort:** M

