# R1: Exact startup attribution and the TLS-growth freeze boundary

## Method

Earlier R1 notes used `perf record` samples. On this host they misattribute:
a dense `instructions:u` profile placed 37% of startup in self-relocation,
which the code cannot retire. This note uses exact counts instead. A ptrace
single-stepper records every retired user RIP of `/app/bin/workload <row>` in
the R0 counts execution roots (pinned image, `CAP_SYS_PTRACE`), and `nm`
symbolizes the trace. Single-step counts each `rep movs/stos` iteration;
`perf stat` counts the instruction once. Excluding those iterations, the trace
matches the counts report: startup 131.7k vs 132.7k for crabc, 69.5k vs 70.1k
for musl. The counts rows remain the acceptance measure.

## Startup (gate: about 54k fewer instructions)

| Work | crabc | musl |
| --- | ---: | ---: |
| Symbol lookup (`lookup_result_at` / `find_sym`) | 46.5k, 90 calls | 47.7k, 112 calls |
| Relocation driver around lookup | 48.3k | 10.6k |
| Interpreter self-relocation | 14.9k | 1.4k |
| Everything else | about 22k | about 9k |

Lookup is at parity. Both sides hash every name with SysV for the SysV-only
main executable. Relinking the merged libc with `--hash-style=both` added
11.4k to lookup and 4.3k to GNU-table decoding, so hash style is not a lever.

The driver is straight-line work of about 450 instructions per symbolic
relocation: `word_resolution` 123 per call, `ordinary_address` 104,
`preflight_object_resolved` and `relocate_initial_graph_inner` about 61 each,
plus `admitted_target`, `direct_symbol` and name-length decoding. Preflight
already retains resolved values, so the earlier transaction-cache proposal is
implemented and is not the remaining cost.

Self-relocation spends about 10k in `.Lself_check_w`. Its one-segment cache
misses whenever RELR targets alternate between the RELRO and data `RW` loads,
and each miss rescans every program header. RELR has 37 words and about 629
targets; 36 RELA entries carry no `RELATIVE` type.

A credible startup design must therefore do all three of these. Check RELR
targets against the precomputed writable loads, keeping complete validation
before any write. Cut per-relocation driver work to about musl's 90
instructions without dropping a hardening check. Remove a few thousand more
from the remainder. The available headroom is about 50–55k against the
required 54k, so the gate is marginal even with all three.

`dlopen_graph` counts the whole process. Its dlopen portion is 51.4k vs 45.0k
(1.14); the row fails on startup and moves with it.

## TLS growth cannot pass under the allocator freeze

The row's `pthread_create` performs the first allocation, so the frozen C
backend initializes: option parsing through `_mi_prim_getenv`,
`_mi_strnicmp`, `_mi_strlcpy` and `_mi_toupper`, then clocks and `sysinfo`.
That retires 90.3k instructions; musl's allocator retires 5.5k in this row.
The 1.10 gate allows about 175k for the whole client process. Even at exact
musl parity for every non-allocator instruction (about 152k), crabc would
retire about 242k. No `ldso/`, `crt/` or libc-startup change can meet this
row while the allocator is frozen.
