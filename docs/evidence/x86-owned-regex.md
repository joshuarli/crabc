# Owned x86 regex evidence

The native owned runtime selects the source-faithful TRE regex implementation
from `libc/src/c_abi/x86_64/owned_regex/` for the
`x86-owned-static-runtime` feature, which the owned dynamic product inherits.
It provides the installed C ABI entries `regcomp`, `regexec`, `regerror`, and
`regfree` for Linux/x86-64 little-endian LP64. The frozen default x86 regex
leaf remains selected outside that feature until its separate retirement
contract is satisfied.

## Source and ownership

The semantic source is the pinned musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` owns that pin. The TRE sources retain Ville Laurikari's
two-clause BSD license in
`libc/src/c_abi/x86_64/owned_regex/LICENSE-TRE-2-CLAUSE-BSD.txt`. The musl
release `COPYRIGHT` remains the provenance for `regerror.c` and the installed
header.

| Pinned musl 1.2.6 source | SHA-256 | Owned Rust target |
| --- | --- | --- |
| `src/regex/tre.h` | `e734e68decc33b5ee983db12cabcbdd2589c2d16088677228087b0e5dc365cf3` | `owned_regex::types` TNFA, tag, submatch, and public-record layouts |
| `src/regex/tre-mem.c` | `4721979ce365a395fd7644335c847a8a97913e87f14348641f7f199b57b93e28` | `owned_regex::memory` arena/list allocation and destruction |
| `src/regex/regcomp.c` | `56b0a765e084a5cd3ed7113a893b50d259265ba76b6bea98889c45d7aec302a0` | `owned_regex::compile` parser, tag placement, TNFA materialization, `regcomp`, and `regfree` |
| `src/regex/regexec.c` | `072e8a1092c98830b48e784fb74ce486f7c39e27207f79f1dd161e2c5d86ba77` | `owned_regex::execute` parallel and backtracking TNFA execution, tag ordering, offsets, and `regexec` |
| `src/regex/regerror.c` | `72b3ab9c63c88c43aa37c4a4d4a89d07f892f42cbbf8801806b7b40135466bb9` | `owned_regex::error::regerror` contiguous message table and bounded copy |

`regcomp` stores its completed TNFA graph through `regex_t.__opaque`; the
source-shaped `regfree` consumes that graph once after its final execution.
The exact public ABI is the installed `include/regex.h`: on this target
`regoff_t` is signed, aligned LP64 `long`. The header has no `REG_STARTEND`
definition, so this runtime does not claim that extension. C/POSIX/C.UTF-8
locale behavior is supplied by the existing wide-character and multibyte
owners; this leaf does not add a locale database or a Rust regex API.

## Intentional differences

These are confined to inputs on which the pinned source reads or moves outside
the caller's NUL-terminated subject; `owned_regex::execute::run_backtrack`
treats them as failed backreferences and backtracks as for any mismatch.

- A backreference into a still-open group (undefined by POSIX, accepted by
  musl) can yield a negative length. musl compares under the wrapped `size_t`
  length and, on equality, moves the matcher backwards; for example
  `\(a\(\2\|x\)b\)*` on `abab` never terminates.
- musl's backtracking matcher keeps the previous character's byte width when
  it restarts at a later start position, so after a UTF-8 multibyte character
  its tag offsets drift from byte offsets. The port keeps that drift exactly,
  but a drifted range that ends past the terminator is not compared. musl
  compares it and advances beyond the string: `\(.*\)*\1a` on the C.UTF-8
  subject `aaa\xc3\xa9\xc3\xa9ba` placed before an unmapped page faults
  under musl. The probe's `--bounded-backreference` mode runs exactly that
  case; the runner requires the musl child to fault with `SIGSEGV` and every
  owned entry to report musl's ordinary-memory answer (match `0,3`, group
  `0,1`).

## Installed-product proof

`./scripts/dev-x86_64.sh owned-regex [--static-sysroot STATIC_SYSROOT]
[DYNAMIC_SYSROOT]` dispatches `compat/x86_64/run_owned_regex.sh`, which builds
fresh owned static and dynamic products when neither product is supplied. It compiles
`compat/x86_64/owned_regex_probe.c` once with the installed dynamic driver and
records hashes for both the source and resulting object. That unchanged object
links against fixed musl, owned static, owned static-PIE, and owned dynamic
PIE/non-PIE products. Dynamic executables run through both kernel-selected and
direct `/lib/ld-crabc-x86_64.so.1` interpreter entry.

The installed-header probe rejects a different `regoff_t` width, alignment,
signedness, or entry signature. It then checks leftmost-longest matching,
captures, BRE backreferences including the empty backreference progress edge,
newline anchors, character classes, case folding, C.UTF-8 byte offsets,
`REG_NOTBOL`, `REG_NOTEOL`, `REG_NOSUB`, source-shaped compile/free/recompile,
final-state tag publication when a later path wins the tag order,
`REG_ICASE` pairing of escaped literals, and `regerror` table/truncation
behavior; each directed case checks its own expected offsets. A deterministic
differential corpus then compiles fixed, structured (nested groups,
alternation, repetition, BRE backreferences to closed groups), and token-soup
BRE/ERE patterns under eight flag sets in both `C` and `C.UTF-8`, and
executes each compiled pattern on fixed, generated, and long subjects under all
`REG_NOTBOL`/`REG_NOTEOL` combinations. Every compile status, `re_nsub`,
execute status, and all ten `regmatch_t` slots fold into one printed FNV-1a
digest per block, so the transcript is judged by comparison with musl rather
than by a checked-in copy; `--corpus-trace` and `--corpus-trace-subjects`
print each observation to localize a divergence. A separate case-fold block
in each locale runs fixed and generated backreference-free patterns over
non-ASCII case pairs and classes (`é`/`É`, the one-way long-s, Kelvin-sign
and final-sigma pairs, four-byte characters, multibyte range endpoints, and
invalid surrogate/out-of-range encodings), so `REG_ICASE` and `C.UTF-8`
classification are compared on the parallel matcher. Directed locale edges
compile and execute under a `uselocale` thread locale while the global locale
stays `C`, execute patterns compiled under one locale in the other, and read
`regerror` text there. Other `CORPUS_SEED` values also reach the drift
difference above: every divergence found in the alternative seeds tried was a
musl match whose offsets extend past the subject terminator, where the port
reports no match. Each owned executable's
stdout and stderr must exactly match the pinned musl execution. The retained object has
exactly one undefined public row for each of `regcomp`, `regexec`, `regerror`,
and `regfree`; pinned musl, the static archive and linked static entries, and
the dynamic shared object each retain the corresponding provider rows.

The runner writes `owned-regex-products.json` and validates it with
`owned_regex_component_receipt.py validate-report`. Its v2 reader rehashes
physical sources, products, tool paths, the installed-header object, retained
commands and raw streams, link receipts and their public validation output,
and copied dynamic execution payloads. Before it interprets the four API rows,
it reruns the sealed read-only `env -i`/`nm` or `readelf` command against the
rehashed physical object, archive, executable, or shared object and requires
the retained raw stream to match exactly. It rejects ambient header origins and
requires the musl transcript to be complete (its final completion line, empty
stderr, zero status) before admitting each byte-identical candidate entry. A full receipt records static ET_EXEC, static PIE, and both
kernel and direct entries for dynamic PIE and non-PIE; a supplied dynamic
product alone yields the explicitly non-complete four-cell development mode.
`--require-static` rejects that development mode. Neither shape closes a
family or asserts promotion or public support.

`compat/x86_64/run_owned_regex_execution.sh` remains the separate private
allocator-failure checkpoint. It uses copied source routing and a recording
allocator to prove compiler and parallel/backtracking cleanup under every
observed allocation-failure edge. It is not replaced by the installed-product
proof and does not establish aggregate runtime closure.

The dynamic qualification catalog requires `regex` for each installed,
relocated, and second product. Its receipt binds this runner to the complete
product and source closure; catalog registration is not an aggregate pass.
