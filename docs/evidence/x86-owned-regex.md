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

## Installed-product proof

`./scripts/dev-x86_64.sh owned-regex [DYNAMIC_SYSROOT]` dispatches
`compat/x86_64/run_owned_regex.sh`, which builds fresh owned static
and dynamic products when no product is supplied. It compiles
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
and `regerror` table/truncation behavior. Each owned executable's stdout and
stderr must exactly match the pinned musl execution, while the runner also
requires each of the four public entries to be a defined global function in
the relevant archive or shared object.

`compat/x86_64/run_owned_regex_execution.sh` remains the separate private
allocator-failure checkpoint. It uses copied source routing and a recording
allocator to prove compiler and parallel/backtracking cleanup under every
observed allocation-failure edge. It is not replaced by the installed-product
proof and does not establish aggregate runtime closure.

The dynamic qualification catalog requires `regex` for each installed,
relocated, and second product. Its receipt binds this runner to the complete
product and source closure; catalog registration is not an aggregate pass.
