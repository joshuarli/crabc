# Private quote-aware wordexp pattern boundary

`libc/src/c_abi/x86_64/owned_pattern.rs` contains the private quote-aware
boundary selected by the x86 wordexp pathname adapter for pathname and
parameter-removal operations. It does not add a C symbol, C flag, header
declaration, or public provider surface. The installed `fnmatch`, `glob`, and
`globfree` paths remain the existing C ABI slice described in
[owned-pattern.md](owned-pattern.md).

The boundary accepts `ShellPattern<'_>`, a borrowed NUL-terminated byte slice
and an equally long byte-aligned protection map. Its terminal byte and map cell
are both zero; all preceding bytes are non-NUL and each map cell is either zero
or one. A one preserves the literal effect of a source quote after the
frontend's early representation normalization. The wordexp adapter removes
zero-width empty markers before it builds this view. `ShellPattern::new` checks
those conditions instead of accepting a core `PatternInput`, which keeps the
matching owner independent of wordexp's parser representation.

`shell_matches` accepts a bounded `&[u8]` value without allocating or reading a
terminator past a parameter-removal prefix or suffix. `shell_glob` returns a
finite `NoActivePattern`, `NoMatch`, or RAII `ShellGlob` result. `ShellGlob`
only lends byte path views while it owns the existing `Glob` allocation, and
its destructor uses the existing `globfree` protocol. A caller therefore copies
matched bytes before the owner drops without learning `glob_t` fields or
freeing interior pointers.

## Quote-aware grammar

POSIX Issue 8 Shell Command Language sections
[2.14.1](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_14_01)
and 2.14.3 order pathname expansion before final quote removal. This implementation
normalizes quote syntax early into bytes plus protection metadata, retaining
the effect that the final shell stage would otherwise apply. Backslash
serialization cannot preserve that distinction: serializing source
`[a"-"z]` as `[a\-z]` makes musl's raw bracket parser treat the backslash as a
member and can turn the protected dash back into a range endpoint. The private
frontend therefore preserves quote metadata for the pattern owner instead of
canonicalizing brackets itself.

`PatternMode::Shell` threads the map through `pat_next`, bracket closing
discovery, bracket matching, the Sea-of-Stars matcher, pathname routing, and
glob traversal. A protected `[`, `]`, `-`, first `!` or `^`, and POSIX nested
class/collating/equivalence delimiter `:`, `.`, or `=` is literal syntax at its
structural position. Protection on ordinary class-name letters is not a syntax
change, so `[[:di"g"it:]]` still recognizes the `digit` class. The shared
bracket walk prevents closing discovery and matching from using different
structural views.

A protected backslash is a literal filename byte. An eligible backslash carried
from expansion-derived raw bytes quotes the following byte outside a bracket;
inside a bracket, POSIX leaves that case unspecified and this private grammar
retains musl's literal-backslash behavior. A slash always separates pathname
components, including when its map cell is protected. Leading-period handling
uses the first logical token: a protected or raw-escaped literal `.` can match
a leading dot, while `[.]` remains a bracket expression under the normal
period rule.

Private glob first scans for an actual unprotected star, question, or valid
bracket token. It reports `NoActivePattern` when none exists, so a raw `\*`
field remains unchanged even if a file named `*` exists. That is distinct from
a parameter-removal pattern, where the same raw bytes match a literal `*`.

## Reused algorithm and provenance

This stays one matcher and one traversal. Musl 1.2.6 release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417` (MIT) maps
`src/regex/fnmatch.c` to `owned_fnmatch.rs` and `src/regex/glob.c` to
`owned_glob.rs`. `PatternMode::C` retains their raw C grammar and public ABI
behavior. `PatternMode::Shell` uses the same Sea-of-Stars algorithm, selected
`locale_multibyte` and `wide_character` owners, existing directory traversal,
match-list allocation, sorting, and release path. Glob duplicates the pattern
once, rebases the map onto that same-length duplicate, and keeps the map live
while temporary separator NUL writes occur during recursion.

The difference is deliberately a private representation of shell quote
protection, not a change to musl's public raw-backslash bracket behavior.
Pinned shell evidence requires the protected-dash and protected-bracket
outcomes; the existing C pattern evidence continues to compare the public C
entry directly with pinned musl.

## Focused evidence

`compat/x86_64/owned_pattern_private_probe.c` is a freestanding C witness for
the cfg-only bridge in `owned_pattern.rs`. It covers quoted `*`, `?`, brackets,
`!`, `-`, protected and eligible backslashes, valid ranges and classes,
malformed brackets, leading dots, separators, UTF-8, invalid bytes, active-token
detection, recursive globbing, and borrowed result paths. The bridge is built
only with `crabc_owned_pattern_private_test`; the normal static archive is
inspected to prove those symbols are absent.

Run `compat/x86_64/run_owned_pattern_private.sh` only in the pinned native
`crabc-core-evidence:x86_64` environment. It retains its disposable evidence
leaf under `.work/x86_64/` on success and failure. It is a private-owner
regression, not installed C ABI/public-promotion, POSIX-family, or native-x86
qualification. The selected pathname adapter uses this boundary; direct
C/product validation remains separate. Run `./scripts/dev-x86_64.sh
owned-pattern` separately for the unchanged public C-mode control.
