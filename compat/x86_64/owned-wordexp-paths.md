# Private x86 wordexp pathname adapter

`libc/src/c_abi/x86_64/owned_wordexp_paths.rs` is the private pathname owner
selected by the deterministic expansion engine and C binding in
`owned_wordexp.rs`. It binds the engine to the owned C pattern and
conventional-passwd providers. It is C ABI compatibility machinery within the
active x86 runtime program and exports no public C symbol; its private API and
fixtures do not by themselves qualify an installed product or public support.

## Quote information and pattern ownership

The core supplies a `PatternInput`: original expansion bytes, one eligibility
bit per byte, and private empty markers. `OwnedShellPattern` omits the empty
markers and copies each remaining byte with its protection bit. One checked
C allocation holds the terminated byte string and the equally sized mask.
`owned_pattern::ShellPattern::new` validates that borrowed view.

The adapter does not serialize protection by inserting backslashes. Quoted
bracket punctuation must keep its original role, and ordinary quoted letters
inside a character-class name must remain ordinary letters. Those rules belong
to the pattern owner's private shell mode. Its public C matcher and glob
behavior remain separate from this additional input representation.

For pathname expansion, `NativeWordexpPaths::expand_pattern` calls
`owned_pattern::shell_glob`. `NoActivePattern` and `NoMatch` leave the original
field intact. In particular, a backslash introduced by an unquoted variable
expansion is retained if the resulting pattern has no active wildcard. Each
successful path is copied through `PathnameMatches` while the `ShellGlob`
owner is live. Its destructor invokes the existing glob result release path;
the adapter neither duplicates `glob_t` nor frees its interior strings.

The four parameter-removal operators call the same pattern matcher. The
adapter visits candidate prefix or suffix boundaries in order, using the
selected `locale_multibyte::mbtowc` decoder. A malformed byte advances by one
so the search always progresses. Smallest-prefix and largest-suffix removal
select the first matching boundary; largest-prefix and smallest-suffix removal
select the last. The matcher takes a bounded borrowed slice, so no allocation
or temporary terminator is needed for an individual candidate. The result is
copied through `ParameterPatternOutput`, and the core applies the enclosing
parameter expansion's quote and field-splitting rules.

These operations follow the substring and pathname rules in POSIX
[Shell Command Language §2.6.2](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_06_02)
and [§2.14](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/utilities/V3_chap02.html#tag_19_14).
The fixed musl matcher and glob source provenance stays with
`owned_pattern.rs`, `owned_fnmatch.rs`, and `owned_glob.rs`.

## Tilde and allocation boundaries

Bare tilde receives the core's current call-local `HOME`. A set value,
including an empty value, is copied through `TildeOutput`; the core protects
the replacement from field splitting and pathname expansion. If `HOME` is
unset, the adapter looks up the current UID through `owned_passwd::getpwuid_r`.
Named tilde uses `owned_passwd::getpwnam_r`. Both retain the existing local
passwd-file profile.

Each lookup uses a private buffer beginning at 1024 bytes, growing with checked
arithmetic only after `ERANGE`. The adapter copies the directory before that
buffer is freed. It does not borrow shared non-reentrant passwd records, read
ambient `HOME`, impose a fixed private lookup capacity, or add an identity
provider. An unknown user or other lookup failure leaves the tilde spelling
unresolved; `ENOMEM` becomes the core's resource error.

`PathStorage` owns every adapter allocation through C `malloc` and `free`.
Capacity calculations reject overflow and sizes above `isize::MAX` before
constructing Rust slices or offsets. The enclosing C wordexp transaction keeps
cancellation disabled while this state is live and keeps LC_CTYPE stable
through the expansion. Glob allocation failure and an aborted traversal use
the C wordexp setup/resource failure category; they are never reclassified as
an undefined-variable or shell-syntax result.

## Private evidence boundary

`./scripts/dev-x86_64.sh wordexp-paths-private` dispatches
`compat/x86_64/run_owned_wordexp_paths_private.sh`. It builds a disposable native
static archive with `crabc_owned_wordexp_paths_private_test` and links
`owned_wordexp_paths_private_probe.c`. The cfg admits only a private fixture
bridge; normal runtime artifacts export no probe symbol and use the selected
deterministic wordexp provider. The runner retains build output, the consumer
status and streams, and the fixture leaf beneath `.work/x86_64`. The private
archive uses the normal builder's pinned tools and complete producer
environment, including the contained Cargo cache. A direct link uses that raw
archive with the normal product's CRT and builtins; the sealed product's libc
archive stays intact and is checked for absence of the private bridge.

The C fixture specifies all four removal operators, quoting inside and outside
patterns, protected bracket members and class-name letters, result splitting
and empty-word rules, C and C.UTF-8 character boundaries, literal and empty
HOME, reentrant named/UID tilde lookup, and actual filesystem glob ordering,
leading-period, escaped-wildcard, and no-match behavior. It uses the real
selected runtime owners. This private witness does not produce a normal
sysroot qualification receipt or installed ABI/public-promotion result. The
selected C binding composes this pathname owner with the deterministic core,
process adapter, and sole result transaction; direct installed/extracted C ABI
evidence remains the separate product validation boundary.
