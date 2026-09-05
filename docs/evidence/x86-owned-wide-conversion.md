# Owned bounded wide conversion

The native owned runtime supplies `mbsnrtowcs`, `wcsnrtombs`, and `wcsdup`
from `libc/src/c_abi/x86_64/owned_wide_conversion.rs`. This is C text-runtime
compatibility machinery within the existing C/POSIX/C.UTF-8 locale profile.
The leaf is selected only by `x86-owned-static-runtime`, inherited by the
owned dynamic runtime. It does not select another encoding, locale database,
wide-time formatter, allocator, or Rust facade API.

## Source and ownership

The semantic source is MIT-licensed musl 1.2.6, release commit
`9fa28ece75d8a2191de7c5bb53bed224c5947417`. Its release archive SHA-256 is
`d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a`;
`compat/upstreams.toml` owns the pin, and upstream `COPYRIGHT` owns the license.

| Source | Rust owner |
| --- | --- |
| `src/multibyte/mbsnrtowcs.c` | `mbsnrtowcs` and `decode_bounded` |
| `src/multibyte/mbsrtowcs.c::resume` | Owned wrapper's saved-state error-cursor repair around the existing bulk helper |
| `src/multibyte/wcsnrtombs.c` | `wcsnrtombs` |
| `src/string/wcsdup.c` | `wcsdup` |

The existing `locale_multibyte::{mbsrtowcs,mbrtowc,wcrtomb}` owns actual
conversion, locale selection, and the two-word `mbstate_t` ABI. The bounded
input loop preserves musl's bulk threshold and 256-element count-only scratch
buffer, then uses the bounded one-character decoder for its tail. The first
opaque state word carries pending UTF-8; the second remains untouched.
Null-state decoding has its own static channel, distinct from `mbrtowc`.
As in adjacent conversion leaves, atomic storage avoids a Rust data race;
callers still serialize a logical sequence or use their own state object.

`mbsnrtowcs` counts converted wide characters, excluding the NUL. Reaching a
NUL sets the caller's source pointer to NULL when output is requested. An
incomplete character consumes the available byte extent and retains pending
state. An encoding error returns `(size_t)-1` and `EILSEQ`, preserving earlier
output. Null-destination calls leave the caller's source pointer unchanged but
can update state. Zero input/output limits and a null source value retain the
source's individual branches.

The bulk helper's frozen artifact explicitly leaves pending-error pointer
details unselected. This owned boundary additionally selects musl's exact
`resume` behavior: if a saved partial character fails before completion, the
returned source cursor is one byte before the continuation supplied to that
bulk call. The wrapper repairs only that diagnostic pointer after the shared
helper reports the error; it does not read through it. The regression keeps
prefix and continuation in one backing array so the returned cursor remains
inside a live object. This changes no frozen helper code or selected-default
contract.

`wcsnrtombs` bounds source elements and destination bytes separately. It never
splits a multibyte output character, excludes the terminating NUL from its
return count, and ignores its state argument. Even zero output capacity can
observe an invalid next wide character and report `EILSEQ`; the existing
encoder determines that outcome. Count-only calls leave the source pointer
unchanged. All null-destination and partial-write branches follow the source.

`wcsdup` uses `wide_character::{wcslen,wmemcpy}` and the runtime's existing C
`malloc` provider. Its result is independent caller-owned storage, released
with ordinary `free`. It copies all wide code units, including values that
would not be valid for a conversion. Allocation failure remains the selected
allocator's NULL/errno result. There are no new dependencies or private
allocation mechanisms; the selected backend's existing provenance applies.

## Focused evidence

`compat/x86_64/run_owned_wide_conversion.sh` builds fresh static and dynamic
products, then compiles `owned_wide_conversion_probe.c` once with the installed
dynamic driver. The same object links against pinned musl 1.2.6 and every
candidate: static, static PIE, dynamic PIE and non-PIE, with both kernel and
direct-interpreter entry for each dynamic executable. Source/object hashes,
function symbol tables, binaries, stdout, and stderr are retained. Candidate
observations must exactly match the oracle. A supplied dynamic product selects
only the four dynamic entries and makes no fresh static-evidence claim.

The probe checks C/POSIX/C.UTF-8 conversion, source/output bounds, count-only
mode, malformed and incomplete UTF-8, signed/surrogate/private code units,
null source values, caller and internal state, untouched second state words,
bulk and tail paths, pending-state bulk errors, independent null-state
channels, zero-limit pending state, thread-local CTYPE overrides, returned cursor positions,
errno, and output canaries. Protected pages prove bounded input reads for both
directions, including zero source counts and the bulk threshold. Duplication checks empty/nonempty
strings, independent ownership, literal code units, and ordinary `free`.

Before implementation, the oracle workload passed and the installed dynamic
link failed with precisely the three missing providers. The later bulk-resume
regression independently failed on the source-cursor difference before the
owned wrapper correction. This is focused family evidence, not complete
native runtime qualification or public x86 platform promotion.
