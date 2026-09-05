// Private Linux/x86-64 `WRDE_NOCMD` lexical preflight.
//
// This is a direct Rust transliteration of musl 1.2.6 release commit
// `9fa28ece75d8a2191de7c5bb53bed224c5947417`,
// `src/misc/wordexp.c::do_wordexp` lines 43-83 (MIT license). It deliberately
// retains that source's small `sq`/`dq`/`np` state machine: this target's C
// compatibility contract is musl, including its `WRDE_BADCHAR` result for
// malformed arithmetic-looking input after its nested-paren count returns to
// zero. The generic `wordexp_nocmd.rs` remains the established hardened
// AArch64 scanner and is intentionally not an x86 source oracle.
//
// Inclusion site: `owned_wordexp.rs`, which provides `c_char`, `c_int`, and
// the `WRDE_*` result constants.

unsafe fn wordexp_nocmd_check(input: *const c_char) -> c_int {
    let mut index = 0usize;
    let mut single_quote = false;
    let mut double_quote = false;
    let mut nested_parentheses = 0usize;

    loop {
        // SAFETY: `wordexp` has already received a non-null C string. The
        // current byte remains within that NUL-terminated object.
        let byte = unsafe { *input.add(index) } as u8;
        if byte == 0 { break; }

        match byte {
            b'\\' => {
                if !single_quote {
                    index += 1;
                    // SAFETY: the byte following a non-NUL backslash is
                    // within the supplied NUL-terminated C string.
                    if unsafe { *input.add(index) } == 0 { return WRDE_SYNTAX; }
                }
            }
            b'\'' => {
                if !double_quote { single_quote = !single_quote; }
            }
            b'"' => {
                if !single_quote { double_quote = !double_quote; }
            }
            b'(' => {
                if nested_parentheses != 0 {
                    nested_parentheses += 1;
                } else if !(single_quote || double_quote) {
                    return WRDE_BADCHAR;
                }
            }
            b')' => {
                if nested_parentheses != 0 {
                    nested_parentheses -= 1;
                } else if !(single_quote || double_quote) {
                    return WRDE_BADCHAR;
                }
            }
            b'\n' | b'|' | b'&' | b';' | b'<' | b'>' | b'{' | b'}' => {
                if !(single_quote || double_quote || nested_parentheses != 0) {
                    return WRDE_BADCHAR;
                }
            }
            b'$' => {
                if !single_quote {
                    // SAFETY: a byte after this non-NUL byte is either the
                    // terminating NUL or another byte in the C string.
                    let next = unsafe { *input.add(index + 1) } as u8;
                    if next == b'(' {
                        // SAFETY: `next` is non-NUL, so its successor is in
                        // the same NUL-terminated C string.
                        if unsafe { *input.add(index + 2) } as u8 == b'(' {
                            index += 2;
                            nested_parentheses += 2;
                        } else {
                            return WRDE_CMDSUB;
                        }
                    }
                }
            }
            b'`' => {
                if !single_quote { return WRDE_CMDSUB; }
            }
            _ => {}
        }
        index += 1;
    }
    0
}
