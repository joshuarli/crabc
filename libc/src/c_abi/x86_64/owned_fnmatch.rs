//! Source-faithful musl 1.2.6 `src/regex/fnmatch.c` matcher.
//!
//! The separately selected Rust facade's byte matcher is intentionally not
//! used here.  C `fnmatch` observes the active CTYPE through `mbtowc`, wide
//! case mapping, and wide bracket classes, including musl's invalid-UTF-8
//! progression rules.  The C entry's pointer obligations remain those of
//! `fnmatch(3)`: both arguments are readable NUL-terminated strings for the
//! complete call.

use core::ffi::{c_char, c_int};

use super::super::{locale_multibyte, wide_character};

const END: c_int = 0;
const UNMATCHABLE: c_int = -2;
const BRACKET: c_int = -3;
const QUESTION: c_int = -4;
const STAR: c_int = -5;

const FNM_PATHNAME: c_int = 0x1;
const FNM_NOESCAPE: c_int = 0x2;
const FNM_PERIOD: c_int = 0x4;
const FNM_LEADING_DIR: c_int = 0x8;
const FNM_CASEFOLD: c_int = 0x10;
const FNM_NOMATCH: c_int = 1;

#[inline]
unsafe fn byte(pointer: *const c_char) -> u8 {
    // SAFETY: the enclosing C ABI contract supplies readable C strings; each
    // caller advances only within a validated NUL-terminated range.
    unsafe { pointer.read() as u8 }
}

/// `str_next` from musl: decode one CTYPE character, treating an invalid
/// sequence as one byte so the star-search progression can consume it.
unsafe fn str_next(string: *const c_char, count: usize, step: &mut usize) -> c_int {
    if count == 0 {
        *step = 0;
        return 0;
    }
    if unsafe { byte(string) } >= 128 {
        let mut character = 0;
        // SAFETY: `string` is readable for the supplied bounded range under
        // fnmatch's C string contract. The selected locale owner publishes
        // musl's conversion errno on malformed input.
        let decoded = unsafe { locale_multibyte::mbtowc(&mut character, string, count) };
        if decoded < 0 {
            *step = 1;
            return -1;
        }
        *step = decoded as usize;
        return character;
    }
    *step = 1;
    unsafe { byte(string) as c_int }
}

/// `pat_next` from musl, including its literal treatment of an unterminated
/// bracket expression and invalid multibyte pattern character.
unsafe fn pat_next(
    mut pattern: *const c_char,
    count: usize,
    step: &mut usize,
    flags: c_int,
) -> c_int {
    if count == 0 || unsafe { byte(pattern) } == 0 {
        *step = 0;
        return END;
    }
    *step = 1;
    let escaped = if unsafe { byte(pattern) } == b'\\'
        && unsafe { byte(pattern.add(1)) } != 0
        && flags & FNM_NOESCAPE == 0
    {
        *step = 2;
        // Musl's escaped branch bypasses bracket/star/question classification:
        // the escaped byte is one literal pattern character.
        pattern = unsafe { pattern.add(1) };
        1usize
    } else {
        0
    };
    if escaped == 0 && unsafe { byte(pattern) } == b'[' {
        let mut cursor = 1usize;
        if cursor < count && matches!(unsafe { byte(pattern.add(cursor)) }, b'^' | b'!') {
            cursor += 1;
        }
        if cursor < count && unsafe { byte(pattern.add(cursor)) } == b']' {
            cursor += 1;
        }
        while cursor < count && unsafe { byte(pattern.add(cursor)) } != 0
            && unsafe { byte(pattern.add(cursor)) } != b']'
        {
            let next = cursor.checked_add(1);
            if next.is_some_and(|next| next < count)
                && unsafe { byte(pattern.add(next.unwrap())) } != 0
                && unsafe { byte(pattern.add(cursor)) } == b'['
                && matches!(unsafe { byte(pattern.add(next.unwrap())) }, b':' | b'.' | b'=')
            {
                let delimiter = unsafe { byte(pattern.add(next.unwrap())) };
                cursor += 2;
                if cursor < count && unsafe { byte(pattern.add(cursor)) } != 0 {
                    cursor += 1;
                }
                while cursor < count && unsafe { byte(pattern.add(cursor)) } != 0
                    && (unsafe { byte(pattern.add(cursor - 1)) } != delimiter
                        || unsafe { byte(pattern.add(cursor)) } != b']')
                {
                    cursor += 1;
                }
                if cursor == count || unsafe { byte(pattern.add(cursor)) } == 0 {
                    break;
                }
            }
            cursor += 1;
        }
        if cursor == count || unsafe { byte(pattern.add(cursor)) } == 0 {
            *step = 1;
            return b'[' as c_int;
        }
        *step = cursor + 1;
        return BRACKET;
    }
    if escaped == 0 && unsafe { byte(pattern) } == b'*' {
        return STAR;
    }
    if escaped == 0 && unsafe { byte(pattern) } == b'?' {
        return QUESTION;
    }
    if unsafe { byte(pattern) } >= 128 {
        let mut character = 0;
        // Keep musl's original `count` even after a leading escape: its C
        // string precondition makes the trailing range readable and the
        // decoder itself consumes only the first complete code point.
        let decoded = unsafe { locale_multibyte::mbtowc(&mut character, pattern, count) };
        if decoded < 0 {
            *step = 0;
            return UNMATCHABLE;
        }
        *step = decoded as usize + escaped;
        return character;
    }
    unsafe { byte(pattern) as c_int }
}

#[inline]
fn casefold(character: c_int) -> c_int {
    let upper = wide_character::towupper(character as u32) as c_int;
    if upper == character {
        wide_character::towlower(character as u32) as c_int
    } else {
        upper
    }
}

/// `match_bracket` from musl. Its caller has already confirmed a closing `]`
/// with `pat_next`, so nested POSIX class scans remain in the caller's pattern.
unsafe fn match_bracket(mut pattern: *const c_char, character: c_int, folded: c_int) -> bool {
    // SAFETY: bracket parsing begins immediately after a validated '['.
    pattern = unsafe { pattern.add(1) };
    let mut inverted = false;
    if matches!(unsafe { byte(pattern) }, b'^' | b'!') {
        inverted = true;
        pattern = unsafe { pattern.add(1) };
    }
    if unsafe { byte(pattern) } == b']' {
        if character == b']' as c_int {
            return !inverted;
        }
        pattern = unsafe { pattern.add(1) };
    } else if unsafe { byte(pattern) } == b'-' {
        if character == b'-' as c_int {
            return !inverted;
        }
        pattern = unsafe { pattern.add(1) };
    }

    // Exactly as the source, the previous expression byte seeds a possible
    // range before the loop reads its next member.
    let mut wide = unsafe { byte(pattern.sub(1)) } as c_int;
    while unsafe { byte(pattern) } != b']' {
        if unsafe { byte(pattern) } == b'-' && unsafe { byte(pattern.add(1)) } != b']' {
            let mut high = 0;
            // The source bounds a bracket range endpoint decode to four bytes.
            let decoded = unsafe { locale_multibyte::mbtowc(&mut high, pattern.add(1), 4) };
            if decoded < 0 {
                return false;
            }
            if wide <= high
                && ((character as u32).wrapping_sub(wide as u32)
                    <= (high as u32).wrapping_sub(wide as u32)
                    || (folded as u32).wrapping_sub(wide as u32)
                        <= (high as u32).wrapping_sub(wide as u32))
            {
                return !inverted;
            }
            // Source continue still reaches the enclosing for-loop increment.
            pattern = unsafe { pattern.add(decoded as usize) };
            continue;
        }
        if unsafe { byte(pattern) } == b'['
            && matches!(unsafe { byte(pattern.add(1)) }, b':' | b'.' | b'=')
        {
            let class_start = unsafe { pattern.add(2) };
            let delimiter = unsafe { byte(pattern.add(1)) };
            pattern = unsafe { pattern.add(3) };
            while unsafe { byte(pattern.sub(1)) } != delimiter || unsafe { byte(pattern) } != b']' {
                pattern = unsafe { pattern.add(1) };
            }
            let class_length = unsafe { pattern.offset_from(class_start) } as usize - 1;
            if delimiter == b':' && class_length < 16 {
                let mut name = [0u8; 16];
                // SAFETY: the validated nested class supplies `class_length`
                // bytes before its delimiter; the fixed source bound leaves a
                // terminator slot in this local buffer.
                unsafe {
                    core::ptr::copy_nonoverlapping(class_start.cast::<u8>(), name.as_mut_ptr(), class_length);
                }
                let descriptor = unsafe { wide_character::wctype(name.as_ptr().cast()) };
                if wide_character::iswctype(character as u32, descriptor) != 0
                    || wide_character::iswctype(folded as u32, descriptor) != 0
                {
                    return !inverted;
                }
            }
            // Source `continue` still runs the enclosing `for (...; p++)`
            // increment after the nested class's closing bracket.
            pattern = unsafe { pattern.add(1) };
            continue;
        }
        if unsafe { byte(pattern) } < 128 {
            wide = unsafe { byte(pattern) } as c_int;
        } else {
            let decoded = unsafe { locale_multibyte::mbtowc(&mut wide, pattern, 4) };
            if decoded < 0 {
                return false;
            }
            pattern = unsafe { pattern.add(decoded as usize - 1) };
        }
        if wide == character || wide == folded {
            return !inverted;
        }
        pattern = unsafe { pattern.add(1) };
    }
    inverted
}

#[inline]
unsafe fn strnlen(mut string: *const c_char, mut maximum: usize) -> usize {
    let mut length = 0usize;
    while maximum != 0 && unsafe { byte(string) } != 0 {
        string = unsafe { string.add(1) };
        maximum -= 1;
        length += 1;
    }
    length
}

/// The `fnmatch_internal` Sea-of-Stars algorithm from musl.
pub(super) unsafe fn fnmatch_internal(
    mut pattern: *const c_char,
    mut pattern_count: usize,
    mut string: *const c_char,
    mut string_count: usize,
    flags: c_int,
) -> c_int {
    let mut pattern_step = 0usize;
    let mut string_step = 0usize;
    let mut tail_count = 0usize;

    if flags & FNM_PERIOD != 0
        && unsafe { byte(string) } == b'.'
        && unsafe { byte(pattern) } != b'.'
    {
        return FNM_NOMATCH;
    }

    loop {
        let token = unsafe { pat_next(pattern, pattern_count, &mut pattern_step, flags) };
        match token {
            UNMATCHABLE => return FNM_NOMATCH,
            STAR => {
                pattern = unsafe { pattern.add(1) };
                pattern_count -= 1;
                break;
            }
            _ => {
                let character = unsafe { str_next(string, string_count, &mut string_step) };
                if character <= 0 {
                    return if token == END { 0 } else { FNM_NOMATCH };
                }
                string = unsafe { string.add(string_step) };
                string_count -= string_step;
                let folded = if flags & FNM_CASEFOLD != 0 { casefold(character) } else { character };
                if token == BRACKET {
                    if !unsafe { match_bracket(pattern, character, folded) } {
                        return FNM_NOMATCH;
                    }
                } else if token != QUESTION && character != token && folded != token {
                    return FNM_NOMATCH;
                }
                pattern = unsafe { pattern.add(pattern_step) };
                pattern_count -= pattern_step;
            }
        }
    }

    pattern_count = unsafe { strnlen(pattern, pattern_count) };
    let end_pattern = unsafe { pattern.add(pattern_count) };
    let mut cursor = pattern;
    let mut pattern_tail = pattern;
    while cursor != end_pattern {
        let remaining = unsafe { end_pattern.offset_from(cursor) } as usize;
        match unsafe { pat_next(cursor, remaining, &mut pattern_step, flags) } {
            UNMATCHABLE => return FNM_NOMATCH,
            STAR => {
                tail_count = 0;
                pattern_tail = unsafe { cursor.add(1) };
            }
            _ => tail_count += 1,
        }
        cursor = unsafe { cursor.add(pattern_step) };
    }

    string_count = unsafe { strnlen(string, string_count) };
    let mut end_string = unsafe { string.add(string_count) };
    if string_count < tail_count {
        return FNM_NOMATCH;
    }
    let mut string_tail = end_string;
    while string_tail != string && tail_count != 0 {
        tail_count -= 1;
        if unsafe { byte(string_tail.sub(1)) } < 128 || !locale_multibyte::locale_ctype_is_utf8() {
            string_tail = unsafe { string_tail.sub(1) };
        } else {
            loop {
                string_tail = unsafe { string_tail.sub(1) };
                if !(unsafe { byte(string_tail) }.wrapping_sub(0x80) < 0x40 && string_tail != string) {
                    break;
                }
            }
        }
    }
    if tail_count != 0 {
        return FNM_NOMATCH;
    }

    cursor = pattern_tail;
    let mut string_cursor = string_tail;
    loop {
        let remaining = unsafe { end_pattern.offset_from(cursor) } as usize;
        let token = unsafe { pat_next(cursor, remaining, &mut pattern_step, flags) };
        cursor = unsafe { cursor.add(pattern_step) };
        let character = unsafe {
            str_next(string_cursor, end_string.offset_from(string_cursor) as usize, &mut string_step)
        };
        if character <= 0 {
            if token != END {
                return FNM_NOMATCH;
            }
            break;
        }
        string_cursor = unsafe { string_cursor.add(string_step) };
        let folded = if flags & FNM_CASEFOLD != 0 { casefold(character) } else { character };
        if token == BRACKET {
            if !unsafe { match_bracket(cursor.sub(pattern_step), character, folded) } {
                return FNM_NOMATCH;
            }
        } else if token != QUESTION && character != token && folded != token {
            return FNM_NOMATCH;
        }
    }

    end_string = string_tail;
    let end_pattern = pattern_tail;
    while pattern != end_pattern {
        let mut component = pattern;
        let mut search = string;
        let mut token = END;
        loop {
            token = unsafe {
                pat_next(
                    component,
                    end_pattern.offset_from(component) as usize,
                    &mut pattern_step,
                    flags,
                )
            };
            component = unsafe { component.add(pattern_step) };
            if token == STAR {
                pattern = component;
                string = search;
                break;
            }
            let character = unsafe { str_next(search, end_string.offset_from(search) as usize, &mut string_step) };
            if character == 0 {
                return FNM_NOMATCH;
            }
            let folded = if flags & FNM_CASEFOLD != 0 { casefold(character) } else { character };
            let matched = if token == BRACKET {
                unsafe { match_bracket(component.sub(pattern_step), character, folded) }
            } else {
                token == QUESTION || character == token || folded == token
            };
            if !matched {
                break;
            }
            search = unsafe { search.add(string_step) };
        }
        if token == STAR {
            continue;
        }
        let character = unsafe { str_next(string, end_string.offset_from(string) as usize, &mut string_step) };
        if character > 0 {
            string = unsafe { string.add(string_step) };
        } else if character < 0 {
            // Musl skips the complete run of malformed bytes after advancing
            // once. A zero decode has no remaining candidate character, so
            // the incomplete component cannot match.
            string = unsafe { string.add(1) };
            while unsafe { str_next(string, end_string.offset_from(string) as usize, &mut string_step) } < 0 {
                string = unsafe { string.add(1) };
            }
        } else {
            return FNM_NOMATCH;
        }
    }
    0
}

/// Public C `fnmatch` with musl's pathname component routing.
///
/// # Safety
///
/// `pattern` and `string` must each designate a readable NUL-terminated C
/// string for the entire call, as required by the C ABI.
#[no_mangle]
pub unsafe extern "C" fn fnmatch(
    mut pattern: *const c_char,
    mut string: *const c_char,
    flags: c_int,
) -> c_int {
    if flags & FNM_PATHNAME != 0 {
        loop {
            let mut string_separator = string;
            while unsafe { byte(string_separator) } != 0 && unsafe { byte(string_separator) } != b'/' {
                string_separator = unsafe { string_separator.add(1) };
            }
            let mut pattern_separator = pattern;
            let mut pattern_step = 0usize;
            let separator = loop {
                let separator = unsafe {
                    pat_next(pattern_separator, usize::MAX, &mut pattern_step, flags)
                };
                if separator == END || separator == b'/' as c_int {
                    break separator;
                }
                pattern_separator = unsafe { pattern_separator.add(pattern_step) };
            };
            if separator != unsafe { byte(string_separator) as c_int }
                && (unsafe { byte(string_separator) } == 0 || flags & FNM_LEADING_DIR == 0)
            {
                return FNM_NOMATCH;
            }
            if unsafe {
                fnmatch_internal(
                    pattern,
                    pattern_separator.offset_from(pattern) as usize,
                    string,
                    string_separator.offset_from(string) as usize,
                    flags,
                )
            } != 0
            {
                return FNM_NOMATCH;
            }
            if separator == END {
                return 0;
            }
            string = unsafe { string_separator.add(1) };
            pattern = unsafe { pattern_separator.add(pattern_step) };
        }
    }
    if flags & FNM_LEADING_DIR != 0 {
        let mut separator = string;
        while unsafe { byte(separator) } != 0 {
            if unsafe { byte(separator) } == b'/'
                && unsafe {
                    fnmatch_internal(
                        pattern,
                        usize::MAX,
                        string,
                        separator.offset_from(string) as usize,
                        flags,
                    )
                } == 0
            {
                return 0;
            }
            separator = unsafe { separator.add(1) };
        }
    }
    unsafe { fnmatch_internal(pattern, usize::MAX, string, usize::MAX, flags) }
}
