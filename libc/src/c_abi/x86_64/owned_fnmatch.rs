//! Source-faithful musl 1.2.6 `src/regex/fnmatch.c` matcher.
//!
//! The separately selected Rust facade's byte matcher is intentionally not
//! used here.  C `fnmatch` observes the active CTYPE through `mbtowc`, wide
//! case mapping, and wide bracket classes, including musl's invalid-UTF-8
//! progression rules.  The C entry's pointer obligations remain those of
//! `fnmatch(3)`: both arguments are readable NUL-terminated strings for the
//! complete call.

use core::ffi::{c_char, c_int};

use super::{ShellPattern, ShellPatternView};
use super::super::{locale_multibyte, wide_character};

pub(super) const END: c_int = 0;
pub(super) const UNMATCHABLE: c_int = -2;
pub(super) const BRACKET: c_int = -3;
pub(super) const QUESTION: c_int = -4;
pub(super) const STAR: c_int = -5;

const FNM_PATHNAME: c_int = 0x1;
const FNM_NOESCAPE: c_int = 0x2;
const FNM_PERIOD: c_int = 0x4;
const FNM_LEADING_DIR: c_int = 0x8;
const FNM_CASEFOLD: c_int = 0x10;
const FNM_NOMATCH: c_int = 1;

/// One interpretation of a pattern byte span. The shell map is rebased only
/// when glob duplicates its source bytes; temporary separator NUL writes keep
/// their original mask index.
#[derive(Clone, Copy)]
pub(super) enum PatternMode<'pattern> {
    C,
    Shell(ShellPatternView<'pattern>),
}

impl<'pattern> PatternMode<'pattern> {
    #[inline]
    pub(super) const fn c() -> Self {
        Self::C
    }

    #[inline]
    pub(super) fn protected_at(self, pointer: *const c_char) -> bool {
        match self {
            Self::C => false,
            Self::Shell(view) => view.protected_at(pointer),
        }
    }

    #[inline]
    pub(super) fn is_shell(self) -> bool {
        matches!(self, Self::Shell(_))
    }
}

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
unsafe fn pat_next_c(
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
unsafe fn shell_structural(mode: PatternMode<'_>, pointer: *const c_char, expected: u8) -> bool {
    (unsafe { byte(pointer) }) == expected && !mode.protected_at(pointer)
}

/// Locate the closing bracket for one nested `[.x.]`, `[=x=]`, or
/// `[:class:]` construct. The bracket detector and matcher share this exact
/// walk so protection cannot make their structural views disagree.
unsafe fn shell_nested_end(
    pattern: *const c_char,
    count: usize,
    opening: usize,
    mode: PatternMode<'_>,
) -> Option<usize> {
    let delimiter_index = opening.checked_add(1)?;
    let delimiter = unsafe { byte(pattern.add(delimiter_index)) };
    let mut cursor = opening.checked_add(2)?;
    while cursor < count && unsafe { byte(pattern.add(cursor)) } != 0 {
        if cursor != 0
            && unsafe { shell_structural(mode, pattern.add(cursor - 1), delimiter) }
            && unsafe { shell_structural(mode, pattern.add(cursor), b']') }
        {
            return Some(cursor);
        }
        cursor = cursor.checked_add(1)?;
    }
    None
}

/// Discover an outer shell bracket with the quote-aware structural grammar.
/// A protected `]` remains a member; a protected `:`/`.`/`=` cannot form a
/// nested delimiter; ordinary protected class-name bytes remain ordinary.
unsafe fn shell_bracket_end(
    pattern: *const c_char,
    count: usize,
    mode: PatternMode<'_>,
) -> Option<usize> {
    let mut cursor = 1usize;
    if cursor < count
        && (unsafe { shell_structural(mode, pattern.add(cursor), b'^') }
            || unsafe { shell_structural(mode, pattern.add(cursor), b'!') })
    {
        cursor += 1;
    }
    if cursor < count && unsafe { shell_structural(mode, pattern.add(cursor), b']') } {
        cursor += 1;
    }
    while cursor < count && unsafe { byte(pattern.add(cursor)) } != 0 {
        if unsafe { shell_structural(mode, pattern.add(cursor), b']') } {
            return Some(cursor);
        }
        let next = cursor.checked_add(1);
        if unsafe { shell_structural(mode, pattern.add(cursor), b'[') }
            && next.is_some_and(|next| {
                next < count
                    && matches!(unsafe { byte(pattern.add(next)) }, b':' | b'.' | b'=')
                    && !mode.protected_at(unsafe { pattern.add(next) })
            })
        {
            let nested_end = unsafe { shell_nested_end(pattern, count, cursor, mode) }?;
            cursor = nested_end.checked_add(1)?;
            continue;
        }
        cursor = cursor.checked_add(1)?;
    }
    None
}

/// Quote-aware private `pat_next`. A raw expansion-derived backslash escapes
/// the next byte outside brackets; a protected backslash is itself literal.
unsafe fn pat_next_shell(
    mut pattern: *const c_char,
    count: usize,
    step: &mut usize,
    flags: c_int,
    mode: PatternMode<'_>,
) -> c_int {
    if count == 0 || unsafe { byte(pattern) } == 0 {
        *step = 0;
        return END;
    }
    *step = 1;
    let escaped = if count > 1
        && unsafe { byte(pattern) } == b'\\'
        && !mode.protected_at(pattern)
        && unsafe { byte(pattern.add(1)) } != 0
        && flags & FNM_NOESCAPE == 0
    {
        *step = 2;
        pattern = unsafe { pattern.add(1) };
        1usize
    } else {
        0
    };
    if escaped == 0 && unsafe { shell_structural(mode, pattern, b'[') } {
        if let Some(closing) = unsafe { shell_bracket_end(pattern, count, mode) } {
            *step = closing + 1;
            return BRACKET;
        }
    }
    if escaped == 0 && unsafe { shell_structural(mode, pattern, b'*') } {
        return STAR;
    }
    if escaped == 0 && unsafe { shell_structural(mode, pattern, b'?') } {
        return QUESTION;
    }
    if unsafe { byte(pattern) } >= 128 {
        let mut character = 0;
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

pub(super) unsafe fn pat_next(
    pattern: *const c_char,
    count: usize,
    step: &mut usize,
    flags: c_int,
    mode: PatternMode<'_>,
) -> c_int {
    match mode {
        PatternMode::C => unsafe { pat_next_c(pattern, count, step, flags) },
        PatternMode::Shell(_) => unsafe { pat_next_shell(pattern, count, step, flags, mode) },
    }
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
unsafe fn match_bracket_c(mut pattern: *const c_char, character: c_int, folded: c_int) -> bool {
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

/// Quote-aware shell bracket matching. This shares `shell_bracket_end` and
/// `shell_nested_end` with `pat_next_shell`, so a protected structural byte
/// cannot alter the discovery/matching boundary halfway through a pattern.
unsafe fn match_bracket_shell(
    pattern: *const c_char,
    count: usize,
    character: c_int,
    folded: c_int,
    mode: PatternMode<'_>,
) -> bool {
    let Some(closing) = (unsafe { shell_bracket_end(pattern, count, mode) }) else {
        return false;
    };
    let mut cursor = 1usize;
    let mut inverted = false;
    if cursor < closing
        && (unsafe { shell_structural(mode, pattern.add(cursor), b'^') }
            || unsafe { shell_structural(mode, pattern.add(cursor), b'!') })
    {
        inverted = true;
        cursor += 1;
    }
    if cursor < closing && unsafe { shell_structural(mode, pattern.add(cursor), b']') } {
        if character == b']' as c_int {
            return !inverted;
        }
        cursor += 1;
    } else if cursor < closing && unsafe { shell_structural(mode, pattern.add(cursor), b'-') } {
        if character == b'-' as c_int {
            return !inverted;
        }
        cursor += 1;
    }

    // Keep musl's prior-expression range seed. A protected dash follows the
    // ordinary literal path below and therefore cannot introduce a range.
    let mut wide = unsafe { byte(pattern.add(cursor.saturating_sub(1))) } as c_int;
    while cursor < closing {
        let current = unsafe { pattern.add(cursor) };
        if unsafe { shell_structural(mode, current, b'-') } && cursor + 1 < closing {
            let mut high = 0;
            let decoded = unsafe { locale_multibyte::mbtowc(&mut high, current.add(1), 4) };
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
            let Some(next) = cursor.checked_add(decoded as usize + 1) else {
                return false;
            };
            cursor = next;
            continue;
        }

        let delimiter_index = cursor.checked_add(1);
        if unsafe { shell_structural(mode, current, b'[') }
            && delimiter_index.is_some_and(|index| {
                index < closing
                    && matches!(unsafe { byte(pattern.add(index)) }, b':' | b'.' | b'=')
                    && !mode.protected_at(unsafe { pattern.add(index) })
            })
        {
            let delimiter = unsafe { byte(pattern.add(delimiter_index.unwrap())) };
            let Some(nested_close) = (unsafe { shell_nested_end(pattern, closing, cursor, mode) }) else {
                return false;
            };
            let class_start = cursor + 2;
            let class_length = nested_close.saturating_sub(class_start + 1);
            if delimiter == b':' && class_length < 16 {
                let mut name = [0u8; 16];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        pattern.add(class_start).cast::<u8>(),
                        name.as_mut_ptr(),
                        class_length,
                    );
                }
                let descriptor = unsafe { wide_character::wctype(name.as_ptr().cast()) };
                if wide_character::iswctype(character as u32, descriptor) != 0
                    || wide_character::iswctype(folded as u32, descriptor) != 0
                {
                    return !inverted;
                }
            }
            cursor = nested_close + 1;
            continue;
        }

        if unsafe { byte(current) } < 128 {
            wide = unsafe { byte(current) } as c_int;
            cursor += 1;
        } else {
            let decoded = unsafe { locale_multibyte::mbtowc(&mut wide, current, 4) };
            if decoded < 0 {
                return false;
            }
            let Some(next) = cursor.checked_add(decoded as usize) else {
                return false;
            };
            cursor = next;
        }
        if wide == character || wide == folded {
            return !inverted;
        }
    }
    inverted
}

unsafe fn match_bracket(
    pattern: *const c_char,
    count: usize,
    character: c_int,
    folded: c_int,
    mode: PatternMode<'_>,
) -> bool {
    match mode {
        PatternMode::C => unsafe { match_bracket_c(pattern, character, folded) },
        PatternMode::Shell(_) => unsafe { match_bracket_shell(pattern, count, character, folded, mode) },
    }
}

/// Shell pathname expansion checks a leading period against the first logical
/// pattern unit. A raw expansion-derived `\\.` is therefore a literal period,
/// while `[.]` remains a bracket expression and retains musl's period rule.
unsafe fn shell_starts_with_literal_period(
    pattern: *const c_char,
    pattern_count: usize,
    flags: c_int,
    mode: PatternMode<'_>,
) -> bool {
    let mut step = 0usize;
    unsafe { pat_next(pattern, pattern_count, &mut step, flags, mode) == b'.' as c_int }
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
    mode: PatternMode<'_>,
) -> c_int {
    let mut pattern_step = 0usize;
    let mut string_step = 0usize;
    let mut tail_count = 0usize;

    // Keep C mode's direct source-byte test. The bounded shell entry has no
    // text terminator beyond `string_count`, and its quote map turns a raw
    // expansion-derived `\\.` into the first logical literal unit.
    let string_starts_with_period = if mode.is_shell() {
        string_count != 0 && unsafe { byte(string) } == b'.'
    } else {
        (unsafe { byte(string) }) == b'.'
    };
    let pattern_starts_with_period = match mode {
        PatternMode::C => (unsafe { byte(pattern) }) == b'.',
        PatternMode::Shell(_) => unsafe {
            shell_starts_with_literal_period(pattern, pattern_count, flags, mode)
        },
    };
    if flags & FNM_PERIOD != 0 && string_starts_with_period && !pattern_starts_with_period {
        return FNM_NOMATCH;
    }

    loop {
        let token = unsafe { pat_next(pattern, pattern_count, &mut pattern_step, flags, mode) };
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
                    if !unsafe { match_bracket(pattern, pattern_count, character, folded, mode) } {
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
        match unsafe { pat_next(cursor, remaining, &mut pattern_step, flags, mode) } {
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
        let token_start = cursor;
        let token = unsafe { pat_next(cursor, remaining, &mut pattern_step, flags, mode) };
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
            if !unsafe { match_bracket(token_start, remaining, character, folded, mode) } {
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
            let component_remaining = unsafe { end_pattern.offset_from(component) } as usize;
            let token_start = component;
            token = unsafe {
                pat_next(
                    component,
                    component_remaining,
                    &mut pattern_step,
                    flags,
                    mode,
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
                unsafe { match_bracket(token_start, component_remaining, character, folded, mode) }
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

/// Internal C-string matcher with the source pathname routing retained for
/// both grammar modes. Public C calls always pass `PatternMode::C`.
pub(super) unsafe fn fnmatch_with_mode(
    mut pattern: *const c_char,
    mut string: *const c_char,
    flags: c_int,
    mode: PatternMode<'_>,
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
                    pat_next(pattern_separator, usize::MAX, &mut pattern_step, flags, mode)
                };
                if separator == END || separator == b'/' as c_int {
                    break separator;
                }
                // Intentional difference: `pat_next` reports an invalid
                // multibyte character as UNMATCHABLE with a zero step, so
                // fnmatch.c's scan (`p+=inc`) never advances or returns.
                // fnmatch_internal rejects any component containing it, so
                // FNM_NOMATCH is the only answer the source can reach.
                if separator == UNMATCHABLE {
                    return FNM_NOMATCH;
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
                    mode,
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
                        mode,
                    )
                } == 0
            {
                return 0;
            }
            separator = unsafe { separator.add(1) };
        }
    }
    unsafe { fnmatch_internal(pattern, usize::MAX, string, usize::MAX, flags, mode) }
}

/// Test the private shell grammar for a true glob token. Invalid multibyte
/// bytes advance one byte here so a later active token remains visible without
/// introducing a second parser/traversal.
pub(super) fn shell_has_active_pattern(pattern: ShellPattern<'_>) -> bool {
    let mut offset = 0usize;
    while offset + 1 < pattern.byte_len() {
        let mut step = 0usize;
        let remaining = pattern.byte_len() - offset;
        let token = unsafe {
            pat_next(
                pattern.pointer().add(offset),
                remaining,
                &mut step,
                0,
                pattern.mode(),
            )
        };
        if matches!(token, STAR | QUESTION | BRACKET) {
            return true;
        }
        let advance = if step == 0 { 1 } else { step };
        let Some(next) = offset.checked_add(advance) else {
            return false;
        };
        if next > pattern.byte_len() {
            return false;
        }
        offset = next;
    }
    false
}

/// Match an exact bounded wordexp value without allocating or reading a text
/// terminator beyond the supplied slice. Word values cannot carry interior
/// NUL, so reject one rather than accepting a prefix.
pub(super) fn shell_matches(pattern: ShellPattern<'_>, string: &[u8]) -> bool {
    if string.iter().any(|byte| *byte == 0) {
        return false;
    }
    unsafe {
        fnmatch_internal(
            pattern.pointer(),
            pattern.byte_len(),
            string.as_ptr().cast(),
            string.len(),
            0,
            pattern.mode(),
        ) == 0
    }
}

// Musl's `src/regex/fnmatch.c` object.
static_archive_member! { fnmatch_source {
    /// Public C `fnmatch` with musl's pathname component routing.
    ///
    /// # Safety
    ///
    /// `pattern` and `string` must each designate a readable NUL-terminated C
    /// string for the entire call, as required by the C ABI.
    #[no_mangle]
    pub unsafe extern "C" fn fnmatch(
        pattern: *const c_char,
        string: *const c_char,
        flags: c_int,
    ) -> c_int {
        unsafe { fnmatch_with_mode(pattern, string, flags, PatternMode::c()) }
    }
}}
