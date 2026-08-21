//! Stateless byte-oriented filename pattern matching.
//!
//! This is the implementation seam for the native Rust facade and the C
//! `fnmatch` adapter. Inputs are borrowed NUL-free byte slices because the C
//! boundary is responsible for converting its NUL-terminated strings first.
//! No allocation, process-global state, locale state, or C ABI call is needed.

/// A `*` may match `/` when this flag is absent.
pub const FNM_PATHNAME: u32 = 0x1;
/// A backslash is an ordinary pattern byte when this flag is present.
pub const FNM_NOESCAPE: u32 = 0x2;
/// A wildcard may not match a leading `.` in a component.
pub const FNM_PERIOD: u32 = 0x4;
/// A pattern may match a directory prefix ending immediately before `/`.
pub const FNM_LEADING_DIR: u32 = 0x8;
/// ASCII case-insensitive matching.
pub const FNM_CASEFOLD: u32 = 0x10;

#[derive(Clone, Copy)]
enum Token {
    End,
    Star { next: usize },
    Question { next: usize },
    Bracket { next: usize },
    Literal { byte: u8, next: usize },
}

#[inline]
fn ascii_casefold(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte.to_ascii_lowercase()
    }
}

#[inline]
fn casefold_enabled(flags: u32) -> bool {
    flags & FNM_CASEFOLD != 0
}

#[inline]
fn bytes_equal(pattern: u8, candidate: u8, flags: u32) -> bool {
    pattern == candidate
        || (casefold_enabled(flags) && ascii_casefold(pattern) == ascii_casefold(candidate))
}

/// Finds the end (exclusive) of a complete bracket expression.
///
/// POSIX character classes, collating elements, and equivalence classes all
/// contain a nested delimiter pair such as `[:alpha:]`; those delimiters do
/// not terminate the outer expression.
fn bracket_end(pattern: &[u8], start: usize) -> Option<usize> {
    let mut cursor = start + 1;
    if cursor < pattern.len() && (pattern[cursor] == b'^' || pattern[cursor] == b'!') {
        cursor += 1;
    }
    if cursor < pattern.len() && pattern[cursor] == b']' {
        cursor += 1;
    }

    while cursor < pattern.len() {
        if pattern[cursor] == b']' {
            return Some(cursor + 1);
        }
        if pattern[cursor] == b'['
            && cursor + 1 < pattern.len()
            && matches!(pattern[cursor + 1], b':' | b'.' | b'=')
        {
            let delimiter = pattern[cursor + 1];
            cursor += 2;
            while cursor + 1 < pattern.len() {
                if pattern[cursor] == delimiter && pattern[cursor + 1] == b']' {
                    cursor += 2;
                    break;
                }
                cursor += 1;
            }
            continue;
        }
        cursor += 1;
    }
    None
}

fn next_token(pattern: &[u8], index: usize, flags: u32) -> Token {
    if index >= pattern.len() {
        return Token::End;
    }
    let byte = pattern[index];

    if byte == b'\\' && flags & FNM_NOESCAPE == 0 && index + 1 < pattern.len() {
        return Token::Literal {
            byte: pattern[index + 1],
            next: index + 2,
        };
    }
    if byte == b'[' {
        if let Some(next) = bracket_end(pattern, index) {
            return Token::Bracket { next };
        }
    }
    match byte {
        b'*' => Token::Star { next: index + 1 },
        b'?' => Token::Question { next: index + 1 },
        byte => Token::Literal {
            byte,
            next: index + 1,
        },
    }
}

fn class_matches(class: &[u8], candidate: u8, folded: u8) -> bool {
    let equal = |byte| candidate == byte || folded == byte;
    let in_range = |low, high| {
        (candidate >= low && candidate <= high) || (folded >= low && folded <= high)
    };
    match class {
        b"alnum" => in_range(b'0', b'9') || in_range(b'A', b'Z') || in_range(b'a', b'z'),
        b"alpha" => in_range(b'A', b'Z') || in_range(b'a', b'z'),
        b"blank" => equal(b' ') || equal(b'\t'),
        b"cntrl" => candidate < 0x20 || candidate == 0x7f,
        b"digit" => in_range(b'0', b'9'),
        b"graph" => candidate >= 0x21 && candidate <= 0x7e,
        b"lower" => in_range(b'a', b'z'),
        b"print" => candidate >= 0x20 && candidate <= 0x7e,
        b"punct" => {
            (candidate >= 0x21 && candidate <= 0x2f)
                || (candidate >= 0x3a && candidate <= 0x40)
                || (candidate >= 0x5b && candidate <= 0x60)
                || (candidate >= 0x7b && candidate <= 0x7e)
        }
        b"space" => {
            equal(b' ')
                || equal(b'\t')
                || equal(b'\n')
                || equal(b'\r')
                || equal(0x0c)
                || equal(0x0b)
        }
        b"upper" => in_range(b'A', b'Z'),
        b"xdigit" => {
            in_range(b'0', b'9') || in_range(b'A', b'F') || in_range(b'a', b'f')
        }
        _ => false,
    }
}

fn bracket_matches(
    pattern: &[u8],
    start: usize,
    next: usize,
    candidate: u8,
    folded: u8,
    flags: u32,
) -> bool {
    let mut cursor = start + 1;
    let end = next - 1;
    let mut inverted = false;
    if cursor < end && (pattern[cursor] == b'^' || pattern[cursor] == b'!') {
        inverted = true;
        cursor += 1;
    }

    // `]` and `-` are ordinary members when they appear first.
    if cursor < end && pattern[cursor] == b']' {
        if candidate == b']' {
            return !inverted;
        }
        cursor += 1;
    } else if cursor < end && pattern[cursor] == b'-' {
        if candidate == b'-' {
            return !inverted;
        }
        cursor += 1;
    }

    while cursor < end {
        if pattern[cursor] == b'-' && cursor + 1 < end && pattern[cursor + 1] != b']' {
            let low = pattern[cursor - 1];
            let high = pattern[cursor + 1];
            if low <= high
                && ((candidate >= low && candidate <= high)
                    || (folded >= low && folded <= high))
            {
                return !inverted;
            }
            cursor += 2;
            continue;
        }

        if pattern[cursor] == b'['
            && cursor + 1 < end
            && matches!(pattern[cursor + 1], b':' | b'.' | b'=')
        {
            let delimiter = pattern[cursor + 1];
            let class_start = cursor + 2;
            let mut close = class_start;
            while close + 1 < end
                && !(pattern[close] == delimiter && pattern[close + 1] == b']')
            {
                close += 1;
            }
            if close + 1 < end {
                let class = &pattern[class_start..close];
                let matched = if delimiter == b':' {
                    class_matches(class, candidate, folded)
                } else {
                    class.len() == 1 && bytes_equal(class[0], candidate, flags)
                };
                if matched {
                    return !inverted;
                }
                cursor = close + 2;
                continue;
            }
        }

        if bytes_equal(pattern[cursor], candidate, flags) {
            return !inverted;
        }
        cursor += 1;
    }
    inverted
}

fn token_matches(
    pattern: &[u8],
    token: Token,
    token_start: usize,
    candidate: u8,
    flags: u32,
) -> bool {
    match token {
        Token::Question { .. } => true,
        Token::Bracket { next } => {
            let folded = if casefold_enabled(flags) {
                ascii_casefold(candidate)
            } else {
                candidate
            };
            bracket_matches(pattern, token_start, next, candidate, folded, flags)
        }
        Token::Literal { byte, .. } => bytes_equal(byte, candidate, flags),
        Token::End | Token::Star { .. } => false,
    }
}

/// Matches a pattern against one component (a slice containing no `/`).
fn component_matches(pattern: &[u8], candidate: &[u8], flags: u32) -> bool {
    if flags & FNM_PERIOD != 0
        && candidate.first() == Some(&b'.')
        && pattern.first() != Some(&b'.')
    {
        return false;
    }

    let pathname = flags & FNM_PATHNAME != 0;
    let mut pattern_index = 0;
    let mut candidate_index = 0;
    let mut star_pattern = None;
    let mut star_candidate = 0;

    loop {
        if pattern_index >= pattern.len() {
            if candidate_index >= candidate.len() {
                return true;
            }
        } else {
            let token_start = pattern_index;
            let token = next_token(pattern, pattern_index, flags);
            match token {
                Token::End => {
                    if candidate_index >= candidate.len() {
                        return true;
                    }
                }
                Token::Star { next } => {
                    star_pattern = Some(next);
                    star_candidate = candidate_index;
                    pattern_index = next;
                    continue;
                }
                _ if candidate_index < candidate.len()
                    && (!pathname || candidate[candidate_index] != b'/')
                    && token_matches(
                        pattern,
                        token,
                        token_start,
                        candidate[candidate_index],
                        flags,
                    ) =>
                {
                    pattern_index = token.next_index();
                    candidate_index += 1;
                    continue;
                }
                _ => {}
            }
        }

        // Backtrack the most recent star by one candidate byte. This is the
        // same bounded, allocation-free strategy used by musl's matcher; the
        // pathname check keeps a star from consuming `/`.
        if let Some(next_pattern) = star_pattern {
            if star_candidate < candidate.len()
                && (!pathname || candidate[star_candidate] != b'/')
            {
                star_candidate += 1;
                candidate_index = star_candidate;
                pattern_index = next_pattern;
                continue;
            }
        }
        return false;
    }
}

impl Token {
    #[inline]
    fn next_index(self) -> usize {
        match self {
            Self::End => 0,
            Self::Star { next }
            | Self::Question { next }
            | Self::Bracket { next }
            | Self::Literal { next, .. } => next,
        }
    }
}

/// Finds the next path separator in a pattern without mistaking a slash in a
/// bracket expression for a pathname boundary. An escaped slash is a
/// separator too, matching the C adapter's token-level split.
fn pattern_component_end(pattern: &[u8], start: usize, flags: u32) -> (usize, usize, bool) {
    let mut cursor = start;
    loop {
        let token = next_token(pattern, cursor, flags);
        match token {
            Token::End => return (pattern.len(), pattern.len(), false),
            Token::Literal { byte: b'/', next } => return (cursor, next, true),
            _ => cursor = token.next_index(),
        }
    }
}

/// Matches a NUL-free byte pattern with musl-compatible `fnmatch` semantics.
///
/// The input contract is intentionally a pair of borrowed slices rather than
/// Rust strings: Unix names are byte sequences and may not be UTF-8. Callers
/// crossing the C ABI should use `CStr::to_bytes()` to preserve the C string's
/// no-interior-NUL boundary.
#[must_use]
pub fn fnmatch(pattern: &[u8], candidate: &[u8], flags: u32) -> bool {
    if flags & FNM_PATHNAME != 0 {
        let mut pattern_start = 0;
        let mut candidate_start = 0;
        let component_flags = flags & !FNM_LEADING_DIR;

        loop {
            let (pattern_end, pattern_next, pattern_has_slash) =
                pattern_component_end(pattern, pattern_start, flags);
            let candidate_end = candidate[candidate_start..]
                .iter()
                .position(|&byte| byte == b'/')
                .map_or(candidate.len(), |offset| candidate_start + offset);
            let candidate_has_slash = candidate_end < candidate.len();

            if pattern_has_slash != candidate_has_slash
                && candidate_has_slash
                && flags & FNM_LEADING_DIR == 0
            {
                return false;
            }
            if !component_matches(
                &pattern[pattern_start..pattern_end],
                &candidate[candidate_start..candidate_end],
                component_flags,
            ) {
                return false;
            }
            if !pattern_has_slash {
                return true;
            }
            if !candidate_has_slash {
                return false;
            }
            pattern_start = pattern_next;
            candidate_start = candidate_end + 1;
        }
    }

    if flags & FNM_LEADING_DIR != 0 {
        for (index, &byte) in candidate.iter().enumerate() {
            if byte == b'/' && component_matches(pattern, &candidate[..index], flags) {
                return true;
            }
        }
    }
    component_matches(pattern, candidate, flags)
}
