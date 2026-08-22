//! Pure byte-string algorithms shared by the native Rust facade.
//!
//! These helpers deliberately stop at the typed `CStr`/byte-slice boundary.
//! They do not allocate, call libc, consult locale state, or communicate
//! through `errno`.  The algorithms follow the Linux/AArch64 musl C locale
//! semantics used by the corresponding compatibility symbols.

use core::cmp::Ordering;
use core::ffi::CStr;

/// Returns the bytes before the terminating NUL in `value`.
#[inline]
pub fn cstr_bytes(value: &CStr) -> &[u8] {
    value.to_bytes()
}

/// Folds one byte using the fixed ASCII C-locale case rule.
#[inline]
pub const fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

/// Compares two byte strings using ASCII case-insensitive comparison.
#[inline]
pub fn ascii_case_insensitive_cmp(left: &[u8], right: &[u8]) -> Ordering {
    let mut index = 0;
    while index < left.len() && index < right.len() {
        let left_byte = ascii_lower(left[index]);
        let right_byte = ascii_lower(right[index]);
        match left_byte.cmp(&right_byte) {
            Ordering::Equal => index += 1,
            ordering => return ordering,
        }
    }
    left.len().cmp(&right.len())
}

/// Returns whether two byte strings compare equal under ASCII case folding.
#[inline]
pub fn ascii_case_insensitive_eq(left: &[u8], right: &[u8]) -> bool {
    ascii_case_insensitive_cmp(left, right) == Ordering::Equal
}

/// Finds the first ASCII-case-insensitive occurrence of `needle`.
///
/// An empty needle is found at offset zero, matching `strcasestr` and the
/// ordinary substring-search convention.
#[inline]
pub fn ascii_case_insensitive_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    for start in 0..=haystack.len() - needle.len() {
        if ascii_case_insensitive_eq(&haystack[start..start + needle.len()], needle) {
            return Some(start);
        }
    }
    None
}

#[inline]
const fn is_ascii_digit(byte: u8) -> bool {
    byte >= b'0' && byte <= b'9'
}

/// Compares two NUL-free version byte strings with musl's `strverscmp` rule.
///
/// A version's maximal common prefix is tracked for its final digit run. For
/// non-zero digit runs, a longer run sorts after a shorter run; a common
/// all-zero run sorts before a following non-digit. This is intentionally the
/// exact musl algorithm rather than a generic numeric parser: punctuation and
/// bytes above ASCII remain ordinary bytes.
#[inline]
pub fn version_cmp(left: &[u8], right: &[u8]) -> Ordering {
    let mut index = 0;
    let mut digit_prefix = 0;
    let mut all_zero = true;

    while index < left.len() && index < right.len() && left[index] == right[index] {
        let byte = left[index];
        if !is_ascii_digit(byte) {
            digit_prefix = index + 1;
            all_zero = true;
        } else if byte != b'0' {
            all_zero = false;
        }
        index += 1;
    }

    if index == left.len() && index == right.len() {
        return Ordering::Equal;
    }

    // The musl expression `c-'1'<9U` is an unsigned test for bytes '1'..'9'.
    let left_nonzero_digit = left
        .get(digit_prefix)
        .is_some_and(|&byte| (byte.wrapping_sub(b'1')) < 9);
    let right_nonzero_digit = right
        .get(digit_prefix)
        .is_some_and(|&byte| (byte.wrapping_sub(b'1')) < 9);
    if left_nonzero_digit && right_nonzero_digit {
        let mut left_end = index;
        while left_end < left.len() && is_ascii_digit(left[left_end]) {
            if left_end >= right.len() || !is_ascii_digit(right[left_end]) {
                return Ordering::Greater;
            }
            left_end += 1;
        }
        if left_end < right.len() && is_ascii_digit(right[left_end]) {
            return Ordering::Less;
        }
    } else if all_zero
        && digit_prefix < index
        && (left.get(index).is_some_and(|&byte| is_ascii_digit(byte))
            || right.get(index).is_some_and(|&byte| is_ascii_digit(byte)))
    {
        let left_digit = left.get(index).copied().unwrap_or(b'0');
        let right_digit = right.get(index).copied().unwrap_or(b'0');
        return left_digit.wrapping_sub(b'0').cmp(&right_digit.wrapping_sub(b'0'));
    }

    left.get(index).copied().unwrap_or(0).cmp(&right.get(index).copied().unwrap_or(0))
}

/// Compares two NUL-terminated strings with musl's `strverscmp` rule.
#[inline]
pub fn cstr_version_cmp(left: &CStr, right: &CStr) -> Ordering {
    version_cmp(left.to_bytes(), right.to_bytes())
}

/// A non-mutating cursor over every delimiter-separated field.
///
/// Unlike tokenization, adjacent and boundary delimiters produce empty
/// fields. A trailing delimiter produces one final empty field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitCursor<'a> {
    input: &'a [u8],
    delimiters: &'a [u8],
    offset: usize,
    finished: bool,
}

impl<'a> SplitCursor<'a> {
    /// Creates a cursor which treats every byte in `delimiters` as a split.
    #[must_use]
    pub const fn new(input: &'a [u8], delimiters: &'a [u8]) -> Self {
        Self {
            input,
            delimiters,
            offset: 0,
            finished: false,
        }
    }

    #[inline]
    fn is_delimiter(&self, byte: u8) -> bool {
        self.delimiters.contains(&byte)
    }

    /// Returns the next field, including empty fields.
    pub fn next_field(&mut self) -> Option<&'a [u8]> {
        if self.finished {
            return None;
        }
        let start = self.offset;
        while self.offset < self.input.len() && !self.is_delimiter(self.input[self.offset]) {
            self.offset += 1;
        }
        let field = &self.input[start..self.offset];
        if self.offset == self.input.len() {
            self.finished = true;
        } else {
            self.offset += 1;
        }
        Some(field)
    }

    /// Returns the unconsumed input, including any delimiters.
    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        if self.finished {
            &[]
        } else {
            &self.input[self.offset..]
        }
    }
}

impl<'a> Iterator for SplitCursor<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.next_field()
    }
}

/// A non-mutating cursor with `strtok_r` semantics: delimiter runs are
/// skipped and only non-empty tokens are returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenCursor<'a> {
    input: &'a [u8],
    delimiters: &'a [u8],
    offset: usize,
}

impl<'a> TokenCursor<'a> {
    /// Creates an independent token cursor.
    #[must_use]
    pub const fn new(input: &'a [u8], delimiters: &'a [u8]) -> Self {
        Self {
            input,
            delimiters,
            offset: 0,
        }
    }

    #[inline]
    fn is_delimiter(&self, byte: u8) -> bool {
        self.delimiters.contains(&byte)
    }

    /// Returns the next non-empty token.
    pub fn next_token(&mut self) -> Option<&'a [u8]> {
        while self.offset < self.input.len() && self.is_delimiter(self.input[self.offset]) {
            self.offset += 1;
        }
        if self.offset == self.input.len() {
            return None;
        }
        let start = self.offset;
        while self.offset < self.input.len() && !self.is_delimiter(self.input[self.offset]) {
            self.offset += 1;
        }
        Some(&self.input[start..self.offset])
    }

    /// Returns the unconsumed suffix. This is useful for inspection/debugging
    /// without exposing the cursor's internal state as a mutable pointer.
    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }
}

impl<'a> Iterator for TokenCursor<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.next_token()
    }
}

#[cfg(test)]
mod tests {
    use super::{ascii_case_insensitive_find, version_cmp, SplitCursor, TokenCursor};
    use core::cmp::Ordering;

    #[test]
    fn ascii_search_and_case_fold_are_byte_oriented() {
        assert_eq!(ascii_case_insensitive_find(b"xxAbCyy", b"aBc"), Some(2));
        assert_eq!(ascii_case_insensitive_find(b"\xffAb", b"ab"), Some(1));
        assert_eq!(ascii_case_insensitive_find(b"abc", b""), Some(0));
        assert_eq!(ascii_case_insensitive_find(b"abc", b"abcd"), None);
    }

    #[test]
    fn split_keeps_empty_fields_and_tokens_skip_delimiter_runs() {
        let mut fields = SplitCursor::new(b",a,,b,", b",");
        assert_eq!(fields.next(), Some(&b""[..]));
        assert_eq!(fields.next(), Some(&b"a"[..]));
        assert_eq!(fields.next(), Some(&b""[..]));
        assert_eq!(fields.next(), Some(&b"b"[..]));
        assert_eq!(fields.next(), Some(&b""[..]));
        assert_eq!(fields.next(), None);

        let mut tokens = TokenCursor::new(b",a,,b,", b",");
        assert_eq!(tokens.next(), Some(&b"a"[..]));
        assert_eq!(tokens.next(), Some(&b"b"[..]));
        assert_eq!(tokens.next(), None);
    }

    #[test]
    fn version_order_matches_musl_edge_policy() {
        assert_eq!(version_cmp(b"a1", b"a2"), Ordering::Less);
        assert_eq!(version_cmp(b"a2", b"a10"), Ordering::Less);
        assert_eq!(version_cmp(b"a10", b"a2"), Ordering::Greater);
        assert_eq!(version_cmp(b"a01", b"a1"), Ordering::Less);
        assert_eq!(version_cmp(b"a1", b"a01"), Ordering::Greater);
        assert_eq!(version_cmp(b"a", b"a"), Ordering::Equal);
        assert_eq!(version_cmp(b"a1", b"a-"), Ordering::Greater);
    }
}
