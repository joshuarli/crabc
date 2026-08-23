//! Bounded native text facilities.
//!
//! This is the Rust-facing text seam, not a wrapper around the public C
//! `iconv` ABI. It accepts borrowed byte slices and returns the shared typed
//! progress/error values directly; no C function, libc state, allocator, or
//! thread-local `errno` participates in conversion.
//!
//! The native slice supports strict UTF-8, ASCII, UTF-16LE/BE, UTF-32LE/BE,
//! Linux/AArch64 little-endian `WChar`, and the shared ISO-8859-2..16
//! single-byte tables. The remaining shared encoding names are retained for
//! the C compatibility facade but remain unsupported here. ISO table slots
//! which were undefined in the extracted source retain their table value;
//! this native policy is separate from future musl C `iconv` parity.
//! The same module also exposes fixed-C/POSIX byte ctype operations whose
//! `u8` boundary deliberately excludes C's EOF and arbitrary-integer
//! conventions.

use core::cmp::Ordering;
use core::ffi::CStr;
use core::ptr;

use crabc_core::iconv as core_iconv;

#[cfg(feature = "alloc")]
use alloc::ffi::CString;

pub use crabc_core::text::{
    ascii_case_insensitive_cmp, ascii_case_insensitive_eq, ascii_case_insensitive_find,
    ascii_lower, cstr_bytes, cstr_version_cmp, version_cmp, SplitCursor, TokenCursor,
};

/// The delimiter cursor used by [`split_fields`].
pub type DelimiterCursor<'a> = SplitCursor<'a>;

/// Errors raised by checked C-string construction and writes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CStrWriteError {
    /// The destination needs at least one byte for its invariant NUL.
    EmptyDestination,
    /// The source contains an interior NUL and is not a C-string payload.
    InteriorNul { index: usize },
    /// An exact operation would exceed the available destination capacity.
    Capacity { needed: usize, capacity: usize },
    /// The caller supplied a destination which was not NUL-terminated.
    MissingTerminator,
}

/// Short alias for the checked text-write error.
pub type TextWriteError = CStrWriteError;

/// The observable result of a bounded or padded byte copy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PaddedCopy {
    copied: usize,
    required: usize,
    padded: usize,
}

impl PaddedCopy {
    /// Creates a result for an operation which copied `copied` bytes and
    /// required `required` source bytes in total.
    #[must_use]
    pub const fn new(copied: usize, required: usize, padded: usize) -> Self {
        Self {
            copied,
            required,
            padded,
        }
    }

    /// Number of source bytes copied, excluding the terminating NUL.
    #[must_use]
    pub const fn copied(self) -> usize {
        self.copied
    }

    /// Number of source bytes which would be needed for an exact copy.
    #[must_use]
    pub const fn required(self) -> usize {
        self.required
    }

    /// Number of NUL padding bytes written after the copied payload.
    #[must_use]
    pub const fn padded(self) -> usize {
        self.padded
    }

    /// Whether the source did not fit in the bounded operation.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.copied < self.required
    }
}

/// Checked operations which preserve a mutable destination's C-string
/// invariant. Implementors always leave a terminating NUL in their storage.
pub trait CStrWrite {
    /// Replaces the current value, failing before mutation if `source` does
    /// not fit. The return value is the copied payload length.
    fn write_exact(&mut self, source: &[u8]) -> Result<usize, CStrWriteError>;

    /// Replaces the current value, copying as much as fits and always writing
    /// a trailing NUL. The result reports the source length and truncation.
    fn write_truncated(&mut self, source: &[u8]) -> Result<PaddedCopy, CStrWriteError>;

    /// Replaces the current value with at most `width` bytes and pads the
    /// unused width with NUL bytes. `width` must leave room for the builder's
    /// invariant terminator.
    fn write_padded(&mut self, source: &[u8], width: usize) -> Result<PaddedCopy, CStrWriteError>;

    /// Appends to the current value, failing before mutation if the complete
    /// result does not fit.
    fn append_exact(&mut self, source: &[u8]) -> Result<usize, CStrWriteError>;

    /// Appends as much as fits and retains the C-string terminator.
    fn append_truncated(&mut self, source: &[u8]) -> Result<PaddedCopy, CStrWriteError>;

    /// Appends at most `limit` source bytes, requiring that the selected
    /// prefix fit completely in the destination.
    fn append_prefix(&mut self, source: &[u8], limit: usize) -> Result<usize, CStrWriteError>;
}

/// A mutable, checked C-string destination.
///
/// The builder owns no storage and never allocates. Its constructor writes the
/// initial NUL, and every mutating operation writes a NUL before returning.
/// Exact operations validate both source shape and capacity before touching
/// the destination, making failure non-mutating.
pub struct CStrBuilder<'a> {
    storage: &'a mut [u8],
    len: usize,
}

impl<'a> CStrBuilder<'a> {
    /// Creates an empty builder over `storage`.
    pub fn new(storage: &'a mut [u8]) -> Result<Self, CStrWriteError> {
        if storage.is_empty() {
            return Err(CStrWriteError::EmptyDestination);
        }
        storage[0] = 0;
        Ok(Self { storage, len: 0 })
    }

    /// Adopts an already initialized C-string buffer without changing it.
    pub fn from_cstr_buffer(storage: &'a mut [u8]) -> Result<Self, CStrWriteError> {
        let Some(len) = storage.iter().position(|&byte| byte == 0) else {
            return Err(CStrWriteError::MissingTerminator);
        };
        Ok(Self { storage, len })
    }

    /// Returns the current payload bytes without its NUL.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    /// Returns the current value as a borrowed C string.
    #[must_use]
    pub fn as_c_str(&self) -> &CStr {
        // SAFETY: `new` and every mutating operation establish the NUL at
        // `len`, and `storage[..=len]` is within the borrowed destination.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.storage[..=self.len]) }
    }

    /// Returns the payload length, excluding the invariant NUL.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns the total destination capacity in bytes.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Returns whether the builder currently contains no payload bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the unused payload capacity before the invariant NUL.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.storage.len() - self.len - 1
    }

    /// Clears the current value while preserving the builder invariant.
    pub fn clear(&mut self) {
        self.len = 0;
        self.storage[0] = 0;
    }

    #[inline]
    fn validate_source(source: &[u8]) -> Result<(), CStrWriteError> {
        if let Some(index) = source.iter().position(|&byte| byte == 0) {
            Err(CStrWriteError::InteriorNul { index })
        } else {
            Ok(())
        }
    }

    #[inline]
    fn copy_payload(&mut self, destination: usize, source: &[u8]) {
        // SAFETY: callers validate that destination..destination+source.len()
        // lies within storage. `copy` permits explicitly supported overlap.
        unsafe {
            ptr::copy(
                source.as_ptr(),
                self.storage.as_mut_ptr().add(destination),
                source.len(),
            );
        }
    }

    #[inline]
    fn terminate(&mut self, length: usize) {
        self.len = length;
        self.storage[length] = 0;
    }
}

impl CStrWrite for CStrBuilder<'_> {
    fn write_exact(&mut self, source: &[u8]) -> Result<usize, CStrWriteError> {
        Self::validate_source(source)?;
        let needed = source.len().saturating_add(1);
        if needed > self.storage.len() {
            return Err(CStrWriteError::Capacity {
                needed,
                capacity: self.storage.len(),
            });
        }
        self.copy_payload(0, source);
        self.terminate(source.len());
        Ok(source.len())
    }

    fn write_truncated(&mut self, source: &[u8]) -> Result<PaddedCopy, CStrWriteError> {
        Self::validate_source(source)?;
        let copied = core::cmp::min(source.len(), self.storage.len() - 1);
        self.copy_payload(0, &source[..copied]);
        self.terminate(copied);
        Ok(PaddedCopy::new(copied, source.len(), 0))
    }

    fn write_padded(&mut self, source: &[u8], width: usize) -> Result<PaddedCopy, CStrWriteError> {
        Self::validate_source(source)?;
        if width >= self.storage.len() {
            return Err(CStrWriteError::Capacity {
                needed: width.saturating_add(1),
                capacity: self.storage.len(),
            });
        }
        let copied = core::cmp::min(source.len(), width);
        self.copy_payload(0, &source[..copied]);
        // Keep the copied prefix intact when the source reaches the padded
        // width. Only the unused interval is padding; the width byte itself
        // is the builder's terminator for an exact-width source.
        if copied < width {
            self.storage[copied..width].fill(0);
        }
        self.storage[width] = 0;
        self.terminate(copied);
        Ok(PaddedCopy::new(copied, source.len(), width - copied))
    }

    fn append_exact(&mut self, source: &[u8]) -> Result<usize, CStrWriteError> {
        Self::validate_source(source)?;
        let needed = self
            .len
            .checked_add(source.len())
            .and_then(|length| length.checked_add(1))
            .unwrap_or(usize::MAX);
        if needed > self.storage.len() {
            return Err(CStrWriteError::Capacity {
                needed,
                capacity: self.storage.len(),
            });
        }
        let start = self.len;
        self.copy_payload(start, source);
        self.terminate(start + source.len());
        Ok(source.len())
    }

    fn append_truncated(&mut self, source: &[u8]) -> Result<PaddedCopy, CStrWriteError> {
        Self::validate_source(source)?;
        let copied = core::cmp::min(source.len(), self.remaining());
        let start = self.len;
        self.copy_payload(start, &source[..copied]);
        self.terminate(start + copied);
        Ok(PaddedCopy::new(copied, source.len(), 0))
    }

    fn append_prefix(&mut self, source: &[u8], limit: usize) -> Result<usize, CStrWriteError> {
        Self::validate_source(source)?;
        let selected = core::cmp::min(source.len(), limit);
        let needed = self
            .len
            .checked_add(selected)
            .and_then(|length| length.checked_add(1))
            .unwrap_or(usize::MAX);
        if needed > self.storage.len() {
            return Err(CStrWriteError::Capacity {
                needed,
                capacity: self.storage.len(),
            });
        }
        let start = self.len;
        self.copy_payload(start, &source[..selected]);
        self.terminate(start + selected);
        Ok(selected)
    }
}

impl CStrBuilder<'_> {
    /// Replaces the current value, requiring the complete payload to fit.
    pub fn write(&mut self, source: &[u8]) -> Result<usize, CStrWriteError> {
        self.write_exact(source)
    }

    /// Appends a payload, requiring the complete result to fit.
    pub fn append(&mut self, source: &[u8]) -> Result<usize, CStrWriteError> {
        self.append_exact(source)
    }

    /// Appends at most `limit` source bytes, as in `strncat`, while retaining
    /// the builder's invariant terminator.
    pub fn append_prefix(&mut self, source: &[u8], limit: usize) -> Result<usize, CStrWriteError> {
        CStrWrite::append_prefix(self, source, limit)
    }

    /// Replaces the current value from a borrowed C string.
    pub fn write_cstr(&mut self, source: &CStr) -> Result<usize, CStrWriteError> {
        self.write_exact(source.to_bytes())
    }

    /// Appends a borrowed C string.
    pub fn append_cstr(&mut self, source: &CStr) -> Result<usize, CStrWriteError> {
        self.append_exact(source.to_bytes())
    }
}

/// Duplicates a borrowed C string using the crate's Rust allocator boundary.
///
/// This convenience exists only with the `alloc` feature. It is not a C
/// `malloc` ABI and never calls libc allocation functions.
#[cfg(feature = "alloc")]
pub fn duplicate(source: &CStr) -> CString {
    // A CStr cannot contain an interior NUL, so this conversion cannot fail.
    CString::new(source.to_bytes()).expect("CStr payload has no interior NUL")
}

/// Duplicates at most `limit` bytes of a C string.
#[cfg(feature = "alloc")]
pub fn duplicate_n(source: &CStr, limit: usize) -> CString {
    CString::new(&source.to_bytes()[..core::cmp::min(source.to_bytes().len(), limit)])
        .expect("CStr payload has no interior NUL")
}

/// Duplicates a byte payload, rejecting an interior NUL.
#[cfg(feature = "alloc")]
pub fn duplicate_bytes(source: &[u8]) -> Result<CString, alloc::ffi::NulError> {
    CString::new(source)
}

/// Allocates an owned copy of a byte payload without interpreting it as UTF-8.
#[cfg(feature = "alloc")]
pub fn duplicate_bytes_lossless(source: &[u8]) -> Result<CString, alloc::ffi::NulError> {
    duplicate_bytes(source)
}

/// Finds an ASCII-case-insensitive substring in a C string and returns the
/// byte offset of its first occurrence.
pub fn find_cstr_case_insensitive(haystack: &CStr, needle: &CStr) -> Option<usize> {
    ascii_case_insensitive_find(haystack.to_bytes(), needle.to_bytes())
}

/// Finds an ASCII-case-insensitive substring and returns the borrowed C-string
/// suffix beginning at that occurrence.
pub fn find_cstr_substring_case_insensitive<'a>(
    haystack: &'a CStr,
    needle: &CStr,
) -> Option<&'a CStr> {
    let offset = find_cstr_case_insensitive(haystack, needle)?;
    // SAFETY: `offset` is within `haystack.to_bytes()`, and the original CStr
    // terminator remains at the end of the suffix.
    Some(unsafe { CStr::from_bytes_with_nul_unchecked(&haystack.to_bytes_with_nul()[offset..]) })
}

/// Compares C strings using musl's byte-oriented version ordering.
pub fn compare_versions(left: &CStr, right: &CStr) -> Ordering {
    cstr_version_cmp(left, right)
}

/// Creates a cursor which preserves empty delimiter-separated fields.
#[must_use]
pub const fn split_fields<'a>(input: &'a [u8], delimiters: &'a [u8]) -> SplitCursor<'a> {
    SplitCursor::new(input, delimiters)
}

/// Creates a cursor with `strtok_r`-style delimiter-run skipping.
#[must_use]
pub const fn tokens<'a>(input: &'a [u8], delimiters: &'a [u8]) -> TokenCursor<'a> {
    TokenCursor::new(input, delimiters)
}

/// The text encodings implemented by the bounded native converter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TextEncoding {
    /// Unicode scalar values encoded as strict UTF-8.
    Utf8,
    /// The 7-bit US-ASCII repertoire.
    Ascii,
    /// Unicode scalar values encoded as little-endian UTF-16 code units.
    Utf16Le,
    /// Unicode scalar values encoded as big-endian UTF-16 code units.
    Utf16Be,
    /// Unicode scalar values encoded as little-endian UTF-32 code units.
    Utf32Le,
    /// Unicode scalar values encoded as big-endian UTF-32 code units.
    Utf32Be,
    /// Linux/AArch64 `wchar_t`: little-endian 32-bit scalar values.
    WChar,
    /// ISO-8859-2 (Latin-2) single-byte encoding.
    Iso8859_2,
    /// ISO-8859-3 (Latin-3) single-byte encoding.
    Iso8859_3,
    /// ISO-8859-4 (Latin-4) single-byte encoding.
    Iso8859_4,
    /// ISO-8859-5 (Cyrillic) single-byte encoding.
    Iso8859_5,
    /// ISO-8859-6 (Arabic) single-byte encoding.
    Iso8859_6,
    /// ISO-8859-7 (Greek) single-byte encoding.
    Iso8859_7,
    /// ISO-8859-8 (Hebrew) single-byte encoding.
    Iso8859_8,
    /// ISO-8859-9 (Latin-5) single-byte encoding.
    Iso8859_9,
    /// ISO-8859-10 (Latin-6) single-byte encoding.
    Iso8859_10,
    /// ISO-8859-11 (Thai/TIS-620 table) single-byte encoding.
    Iso8859_11,
    /// ISO-8859-13 (Latin-7) single-byte encoding.
    Iso8859_13,
    /// ISO-8859-14 (Latin-8) single-byte encoding.
    Iso8859_14,
    /// ISO-8859-15 (Latin-9) single-byte encoding.
    Iso8859_15,
    /// ISO-8859-16 (Latin-10) single-byte encoding.
    Iso8859_16,
}

impl TextEncoding {
    /// Parses a supported encoding name without allocation.
    ///
    /// Matching is case- and punctuation-insensitive, as in the shared core
    /// name parser. Names for encodings which remain outside this native
    /// facade's strict subset intentionally return `None`.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match core_iconv::Encoding::from_name(name) {
            Some(core_iconv::Encoding::Utf8) => Some(Self::Utf8),
            Some(core_iconv::Encoding::Ascii) => Some(Self::Ascii),
            Some(core_iconv::Encoding::Utf16Le) => Some(Self::Utf16Le),
            Some(core_iconv::Encoding::Utf16Be) => Some(Self::Utf16Be),
            Some(core_iconv::Encoding::Utf32Le) => Some(Self::Utf32Le),
            Some(core_iconv::Encoding::Utf32Be) => Some(Self::Utf32Be),
            Some(core_iconv::Encoding::WChar) => Some(Self::WChar),
            Some(core_iconv::Encoding::Iso8859_2) => Some(Self::Iso8859_2),
            Some(core_iconv::Encoding::Iso8859_3) => Some(Self::Iso8859_3),
            Some(core_iconv::Encoding::Iso8859_4) => Some(Self::Iso8859_4),
            Some(core_iconv::Encoding::Iso8859_5) => Some(Self::Iso8859_5),
            Some(core_iconv::Encoding::Iso8859_6) => Some(Self::Iso8859_6),
            Some(core_iconv::Encoding::Iso8859_7) => Some(Self::Iso8859_7),
            Some(core_iconv::Encoding::Iso8859_8) => Some(Self::Iso8859_8),
            Some(core_iconv::Encoding::Iso8859_9) => Some(Self::Iso8859_9),
            Some(core_iconv::Encoding::Iso8859_10) => Some(Self::Iso8859_10),
            Some(core_iconv::Encoding::Iso8859_11) => Some(Self::Iso8859_11),
            Some(core_iconv::Encoding::Iso8859_13) => Some(Self::Iso8859_13),
            Some(core_iconv::Encoding::Iso8859_14) => Some(Self::Iso8859_14),
            Some(core_iconv::Encoding::Iso8859_15) => Some(Self::Iso8859_15),
            Some(core_iconv::Encoding::Iso8859_16) => Some(Self::Iso8859_16),
            Some(_) | None => None,
        }
    }

    const fn as_core(self) -> core_iconv::Encoding {
        match self {
            Self::Utf8 => core_iconv::Encoding::Utf8,
            Self::Ascii => core_iconv::Encoding::Ascii,
            Self::Utf16Le => core_iconv::Encoding::Utf16Le,
            Self::Utf16Be => core_iconv::Encoding::Utf16Be,
            Self::Utf32Le => core_iconv::Encoding::Utf32Le,
            Self::Utf32Be => core_iconv::Encoding::Utf32Be,
            Self::WChar => core_iconv::Encoding::WChar,
            Self::Iso8859_2 => core_iconv::Encoding::Iso8859_2,
            Self::Iso8859_3 => core_iconv::Encoding::Iso8859_3,
            Self::Iso8859_4 => core_iconv::Encoding::Iso8859_4,
            Self::Iso8859_5 => core_iconv::Encoding::Iso8859_5,
            Self::Iso8859_6 => core_iconv::Encoding::Iso8859_6,
            Self::Iso8859_7 => core_iconv::Encoding::Iso8859_7,
            Self::Iso8859_8 => core_iconv::Encoding::Iso8859_8,
            Self::Iso8859_9 => core_iconv::Encoding::Iso8859_9,
            Self::Iso8859_10 => core_iconv::Encoding::Iso8859_10,
            Self::Iso8859_11 => core_iconv::Encoding::Iso8859_11,
            Self::Iso8859_13 => core_iconv::Encoding::Iso8859_13,
            Self::Iso8859_14 => core_iconv::Encoding::Iso8859_14,
            Self::Iso8859_15 => core_iconv::Encoding::Iso8859_15,
            Self::Iso8859_16 => core_iconv::Encoding::Iso8859_16,
        }
    }
}

/// The short encoding name retained for consistency with the core API.
pub type Encoding = TextEncoding;

/// A borrowed-slice native text converter.
///
/// Conversion is resumable at scalar boundaries. On a typed failure, use
/// [`ConvertError::consumed`] and [`ConvertError::produced`] to resume with
/// the remaining input and output slices. The converter owns no input or
/// output storage and has no C ABI or `errno` state.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TextConverter {
    inner: core_iconv::Converter,
    from: TextEncoding,
    to: TextEncoding,
}

impl TextConverter {
    /// Creates a converter for one of the supported native encodings.
    #[must_use]
    pub const fn new(from: TextEncoding, to: TextEncoding) -> Self {
        Self {
            inner: core_iconv::Converter::new(from.as_core(), to.as_core()),
            from,
            to,
        }
    }

    /// Returns the source encoding.
    #[must_use]
    pub const fn from(&self) -> TextEncoding {
        self.from
    }

    /// Returns the destination encoding.
    #[must_use]
    pub const fn to(&self) -> TextEncoding {
        self.to
    }

    /// Converts complete source scalars which fit in `output`.
    ///
    /// The returned [`Conversion`] or [`ConvertError`] reports byte progress;
    /// no partial scalar is consumed. An incomplete final scalar, malformed
    /// input, output exhaustion, or an unrepresentable destination scalar is
    /// represented by the typed error rather than a C sentinel or `errno`.
    pub fn convert(&mut self, input: &[u8], output: &mut [u8]) -> Result<Conversion, ConvertError> {
        self.inner.convert(input, output)
    }

    /// Converts with an explicit policy for destination-repertoire misses.
    pub fn convert_with(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        policy: Unrepresentable,
    ) -> Result<Conversion, ConvertError> {
        self.inner.convert_with(input, output, policy)
    }

    /// Resets conversion state. The supported codecs are stateless today.
    pub const fn reset(&mut self) {
        self.inner.reset()
    }
}

/// The short converter name retained for consistency with the core API.
pub type Converter = TextConverter;

/// Successful conversion progress and substitution count.
pub use core_iconv::Conversion;

/// Typed conversion failure carrying resumable byte progress.
pub use core_iconv::ConvertError;

/// Policy for destination scalars which are not representable.
pub use core_iconv::Unrepresentable;

/// Descriptive aliases for callers which prefer the facade's domain names.
pub type TextConversion = Conversion;
/// Descriptive alias for the typed conversion failure.
pub type TextConvertError = ConvertError;
/// Descriptive alias for the replacement policy.
pub type TextUnrepresentable = Unrepresentable;

/// An allocation-free parser for an explicitly selected ASCII integer radix.
///
/// `NumberParser` deliberately has a smaller, more explicit contract than the
/// C `strto*` family: it never skips whitespace, consults locale state, writes
/// an end pointer, or communicates overflow through `errno`. A successful
/// parse consumes the entire borrowed slice. Radix prefixes such as `0x` are
/// not special; callers select radix 16 and pass the digits they intend to
/// parse. This keeps sign, radix, and input-boundary policy visible to a Rust
/// caller instead of importing C's base-zero and partial-consumption rules.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NumberParser {
    radix: u8,
}

impl NumberParser {
    /// Creates a parser for an ASCII radix from 2 through 36.
    #[must_use]
    pub const fn new(radix: u8) -> Option<Self> {
        if radix < 2 || radix > 36 {
            None
        } else {
            Some(Self { radix })
        }
    }

    /// Creates the ordinary decimal parser.
    #[must_use]
    pub const fn decimal() -> Self {
        Self { radix: 10 }
    }

    /// Returns the configured radix.
    #[must_use]
    pub const fn radix(self) -> u8 {
        self.radix
    }

    /// Parses an unsigned 64-bit integer from the complete input slice.
    ///
    /// Unsigned syntax contains digits only: neither `+` nor `-` is accepted.
    /// ASCII upper- and lower-case letters represent values 10 through 35.
    pub fn parse_u64(self, input: &[u8]) -> Result<u64, NumberParseError> {
        if input.is_empty() {
            return Err(NumberParseError::Empty);
        }
        if input[0] == b'+' || input[0] == b'-' {
            return Err(NumberParseError::UnexpectedSign { byte: input[0] });
        }
        self.parse_digits(input, 0, u64::MAX)
    }

    /// Parses a signed 64-bit integer from the complete input slice.
    ///
    /// A leading ASCII `+` or `-` is optional. There must be at least one
    /// digit after the sign, and the complete input must be valid in the
    /// configured radix.
    pub fn parse_i64(self, input: &[u8]) -> Result<i64, NumberParseError> {
        if input.is_empty() {
            return Err(NumberParseError::Empty);
        }

        let (negative, start, limit) = match input[0] {
            b'+' => (false, 1, i64::MAX as u64),
            b'-' => (true, 1, (i64::MAX as u64) + 1),
            _ => (false, 0, i64::MAX as u64),
        };
        let magnitude = self.parse_digits(input, start, limit)?;
        if negative {
            if magnitude == 1u64 << 63 {
                Ok(i64::MIN)
            } else {
                Ok(-(magnitude as i64))
            }
        } else {
            Ok(magnitude as i64)
        }
    }

    fn parse_digits(self, input: &[u8], start: usize, limit: u64) -> Result<u64, NumberParseError> {
        if start == input.len() {
            return if start == 0 {
                Err(NumberParseError::Empty)
            } else {
                Err(NumberParseError::SignWithoutDigits)
            };
        }

        let mut value = 0u64;
        let mut index = start;
        while index < input.len() {
            let byte = input[index];
            let digit = match Self::digit_value(byte) {
                Some(digit) if digit < self.radix => u64::from(digit),
                _ => return Err(NumberParseError::InvalidDigit { index, byte }),
            };
            let radix = u64::from(self.radix);
            if value > (limit - digit) / radix {
                return Err(NumberParseError::Overflow);
            }
            value = value * radix + digit;
            index += 1;
        }
        Ok(value)
    }

    const fn digit_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'z' => Some(byte - b'a' + 10),
            b'A'..=b'Z' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
}

/// The explicit failure modes of [`NumberParser`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NumberParseError {
    /// The input slice contained no bytes.
    Empty,
    /// A signed parse contained only a leading sign.
    SignWithoutDigits,
    /// An unsigned parse began with `+` or `-`.
    UnexpectedSign { byte: u8 },
    /// A byte was not a digit in the selected radix. `index` is a byte offset.
    InvalidDigit { index: usize, byte: u8 },
    /// The complete digit sequence exceeded the destination integer range.
    Overflow,
}

/// The C/POSIX byte-character classes in the fixed `C` locale.
///
/// This is a native byte API, not a spelling of the C `<ctype.h>` ABI. Every
/// operation below accepts a `u8`, so a negative C `int`, the `EOF` sentinel,
/// and values outside the unsigned-byte range cannot enter the contract. A
/// byte greater than `0x7f` is valid input but is not an ASCII character: its
/// classification is [`AsciiClass::EMPTY`], `is_ascii` returns `false`, and
/// case conversion leaves it unchanged. No locale, `_l` handle, wide
/// character, or thread-local `errno` state participates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AsciiClass(u8);

impl AsciiClass {
    /// No C/POSIX class bits are set.
    pub const EMPTY: Self = Self(0);
    /// The byte is an ASCII uppercase letter (`A`–`Z`).
    pub const UPPER: Self = Self(1 << 0);
    /// The byte is an ASCII lowercase letter (`a`–`z`).
    pub const LOWER: Self = Self(1 << 1);
    /// The byte is an ASCII decimal digit (`0`–`9`).
    pub const DIGIT: Self = Self(1 << 2);
    /// The byte is one of the six C/POSIX whitespace bytes.
    pub const SPACE: Self = Self(1 << 3);
    /// The byte is ASCII punctuation.
    pub const PUNCT: Self = Self(1 << 4);
    /// The byte is an ASCII control byte.
    pub const CNTRL: Self = Self(1 << 5);
    /// The byte is ASCII space or horizontal tab.
    pub const BLANK: Self = Self(1 << 6);
    /// The byte is an ASCII hexadecimal digit.
    pub const XDIGIT: Self = Self(1 << 7);

    /// Classifies one byte using the locale-independent C/POSIX table.
    ///
    /// High bytes (`0x80..=0xff`) deliberately produce [`Self::EMPTY`].
    /// This does not treat them as invalid input; it records the C-locale
    /// result for a valid unsigned byte without the C `EOF` ambiguity.
    #[must_use]
    pub const fn classify(byte: u8) -> Self {
        let mut bits = 0u8;
        if byte >= b'A' && byte <= b'Z' {
            bits |= Self::UPPER.0;
        }
        if byte >= b'a' && byte <= b'z' {
            bits |= Self::LOWER.0;
        }
        if byte >= b'0' && byte <= b'9' {
            bits |= Self::DIGIT.0;
        }
        if matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c' | b'\x0b') {
            bits |= Self::SPACE.0;
        }
        if (byte >= b'!' && byte <= b'/')
            || (byte >= b':' && byte <= b'@')
            || (byte >= b'[' && byte <= b'`')
            || (byte >= b'{' && byte <= b'~')
        {
            bits |= Self::PUNCT.0;
        }
        if byte < 0x20 || byte == 0x7f {
            bits |= Self::CNTRL.0;
        }
        if byte == b' ' || byte == b'\t' {
            bits |= Self::BLANK.0;
        }
        if (byte >= b'0' && byte <= b'9')
            || (byte >= b'A' && byte <= b'F')
            || (byte >= b'a' && byte <= b'f')
        {
            bits |= Self::XDIGIT.0;
        }
        Self(bits)
    }

    /// Returns the raw class-bit representation.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Returns whether every bit in `required` is set.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Returns whether this classification has no class bits.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether this byte is an ASCII alphanumeric character.
    #[must_use]
    pub const fn is_alnum(self) -> bool {
        self.contains(Self::UPPER) || self.contains(Self::LOWER) || self.contains(Self::DIGIT)
    }

    /// Returns whether this byte is an ASCII letter.
    #[must_use]
    pub const fn is_alpha(self) -> bool {
        self.contains(Self::UPPER) || self.contains(Self::LOWER)
    }

    /// Returns whether this byte is an ASCII blank.
    #[must_use]
    pub const fn is_blank(self) -> bool {
        self.contains(Self::BLANK)
    }

    /// Returns whether this byte is an ASCII control character.
    #[must_use]
    pub const fn is_cntrl(self) -> bool {
        self.contains(Self::CNTRL)
    }

    /// Returns whether this byte is an ASCII decimal digit.
    #[must_use]
    pub const fn is_digit(self) -> bool {
        self.contains(Self::DIGIT)
    }

    /// Returns whether this byte is an ASCII graphical character.
    #[must_use]
    pub const fn is_graph(self) -> bool {
        self.is_alnum() || self.contains(Self::PUNCT)
    }

    /// Returns whether this byte is an ASCII lowercase letter.
    #[must_use]
    pub const fn is_lower(self) -> bool {
        self.contains(Self::LOWER)
    }

    /// Returns whether this byte is an ASCII printable character.
    #[must_use]
    pub const fn is_print(self) -> bool {
        self.is_graph() || self.contains(Self::BLANK)
    }

    /// Returns whether this byte is ASCII punctuation.
    #[must_use]
    pub const fn is_punct(self) -> bool {
        self.contains(Self::PUNCT)
    }

    /// Returns whether this byte is one of the six C/POSIX whitespace bytes.
    #[must_use]
    pub const fn is_space(self) -> bool {
        self.contains(Self::SPACE)
    }

    /// Returns whether this byte is an ASCII uppercase letter.
    #[must_use]
    pub const fn is_upper(self) -> bool {
        self.contains(Self::UPPER)
    }

    /// Returns whether this byte is an ASCII hexadecimal digit.
    #[must_use]
    pub const fn is_xdigit(self) -> bool {
        self.contains(Self::XDIGIT)
    }
}

/// Returns whether `byte` is in the 7-bit ASCII range.
#[must_use]
#[inline]
pub const fn is_ascii(byte: u8) -> bool {
    byte <= 0x7f
}

/// Maps a byte to its 7-bit ASCII value, matching C `toascii`.
#[must_use]
#[inline]
pub const fn to_ascii(byte: u8) -> u8 {
    byte & 0x7f
}

/// Maps an ASCII uppercase byte to lowercase; all other bytes are unchanged.
#[must_use]
#[inline]
pub const fn to_lower(byte: u8) -> u8 {
    if AsciiClass::classify(byte).is_upper() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

/// Maps an ASCII lowercase byte to uppercase; all other bytes are unchanged.
#[must_use]
#[inline]
pub const fn to_upper(byte: u8) -> u8 {
    if AsciiClass::classify(byte).is_lower() {
        byte - (b'a' - b'A')
    } else {
        byte
    }
}

/// Returns whether `byte` is alphanumeric in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_alnum(byte: u8) -> bool {
    AsciiClass::classify(byte).is_alnum()
}

/// Returns whether `byte` is alphabetic in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_alpha(byte: u8) -> bool {
    AsciiClass::classify(byte).is_alpha()
}

/// Returns whether `byte` is a blank byte in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_blank(byte: u8) -> bool {
    AsciiClass::classify(byte).is_blank()
}

/// Returns whether `byte` is a control byte in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_cntrl(byte: u8) -> bool {
    AsciiClass::classify(byte).is_cntrl()
}

/// Returns whether `byte` is a decimal digit in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_digit(byte: u8) -> bool {
    AsciiClass::classify(byte).is_digit()
}

/// Returns whether `byte` is graphical in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_graph(byte: u8) -> bool {
    AsciiClass::classify(byte).is_graph()
}

/// Returns whether `byte` is lowercase in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_lower(byte: u8) -> bool {
    AsciiClass::classify(byte).is_lower()
}

/// Returns whether `byte` is printable in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_print(byte: u8) -> bool {
    AsciiClass::classify(byte).is_print()
}

/// Returns whether `byte` is punctuation in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_punct(byte: u8) -> bool {
    AsciiClass::classify(byte).is_punct()
}

/// Returns whether `byte` is whitespace in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_space(byte: u8) -> bool {
    AsciiClass::classify(byte).is_space()
}

/// Returns whether `byte` is uppercase in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_upper(byte: u8) -> bool {
    AsciiClass::classify(byte).is_upper()
}

/// Returns whether `byte` is a hexadecimal digit in the C/POSIX locale.
#[must_use]
#[inline]
pub const fn is_xdigit(byte: u8) -> bool {
    AsciiClass::classify(byte).is_xdigit()
}

#[cfg(test)]
mod tests {
    use super::{
        is_alnum, is_alpha, is_ascii, is_blank, is_cntrl, is_digit, is_graph, is_lower, is_print,
        is_punct, is_space, is_upper, is_xdigit, to_ascii, to_lower, to_upper, AsciiClass,
        ConvertError, NumberParseError, NumberParser, TextConverter, TextEncoding, Unrepresentable,
    };

    #[test]
    fn number_parser_requires_complete_explicit_integer_syntax() {
        let decimal = NumberParser::decimal();
        assert_eq!(decimal.radix(), 10);
        assert_eq!(decimal.parse_u64(b"18446744073709551615"), Ok(u64::MAX));
        assert_eq!(decimal.parse_i64(b"+9223372036854775807"), Ok(i64::MAX));
        assert_eq!(decimal.parse_i64(b"-9223372036854775808"), Ok(i64::MIN));

        assert_eq!(
            decimal.parse_u64(b"12tail"),
            Err(NumberParseError::InvalidDigit {
                index: 2,
                byte: b't'
            })
        );
        assert_eq!(
            decimal.parse_u64(b" 12"),
            Err(NumberParseError::InvalidDigit {
                index: 0,
                byte: b' '
            })
        );
        assert_eq!(
            decimal.parse_u64(b"+12"),
            Err(NumberParseError::UnexpectedSign { byte: b'+' })
        );
        assert_eq!(
            decimal.parse_i64(b"-"),
            Err(NumberParseError::SignWithoutDigits)
        );
        assert_eq!(decimal.parse_i64(b""), Err(NumberParseError::Empty));
    }

    #[test]
    fn number_parser_checks_signed_and_unsigned_boundaries() {
        let decimal = NumberParser::decimal();
        assert_eq!(
            decimal.parse_u64(b"18446744073709551616"),
            Err(NumberParseError::Overflow)
        );
        assert_eq!(
            decimal.parse_i64(b"9223372036854775808"),
            Err(NumberParseError::Overflow)
        );
        assert_eq!(
            decimal.parse_i64(b"-9223372036854775809"),
            Err(NumberParseError::Overflow)
        );
    }

    #[test]
    fn number_parser_uses_only_the_selected_ascii_radix() {
        assert_eq!(NumberParser::new(1), None);
        assert_eq!(NumberParser::new(37), None);

        let binary = NumberParser::new(2).expect("binary radix");
        assert_eq!(binary.parse_u64(b"101101"), Ok(45));
        assert_eq!(
            binary.parse_u64(b"102"),
            Err(NumberParseError::InvalidDigit {
                index: 2,
                byte: b'2'
            })
        );

        let hexadecimal = NumberParser::new(16).expect("hexadecimal radix");
        assert_eq!(hexadecimal.parse_u64(b"deadBEEF"), Ok(0xdead_beef));
        assert_eq!(
            hexadecimal.parse_u64(b"0x2a"),
            Err(NumberParseError::InvalidDigit {
                index: 1,
                byte: b'x'
            })
        );

        let base_36 = NumberParser::new(36).expect("base-36 radix");
        assert_eq!(base_36.parse_i64(b"-Z"), Ok(-35));
    }

    #[test]
    fn names_are_bounded_to_the_native_strict_subset() {
        assert_eq!(TextEncoding::from_name(b"UTF-8"), Some(TextEncoding::Utf8));
        assert_eq!(
            TextEncoding::from_name(b"us_ascii"),
            Some(TextEncoding::Ascii)
        );
        assert_eq!(
            TextEncoding::from_name(b"UTF-16LE"),
            Some(TextEncoding::Utf16Le)
        );
        assert_eq!(
            TextEncoding::from_name(b"UTF-16BE"),
            Some(TextEncoding::Utf16Be)
        );
        assert_eq!(
            TextEncoding::from_name(b"ucs4le"),
            Some(TextEncoding::Utf32Le)
        );
        assert_eq!(
            TextEncoding::from_name(b"ucs4be"),
            Some(TextEncoding::Utf32Be)
        );
        assert_eq!(
            TextEncoding::from_name(b"wchar-t"),
            Some(TextEncoding::WChar)
        );
        assert_eq!(TextEncoding::from_name(b"ISO-8859-1"), None);
        assert_eq!(TextEncoding::from_name(b"KOI8R"), None);
        assert_eq!(TextEncoding::from_name(b"not-an-encoding"), None);
    }

    #[test]
    fn converter_preserves_typed_progress_and_round_trips_utf8() {
        let input = "A€😀".as_bytes();
        let mut encoded = [0u8; 32];
        let mut to_utf32 = TextConverter::new(TextEncoding::Utf8, TextEncoding::Utf32Le);
        let conversion = to_utf32
            .convert(input, &mut encoded)
            .expect("UTF-32 conversion");
        assert_eq!(conversion.consumed, input.len());
        assert_eq!(conversion.produced, 12);
        assert_eq!(to_utf32.from(), TextEncoding::Utf8);
        assert_eq!(to_utf32.to(), TextEncoding::Utf32Le);

        let mut decoded = [0u8; 32];
        let mut to_utf8 = TextConverter::new(TextEncoding::Utf32Le, TextEncoding::Utf8);
        let decoded_conversion = to_utf8
            .convert(&encoded[..conversion.produced], &mut decoded)
            .expect("UTF-8 conversion");
        assert_eq!(&decoded[..decoded_conversion.produced], input);
    }

    #[test]
    fn output_full_and_replacement_report_resumable_progress() {
        let mut converter = TextConverter::new(TextEncoding::Utf8, TextEncoding::Utf16Le);
        let mut output = [0u8; 2];
        assert_eq!(
            converter.convert(b"AB", &mut output),
            Err(ConvertError::OutputFull {
                consumed: 1,
                produced: 2,
            })
        );

        let mut ascii = TextConverter::new(TextEncoding::Utf8, TextEncoding::Ascii);
        let mut replacement = [0u8; 2];
        let conversion = ascii
            .convert_with(
                "é".as_bytes(),
                &mut replacement,
                Unrepresentable::Byte(b'*'),
            )
            .expect("replacement conversion");
        assert_eq!(conversion.consumed, 2);
        assert_eq!(conversion.produced, 1);
        assert_eq!(conversion.substitutions, 1);
        assert_eq!(&replacement[..1], b"*");
    }

    #[test]
    fn malformed_and_incomplete_input_stays_unconsumed() {
        let mut converter = TextConverter::new(TextEncoding::Utf8, TextEncoding::Ascii);
        assert_eq!(
            converter.convert(&[0xe2, 0x82], &mut [0; 8]),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            converter.convert(&[0xe2, 0x28], &mut [0; 8]),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );
    }

    #[test]
    fn c_locale_byte_classes_match_the_fixed_ascii_table() {
        assert!(is_alnum(b'A'));
        assert!(is_alnum(b'7'));
        assert!(!is_alnum(b'_'));
        assert!(is_alpha(b'z'));
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'\n'));
        assert!(is_cntrl(0));
        assert!(is_cntrl(0x7f));
        assert!(!is_cntrl(b' '));
        assert!(is_digit(b'0'));
        assert!(!is_digit(b'9' + 1));
        assert!(is_graph(b'!'));
        assert!(!is_graph(b' '));
        assert!(is_lower(b'a'));
        assert!(!is_lower(b'A'));
        assert!(is_print(b' '));
        assert!(!is_print(0x1f));
        assert!(is_punct(b'!'));
        assert!(!is_punct(b'A'));
        assert!(is_space(b'\n'));
        assert!(is_space(b'\r'));
        assert!(is_space(b'\x0b'));
        assert!(is_upper(b'Z'));
        assert!(is_xdigit(b'F'));
        assert!(is_xdigit(b'f'));
        assert!(!is_xdigit(b'g'));

        let letter = AsciiClass::classify(b'A');
        assert!(letter.contains(AsciiClass::UPPER));
        assert!(letter.is_alpha());
        assert!(!letter.is_digit());
        assert!(letter.is_xdigit());
        assert_eq!(letter.bits(), AsciiClass::UPPER.bits() | AsciiClass::XDIGIT.bits());
    }

    #[test]
    fn high_bytes_are_valid_bytes_but_not_ascii_and_c_int_eof_is_not_a_type() {
        for byte in 0x80..=u8::MAX {
            assert!(!is_ascii(byte));
            assert_eq!(AsciiClass::classify(byte), AsciiClass::EMPTY);
            assert!(!is_alnum(byte));
            assert!(!is_alpha(byte));
            assert!(!is_graph(byte));
            assert!(!is_print(byte));
            assert_eq!(to_lower(byte), byte);
            assert_eq!(to_upper(byte), byte);
        }

        assert!(is_ascii(0x7f));
        assert!(!is_ascii(0x80));
        assert_eq!(to_ascii(0xff), 0x7f);
        assert_eq!(to_ascii(0x80), 0);
        assert_eq!(to_lower(0), 0);
        assert_eq!(to_upper(0), 0);
        // The public signatures accept only u8. Consequently C's -1/EOF and
        // every other out-of-range c_int must be rejected before reaching the
        // native facade instead of acquiring an accidental meaning.
        assert!(u8::try_from(-1_i16).is_err());
        assert!(u8::try_from(256_u16).is_err());
    }
}
