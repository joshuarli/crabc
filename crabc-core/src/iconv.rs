//! Allocation-free character-set conversion primitives.
//!
//! This is the foundation for crabc's native converter and a future shared
//! C `iconv` adapter.  It deliberately operates on borrowed slices and
//! returns typed progress/errors instead of C pointer-to-pointer updates or
//! TLS `errno`.  The ISO-8859 family table data is shared here, while the C
//! adapter retains ownership of its pointer/error contract. The scalar
//! converter remains intentionally small in this first slice; additional
//! encodings can be added without changing its ownership or error contracts.

/// Character encodings understood by the crabc converter.
//
// Keep the complete planned encoding vocabulary in this enum even while the
// The native implementation supports the scalar codecs and the shared
// ISO-8859-2..16 single-byte tables below. The non-exhaustive marker keeps
// adding a future table-backed encoding source compatible for callers which
// match the public type.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Encoding {
    /// UTF-8 as specified by Unicode scalar-value encoding rules.
    Utf8,
    /// ASCII (the 7-bit US-ASCII repertoire).
    Ascii,
    /// UTF-16 with little-endian code units.
    Utf16Le,
    /// UTF-16 with big-endian code units.
    Utf16Be,
    /// UTF-32 with little-endian code units.
    Utf32Le,
    /// UTF-32 with big-endian code units.
    Utf32Be,
    /// Linux/AArch64 `wchar_t`, currently a little-endian 32-bit scalar.
    WChar,
    /// ISO-8859-1 / Latin-1.
    Latin1,
    /// Windows code page 1252.
    Windows1252,
    /// Windows code page 1251.
    Windows1251,
    /// KOI8-R.
    Koi8R,
    /// GBK.
    Gbk,
    /// GB2312.
    Gb2312,
    /// Big5.
    Big5,
    /// EUC-JP.
    EucJp,
    /// Shift-JIS.
    ShiftJis,
    /// ISO-8859-2.
    Iso8859_2,
    /// ISO-8859-3.
    Iso8859_3,
    /// ISO-8859-4.
    Iso8859_4,
    /// ISO-8859-5.
    Iso8859_5,
    /// ISO-8859-6.
    Iso8859_6,
    /// ISO-8859-7.
    Iso8859_7,
    /// ISO-8859-8.
    Iso8859_8,
    /// ISO-8859-9.
    Iso8859_9,
    /// ISO-8859-10.
    Iso8859_10,
    /// ISO-8859-11 / TIS-620.
    Iso8859_11,
    /// ISO-8859-13.
    Iso8859_13,
    /// ISO-8859-14.
    Iso8859_14,
    /// ISO-8859-15.
    Iso8859_15,
    /// ISO-8859-16.
    Iso8859_16,
}

impl Encoding {
    /// Parses the spelling accepted by crabc's C `iconv_open` entry point.
    ///
    /// ASCII punctuation and case are ignored, matching the existing C
    /// adapter's name matching while retaining the caller's original bytes.
    /// Unknown or overlong names return `None` without allocation.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        fn normalized_equals(name: &[u8], target: &[u8]) -> bool {
            let mut name_index = 0;
            let mut target_index = 0;
            loop {
                while name_index < name.len() && !name[name_index].is_ascii_alphanumeric() {
                    name_index += 1;
                }
                while target_index < target.len() && !target[target_index].is_ascii_alphanumeric() {
                    target_index += 1;
                }
                match (name.get(name_index), target.get(target_index)) {
                    (None, None) => return true,
                    (Some(name_byte), Some(target_byte))
                        if name_byte.to_ascii_lowercase() == target_byte.to_ascii_lowercase() =>
                    {
                        name_index += 1;
                        target_index += 1;
                    }
                    _ => return false,
                }
            }
        }

        macro_rules! aliases {
            ($($encoding:ident => [$($alias:expr),+ $(,)?]),+ $(,)?) => {
                $(
                    if $(normalized_equals(name, $alias.as_bytes())) ||+ {
                        return Some(Self::$encoding);
                    }
                )+
            };
        }

        aliases! {
            Utf8 => ["utf8", "utf-8", "char"],
            Utf16Le => ["utf16le", "utf-16le"],
            Utf16Be => ["utf16be", "utf-16be"],
            Utf32Le => ["utf32le", "utf-32le", "ucs4le"],
            Utf32Be => ["utf32be", "utf-32be", "ucs4be"],
            WChar => ["wchart", "wchar-t"],
            Ascii => ["ascii", "usascii", "iso646"],
            Latin1 => ["iso88591", "iso-8859-1", "latin1"],
            Iso8859_2 => ["iso88592", "iso-8859-2"],
            Iso8859_3 => ["iso88593", "iso-8859-3"],
            Iso8859_4 => ["iso88594", "iso-8859-4"],
            Iso8859_5 => ["iso88595", "iso-8859-5"],
            Iso8859_6 => ["iso88596", "iso-8859-6"],
            Iso8859_7 => ["iso88597", "iso-8859-7"],
            Iso8859_8 => ["iso88598", "iso-8859-8"],
            Iso8859_9 => ["iso88599", "iso-8859-9"],
            Iso8859_10 => ["iso885910", "iso-8859-10"],
            Iso8859_11 => ["iso885911", "iso-8859-11", "tis620"],
            Iso8859_13 => ["iso885913", "iso-8859-13"],
            Iso8859_14 => ["iso885914", "iso-8859-14"],
            Iso8859_15 => ["iso885915", "iso-8859-15"],
            Iso8859_16 => ["iso885916", "iso-8859-16"],
            Windows1252 => ["cp1252", "windows1252", "windows-1252"],
            Windows1251 => ["cp1251", "windows1251", "windows-1251"],
            Koi8R => ["koi8r", "koi8-r"],
            Gbk => ["gbk", "cp936"],
            Gb2312 => ["gb2312"],
            Big5 => ["big5", "bigfive", "cp950"],
            EucJp => ["eucjp", "euc-jp"],
            ShiftJis => ["shiftjis", "sjis", "cp932"],
        }
        None
    }

    /// Returns whether the bounded scalar codec implements this encoding.
    ///
    /// The ISO-8859-2..16 variants use the shared single-byte tables below.
    /// Their undefined table slots intentionally retain the extracted table
    /// value (currently the byte's same-valued scalar), so this native seam
    /// does not silently invent an invalid-sequence policy. Musl-compatible
    /// C `iconv` undefined-byte behavior remains an adapter-parity question.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::Utf8
                | Self::Ascii
                | Self::Utf16Le
                | Self::Utf16Be
                | Self::Utf32Le
                | Self::Utf32Be
                | Self::WChar
                | Self::Iso8859_2
                | Self::Iso8859_3
                | Self::Iso8859_4
                | Self::Iso8859_5
                | Self::Iso8859_6
                | Self::Iso8859_7
                | Self::Iso8859_8
                | Self::Iso8859_9
                | Self::Iso8859_10
                | Self::Iso8859_11
                | Self::Iso8859_13
                | Self::Iso8859_14
                | Self::Iso8859_15
                | Self::Iso8859_16
        )
    }
}

// The C adapter still owns its pointer/error contract, but the ISO-8859
// repertoire tables are data-only and can be shared without carrying that
// contract into this crate. Keeping the tables in this module gives the
// eventual typed converter a single source of byte-to-scalar data.
include!("iconv_iso8859.rs");

/// One of the single-byte ISO-8859 table-backed encodings currently present
/// in the legacy iconv implementation.
///
/// These accessors preserve the existing table data exactly. They do not
/// claim that the legacy C adapter's aliases, error progress, or undefined
/// byte policy are the final musl contract; those remain a separate adapter
/// parity task.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Iso8859 {
    /// ISO-8859-2 (Latin-2).
    Iso8859_2,
    /// ISO-8859-3 (Latin-3).
    Iso8859_3,
    /// ISO-8859-4 (Latin-4).
    Iso8859_4,
    /// ISO-8859-5 (Cyrillic).
    Iso8859_5,
    /// ISO-8859-6 (Arabic).
    Iso8859_6,
    /// ISO-8859-7 (Greek).
    Iso8859_7,
    /// ISO-8859-8 (Hebrew).
    Iso8859_8,
    /// ISO-8859-9 (Latin-5).
    Iso8859_9,
    /// ISO-8859-10 (Latin-6).
    Iso8859_10,
    /// ISO-8859-11 (Thai/TIS-620 table).
    Iso8859_11,
    /// ISO-8859-13 (Latin-7).
    Iso8859_13,
    /// ISO-8859-14 (Latin-8).
    Iso8859_14,
    /// ISO-8859-15 (Latin-9).
    Iso8859_15,
    /// ISO-8859-16 (Latin-10).
    Iso8859_16,
}

impl Iso8859 {
    /// Returns the table family member represented by an [`Encoding`].
    #[must_use]
    pub const fn from_encoding(encoding: Encoding) -> Option<Self> {
        match encoding {
            Encoding::Iso8859_2 => Some(Self::Iso8859_2),
            Encoding::Iso8859_3 => Some(Self::Iso8859_3),
            Encoding::Iso8859_4 => Some(Self::Iso8859_4),
            Encoding::Iso8859_5 => Some(Self::Iso8859_5),
            Encoding::Iso8859_6 => Some(Self::Iso8859_6),
            Encoding::Iso8859_7 => Some(Self::Iso8859_7),
            Encoding::Iso8859_8 => Some(Self::Iso8859_8),
            Encoding::Iso8859_9 => Some(Self::Iso8859_9),
            Encoding::Iso8859_10 => Some(Self::Iso8859_10),
            Encoding::Iso8859_11 => Some(Self::Iso8859_11),
            Encoding::Iso8859_13 => Some(Self::Iso8859_13),
            Encoding::Iso8859_14 => Some(Self::Iso8859_14),
            Encoding::Iso8859_15 => Some(Self::Iso8859_15),
            Encoding::Iso8859_16 => Some(Self::Iso8859_16),
            _ => None,
        }
    }

    /// Returns the corresponding planned [`Encoding`] variant.
    #[must_use]
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::Iso8859_2 => Encoding::Iso8859_2,
            Self::Iso8859_3 => Encoding::Iso8859_3,
            Self::Iso8859_4 => Encoding::Iso8859_4,
            Self::Iso8859_5 => Encoding::Iso8859_5,
            Self::Iso8859_6 => Encoding::Iso8859_6,
            Self::Iso8859_7 => Encoding::Iso8859_7,
            Self::Iso8859_8 => Encoding::Iso8859_8,
            Self::Iso8859_9 => Encoding::Iso8859_9,
            Self::Iso8859_10 => Encoding::Iso8859_10,
            Self::Iso8859_11 => Encoding::Iso8859_11,
            Self::Iso8859_13 => Encoding::Iso8859_13,
            Self::Iso8859_14 => Encoding::Iso8859_14,
            Self::Iso8859_15 => Encoding::Iso8859_15,
            Self::Iso8859_16 => Encoding::Iso8859_16,
        }
    }

    /// Decodes one byte using this table's existing scalar mapping.
    #[must_use]
    #[inline]
    pub fn decode(self, byte: u8) -> u32 {
        match self {
            Self::Iso8859_2 => iso8859_to_u(&ISO8859_2_TO_U, byte),
            Self::Iso8859_3 => iso8859_to_u(&ISO8859_3_TO_U, byte),
            Self::Iso8859_4 => iso8859_to_u(&ISO8859_4_TO_U, byte),
            Self::Iso8859_5 => iso8859_to_u(&ISO8859_5_TO_U, byte),
            Self::Iso8859_6 => iso8859_to_u(&ISO8859_6_TO_U, byte),
            Self::Iso8859_7 => iso8859_to_u(&ISO8859_7_TO_U, byte),
            Self::Iso8859_8 => iso8859_to_u(&ISO8859_8_TO_U, byte),
            Self::Iso8859_9 => iso8859_to_u(&ISO8859_9_TO_U, byte),
            Self::Iso8859_10 => iso8859_to_u(&ISO8859_10_TO_U, byte),
            Self::Iso8859_11 => iso8859_to_u(&ISO8859_11_TO_U, byte),
            Self::Iso8859_13 => iso8859_to_u(&ISO8859_13_TO_U, byte),
            Self::Iso8859_14 => iso8859_to_u(&ISO8859_14_TO_U, byte),
            Self::Iso8859_15 => iso8859_to_u(&ISO8859_15_TO_U, byte),
            Self::Iso8859_16 => iso8859_to_u(&ISO8859_16_TO_U, byte),
        }
    }

    /// Finds the first table byte representing `codepoint`.
    #[must_use]
    #[inline]
    pub fn encode(self, codepoint: u32) -> Option<u8> {
        match self {
            Self::Iso8859_2 => u_to_iso8859(&ISO8859_2_TO_U, codepoint),
            Self::Iso8859_3 => u_to_iso8859(&ISO8859_3_TO_U, codepoint),
            Self::Iso8859_4 => u_to_iso8859(&ISO8859_4_TO_U, codepoint),
            Self::Iso8859_5 => u_to_iso8859(&ISO8859_5_TO_U, codepoint),
            Self::Iso8859_6 => u_to_iso8859(&ISO8859_6_TO_U, codepoint),
            Self::Iso8859_7 => u_to_iso8859(&ISO8859_7_TO_U, codepoint),
            Self::Iso8859_8 => u_to_iso8859(&ISO8859_8_TO_U, codepoint),
            Self::Iso8859_9 => u_to_iso8859(&ISO8859_9_TO_U, codepoint),
            Self::Iso8859_10 => u_to_iso8859(&ISO8859_10_TO_U, codepoint),
            Self::Iso8859_11 => u_to_iso8859(&ISO8859_11_TO_U, codepoint),
            Self::Iso8859_13 => u_to_iso8859(&ISO8859_13_TO_U, codepoint),
            Self::Iso8859_14 => u_to_iso8859(&ISO8859_14_TO_U, codepoint),
            Self::Iso8859_15 => u_to_iso8859(&ISO8859_15_TO_U, codepoint),
            Self::Iso8859_16 => u_to_iso8859(&ISO8859_16_TO_U, codepoint),
        }
    }
}

/// Policy for code points which cannot be represented in the destination.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Unrepresentable {
    /// Stop with [`ConvertError::Unrepresentable`].
    Error,
    /// Emit one literal byte and count a substitution.
    ///
    /// This is intentionally a byte policy rather than a Unicode replacement
    /// character: it preserves crabc's existing C compatibility behavior,
    /// where an unrepresentable scalar is replaced with `'*'` in the output.
    Byte(u8),
}

/// A conversion operation's successfully consumed and produced counts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Conversion {
    /// Number of source bytes consumed.
    pub consumed: usize,
    /// Number of destination bytes produced.
    pub produced: usize,
    /// Number of source scalars replaced under [`Unrepresentable::Byte`].
    pub substitutions: usize,
}

/// A typed conversion failure with resumable progress.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConvertError {
    /// One of the planned table-backed encodings has not been extracted yet.
    Unsupported { from: Encoding, to: Encoding },
    /// The source ends in a valid prefix of one scalar.
    Incomplete { consumed: usize, produced: usize },
    /// The source contains an invalid scalar sequence.
    Invalid { consumed: usize, produced: usize },
    /// The destination cannot hold the next encoded scalar.
    OutputFull { consumed: usize, produced: usize },
    /// The decoded scalar is not in the destination repertoire.
    Unrepresentable {
        consumed: usize,
        produced: usize,
        codepoint: u32,
    },
}

impl ConvertError {
    /// Returns the source bytes consumed before this error.
    #[must_use]
    pub const fn consumed(self) -> usize {
        match self {
            Self::Unsupported { .. } => 0,
            Self::Incomplete { consumed, .. }
            | Self::Invalid { consumed, .. }
            | Self::OutputFull { consumed, .. }
            | Self::Unrepresentable { consumed, .. } => consumed,
        }
    }

    /// Returns the destination bytes produced before this error.
    #[must_use]
    pub const fn produced(self) -> usize {
        match self {
            Self::Unsupported { .. } => 0,
            Self::Incomplete { produced, .. }
            | Self::Invalid { produced, .. }
            | Self::OutputFull { produced, .. }
            | Self::Unrepresentable { produced, .. } => produced,
        }
    }
}

/// A borrowed-slice character-set converter.
///
/// The first implementation has no shift state, but the converter is still
/// mutably borrowed by [`Self::convert`] and has [`Self::reset`] so stateful
/// table-backed encodings can be added without changing its ownership or
/// call-site contract.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Converter {
    from: Encoding,
    to: Encoding,
}

impl Converter {
    /// Creates a converter from `from` to `to`.
    #[must_use]
    pub const fn new(from: Encoding, to: Encoding) -> Self {
        Self { from, to }
    }

    /// Returns the source encoding.
    #[must_use]
    pub const fn from(&self) -> Encoding {
        self.from
    }

    /// Returns the destination encoding.
    #[must_use]
    pub const fn to(&self) -> Encoding {
        self.to
    }

    /// Converts all complete source scalars which fit in `output`.
    ///
    /// An empty input succeeds with zero progress.  If a source scalar is
    /// incomplete, malformed, unrepresentable, or does not fit, the error
    /// reports progress before that scalar; the caller can resume at
    /// `input[error.consumed()..]` and `output[error.produced()..]`.
    pub fn convert(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> core::result::Result<Conversion, ConvertError> {
        self.convert_with(input, output, Unrepresentable::Error)
    }

    /// Converts using an explicit policy for destination-repertoire misses.
    pub fn convert_with(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        policy: Unrepresentable,
    ) -> core::result::Result<Conversion, ConvertError> {
        if !self.from.is_supported() || !self.to.is_supported() {
            return Err(ConvertError::Unsupported {
                from: self.from,
                to: self.to,
            });
        }

        let mut consumed = 0;
        let mut produced = 0;
        let mut substitutions = 0;
        while consumed < input.len() {
            let (codepoint, source_len) = match decode_scalar(self.from, &input[consumed..]) {
                Ok(value) => value,
                Err(DecodeError::Incomplete) => {
                    return Err(ConvertError::Incomplete { consumed, produced });
                }
                Err(DecodeError::Invalid) => {
                    return Err(ConvertError::Invalid { consumed, produced });
                }
            };

            let mut encoded = [0u8; 4];
            let encoded_len = match encode_scalar(self.to, codepoint, &mut encoded) {
                Ok(length) => length,
                Err(EncodeError::Unrepresentable) => match policy {
                    Unrepresentable::Error => {
                        return Err(ConvertError::Unrepresentable {
                            consumed,
                            produced,
                            codepoint,
                        });
                    }
                    Unrepresentable::Byte(replacement) => {
                        if output.len().saturating_sub(produced) < 1 {
                            return Err(ConvertError::OutputFull { consumed, produced });
                        }
                        output[produced] = replacement;
                        produced += 1;
                        consumed += source_len;
                        substitutions += 1;
                        continue;
                    }
                },
            };

            if output.len().saturating_sub(produced) < encoded_len {
                return Err(ConvertError::OutputFull { consumed, produced });
            }
            output[produced..produced + encoded_len].copy_from_slice(&encoded[..encoded_len]);
            consumed += source_len;
            produced += encoded_len;
        }

        Ok(Conversion {
            consumed,
            produced,
            substitutions,
        })
    }

    /// Resets any stateful conversion state.
    ///
    /// The extracted codecs are stateless, so this is currently a no-op.
    pub const fn reset(&mut self) {}
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DecodeError {
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum EncodeError {
    Unrepresentable,
}

fn decode_scalar(
    encoding: Encoding,
    input: &[u8],
) -> core::result::Result<(u32, usize), DecodeError> {
    match encoding {
        Encoding::Utf8 => decode_utf8(input),
        Encoding::Ascii => decode_ascii(input),
        Encoding::Utf16Le => decode_utf16le(input),
        Encoding::Utf16Be => decode_utf16be(input),
        Encoding::Utf32Le | Encoding::WChar => decode_utf32le(input),
        Encoding::Utf32Be => decode_utf32be(input),
        _ => {
            let table = Iso8859::from_encoding(encoding).ok_or(DecodeError::Invalid)?;
            let byte = *input.first().ok_or(DecodeError::Incomplete)?;
            Ok((table.decode(byte), 1))
        }
    }
}

fn decode_ascii(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    let byte = *input.first().ok_or(DecodeError::Incomplete)?;
    if byte < 0x80 {
        Ok((byte as u32, 1))
    } else {
        Err(DecodeError::Invalid)
    }
}

fn decode_utf8(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    let first = *input.first().ok_or(DecodeError::Incomplete)?;
    if first < 0x80 {
        return Ok((first as u32, 1));
    }

    let (length, minimum_second, maximum_second, initial) = match first {
        0xc2..=0xdf => (2, 0x80, 0xbf, (first & 0x1f) as u32),
        0xe0 => (3, 0xa0, 0xbf, (first & 0x0f) as u32),
        0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf, (first & 0x0f) as u32),
        0xed => (3, 0x80, 0x9f, (first & 0x0f) as u32),
        0xf0 => (4, 0x90, 0xbf, (first & 0x07) as u32),
        0xf1..=0xf3 => (4, 0x80, 0xbf, (first & 0x07) as u32),
        0xf4 => (4, 0x80, 0x8f, (first & 0x07) as u32),
        _ => return Err(DecodeError::Invalid),
    };

    if input.len() >= 2 {
        let second = input[1];
        if second < minimum_second || second > maximum_second {
            return Err(DecodeError::Invalid);
        }
    }
    let available_length = core::cmp::min(input.len(), length);
    if available_length > 2 {
        for &byte in &input[2..available_length] {
            if byte & 0xc0 != 0x80 {
                return Err(DecodeError::Invalid);
            }
        }
    }
    if input.len() < length {
        return Err(DecodeError::Incomplete);
    }

    let second = input[1];
    let mut codepoint = (initial << 6) | (second & 0x3f) as u32;
    for &byte in &input[2..length] {
        codepoint = (codepoint << 6) | (byte & 0x3f) as u32;
    }
    Ok((codepoint, length))
}

fn decode_utf16le(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    decode_utf16(input, false)
}

fn decode_utf16be(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    decode_utf16(input, true)
}

fn decode_utf16(input: &[u8], big_endian: bool) -> core::result::Result<(u32, usize), DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::Incomplete);
    }
    let first_bytes = [input[0], input[1]];
    let first = if big_endian {
        u16::from_be_bytes(first_bytes)
    } else {
        u16::from_le_bytes(first_bytes)
    };
    match first {
        0xd800..=0xdbff => {
            if input.len() < 4 {
                return Err(DecodeError::Incomplete);
            }
            let second_bytes = [input[2], input[3]];
            let second = if big_endian {
                u16::from_be_bytes(second_bytes)
            } else {
                u16::from_le_bytes(second_bytes)
            };
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(DecodeError::Invalid);
            }
            let high = (first - 0xd800) as u32;
            let low = (second - 0xdc00) as u32;
            Ok(((high << 10) + low + 0x1_0000, 4))
        }
        0xdc00..=0xdfff => Err(DecodeError::Invalid),
        _ => Ok((first as u32, 2)),
    }
}

fn decode_utf32le(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    decode_utf32(input, false)
}

fn decode_utf32be(input: &[u8]) -> core::result::Result<(u32, usize), DecodeError> {
    decode_utf32(input, true)
}

fn decode_utf32(input: &[u8], big_endian: bool) -> core::result::Result<(u32, usize), DecodeError> {
    if input.len() < 4 {
        return Err(DecodeError::Incomplete);
    }
    let bytes = [input[0], input[1], input[2], input[3]];
    let codepoint = if big_endian {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    };
    if codepoint > 0x10_ffff || (0xd800..=0xdfff).contains(&codepoint) {
        return Err(DecodeError::Invalid);
    }
    Ok((codepoint, 4))
}

fn encode_scalar(
    encoding: Encoding,
    codepoint: u32,
    output: &mut [u8; 4],
) -> core::result::Result<usize, EncodeError> {
    match encoding {
        Encoding::Utf8 => {
            if codepoint < 0x80 {
                output[0] = codepoint as u8;
                Ok(1)
            } else if codepoint < 0x800 {
                output[0] = 0xc0 | (codepoint >> 6) as u8;
                output[1] = 0x80 | (codepoint & 0x3f) as u8;
                Ok(2)
            } else if codepoint < 0x1_0000 {
                output[0] = 0xe0 | (codepoint >> 12) as u8;
                output[1] = 0x80 | ((codepoint >> 6) & 0x3f) as u8;
                output[2] = 0x80 | (codepoint & 0x3f) as u8;
                Ok(3)
            } else {
                output[0] = 0xf0 | (codepoint >> 18) as u8;
                output[1] = 0x80 | ((codepoint >> 12) & 0x3f) as u8;
                output[2] = 0x80 | ((codepoint >> 6) & 0x3f) as u8;
                output[3] = 0x80 | (codepoint & 0x3f) as u8;
                Ok(4)
            }
        }
        Encoding::Ascii => {
            if codepoint < 0x80 {
                output[0] = codepoint as u8;
                Ok(1)
            } else {
                Err(EncodeError::Unrepresentable)
            }
        }
        Encoding::Utf16Le => {
            if codepoint < 0x1_0000 {
                let unit = codepoint as u16;
                let bytes = unit.to_le_bytes();
                output[0] = bytes[0];
                output[1] = bytes[1];
                Ok(2)
            } else {
                let scalar = codepoint - 0x1_0000;
                let high = (0xd800 + (scalar >> 10)) as u16;
                let low = (0xdc00 + (scalar & 0x3ff)) as u16;
                let high = high.to_le_bytes();
                let low = low.to_le_bytes();
                output[0] = high[0];
                output[1] = high[1];
                output[2] = low[0];
                output[3] = low[1];
                Ok(4)
            }
        }
        Encoding::Utf16Be => {
            if codepoint < 0x1_0000 {
                let bytes = (codepoint as u16).to_be_bytes();
                output[0] = bytes[0];
                output[1] = bytes[1];
                Ok(2)
            } else {
                let scalar = codepoint - 0x1_0000;
                let high = (0xd800 + (scalar >> 10)) as u16;
                let low = (0xdc00 + (scalar & 0x3ff)) as u16;
                let high = high.to_be_bytes();
                let low = low.to_be_bytes();
                output[0] = high[0];
                output[1] = high[1];
                output[2] = low[0];
                output[3] = low[1];
                Ok(4)
            }
        }
        Encoding::Utf32Le | Encoding::WChar => {
            output.copy_from_slice(&codepoint.to_le_bytes());
            Ok(4)
        }
        Encoding::Utf32Be => {
            output.copy_from_slice(&codepoint.to_be_bytes());
            Ok(4)
        }
        _ => {
            let table = Iso8859::from_encoding(encoding).ok_or(EncodeError::Unrepresentable)?;
            output[0] = table
                .encode(codepoint)
                .ok_or(EncodeError::Unrepresentable)?;
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ConvertError, Converter, Encoding, Iso8859, Unrepresentable};

    #[test]
    fn utf8_round_trip_and_progress_are_typed() {
        let input = "A€😀".as_bytes();
        let mut encoded = [0u8; 32];
        let mut to_utf32 = Converter::new(Encoding::Utf8, Encoding::Utf32Le);
        let conversion = to_utf32.convert(input, &mut encoded).unwrap();
        assert_eq!(conversion.consumed, input.len());
        assert_eq!(conversion.produced, 12);

        let mut decoded = [0u8; 32];
        let mut to_utf8 = Converter::new(Encoding::Utf32Le, Encoding::Utf8);
        let conversion = to_utf8
            .convert(&encoded[..conversion.produced], &mut decoded)
            .unwrap();
        assert_eq!(&decoded[..conversion.produced], input);
    }

    #[test]
    fn malformed_and_incomplete_sequences_do_not_consume_input() {
        let mut converter = Converter::new(Encoding::Utf8, Encoding::Ascii);
        assert_eq!(
            converter.convert(&[0xe2], &mut [0; 8]),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            converter.convert(&[0xe2, 0x82], &mut [0; 8]),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            converter.convert(&[0xe2, 0x28, 0xa1], &mut [0; 8]),
            Err(ConvertError::Invalid {
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
        assert_eq!(
            converter.convert(&[0xf0, 0x8f, 0x80, 0x80], &mut [0; 8]),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );
    }

    #[test]
    fn output_full_reports_prior_progress() {
        let mut converter = Converter::new(Encoding::Utf8, Encoding::Utf16Le);
        let mut output = [0u8; 2];
        assert_eq!(
            converter.convert("AB".as_bytes(), &mut output),
            Err(ConvertError::OutputFull {
                consumed: 1,
                produced: 2,
            })
        );
    }

    #[test]
    fn utf16_surrogates_and_utf32_scalars_are_strict() {
        let mut converter = Converter::new(Encoding::Utf16Le, Encoding::Utf8);
        let mut output = [0u8; 8];
        let conversion = converter
            .convert(&[0x3c, 0xd8, 0x0c, 0xdf], &mut output)
            .unwrap();
        assert_eq!(&output[..conversion.produced], "🌌".as_bytes());

        assert_eq!(
            converter.convert(&[0x00, 0xd8, 0x00, 0x00], &mut output),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );

        let mut converter = Converter::new(Encoding::Utf32Le, Encoding::Utf8);
        assert_eq!(
            converter.convert(&[0x00, 0x00, 0x11, 0x00], &mut output),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );
    }

    #[test]
    fn big_endian_and_wchar_scalars_use_explicit_byte_order() {
        let input = "A€😀".as_bytes();

        let mut utf16be = [0u8; 16];
        let mut to_utf16be = Converter::new(Encoding::Utf8, Encoding::Utf16Be);
        let conversion = to_utf16be.convert(input, &mut utf16be).unwrap();
        assert_eq!(
            &utf16be[..conversion.produced],
            &[0x00, 0x41, 0x20, 0xac, 0xd8, 0x3d, 0xde, 0x00]
        );

        let mut decoded = [0u8; 16];
        let mut from_utf16be = Converter::new(Encoding::Utf16Be, Encoding::Utf8);
        let conversion = from_utf16be
            .convert(&utf16be[..conversion.produced], &mut decoded)
            .unwrap();
        assert_eq!(&decoded[..conversion.produced], input);

        let mut utf32be = [0u8; 16];
        let mut to_utf32be = Converter::new(Encoding::Utf8, Encoding::Utf32Be);
        let conversion = to_utf32be.convert(input, &mut utf32be).unwrap();
        assert_eq!(
            &utf32be[..conversion.produced],
            &[0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x20, 0xac, 0x00, 0x01, 0xf6, 0x00]
        );

        let mut wchar = [0u8; 16];
        let mut to_wchar = Converter::new(Encoding::Utf8, Encoding::WChar);
        let conversion = to_wchar.convert(input, &mut wchar).unwrap();
        assert_eq!(
            &wchar[..conversion.produced],
            &[0x41, 0x00, 0x00, 0x00, 0xac, 0x20, 0x00, 0x00, 0x00, 0xf6, 0x01, 0x00]
        );

        let mut decoded = [0u8; 16];
        let mut from_wchar = Converter::new(Encoding::WChar, Encoding::Utf8);
        let conversion = from_wchar
            .convert(&wchar[..conversion.produced], &mut decoded)
            .unwrap();
        assert_eq!(&decoded[..conversion.produced], input);

        assert_eq!(
            Converter::new(Encoding::Utf16Be, Encoding::Utf8)
                .convert(&[0xd8, 0x3d, 0x00, 0x41], &mut decoded),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            Converter::new(Encoding::Utf32Be, Encoding::Utf8)
                .convert(&[0x00, 0x11, 0x00, 0x00], &mut decoded),
            Err(ConvertError::Invalid {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            Converter::new(Encoding::Utf16Be, Encoding::Utf8).convert(&[0xd8], &mut decoded),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            Converter::new(Encoding::Utf32Be, Encoding::Utf8)
                .convert(&[0x00, 0x00, 0x00], &mut decoded),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
        assert_eq!(
            Converter::new(Encoding::WChar, Encoding::Utf8)
                .convert(&[0x41, 0x00, 0x00], &mut decoded),
            Err(ConvertError::Incomplete {
                consumed: 0,
                produced: 0,
            })
        );
    }

    #[test]
    fn explicit_replacement_is_counted_without_errno_or_allocation() {
        let mut converter = Converter::new(Encoding::Utf8, Encoding::Ascii);
        let mut output = [0u8; 4];
        let conversion = converter
            .convert_with("é".as_bytes(), &mut output, Unrepresentable::Byte(b'*'))
            .unwrap();
        assert_eq!(
            conversion,
            super::Conversion {
                consumed: 2,
                produced: 1,
                substitutions: 1,
            }
        );
        assert_eq!(&output[..1], b"*");
    }

    #[test]
    fn names_are_punctuation_insensitive_and_unknown_names_fail() {
        assert_eq!(Encoding::from_name(b"UTF-16LE"), Some(Encoding::Utf16Le));
        assert_eq!(Encoding::from_name(b"iso_8859-1"), Some(Encoding::Latin1));
        assert_eq!(Encoding::from_name(b"NONSENSE"), None);
    }

    #[test]
    fn future_table_codecs_are_represented_but_report_unsupported() {
        let mut converter = Converter::new(Encoding::Utf8, Encoding::Latin1);
        assert_eq!(
            converter.convert(b"A", &mut [0; 4]),
            Err(ConvertError::Unsupported {
                from: Encoding::Utf8,
                to: Encoding::Latin1,
            })
        );
    }

    #[test]
    fn iso8859_table_codecs_convert_all_supported_variants() {
        let encodings = [
            Encoding::Iso8859_2,
            Encoding::Iso8859_3,
            Encoding::Iso8859_4,
            Encoding::Iso8859_5,
            Encoding::Iso8859_6,
            Encoding::Iso8859_7,
            Encoding::Iso8859_8,
            Encoding::Iso8859_9,
            Encoding::Iso8859_10,
            Encoding::Iso8859_11,
            Encoding::Iso8859_13,
            Encoding::Iso8859_14,
            Encoding::Iso8859_15,
            Encoding::Iso8859_16,
        ];

        for encoding in encodings {
            assert!(encoding.is_supported());

            let mut encoded = [0u8; 2];
            let mut to_table = Converter::new(Encoding::Utf8, encoding);
            let conversion = to_table.convert(b"AZ", &mut encoded).unwrap();
            assert_eq!(
                conversion,
                super::Conversion {
                    consumed: 2,
                    produced: 2,
                    substitutions: 0,
                }
            );
            assert_eq!(&encoded, b"AZ");

            let mut decoded = [0u8; 2];
            let mut to_utf8 = Converter::new(encoding, Encoding::Utf8);
            let conversion = to_utf8.convert(&encoded, &mut decoded).unwrap();
            assert_eq!(conversion.consumed, 2);
            assert_eq!(conversion.produced, 2);
            assert_eq!(&decoded, b"AZ");
        }
    }

    #[test]
    fn iso8859_table_mapping_and_undefined_slot_policy_are_explicit() {
        let mut from_iso2 = Converter::new(Encoding::Iso8859_2, Encoding::Utf8);
        let mut utf8 = [0u8; 4];
        let conversion = from_iso2.convert(&[0xa1], &mut utf8).unwrap();
        assert_eq!(conversion.produced, 2);
        assert_eq!(&utf8[..2], "Ą".as_bytes());

        let mut to_iso15 = Converter::new(Encoding::Utf8, Encoding::Iso8859_15);
        let mut iso15 = [0u8; 1];
        let conversion = to_iso15.convert("€".as_bytes(), &mut iso15).unwrap();
        assert_eq!(conversion.produced, 1);
        assert_eq!(iso15[0], 0xa4);

        // ISO-8859-6 leaves 0xa1 undefined. The extracted table deliberately
        // retains that slot as U+00A1; conversion therefore remains a valid
        // one-byte decode until the musl C-adapter policy is specified.
        let mut from_iso6 = Converter::new(Encoding::Iso8859_6, Encoding::Utf8);
        let conversion = from_iso6.convert(&[0xa1], &mut utf8).unwrap();
        assert_eq!(conversion.produced, 2);
        assert_eq!(&utf8[..2], "¡".as_bytes());
    }

    #[test]
    fn iso8859_tables_are_shared_through_typed_data_access() {
        let tables = [
            Iso8859::Iso8859_2,
            Iso8859::Iso8859_3,
            Iso8859::Iso8859_4,
            Iso8859::Iso8859_5,
            Iso8859::Iso8859_6,
            Iso8859::Iso8859_7,
            Iso8859::Iso8859_8,
            Iso8859::Iso8859_9,
            Iso8859::Iso8859_10,
            Iso8859::Iso8859_11,
            Iso8859::Iso8859_13,
            Iso8859::Iso8859_14,
            Iso8859::Iso8859_15,
            Iso8859::Iso8859_16,
        ];

        for table in tables {
            assert_eq!(Iso8859::from_encoding(table.encoding()), Some(table));
            assert_eq!(table.decode(b'A'), u32::from(b'A'));
            assert_eq!(table.decode(0x80), 0x80);
            assert_eq!(table.encode(table.decode(b'A')), Some(b'A'));
            assert_eq!(table.encode(table.decode(0x80)), Some(0x80));
        }

        assert_eq!(Iso8859::Iso8859_2.decode(0xa1), 0x0104);
        assert_eq!(Iso8859::Iso8859_5.decode(0xb0), 0x0410);
        assert_eq!(Iso8859::Iso8859_15.decode(0xa4), 0x20ac);
        assert_eq!(Iso8859::Iso8859_16.encode(0x0104), Some(0xa1));
        assert_eq!(Iso8859::Iso8859_15.encode(0x20ac), Some(0xa4));
        assert_eq!(Iso8859::Iso8859_2.encode(0x1f600), None);
    }
}
