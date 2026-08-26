//! Native representations of the small legacy numeric formats retained by
//! musl's public ABI.
//!
//! The C `a64l`/`l64a` pair is not a general-purpose base-64 codec.  It
//! encodes the low 32 bits of a `long` in at most six least-significant-digit
//! radix-64 characters, using musl's historical `./0-9A-Za-z` alphabet.  The
//! typed API keeps that representation explicit and makes the point at which
//! decoding stops observable without exposing a C pointer or `errno`.

/// Musl's POSIX radix-64 alphabet, ordered by the numeric value of a digit.
pub const RADIX64_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The maximum number of characters consumed by `a64l` or emitted by `l64a`.
pub const MAX_ENCODED_DIGITS: usize = 6;

/// Why [`EncodedLong::decode`] stopped consuming its input.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DecodeStatus {
    /// The borrowed input ended before a NUL or an invalid character.
    EndOfInput,
    /// A NUL byte ended the C-string representation.
    Nul,
    /// The first byte outside the radix-64 alphabet was encountered.
    InvalidByte { index: usize, byte: u8 },
    /// Six digits have been consumed; the format deliberately has no seventh
    /// digit even when the input contains more bytes.
    DigitLimit,
}

/// Short spelling for the typed decoder stop status.
pub type DecodeStop = DecodeStatus;

/// Result of decoding one bounded radix-64-long value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DecodedLong {
    /// The low 32-bit payload sign-extended to staged Linux 64-bit `long` width.
    pub value: i64,
    /// Number of input bytes consumed, excluding the stopping byte.
    pub consumed: usize,
    /// The typed reason decoding stopped.
    pub status: DecodeStatus,
}

/// Alias emphasizing that decoding always returns a typed stop outcome.
pub type DecodeOutcome = DecodedLong;

impl DecodedLong {
    /// Returns the decoded staged Linux 64-bit `long` value.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.value
    }

    /// Returns the number of consumed radix-64 characters.
    #[must_use]
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    /// Returns why decoding stopped.
    #[must_use]
    pub const fn status(self) -> DecodeStatus {
        self.status
    }

    /// Compatibility spelling for callers which describe the status as a
    /// stop rather than an input status.
    #[must_use]
    pub const fn stop(self) -> DecodeStatus {
        self.status
    }
}

/// The bounded musl radix-64 representation of a staged Linux 64-bit `long`.
///
/// The representation owns its six-byte inline storage, so it remains useful
/// in `no_std` code and never inherits `l64a`'s process-global return buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EncodedLong {
    bytes: [u8; MAX_ENCODED_DIGITS],
    len: u8,
}

impl EncodedLong {
    /// Constructs the bounded representation for a staged Linux 64-bit `long` value.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self::encode(value)
    }

    /// Encodes the low 32 bits of `value` in least-significant-digit order.
    /// Zero has the historical empty representation.
    #[must_use]
    pub const fn encode(value: i64) -> Self {
        let mut remaining = value as u32;
        let mut bytes = [0; MAX_ENCODED_DIGITS];
        let mut len = 0usize;
        while remaining != 0 && len < MAX_ENCODED_DIGITS {
            bytes[len] = RADIX64_ALPHABET[(remaining & 63) as usize];
            remaining >>= 6;
            len += 1;
        }
        Self {
            bytes,
            len: len as u8,
        }
    }

    /// Alias for [`Self::encode`] that names the source type explicitly.
    #[must_use]
    pub const fn from_long(value: i64) -> Self {
        Self::encode(value)
    }

    /// Alias for [`Self::encode`] for code which uses integer terminology.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        Self::encode(value)
    }

    /// Decodes at most one C-string-like radix-64-long value.
    ///
    /// The first NUL or invalid byte is not consumed.  As with musl, a value
    /// is limited to six digits; the resulting payload is converted through
    /// `u32` then `i32`, providing the required 64-bit sign extension.
    #[must_use]
    pub fn decode(input: &[u8]) -> DecodedLong {
        let mut value = 0u32;
        let mut index = 0usize;
        while index < input.len() && index < MAX_ENCODED_DIGITS {
            let byte = input[index];
            if byte == 0 {
                return DecodedLong {
                    value: (value as i32) as i64,
                    consumed: index,
                    status: DecodeStatus::Nul,
                };
            }
            let Some(digit) = radix64_digit(byte) else {
                return DecodedLong {
                    value: (value as i32) as i64,
                    consumed: index,
                    status: DecodeStatus::InvalidByte { index, byte },
                };
            };
            value |= (digit as u32) << (index * 6);
            index += 1;
        }

        let status = if index == MAX_ENCODED_DIGITS && input.len() > index {
            DecodeStatus::DigitLimit
        } else {
            DecodeStatus::EndOfInput
        };
        DecodedLong {
            value: (value as i32) as i64,
            consumed: index,
            status,
        }
    }

    /// Descriptive alias for [`Self::decode`].
    #[must_use]
    pub fn decode_value(input: &[u8]) -> DecodedLong {
        Self::decode(input)
    }

    /// Returns the encoded bytes without a trailing NUL.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Returns the number of encoded digits.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns whether this is the historical empty representation of zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the encoded value after the 64-bit sign extension step.
    #[must_use]
    pub fn value(&self) -> i64 {
        Self::decode(self.as_bytes()).value
    }
}

impl AsRef<[u8]> for EncodedLong {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<i64> for EncodedLong {
    fn from(value: i64) -> Self {
        Self::encode(value)
    }
}

#[inline]
const fn radix64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'.' => Some(0),
        b'/' => Some(1),
        b'0'..=b'9' => Some(byte - b'0' + 2),
        b'A'..=b'Z' => Some(byte - b'A' + 12),
        b'a'..=b'z' => Some(byte - b'a' + 38),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodeStatus, EncodedLong, MAX_ENCODED_DIGITS};

    #[test]
    fn zero_is_empty_and_round_trips() {
        let encoded = EncodedLong::encode(0);
        assert!(encoded.is_empty());
        assert_eq!(encoded.as_bytes(), b"");
        assert_eq!(EncodedLong::decode(b"\0").value, 0);
    }

    #[test]
    fn digits_are_lsb_first_and_stop_at_invalid_input() {
        assert_eq!(EncodedLong::decode(b"./0123").value, 0x440c2040);
        assert_eq!(
            EncodedLong::decode(b"2!").status,
            DecodeStatus::InvalidByte {
                index: 1,
                byte: b'!',
            }
        );
        assert_eq!(EncodedLong::decode(b"2!").consumed, 1);
    }

    #[test]
    fn low_32_bits_and_sign_extension_match_musl() {
        let encoded = EncodedLong::encode(0x1_0000_0001);
        assert_eq!(encoded.value(), 1);
        assert_eq!(EncodedLong::encode(-1).value(), -1);
        assert!(EncodedLong::encode(-1).len() <= MAX_ENCODED_DIGITS);
    }

    #[test]
    fn six_digit_limit_is_typed() {
        let outcome = EncodedLong::decode(b"......x");
        assert_eq!(outcome.consumed, MAX_ENCODED_DIGITS);
        assert_eq!(outcome.status, DecodeStatus::DigitLimit);
    }
}
