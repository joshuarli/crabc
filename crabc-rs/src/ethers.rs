//! Bounded, caller-supplied `/etc/ethers` records.
//!
//! This is a crabc-specific native extension, not an implicit `/etc/ethers`
//! lookup and not a claim of musl parity. Musl's C host/database functions are
//! stubs here; callers that want this behavior provide the file bytes (or any
//! other bounded source) explicitly. The parser has no C ABI, filesystem, TLS
//! `errno`, or process-global state.

use crate::net::{EthernetAddress, Ipv6Addr};

/// A borrowed record parsed from one bounded ethers line.
///
/// The hostname remains a byte slice because the C grammar does not require
/// UTF-8. Its lifetime is tied to the caller's input line; use
/// [`EthernetDatabase`] when owned records are needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetRecord<'a> {
    address: EthernetAddress,
    hostname: &'a [u8],
}

impl<'a> EthernetRecord<'a> {
    /// Returns the parsed Ethernet address.
    #[must_use]
    pub const fn address(self) -> EthernetAddress {
        self.address
    }

    /// Returns the hostname bytes exactly as supplied by the line.
    #[must_use]
    pub const fn hostname(self) -> &'a [u8] {
        self.hostname
    }

    /// Copies this borrowed record into an owned entry.
    ///
    /// Allocation failure is reported as [`crate::Errno::NOBUFS`]. The
    /// operation never calls a C allocator and never publishes a partial
    /// hostname.
    #[cfg(feature = "alloc")]
    pub fn try_to_owned(self) -> crate::Result<EthernetEntry> {
        let mut hostname = alloc::vec::Vec::new();
        hostname
            .try_reserve(self.hostname.len())
            .map_err(|_| crate::Errno::NOBUFS)?;
        hostname.extend_from_slice(self.hostname);
        Ok(EthernetEntry {
            address: self.address,
            hostname,
        })
    }
}

/// The result of parsing one bounded line.
///
/// `Blank` and `Comment` are intentionally distinct from `Invalid`: database
/// ingestion skips all three non-record cases, while direct callers can tell
/// a malformed record from an intentionally empty/comment line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EthernetLine<'a> {
    /// A valid address/hostname record borrowing from the input line.
    Record(EthernetRecord<'a>),
    /// A line containing only whitespace.
    Blank,
    /// A comment line, including one with leading whitespace.
    Comment,
    /// A non-empty, non-comment line that does not match the ethers grammar.
    Invalid,
}

impl<'a> EthernetLine<'a> {
    /// Returns the record when this is a valid line.
    #[must_use]
    pub const fn record(self) -> Option<EthernetRecord<'a>> {
        match self {
            Self::Record(record) => Some(record),
            Self::Blank | Self::Comment | Self::Invalid => None,
        }
    }
}

/// Parses one complete, caller-bounded ethers line.
///
/// The address portion follows crabc's current `ether_line` grammar: six
/// colon-separated hexadecimal components, each one or two digits, followed by
/// at least one whitespace byte and one non-space hostname token. Whitespace
/// is the C `isspace` subset used by that implementation (` `, tab, newline,
/// carriage return, vertical tab, or form feed). A `#` after the hostname
/// starts a comment. Leading whitespace before a record is invalid, matching
/// the existing C parser; leading whitespace before a comment is recognized as
/// a comment for convenient database ingestion.
///
/// No NUL-terminated string is assumed and no byte outside `line` is read.
#[must_use]
pub fn parse_line(line: &[u8]) -> EthernetLine<'_> {
    let first_non_space = line.iter().position(|&byte| !ethers_space(byte));
    let Some(first_non_space) = first_non_space else {
        return EthernetLine::Blank;
    };
    if line[first_non_space] == b'#' {
        return EthernetLine::Comment;
    }

    let Some(record) = parse_record(line) else {
        return EthernetLine::Invalid;
    };
    EthernetLine::Record(record)
}

/// Parses only a valid record, returning `None` for all other line kinds.
///
/// [`parse_line`] should be used when callers need to distinguish malformed
/// input from blank and comment lines.
#[must_use]
pub fn parse_record(line: &[u8]) -> Option<EthernetRecord<'_>> {
    let (address, hostname_start) = parse_address(line)?;
    let mut cursor = hostname_start;
    while cursor < line.len() && ethers_space(line[cursor]) {
        cursor += 1;
    }
    if cursor == line.len() || line[cursor] == b'#' {
        return None;
    }

    let hostname_start = cursor;
    while cursor < line.len() && !ethers_space(line[cursor]) && line[cursor] != b'#' {
        // NUL is not a valid byte in a bounded native token: accepting it
        // would recreate the C string's hidden end-of-input boundary.
        if line[cursor] == 0 {
            return None;
        }
        cursor += 1;
    }
    if cursor == hostname_start {
        return None;
    }

    // As in crabc's existing ether_line implementation, anything after the
    // first hostname token is ignored once it is separated by whitespace; a
    // '#' starts an explicitly ignored comment tail.
    Some(EthernetRecord {
        address,
        hostname: &line[hostname_start..cursor],
    })
}

fn parse_address(line: &[u8]) -> Option<(EthernetAddress, usize)> {
    let mut octets = [0u8; 6];
    let mut cursor = 0usize;

    for (index, octet) in octets.iter_mut().enumerate() {
        let first = ethers_hex(line.get(cursor).copied()?)?;
        cursor += 1;

        if index < 5 {
            if line.get(cursor).copied() == Some(b':') {
                cursor += 1;
            } else {
                let second = ethers_hex(line.get(cursor).copied()?)?;
                cursor += 1;
                if line.get(cursor).copied() != Some(b':') {
                    return None;
                }
                cursor += 1;
                *octet = (first << 4) | second;
                continue;
            }
            *octet = first;
        } else {
            match line.get(cursor).copied() {
                Some(byte) if ethers_hex(byte).is_some() => {
                    let second = match ethers_hex(byte) {
                        Some(value) => value,
                        None => return None,
                    };
                    *octet = (first << 4) | second;
                    cursor += 1;
                }
                Some(byte) if ethers_space(byte) => *octet = first,
                None => *octet = first,
                _ => return None,
            }
        }
    }

    if line
        .get(cursor)
        .copied()
        .is_some_and(|byte| !ethers_space(byte))
    {
        return None;
    }
    Some((EthernetAddress::new(octets), cursor))
}

#[inline]
const fn ethers_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
}

#[inline]
const fn ethers_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// An owned ethers record.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthernetEntry {
    address: EthernetAddress,
    hostname: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl EthernetEntry {
    /// Returns the parsed Ethernet address.
    #[must_use]
    pub const fn address(&self) -> EthernetAddress {
        self.address
    }

    /// Returns the owned hostname bytes.
    #[must_use]
    pub fn hostname(&self) -> &[u8] {
        &self.hostname
    }
}

/// A caller-owned, source-ordered collection of valid ethers records.
///
/// `from_bytes` and [`Self::ingest`] consume no implicit path and perform no
/// I/O. Every malformed, blank, or comment line is skipped. Valid duplicate
/// hostnames are retained in input order, and [`Self::lookup_hostname`] returns
/// the first matching record using ASCII case-insensitive comparison.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EthernetDatabase {
    entries: alloc::vec::Vec<EthernetEntry>,
}

#[cfg(feature = "alloc")]
impl EthernetDatabase {
    /// Creates an empty database.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
        }
    }

    /// Parses caller-supplied bytes into a source-ordered database.
    ///
    /// Allocation failure is reported as [`crate::Errno::NOBUFS`]. Malformed,
    /// blank, and comment lines are skipped before allocation is attempted.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let mut database = Self::new();
        database.ingest(bytes)?;
        Ok(database)
    }

    /// Appends valid records from caller-supplied bytes.
    pub fn ingest(&mut self, bytes: &[u8]) -> crate::Result<()> {
        for line in bytes.split(|&byte| byte == b'\n') {
            if let EthernetLine::Record(record) = parse_line(line) {
                let entry = record.try_to_owned()?;
                self.entries
                    .try_reserve(1)
                    .map_err(|_| crate::Errno::NOBUFS)?;
                self.entries.push(entry);
            }
        }
        Ok(())
    }

    /// Returns entries in their original source order.
    #[must_use]
    pub fn entries(&self) -> &[EthernetEntry] {
        &self.entries
    }

    /// Iterates over entries in source order.
    pub fn iter(&self) -> core::slice::Iter<'_, EthernetEntry> {
        self.entries.iter()
    }

    /// Returns the number of valid records retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no valid records were retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Finds the first address whose hostname equals `hostname` ignoring only
    /// ASCII letter case.
    #[must_use]
    pub fn lookup_hostname(&self, hostname: &[u8]) -> Option<EthernetAddress> {
        self.entries
            .iter()
            .find(|entry| ascii_case_equal(entry.hostname(), hostname))
            .map(EthernetEntry::address)
    }

    /// Finds the first entry whose address equals `address`.
    #[must_use]
    pub fn lookup_address(&self, address: EthernetAddress) -> Option<&EthernetEntry> {
        self.entries.iter().find(|entry| entry.address == address)
    }

    /// Finds the first entry whose hostname equals `hostname`, returning the
    /// owned record when callers need both fields.
    #[must_use]
    pub fn lookup_hostname_entry(&self, hostname: &[u8]) -> Option<&EthernetEntry> {
        self.entries
            .iter()
            .find(|entry| ascii_case_equal(entry.hostname(), hostname))
    }
}

#[cfg(feature = "alloc")]
impl<'a> IntoIterator for &'a EthernetDatabase {
    type Item = &'a EthernetEntry;
    type IntoIter = core::slice::Iter<'a, EthernetEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

#[cfg(feature = "alloc")]
fn ascii_case_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(&left, &right)| {
            ascii_lower(left) == ascii_lower(right)
        })
}

#[cfg(feature = "alloc")]
#[inline]
fn ascii_lower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

/// The native value corresponding to C's `in6addr_any` object.
pub const IN6ADDR_ANY: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

/// The native value corresponding to C's `in6addr_loopback` object.
pub const IN6ADDR_LOOPBACK: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// Namespaced native values corresponding to C's IPv6 address objects.
///
/// These are values, not mutable C-compatible globals: callers can copy them,
/// borrow them, or pass their octets to a separately owned socket address.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv6Constants;

impl Ipv6Constants {
    /// All-zero IPv6 address (`in6addr_any`).
    pub const ANY: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
    /// Alias using the standard Rust address name.
    pub const UNSPECIFIED: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
    /// IPv6 loopback address (`in6addr_loopback`).
    pub const LOOPBACK: Ipv6Addr = Ipv6Addr::LOCALHOST;
    /// Alias using the standard Rust address name.
    pub const LOCALHOST: Ipv6Addr = Ipv6Addr::LOCALHOST;
}
