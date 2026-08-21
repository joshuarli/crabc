//! Caller-owned hosts, services, and protocols databases.
//!
//! These parsers are intentionally independent of `/etc` and libc's static
//! netdb state. A caller supplies the bytes (for example, from a sandboxed
//! configuration source), and every lookup returns an owned typed value. The
//! module does not expose the C `gethostby*`/`getservby*` ABI or its mutable
//! result storage.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::resolver::IpAddress;

/// Errors from parsing a caller-provided netdb text snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetDbError {
    /// A line has an invalid field shape or an invalid address/number.
    InvalidInput,
    /// A value exceeded the bounded native representation.
    Overflow,
}

/// An owned hosts-file entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEntry {
    name: String,
    aliases: Vec<String>,
    addresses: Vec<IpAddress>,
}

impl HostEntry {
    /// Returns the canonical host name.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }

    /// Returns aliases owned by this entry.
    #[must_use]
    pub fn aliases(&self) -> &[String] { &self.aliases }

    /// Returns addresses in source order.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddress] { &self.addresses }
}

/// A deterministic, caller-owned hosts database.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostDatabase {
    entries: Vec<HostEntry>,
}

impl HostDatabase {
    /// Parses hosts-file syntax from a caller-owned byte snapshot.
    pub fn from_bytes(input: &[u8]) -> core::result::Result<Self, NetDbError> {
        let mut entries: Vec<HostEntry> = Vec::new();
        for line in input.split(|&byte| byte == b'\n' || byte == b'\r') {
            let line = line.split(|&byte| byte == b'#').next().unwrap_or_default();
            let fields = fields(line);
            if fields.is_empty() { continue; }
            if fields.len() < 2 { return Err(NetDbError::InvalidInput); }
            let address = IpAddress::parse(fields[0]).ok_or(NetDbError::InvalidInput)?;
            let name = text(fields[1])?;
            let mut aliases = Vec::new();
            for field in &fields[2..] {
                aliases.push(text(field)?);
            }
            if let Some(existing) = entries.iter_mut().find(|entry| entry.name.eq_ignore_ascii_case(&name)) {
                if !existing.addresses.contains(&address) { existing.addresses.push(address); }
                for alias in aliases {
                    if !existing.aliases.iter().any(|known| known.eq_ignore_ascii_case(&alias)) {
                        existing.aliases.push(alias);
                    }
                }
            } else {
                entries.push(HostEntry { name, aliases, addresses: vec![address] });
            }
        }
        Ok(Self { entries })
    }

    /// Returns a cloned owned match by canonical name or alias.
    #[must_use]
    pub fn lookup(&self, name: &str, family: Option<crate::net::AddressFamily>) -> Option<HostEntry> {
        self.entries.iter().find_map(|entry| {
            let matches_name = entry.name.eq_ignore_ascii_case(name)
                || entry.aliases.iter().any(|alias| alias.eq_ignore_ascii_case(name));
            if !matches_name { return None; }
            let mut result = entry.clone();
            if let Some(family) = family {
                result.addresses.retain(|address| address.family() == family);
            }
            (!result.addresses.is_empty()).then_some(result)
        })
    }

    /// Returns the number of parsed entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Returns whether the database contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

/// A service transport understood by the bounded netdb slice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServiceProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// A protocol name retained as an owned numeric-independent token.
    Other,
}

impl ServiceProtocol {
    fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"tcp" => Some(Self::Tcp),
            b"udp" => Some(Self::Udp),
            _ if !value.is_empty() => Some(Self::Other),
            _ => None,
        }
    }

    /// Returns the conventional Linux IP protocol number, or zero for other.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other => 0,
        }
    }
}

/// An owned `/etc/services`-style entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceEntry {
    name: String,
    aliases: Vec<String>,
    port: u16,
    protocol: ServiceProtocol,
}

impl ServiceEntry {
    /// Returns the canonical service name.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }

    /// Returns aliases owned by this entry.
    #[must_use]
    pub fn aliases(&self) -> &[String] { &self.aliases }

    /// Returns the host-order service port.
    #[must_use]
    pub const fn port(&self) -> u16 { self.port }

    /// Returns the parsed transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> ServiceProtocol { self.protocol }
}

/// A deterministic, caller-owned services database.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceDatabase {
    entries: Vec<ServiceEntry>,
}

impl ServiceDatabase {
    /// Parses `/etc/services`-style text from a caller-owned snapshot.
    pub fn from_bytes(input: &[u8]) -> core::result::Result<Self, NetDbError> {
        let mut entries = Vec::new();
        for line in input.split(|&byte| byte == b'\n' || byte == b'\r') {
            let line = line.split(|&byte| byte == b'#').next().unwrap_or_default();
            let fields = fields(line);
            if fields.is_empty() { continue; }
            if fields.len() < 2 { return Err(NetDbError::InvalidInput); }
            let (port, protocol) = parse_service_spec(fields[1])?;
            let name = text(fields[0])?;
            let mut aliases = Vec::new();
            for field in &fields[2..] { aliases.push(text(field)?); }
            entries.push(ServiceEntry { name, aliases, port, protocol });
        }
        Ok(Self { entries })
    }

    /// Returns a cloned owned match by name or alias and optional protocol.
    #[must_use]
    pub fn lookup(&self, name: &str, protocol: Option<ServiceProtocol>) -> Option<ServiceEntry> {
        self.entries.iter().find(|entry| {
            let matches_name = entry.name.eq_ignore_ascii_case(name)
                || entry.aliases.iter().any(|alias| alias.eq_ignore_ascii_case(name));
            matches_name && protocol.map_or(true, |requested| requested == entry.protocol)
        }).cloned()
    }

    /// Returns a cloned owned match by host-order port and optional protocol.
    #[must_use]
    pub fn lookup_port(&self, port: u16, protocol: Option<ServiceProtocol>) -> Option<ServiceEntry> {
        self.entries.iter().find(|entry| {
            entry.port == port && protocol.map_or(true, |requested| requested == entry.protocol)
        }).cloned()
    }

    /// Returns the number of parsed entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Returns whether the database contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

/// An owned `/etc/protocols`-style entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolEntry {
    name: String,
    aliases: Vec<String>,
    number: u16,
}

impl ProtocolEntry {
    /// Returns the canonical protocol name.
    #[must_use]
    pub fn name(&self) -> &str { &self.name }

    /// Returns aliases owned by this entry.
    #[must_use]
    pub fn aliases(&self) -> &[String] { &self.aliases }

    /// Returns the Linux protocol number.
    #[must_use]
    pub const fn number(&self) -> u16 { self.number }
}

/// A deterministic, caller-owned protocols database.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProtocolDatabase {
    entries: Vec<ProtocolEntry>,
}

impl ProtocolDatabase {
    /// Parses `/etc/protocols`-style text from a caller-owned snapshot.
    pub fn from_bytes(input: &[u8]) -> core::result::Result<Self, NetDbError> {
        let mut entries = Vec::new();
        for line in input.split(|&byte| byte == b'\n' || byte == b'\r') {
            let line = line.split(|&byte| byte == b'#').next().unwrap_or_default();
            let fields = fields(line);
            if fields.is_empty() { continue; }
            if fields.len() < 2 { return Err(NetDbError::InvalidInput); }
            let name = text(fields[0])?;
            let number = parse_u16(fields[1])?;
            let mut aliases = Vec::new();
            for field in &fields[2..] { aliases.push(text(field)?); }
            entries.push(ProtocolEntry { name, aliases, number });
        }
        Ok(Self { entries })
    }

    /// Returns a cloned owned match by name or alias.
    #[must_use]
    pub fn lookup_name(&self, name: &str) -> Option<ProtocolEntry> {
        self.entries.iter().find(|entry| {
            entry.name.eq_ignore_ascii_case(name)
                || entry.aliases.iter().any(|alias| alias.eq_ignore_ascii_case(name))
        }).cloned()
    }

    /// Returns a cloned owned match by Linux protocol number.
    #[must_use]
    pub fn lookup_number(&self, number: u16) -> Option<ProtocolEntry> {
        self.entries.iter().find(|entry| entry.number == number).cloned()
    }

    /// Returns the number of parsed entries.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Returns whether the database contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

fn text(value: &[u8]) -> core::result::Result<String, NetDbError> {
    if value.is_empty() || value.contains(&0) { return Err(NetDbError::InvalidInput); }
    String::from_utf8(value.to_vec()).map_err(|_| NetDbError::InvalidInput)
}

fn fields(line: &[u8]) -> Vec<&[u8]> {
    line.split(|&byte| byte == b' ' || byte == b'\t' || byte == b'\x0b' || byte == b'\x0c')
        .filter(|field| !field.is_empty())
        .collect()
}

fn parse_service_spec(value: &[u8]) -> core::result::Result<(u16, ServiceProtocol), NetDbError> {
    let Some(separator) = value.iter().position(|&byte| byte == b'/') else {
        return Err(NetDbError::InvalidInput);
    };
    let port = parse_u16(&value[..separator])?;
    let protocol = ServiceProtocol::parse(&value[separator + 1..]).ok_or(NetDbError::InvalidInput)?;
    Ok((port, protocol))
}

fn parse_u16(value: &[u8]) -> core::result::Result<u16, NetDbError> {
    if value.is_empty() { return Err(NetDbError::InvalidInput); }
    let mut result = 0u32;
    for &byte in value {
        if !byte.is_ascii_digit() { return Err(NetDbError::InvalidInput); }
        result = result.checked_mul(10).and_then(|value| value.checked_add((byte - b'0') as u32)).ok_or(NetDbError::Overflow)?;
    }
    u16::try_from(result).map_err(|_| NetDbError::Overflow)
}
