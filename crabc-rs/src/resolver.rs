//! Caller-owned DNS resolution without the public libc resolver ABI.
//!
//! `Resolver` owns only its explicit configuration and each lookup owns its
//! result values. It never reads `_res`, `h_errno`, or TLS `errno`, and it does
//! not call `getaddrinfo`, `getnameinfo`, or `ToSocketAddrs`. The bounded DNS
//! wire/exchange seam lives in `crabc-core::resolver`.

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;

use bitflags::bitflags;

use crate::net::{AddressFamily, SocketType};
use crate::Errno;

/// An owned IPv4 or IPv6 address represented in network byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpAddress {
    /// An IPv4 address.
    V4([u8; 4]),
    /// An IPv6 address.
    V6([u8; 16]),
}

impl IpAddress {
    /// Parses a presentation-format IPv4 or IPv6 address without libc.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<Self> {
        parse_ipv4(value).map(Self::V4).or_else(|| parse_ipv6(value).map(Self::V6))
    }

    /// Returns the corresponding Linux address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            Self::V4(_) => AddressFamily::INET,
            Self::V6(_) => AddressFamily::INET6,
        }
    }

    /// Returns the address bytes in network order.
    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        match self {
            Self::V4(value) => [value[0], value[1], value[2], value[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Self::V6(value) => value,
        }
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(bytes) => write!(formatter, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
            Self::V6(bytes) => fmt_ipv6(formatter, bytes),
        }
    }
}

/// A typed IP endpoint returned by native resolver operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SocketAddress {
    address: IpAddress,
    port: u16,
    scope_id: u32,
}

impl SocketAddress {
    /// Creates an endpoint with a host-order port.
    #[must_use]
    pub const fn new(address: IpAddress, port: u16) -> Self {
        Self { address, port, scope_id: 0 }
    }

    /// Creates an IPv6 endpoint with an interface scope identifier.
    #[must_use]
    pub const fn new_scoped(address: IpAddress, port: u16, scope_id: u32) -> Self {
        Self { address, port, scope_id }
    }

    /// Returns the endpoint's IP address.
    #[must_use]
    pub const fn ip(self) -> IpAddress { self.address }

    /// Returns the endpoint's host-order port.
    #[must_use]
    pub const fn port(self) -> u16 { self.port }

    /// Returns the IPv6 scope identifier, or zero for IPv4.
    #[must_use]
    pub const fn scope_id(self) -> u32 { self.scope_id }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            IpAddress::V4(_) => write!(formatter, "{}:{}", self.address, self.port),
            IpAddress::V6(_) if self.scope_id == 0 => write!(formatter, "[{}]:{}", self.address, self.port),
            IpAddress::V6(_) => write!(formatter, "[{}%{}]:{}", self.address, self.scope_id, self.port),
        }
    }
}

/// Typed resolver failure categories; no C `EAI_*` value or TLS error is exposed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResolveError {
    /// The name has no records of the requested family.
    NameNotFound,
    /// The server answered successfully but supplied no requested record.
    NoData,
    /// The nameserver reported a temporary failure or timed out.
    Temporary,
    /// The nameserver reported a permanent protocol failure.
    Failure,
    /// The requested family, service, or flag combination is invalid.
    InvalidInput,
    /// A named service was not found in the caller-supplied database.
    ServiceNotFound,
    /// A direct kernel operation failed.
    System(Errno),
    /// A native output buffer could not represent the result.
    Overflow,
}

impl From<Errno> for ResolveError {
    fn from(error: Errno) -> Self {
        Self::System(error)
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameNotFound => formatter.write_str("name not found"),
            Self::NoData => formatter.write_str("no data"),
            Self::Temporary => formatter.write_str("temporary resolver failure"),
            Self::Failure => formatter.write_str("resolver failure"),
            Self::InvalidInput => formatter.write_str("invalid resolver input"),
            Self::ServiceNotFound => formatter.write_str("service not found"),
            Self::System(error) => write!(formatter, "system error {}", error.raw()),
            Self::Overflow => formatter.write_str("resolver result overflow"),
        }
    }
}

bitflags! {
    /// Musl-compatible address lookup flags represented without raw C hints.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct LookupFlags: u32 {
        /// Return wildcard addresses for a null node name.
        const PASSIVE = 0x0001;
        /// Preserve the canonical name in [`AddressResults`].
        const CANONNAME = 0x0002;
        /// Refuse DNS and hosts lookup when the node is not numeric.
        const NUMERICHOST = 0x0004;
        /// Permit IPv4 addresses to be represented as IPv4-mapped IPv6.
        const V4MAPPED = 0x0008;
        /// Keep both native IPv6 and mapped IPv4 results.
        const ALL = 0x0010;
        /// Reserved for the future interface-address capability slice.
        const ADDRCONFIG = 0x0020;
        /// Require a numeric service string.
        const NUMERICSERV = 0x0400;
    }
}

/// Typed constraints for a forward address lookup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LookupOptions {
    /// Requested address family.
    pub family: AddressFamily,
    /// Optional socket type; absent means stream and datagram choices.
    pub socket_type: Option<SocketType>,
    /// Optional Linux protocol number.
    pub protocol: Option<u32>,
    /// Lookup policy flags.
    pub flags: LookupFlags,
}

impl Default for LookupOptions {
    fn default() -> Self {
        Self {
            family: AddressFamily::UNSPEC,
            socket_type: None,
            protocol: None,
            flags: LookupFlags::empty(),
        }
    }
}

/// One owned address/protocol combination from a forward lookup.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AddressInfo {
    address: SocketAddress,
    socket_type: SocketType,
    protocol: u32,
}

impl AddressInfo {
    /// Returns the address and port.
    #[must_use]
    pub const fn address(&self) -> SocketAddress { self.address }

    /// Returns the requested socket type.
    #[must_use]
    pub const fn socket_type(&self) -> SocketType { self.socket_type }

    /// Returns the Linux protocol number; zero means unspecified.
    #[must_use]
    pub const fn protocol(&self) -> u32 { self.protocol }
}

/// Owned forward-lookup results with an iterator-friendly representation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressResults {
    entries: Vec<AddressInfo>,
    canonical_name: Option<String>,
}

impl AddressResults {
    /// Returns all address entries in resolver order.
    #[must_use]
    pub fn as_slice(&self) -> &[AddressInfo] { &self.entries }

    /// Returns an iterator borrowing the owned result.
    pub fn iter(&self) -> core::slice::Iter<'_, AddressInfo> { self.entries.iter() }

    /// Returns the owned canonical name when requested and available.
    #[must_use]
    pub fn canonical_name(&self) -> Option<&str> { self.canonical_name.as_deref() }
}

impl IntoIterator for AddressResults {
    type Item = AddressInfo;
    type IntoIter = alloc::vec::IntoIter<AddressInfo>;

    fn into_iter(self) -> Self::IntoIter { self.entries.into_iter() }
}

/// Typed reverse-lookup flags.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NameInfoOptions {
    /// Return only numeric host text.
    pub numeric_host: bool,
    /// Require a reverse name instead of falling back to numeric text.
    pub name_required: bool,
    /// Return only numeric service text.
    pub numeric_service: bool,
}

impl Default for NameInfoOptions {
    fn default() -> Self {
        Self { numeric_host: false, name_required: false, numeric_service: false }
    }
}

/// Owned result of a reverse lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameInfo {
    host: String,
    service: Option<String>,
}

impl NameInfo {
    /// Returns the owned host name or numeric fallback.
    #[must_use]
    pub fn host(&self) -> &str { &self.host }

    /// Returns the owned service name or numeric service text.
    #[must_use]
    pub fn service(&self) -> Option<&str> { self.service.as_deref() }
}

/// A resolver whose configuration and lifetime are wholly caller-owned.
#[derive(Clone, Debug)]
pub struct Resolver {
    config: ResolverConfig,
}

impl Resolver {
    /// Creates a resolver with explicit nameservers and no hidden system state.
    #[must_use]
    pub const fn new(config: ResolverConfig) -> Self { Self { config } }

    /// Returns the immutable configuration owned by this resolver.
    #[must_use]
    pub const fn config(&self) -> &ResolverConfig { &self.config }

    /// Resolves a node and optional numeric service into owned typed entries.
    pub fn lookup(
        &self,
        node: Option<&str>,
        service: Option<&str>,
        options: LookupOptions,
    ) -> core::result::Result<AddressResults, ResolveError> {
        if options.flags.contains(LookupFlags::ADDRCONFIG) {
            // Interface-aware address selection needs a separate direct
            // netlink/sysfs seam. Do not silently claim the C flag here.
            return Err(ResolveError::InvalidInput);
        }
        let socket_types = service_choices(service, &options)?;
        let mut addresses = Vec::new();
        let mut canonical = None;
        if let Some(node) = node {
            if node.is_empty() || node.as_bytes().contains(&0) {
                return Err(ResolveError::InvalidInput);
            }
            if let Some(numeric) = IpAddress::parse(node.as_bytes()) {
                if options.family != AddressFamily::UNSPEC && options.family != numeric.family() {
                    if !(options.family == AddressFamily::INET6
                        && numeric.family() == AddressFamily::INET
                        && options.flags.contains(LookupFlags::V4MAPPED))
                    {
                        return Err(ResolveError::NameNotFound);
                    }
                }
                addresses.push(if options.family == AddressFamily::INET6
                    && numeric.family() == AddressFamily::INET
                    && options.flags.contains(LookupFlags::V4MAPPED)
                {
                    let bytes = match numeric {
                        IpAddress::V4(bytes) => bytes,
                        IpAddress::V6(_) => unreachable!(),
                    };
                    IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    numeric
                });
                canonical = Some(node.to_owned());
            } else if options.flags.contains(LookupFlags::NUMERICHOST) {
                return Err(ResolveError::NameNotFound);
            } else {
                let mut candidates = Vec::new();
                let name = node.trim_end_matches('.');
                if name.is_empty() {
                    return Err(ResolveError::InvalidInput);
                }
                let absolute = node.ends_with('.');
                if !absolute && name.as_bytes().iter().filter(|&&byte| byte == b'.').count() < self.config.ndots as usize {
                    for suffix in &self.config.search_domains {
                        candidates.push(format_domain(name, suffix));
                    }
                }
                candidates.push(name.to_owned());
                let mut saw_no_data = false;
                for candidate in candidates {
                    match self.lookup_dns(candidate.as_bytes(), options.family, options.flags) {
                        Ok((found, name)) if !found.is_empty() => {
                            addresses = found;
                            canonical = name.or_else(|| Some(candidate));
                            break;
                        }
                        Err(ResolveError::NoData) => saw_no_data = true,
                        Err(ResolveError::NameNotFound) => {}
                        Err(error) => return Err(error),
                        _ => {}
                    }
                }
                if addresses.is_empty() {
                    return Err(if saw_no_data { ResolveError::NoData } else { ResolveError::NameNotFound });
                }
            }
        } else {
            let families = match options.family {
                family if family == AddressFamily::INET => [Some(IpAddress::V4([0; 4])), None],
                family if family == AddressFamily::INET6 => [Some(IpAddress::V6([0; 16])), None],
                _ => [Some(IpAddress::V4([127, 0, 0, 1])), Some(IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))],
            };
            for address in families.into_iter().flatten() {
                addresses.push(if options.flags.contains(LookupFlags::PASSIVE) {
                    match address { IpAddress::V4(_) => IpAddress::V4([0; 4]), IpAddress::V6(_) => IpAddress::V6([0; 16]) }
                } else { address });
            }
        }
        let mut entries = Vec::new();
        for address in addresses {
            for (socket_type, protocol) in socket_types.iter().copied() {
                entries.push(AddressInfo { address: SocketAddress::new(address, service_port(service)?), socket_type, protocol });
            }
        }
        Ok(AddressResults { entries, canonical_name: options.flags.contains(LookupFlags::CANONNAME).then_some(canonical).flatten() })
    }

    /// Performs a reverse DNS PTR lookup with numeric fallback.
    pub fn reverse_lookup(
        &self,
        address: SocketAddress,
        service: Option<u16>,
        options: NameInfoOptions,
    ) -> core::result::Result<NameInfo, ResolveError> {
        let numeric_host = address.ip().to_string();
        let host = if options.numeric_host {
            numeric_host
        } else {
            let query_name = reverse_name(address.ip());
            let mut query = [0u8; 512];
            let query_len = crabc_core::resolver::encode_query(
                query_name.as_bytes(),
                crabc_core::resolver::TYPE_PTR,
                query_id(),
                &mut query,
            )?;
            let id = u16::from_be_bytes([query[0], query[1]]);
            let mut answer = [0u8; 4096];
            let length = crabc_core::resolver::exchange(&self.config.exchange, &query[..query_len], id, &mut answer)
                .map_err(map_exchange_error)?;
            let response = crabc_core::resolver::DnsResponse::parse(&answer[..length], query_name.as_bytes(), crabc_core::resolver::TYPE_PTR, id)
                .map_err(|_| ResolveError::Failure)?;
            if response.truncated() {
                return Err(ResolveError::Failure);
            }
            let mut output = [0u8; 256];
            match response.response_code() {
                3 => None,
                2 => return Err(ResolveError::Temporary),
                code if code != 0 => return Err(ResolveError::Failure),
                _ => response.rdata_at(crabc_core::resolver::TYPE_PTR, 0, &mut output)
                    .map_err(|_| ResolveError::Failure)?
                    .and_then(|length| core::str::from_utf8(&output[..length]).ok().map(str::to_owned)),
            }
            .unwrap_or_else(|| {
                if options.name_required { String::new() } else { numeric_host }
            })
        };
        if host.is_empty() && options.name_required {
            return Err(ResolveError::NameNotFound);
        }
        let service = service.map(|port| port.to_string());
        Ok(NameInfo { host, service })
    }

    fn lookup_dns(&self, name: &[u8], family: AddressFamily, flags: LookupFlags) -> core::result::Result<(Vec<IpAddress>, Option<String>), ResolveError> {
        let types: &[u16] = if family == AddressFamily::INET { &[crabc_core::resolver::TYPE_A] }
            else if family == AddressFamily::INET6 && flags.contains(LookupFlags::V4MAPPED) { &[crabc_core::resolver::TYPE_AAAA, crabc_core::resolver::TYPE_A] }
            else if family == AddressFamily::INET6 { &[crabc_core::resolver::TYPE_AAAA] }
            else { &[crabc_core::resolver::TYPE_A, crabc_core::resolver::TYPE_AAAA] };
        let mut addresses = Vec::new();
        let mut canonical = None;
        let mut saw_no_data = false;
        for &record_type in types {
            if record_type == crabc_core::resolver::TYPE_A
                && family == AddressFamily::INET6
                && flags.contains(LookupFlags::V4MAPPED)
                && !flags.contains(LookupFlags::ALL)
                && !addresses.is_empty()
            {
                break;
            }
            let id = query_id();
            let mut query = [0u8; 512];
            let query_len = crabc_core::resolver::encode_query(name, record_type, id, &mut query)
                .map_err(|_| ResolveError::InvalidInput)?;
            let mut answer = [0u8; 4096];
            let length = crabc_core::resolver::exchange(&self.config.exchange, &query[..query_len], id, &mut answer)
                .map_err(map_exchange_error)?;
            let response = crabc_core::resolver::DnsResponse::parse(&answer[..length], name, record_type, id)
                .map_err(|_| ResolveError::Failure)?;
            if response.truncated() {
                return Err(ResolveError::Failure);
            }
            match response.response_code() {
                3 => continue,
                2 => return Err(ResolveError::Temporary),
                code if code != 0 => return Err(ResolveError::Failure),
                _ => {}
            }
            let mut cname = [0u8; 256];
            if canonical.is_none() {
                if let Some(length) = response.rdata_at(crabc_core::resolver::TYPE_CNAME, 0, &mut cname)
                    .map_err(|_| ResolveError::Failure)?
                {
                    canonical = core::str::from_utf8(&cname[..length]).ok().map(str::to_owned);
                }
            }
            let mut ordinal = 0usize;
            loop {
                let mut bytes = [0u8; 16];
                let found = response.rdata_at(record_type, ordinal, &mut bytes)
                    .map_err(|_| ResolveError::Failure)?;
                let Some(length) = found else { break };
                match (record_type, length) {
                    (crabc_core::resolver::TYPE_A, 4) if family == AddressFamily::INET6 && flags.contains(LookupFlags::V4MAPPED) => addresses.push(IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, bytes[0], bytes[1], bytes[2], bytes[3]])),
                    (crabc_core::resolver::TYPE_A, 4) => addresses.push(IpAddress::V4([bytes[0], bytes[1], bytes[2], bytes[3]])),
                    (crabc_core::resolver::TYPE_AAAA, 16) => addresses.push(IpAddress::V6(bytes)),
                    _ => return Err(ResolveError::Failure),
                }
                ordinal += 1;
            }
            if addresses.is_empty() { saw_no_data = true; }
        }
        if addresses.is_empty() {
            Err(if saw_no_data { ResolveError::NoData } else { ResolveError::NameNotFound })
        } else {
            Ok((addresses, canonical))
        }
    }
}

/// Explicit resolver configuration. No constructor reads `/etc/resolv.conf`.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    pub(crate) exchange: crabc_core::resolver::ExchangeConfig,
    search_domains: Vec<String>,
    ndots: u8,
}

impl ResolverConfig {
    /// Creates an empty configuration with musl-compatible bounds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchange: crabc_core::resolver::ExchangeConfig {
                nameservers: [crabc_core::resolver::NameServer::ipv4([127, 0, 0, 1]); crabc_core::resolver::MAX_NAMESERVERS],
                nameserver_count: 0,
                timeout_ms: 1000,
                attempts: 2,
            },
            search_domains: Vec::new(),
            ndots: 1,
        }
    }

    /// Adds one nameserver in configured order.
    pub fn add_nameserver(&mut self, address: IpAddress) -> core::result::Result<(), ResolveError> {
        self.add_nameserver_on_port(address, 53)
    }

    /// Adds one nameserver with an explicit host-order UDP port.
    ///
    /// The port override keeps deterministic private fixtures isolated from
    /// the process-wide DNS service while preserving the same direct syscall
    /// exchange path used for port 53.
    pub fn add_nameserver_on_port(&mut self, address: IpAddress, port: u16) -> core::result::Result<(), ResolveError> {
        if self.exchange.nameserver_count >= crabc_core::resolver::MAX_NAMESERVERS {
            return Err(ResolveError::Overflow);
        }
        let mut server = match address {
            IpAddress::V4(bytes) => crabc_core::resolver::NameServer::ipv4(bytes),
            IpAddress::V6(bytes) => crabc_core::resolver::NameServer::ipv6(bytes, 0),
        };
        server.port = port;
        self.exchange.nameservers[self.exchange.nameserver_count] = server;
        self.exchange.nameserver_count += 1;
        Ok(())
    }

    /// Adds a search suffix, preserving explicit configuration ownership.
    pub fn add_search_domain(&mut self, domain: &str) -> core::result::Result<(), ResolveError> {
        if self.search_domains.len() >= 6 || IpAddress::parse(domain.as_bytes()).is_some() {
            return Err(ResolveError::InvalidInput);
        }
        if domain.is_empty() || domain.as_bytes().contains(&0) {
            return Err(ResolveError::InvalidInput);
        }
        self.search_domains.push(domain.trim_end_matches('.').to_owned());
        Ok(())
    }

    /// Sets the per-server DNS timeout in milliseconds.
    pub fn set_timeout_ms(&mut self, timeout_ms: u32) -> core::result::Result<(), ResolveError> {
        if timeout_ms == 0 { return Err(ResolveError::InvalidInput); }
        self.exchange.timeout_ms = timeout_ms;
        Ok(())
    }

    /// Sets the configured-order retry count.
    pub fn set_attempts(&mut self, attempts: u8) -> core::result::Result<(), ResolveError> {
        if attempts == 0 { return Err(ResolveError::InvalidInput); }
        self.exchange.attempts = attempts;
        Ok(())
    }

    /// Sets musl's `ndots` search threshold.
    pub fn set_ndots(&mut self, ndots: u8) -> core::result::Result<(), ResolveError> {
        if ndots > 15 { return Err(ResolveError::InvalidInput); }
        self.ndots = ndots;
        Ok(())
    }
}

impl Default for ResolverConfig {
    fn default() -> Self { Self::new() }
}

fn service_choices(service: Option<&str>, options: &LookupOptions) -> core::result::Result<Vec<(SocketType, u32)>, ResolveError> {
    let mut types = Vec::new();
    if let Some(socket_type) = options.socket_type {
        types.push(socket_type);
    } else if options.protocol == Some(6) {
        types.push(SocketType::STREAM);
    } else if options.protocol == Some(17) {
        types.push(SocketType::DGRAM);
    } else {
        types.push(SocketType::STREAM);
        types.push(SocketType::DGRAM);
    }
    let mut choices = Vec::new();
    for socket_type in types {
        let protocol = options.protocol.unwrap_or(match socket_type {
            value if value == SocketType::STREAM => 6,
            value if value == SocketType::DGRAM => 17,
            _ => 0,
        });
        if options.protocol.is_some()
            && ((socket_type == SocketType::STREAM && protocol != 6)
                || (socket_type == SocketType::DGRAM && protocol != 17))
        {
            return Err(ResolveError::InvalidInput);
        }
        choices.push((socket_type, protocol));
    }
    if service.is_some() && options.flags.contains(LookupFlags::NUMERICSERV) {
        // `service_port` below is deliberately numeric-only in this first
        // slice; retaining this check makes the unsupported named-service
        // policy explicit instead of falling back to a process-global DB.
        let _ = service_port(service)?;
    }
    Ok(choices)
}

fn service_port(service: Option<&str>) -> core::result::Result<u16, ResolveError> {
    service.map(|value| parse_decimal(value.as_bytes()).ok_or(ResolveError::ServiceNotFound)).transpose().map(|value| value.unwrap_or(0))
}

fn map_exchange_error(error: Errno) -> ResolveError {
    if error == Errno::TIMEDOUT || error == Errno::AGAIN { ResolveError::Temporary } else { ResolveError::System(error) }
}

fn query_id() -> u16 {
    let mut bytes = [0u8; 2];
    // A failed entropy read only affects transaction uniqueness; the direct
    // protocol and source validation remain intact for the bounded slice.
    if unsafe { crabc_core::rand::getrandom_raw(bytes.as_mut_ptr(), bytes.len(), 0) }.is_err() {
        0xcabc
    } else {
        u16::from_ne_bytes(bytes)
    }
}

fn format_domain(name: &str, suffix: &str) -> String {
    let mut result = String::with_capacity(name.len() + suffix.len() + 1);
    result.push_str(name);
    result.push('.');
    result.push_str(suffix);
    result
}

fn reverse_name(address: IpAddress) -> String {
    let mut result = String::new();
    match address {
        IpAddress::V4(bytes) => {
            for byte in bytes.into_iter().rev() { let _ = write!(result, "{}.", byte); }
            result.push_str("in-addr.arpa");
        }
        IpAddress::V6(bytes) => {
            for byte in bytes.into_iter().rev() {
                let _ = write!(result, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            result.push_str("ip6.arpa");
        }
    }
    result
}

fn parse_decimal(value: &[u8]) -> Option<u16> {
    if value.is_empty() { return None; }
    let mut number = 0u32;
    for &byte in value {
        if !byte.is_ascii_digit() { return None; }
        number = number.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }
    (number <= u16::MAX as u32).then_some(number as u16)
}

fn parse_ipv4(value: &[u8]) -> Option<[u8; 4]> {
    let mut result = [0u8; 4];
    let mut part = 0usize;
    let mut number = 0u16;
    let mut digits = 0usize;
    for &byte in value.iter().chain(core::iter::once(&b'.')) {
        if byte.is_ascii_digit() {
            number = number.checked_mul(10)?.checked_add((byte - b'0') as u16)?;
            if number > 255 { return None; }
            digits += 1;
        } else if byte == b'.' && digits != 0 && part < 4 {
            result[part] = number as u8;
            part += 1;
            number = 0;
            digits = 0;
        } else {
            return None;
        }
    }
    (part == 4).then_some(result)
}

fn parse_ipv6(value: &[u8]) -> Option<[u8; 16]> {
    if !value.contains(&b':') { return None; }
    let mut groups = [0u16; 8];
    if let Some(compression) = value.windows(2).position(|window| window == b"::") {
        // A second `::` is ambiguous and therefore rejected. The two sides
        // are parsed independently, then the omitted groups are inserted in
        // the middle (including the legal leading/trailing `::` forms).
        if value[compression + 2..].windows(2).any(|window| window == b"::") {
            return None;
        }
        let left = parse_ipv6_side(&value[..compression], &mut groups, 0)?;
        let mut right_groups = [0u16; 8];
        let right = parse_ipv6_side(&value[compression + 2..], &mut right_groups, 0)?;
        if left + right >= 8 { return None; }
        for index in (0..right).rev() {
            groups[8 - right + index] = right_groups[index];
        }
    } else if parse_ipv6_side(value, &mut groups, 0)? != 8 {
        return None;
    }
    let mut result = [0u8; 16];
    for (index, group) in groups.into_iter().enumerate() { result[index * 2..index * 2 + 2].copy_from_slice(&group.to_be_bytes()); }
    Some(result)
}

fn parse_ipv6_side(value: &[u8], groups: &mut [u16; 8], mut count: usize) -> Option<usize> {
    if value.is_empty() { return Some(count); }
    for (index, token) in value.split(|&byte| byte == b':').enumerate() {
        if token.is_empty() { return None; }
        if token.contains(&b'.') {
            if index + 1 != value.split(|&byte| byte == b':').count() { return None; }
            let ipv4 = parse_ipv4(token)?;
            if count + 2 > 8 { return None; }
            groups[count] = u16::from_be_bytes([ipv4[0], ipv4[1]]);
            groups[count + 1] = u16::from_be_bytes([ipv4[2], ipv4[3]]);
            count += 2;
        } else {
            if count >= 8 { return None; }
            groups[count] = parse_hex(token)?;
            count += 1;
        }
    }
    Some(count)
}

fn parse_hex(value: &[u8]) -> Option<u16> {
    if value.is_empty() || value.len() > 4 { return None; }
    let mut result = 0u16;
    for &byte in value {
        let digit = match byte { b'0'..=b'9' => byte - b'0', b'a'..=b'f' => byte - b'a' + 10, b'A'..=b'F' => byte - b'A' + 10, _ => return None };
        result = (result << 4) | digit as u16;
    }
    Some(result)
}

fn fmt_ipv6(formatter: &mut fmt::Formatter<'_>, bytes: [u8; 16]) -> fmt::Result {
    let mut groups = [0u16; 8];
    for index in 0..8 { groups[index] = u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]); }
    let mut best_start = 8usize;
    let mut best_len = 0usize;
    let mut index = 0usize;
    while index < 8 {
        if groups[index] == 0 {
            let start = index;
            while index < 8 && groups[index] == 0 { index += 1; }
            if index - start > best_len { best_start = start; best_len = index - start; }
        } else { index += 1; }
    }
    if best_len < 2 { best_start = 8; }
    let mut index = 0usize;
    let mut separator_before_group = false;
    while index < 8 {
        if index == best_start {
            // The compression marker includes both separators needed after a
            // preceding group and before a following group. In particular,
            // leave the next group separator-free for `::1`, not `:::1`.
            formatter.write_str("::")?;
            index += best_len;
            separator_before_group = false;
            if index == 8 { break; }
        } else {
            if separator_before_group { formatter.write_str(":")?; }
            write!(formatter, "{:x}", groups[index])?;
            separator_before_group = true;
            index += 1;
        }
    }
    Ok(())
}
