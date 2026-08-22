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

pub use crate::net::{IpAddress, SocketAddress};
use crate::net::{AddressFamily, SocketType};
use crate::netdb::{HostDatabase, NetDbError};
use crate::Errno;

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
                let dots = name.as_bytes().iter().filter(|&&byte| byte == b'.').count();
                let search_first = !absolute && dots < self.config.ndots as usize;
                if search_first {
                    for suffix in &self.config.search_domains {
                        push_candidate(&mut candidates, format_domain(name, suffix));
                    }
                }
                push_candidate(&mut candidates, name.to_owned());
                if !search_first && !absolute {
                    for suffix in &self.config.search_domains {
                        push_candidate(&mut candidates, format_domain(name, suffix));
                    }
                }
                let mut saw_no_data = false;
                for candidate in candidates {
                    if let Some((found, host_name)) = self.lookup_hosts(&candidate, options) {
                        addresses = found;
                        canonical = Some(host_name);
                        break;
                    }
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
        let mut current = String::from_utf8(name.to_vec()).map_err(|_| ResolveError::InvalidInput)?;
        let mut visited = Vec::new();
        let mut canonical = None;
        for _ in 0..8 {
            if visited.iter().any(|known: &String| known.eq_ignore_ascii_case(&current)) {
                return Err(ResolveError::Failure);
            }
            visited.push(current.clone());
            let answer = self.lookup_dns_once(current.as_bytes(), family, flags)?;
            if answer.canonical.is_some() {
                canonical = answer.canonical.clone();
            }
            if !answer.addresses.is_empty() {
                return Ok((answer.addresses, canonical));
            }
            let Some(next) = answer.cname else {
                return Err(if answer.saw_no_data { ResolveError::NoData } else { ResolveError::NameNotFound });
            };
            current = next;
        }
        Err(ResolveError::Failure)
    }

    fn lookup_dns_once(&self, name: &[u8], family: AddressFamily, flags: LookupFlags) -> core::result::Result<DnsLookup, ResolveError> {
        let types: &[u16] = if family == AddressFamily::INET { &[crabc_core::resolver::TYPE_A] }
            else if family == AddressFamily::INET6 && flags.contains(LookupFlags::V4MAPPED) { &[crabc_core::resolver::TYPE_AAAA, crabc_core::resolver::TYPE_A] }
            else if family == AddressFamily::INET6 { &[crabc_core::resolver::TYPE_AAAA] }
            else { &[crabc_core::resolver::TYPE_A, crabc_core::resolver::TYPE_AAAA] };
        let mut addresses = Vec::new();
        let mut canonical = None;
        let mut cname = None;
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
            let mut cname_bytes = [0u8; 256];
            if cname.is_none() {
                if let Some(length) = response.rdata_at(crabc_core::resolver::TYPE_CNAME, 0, &mut cname_bytes)
                    .map_err(|_| ResolveError::Failure)?
                {
                    let target = core::str::from_utf8(&cname_bytes[..length]).map_err(|_| ResolveError::Failure)?;
                    if target.is_empty() {
                        return Err(ResolveError::Failure);
                    }
                    cname = Some(target.to_owned());
                    canonical = cname.clone();
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
        Ok(DnsLookup { addresses, canonical, cname, saw_no_data })
    }

    fn lookup_hosts(&self, name: &str, options: LookupOptions) -> Option<(Vec<IpAddress>, String)> {
        let entry = self.config.hosts.as_ref()?.lookup(name, None)?;
        let mut addresses = Vec::new();
        for address in entry.addresses() {
            match (options.family, address) {
                (family, IpAddress::V4(_)) if family == AddressFamily::INET || family == AddressFamily::UNSPEC => addresses.push(*address),
                (AddressFamily::INET6, IpAddress::V6(_)) => addresses.push(*address),
                (AddressFamily::INET6, IpAddress::V4(bytes)) if options.flags.contains(LookupFlags::V4MAPPED) => addresses.push(IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, bytes[0], bytes[1], bytes[2], bytes[3]])),
                _ => {}
            }
        }
        if addresses.is_empty() { None } else { Some((addresses, entry.name().to_owned())) }
    }
}

struct DnsLookup {
    addresses: Vec<IpAddress>,
    canonical: Option<String>,
    cname: Option<String>,
    saw_no_data: bool,
}

/// Explicit resolver configuration. [`Self::new`] stays empty and explicit;
/// [`Self::from_system`] is the opt-in direct snapshot loader.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    pub(crate) exchange: crabc_core::resolver::ExchangeConfig,
    search_domains: Vec<String>,
    ndots: u8,
    hosts: Option<HostDatabase>,
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
            hosts: None,
        }
    }

    /// Builds a resolver from caller-owned `/etc/resolv.conf` and hosts
    /// snapshots. No process-global resolver state is consulted.
    pub fn from_bytes(resolv_conf: &[u8], hosts: &[u8]) -> core::result::Result<Self, ResolveError> {
        let mut config = Self::new();
        parse_resolv_conf(resolv_conf, &mut config)?;
        config.hosts = Some(HostDatabase::from_bytes(hosts).map_err(map_netdb_error)?);
        Ok(config)
    }

    /// Loads bounded `/etc/resolv.conf` and `/etc/hosts` snapshots through
    /// direct Linux file operations, then returns an owned configuration.
    pub fn from_system() -> core::result::Result<Self, ResolveError> {
        let resolv_conf = read_system_file(b"/etc/resolv.conf")?;
        let hosts = read_system_file(b"/etc/hosts")?;
        Self::from_bytes(&resolv_conf, &hosts)
    }

    /// Adds or replaces the caller-owned hosts snapshot used before DNS.
    pub fn set_hosts(&mut self, hosts: HostDatabase) {
        self.hosts = Some(hosts);
    }

    /// Returns the caller-owned hosts snapshot, when configured.
    #[must_use]
    pub fn hosts(&self) -> Option<&HostDatabase> {
        self.hosts.as_ref()
    }

    /// Returns search suffixes in candidate order.
    #[must_use]
    pub fn search_domains(&self) -> &[String] {
        &self.search_domains
    }

    /// Returns the `ndots` threshold used for search ordering.
    #[must_use]
    pub const fn ndots(&self) -> u8 {
        self.ndots
    }

    /// Returns the configured nameserver count.
    #[must_use]
    pub fn nameserver_count(&self) -> usize {
        self.exchange.nameserver_count
    }

    /// Returns the per-server DNS timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.exchange.timeout_ms
    }

    /// Returns the configured-order retry count.
    #[must_use]
    pub const fn attempts(&self) -> u8 {
        self.exchange.attempts
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
        let domain = domain.trim_end_matches('.');
        if !valid_domain(domain) {
            return Err(ResolveError::InvalidInput);
        }
        self.search_domains.push(domain.to_owned());
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

fn parse_resolv_conf(input: &[u8], config: &mut ResolverConfig) -> core::result::Result<(), ResolveError> {
    let mut search_seen = false;
    for line in input.split(|&byte| byte == b'\n' || byte == b'\r') {
        let line = line
            .split(|&byte| byte == b'#' || byte == b';')
            .next()
            .unwrap_or_default();
        let fields: Vec<&[u8]> = line
            .split(|&byte| byte == b' ' || byte == b'\t' || byte == b'\x0b' || byte == b'\x0c')
            .filter(|field| !field.is_empty())
            .collect();
        if fields.is_empty() { continue; }
        match fields[0] {
            b"nameserver" => {
                if fields.len() != 2 { return Err(ResolveError::InvalidInput); }
                let address = IpAddress::parse(fields[1]).ok_or(ResolveError::InvalidInput)?;
                config.add_nameserver(address)?;
            }
            b"search" => {
                if fields.len() < 2 { return Err(ResolveError::InvalidInput); }
                config.search_domains.clear();
                for field in &fields[1..] {
                    let domain = core::str::from_utf8(field).map_err(|_| ResolveError::InvalidInput)?;
                    config.add_search_domain(domain)?;
                }
                search_seen = true;
            }
            b"domain" => {
                if fields.len() != 2 { return Err(ResolveError::InvalidInput); }
                if !search_seen {
                    config.search_domains.clear();
                    let domain = core::str::from_utf8(fields[1]).map_err(|_| ResolveError::InvalidInput)?;
                    config.add_search_domain(domain)?;
                }
            }
            b"options" => {
                for option in &fields[1..] {
                    parse_resolver_option(option, config)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_resolver_option(option: &[u8], config: &mut ResolverConfig) -> core::result::Result<(), ResolveError> {
    let Some(separator) = option.iter().position(|&byte| byte == b':') else {
        return Ok(());
    };
    let value = &option[separator + 1..];
    match &option[..separator] {
        b"ndots" => config.set_ndots(parse_decimal_u8(value).ok_or(ResolveError::InvalidInput)?)?,
        b"timeout" => {
            let seconds = parse_decimal_u32(value).ok_or(ResolveError::InvalidInput)?;
            let millis = seconds.checked_mul(1000).ok_or(ResolveError::Overflow)?;
            config.set_timeout_ms(millis)?;
        }
        b"attempts" => config.set_attempts(parse_decimal_u8(value).ok_or(ResolveError::InvalidInput)?)?,
        _ => {}
    }
    Ok(())
}

fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.as_bytes().contains(&0) { return false; }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes().iter().all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    })
}

fn read_system_file(path: &[u8]) -> core::result::Result<Vec<u8>, ResolveError> {
    let descriptor = crate::fs::open(path, crate::fs::OFlags::RDONLY | crate::fs::OFlags::CLOEXEC, crate::fs::Mode::empty())?;
    let mut snapshot = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = match crabc_core::io::read(descriptor.as_raw_fd(), &mut chunk) {
            Ok(read) => read,
            Err(Errno::INTR) => continue,
            Err(error) => return Err(ResolveError::System(error)),
        };
        if read == 0 { break; }
        let new_length = snapshot.len().checked_add(read).ok_or(ResolveError::Overflow)?;
        if new_length > 1024 * 1024 { return Err(ResolveError::Overflow); }
        snapshot.extend_from_slice(&chunk[..read]);
    }
    Ok(snapshot)
}

fn map_netdb_error(error: NetDbError) -> ResolveError {
    match error {
        NetDbError::InvalidInput => ResolveError::InvalidInput,
        NetDbError::Overflow => ResolveError::Overflow,
        NetDbError::System(error) => ResolveError::System(error),
    }
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

fn push_candidate(candidates: &mut Vec<String>, candidate: String) {
    if !candidates.iter().any(|known| known.eq_ignore_ascii_case(&candidate)) {
        candidates.push(candidate);
    }
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

fn parse_decimal_u8(value: &[u8]) -> Option<u8> {
    let number = parse_decimal(value)?;
    u8::try_from(number).ok()
}

fn parse_decimal_u32(value: &[u8]) -> Option<u32> {
    if value.is_empty() { return None; }
    let mut number = 0u32;
    for &byte in value {
        if !byte.is_ascii_digit() { return None; }
        number = number.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }
    Some(number)
}
