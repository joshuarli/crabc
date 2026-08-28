//! Native x86-64 regression for the alloc-backed resolver and hosts snapshot.
//!
//! Every DNS exchange uses one local loopback fixture. The test admits the
//! caller-owned resolver and `/etc/hosts` boundary only; it deliberately does
//! not select service/protocol databases, C resolver state, or external DNS.

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use crabc_rs::net::{AddressFamily, SocketType};
use crabc_rs::netdb::{HostDatabase, NetDbError};
use crabc_rs::resolver::{
    IpAddress, LookupFlags, LookupOptions, NameInfoOptions, ResolveError, Resolver,
    ResolverConfig, SocketAddress,
};

fn wire_name(name: &str) -> Vec<u8> {
    let mut output = Vec::new();
    for label in name.split('.') {
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output
}

fn question_name(request: &[u8]) -> String {
    let mut cursor = 12;
    let mut labels = Vec::new();
    while request[cursor] != 0 {
        let length = request[cursor] as usize;
        cursor += 1;
        labels.push(std::str::from_utf8(&request[cursor..cursor + length]).unwrap());
        cursor += length;
    }
    labels.join(".")
}

fn dns_name_answer(request: &[u8], record_type: u16, name: &str) -> Vec<u8> {
    let identifier = u16::from_be_bytes([request[0], request[1]]);
    let data = wire_name(name);
    let mut response = Vec::with_capacity(request.len() + 12 + data.len());
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&record_type.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
    response.extend_from_slice(&data);
    response
}

fn dns_a_answer(request: &[u8], address: [u8; 4]) -> Vec<u8> {
    let identifier = u16::from_be_bytes([request[0], request[1]]);
    let mut response = Vec::with_capacity(request.len() + 16);
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
    response.extend_from_slice(&address);
    response
}

fn dns_aaaa_answer(request: &[u8], address: [u8; 16]) -> Vec<u8> {
    let identifier = u16::from_be_bytes([request[0], request[1]]);
    let mut response = Vec::with_capacity(request.len() + 28);
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
    response.extend_from_slice(&address);
    response
}

fn query_config(port: u16) -> ResolverConfig {
    let mut config = ResolverConfig::new();
    config
        .add_nameserver_on_port(IpAddress::parse(b"127.0.0.1").unwrap(), port)
        .unwrap();
    config.set_attempts(1).unwrap();
    config.set_timeout_ms(250).unwrap();
    config
}

#[test]
fn x86_64_hosts_snapshot_is_owned_case_insensitive_and_precedes_dns() {
    let mut input = b"# comment\r\n192.0.2.17 canonical.example.test alias.example.test\n2001:db8::17 CANONICAL.EXAMPLE.TEST alias-v6.example.test ALIAS.EXAMPLE.TEST\n192.0.2.17 canonical.example.test extra.example.test # duplicate address\n198.51.100.9 second.example.test second-alias.example.test\n".to_vec();
    let hosts = HostDatabase::from_bytes(&input).expect("parse hosts snapshot");
    input.fill(b'x');
    assert_eq!(hosts.len(), 2);
    assert_eq!(hosts.entries()[0].name(), "canonical.example.test");
    assert_eq!(
        hosts.entries()[0].aliases(),
        &["alias.example.test", "alias-v6.example.test", "extra.example.test"]
    );
    assert_eq!(
        hosts.entries()[0].addresses(),
        &[
            IpAddress::parse(b"192.0.2.17").unwrap(),
            IpAddress::parse(b"2001:db8::17").unwrap(),
        ]
    );
    let host = hosts
        .lookup("ALIAS.EXAMPLE.TEST", Some(AddressFamily::INET))
        .expect("case-insensitive alias lookup");
    assert_eq!(host.name(), "canonical.example.test");
    assert_eq!(host.addresses(), &[IpAddress::parse(b"192.0.2.17").unwrap()]);
    assert_eq!(
        hosts
            .lookup("canonical.example.test", Some(AddressFamily::INET6))
            .expect("IPv6 family-filtered lookup")
            .addresses(),
        &[IpAddress::parse(b"2001:db8::17").unwrap()]
    );
    assert_eq!(hosts.iter().count(), hosts.len());
    let copied_host = hosts
        .lookup("extra.example.test", None)
        .expect("owned lookup result");
    drop(hosts);
    assert_eq!(copied_host.name(), "canonical.example.test");
    assert_eq!(copied_host.addresses().len(), 2);
    assert_eq!(
        HostDatabase::from_bytes(b"192.0.2.17 valid.example.test\nnot-an-address invalid.example.test"),
        Err(NetDbError::InvalidInput)
    );

    let config = ResolverConfig::from_bytes(
        b"",
        b"192.0.2.17 canonical.example.test alias.example.test\n",
    )
    .expect("parse caller-owned resolver and hosts snapshots");
    assert_eq!(config.nameserver_count(), 0);
    let result = Resolver::new(config)
        .lookup(
            Some("alias.example.test"),
            Some("443"),
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME | LookupFlags::NUMERICSERV,
            },
        )
        .expect("hosts lookup must precede the configured DNS server");
    assert_eq!(result.canonical_name(), Some("canonical.example.test"));
    assert_eq!(result.as_slice().len(), 1);
    assert_eq!(
        result.as_slice()[0].address().ip(),
        IpAddress::parse(b"192.0.2.17").unwrap()
    );
    assert_eq!(result.as_slice()[0].address().port(), 443);
    assert_eq!(result.as_slice()[0].socket_type(), SocketType::STREAM);
    assert_eq!(result.as_slice()[0].protocol(), 6);
    assert_eq!(
        Resolver::new(ResolverConfig::default()).lookup(
            Some("127.0.0.1"),
            Some("domain"),
            LookupOptions::default(),
        ),
        Err(ResolveError::ServiceNotFound)
    );
    assert!(matches!(
        ResolverConfig::from_bytes(b"nameserver not-an-address\n", b""),
        Err(ResolveError::InvalidInput)
    ));
    assert!(matches!(
        ResolverConfig::from_bytes(b"", b"not-an-address invalid.example.test"),
        Err(ResolveError::InvalidInput)
    ));
}

#[test]
fn x86_64_resolver_numeric_and_null_node_policy_remains_typed_and_local() {
    let resolver = Resolver::new(ResolverConfig::default());
    let numeric = resolver
        .lookup(
            Some("2001:db8::42"),
            Some("443"),
            LookupOptions {
                family: AddressFamily::INET6,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::NUMERICHOST | LookupFlags::NUMERICSERV | LookupFlags::CANONNAME,
            },
        )
        .expect("numeric IPv6 lookup must not need a nameserver");
    assert_eq!(numeric.canonical_name(), Some("2001:db8::42"));
    assert_eq!(numeric.as_slice().len(), 1);
    assert_eq!(
        numeric.as_slice()[0].address().ip(),
        IpAddress::parse(b"2001:db8::42").unwrap()
    );
    assert_eq!(numeric.as_slice()[0].address().port(), 443);

    let mapped = resolver
        .lookup(
            Some("192.0.2.42"),
            None,
            LookupOptions {
                family: AddressFamily::INET6,
                flags: LookupFlags::NUMERICHOST | LookupFlags::V4MAPPED,
                ..LookupOptions::default()
            },
        )
        .expect("numeric IPv4 maps only when explicitly requested");
    assert_eq!(
        mapped.as_slice()[0].address().ip(),
        IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 42])
    );

    let passive = resolver
        .lookup(
            None,
            None,
            LookupOptions {
                family: AddressFamily::INET,
                flags: LookupFlags::PASSIVE,
                ..LookupOptions::default()
            },
        )
        .expect("null passive node is local");
    assert_eq!(passive.as_slice()[0].address().ip(), IpAddress::V4([0; 4]));
    assert_eq!(
        resolver.lookup(
            Some("not-numeric.example.test"),
            None,
            LookupOptions {
                flags: LookupFlags::NUMERICHOST,
                ..LookupOptions::default()
            },
        ),
        Err(ResolveError::NameNotFound)
    );
    assert_eq!(
        resolver.lookup(
            Some("127.0.0.1"),
            None,
            LookupOptions {
                flags: LookupFlags::ADDRCONFIG,
                ..LookupOptions::default()
            },
        ),
        Err(ResolveError::InvalidInput)
    );
    let reverse = resolver
        .reverse_lookup(
            SocketAddress::new(IpAddress::V4([192, 0, 2, 7]), 53),
            Some(53),
            NameInfoOptions {
                numeric_host: true,
                ..NameInfoOptions::default()
            },
        )
        .expect("numeric reverse lookup must not need a nameserver");
    assert_eq!(reverse.host(), "192.0.2.7");
    assert_eq!(reverse.service(), Some("53"));
}

#[test]
fn x86_64_resolver_search_cname_and_ptr_use_the_local_configured_server() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind local DNS fixture");
    let port = server.local_addr().expect("fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];

        let (length, peer) = server.recv_from(&mut request).expect("receive search query");
        let first_request = &request[..length];
        assert_eq!(question_name(first_request), "alias.example.test");
        assert_eq!(&first_request[length - 4..length - 2], &[0, 1]);
        server
            .send_to(&dns_name_answer(first_request, 5, "target.example.test"), peer)
            .expect("send CNAME answer");

        let (length, peer) = server.recv_from(&mut request).expect("receive CNAME target query");
        let second_request = &request[..length];
        assert_eq!(question_name(second_request), "target.example.test");
        assert_eq!(&second_request[length - 4..length - 2], &[0, 1]);
        server
            .send_to(&dns_a_answer(second_request, [198, 51, 100, 42]), peer)
            .expect("send A answer");

        let (length, peer) = server.recv_from(&mut request).expect("receive PTR query");
        let third_request = &request[..length];
        assert_eq!(question_name(third_request), "42.100.51.198.in-addr.arpa");
        assert_eq!(&third_request[length - 4..length - 2], &[0, 12]);
        server
            .send_to(&dns_name_answer(third_request, 12, "ptr.example.test"), peer)
            .expect("send PTR answer");
    });

    let mut config = query_config(port);
    config.add_search_domain("example.test").unwrap();
    config.set_ndots(1).unwrap();
    let resolver = Resolver::new(config);
    let result = resolver
        .lookup(
            Some("alias"),
            Some("443"),
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME | LookupFlags::NUMERICSERV,
            },
        )
        .expect("CNAME lookup through local DNS fixture");
    assert_eq!(result.canonical_name(), Some("target.example.test"));
    assert_eq!(
        result.as_slice()[0].address().ip(),
        IpAddress::parse(b"198.51.100.42").unwrap()
    );

    let reverse = resolver
        .reverse_lookup(
            SocketAddress::new(IpAddress::parse(b"198.51.100.42").unwrap(), 443),
            Some(443),
            NameInfoOptions::default(),
        )
        .expect("PTR lookup through local DNS fixture");
    worker.join().expect("DNS fixture completed");
    assert_eq!(reverse.host(), "ptr.example.test");
    assert_eq!(reverse.service(), Some("443"));
}

#[test]
fn x86_64_resolver_aaaa_and_timeout_map_through_the_facade() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind IPv6 DNS fixture");
    let port = server.local_addr().expect("fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).expect("receive AAAA query");
        let request = &request[..length];
        assert_eq!(&request[length - 4..length - 2], &[0, 28]);
        server
            .send_to(
                &dns_aaaa_answer(
                    request,
                    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
                ),
                peer,
            )
            .expect("send AAAA answer");
    });
    let result = Resolver::new(query_config(port))
        .lookup(
            Some("ipv6.example.test"),
            None,
            LookupOptions {
                family: AddressFamily::INET6,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME,
            },
        )
        .expect("AAAA lookup through local fixture");
    worker.join().expect("IPv6 DNS fixture completed");
    assert_eq!(
        result.as_slice()[0].address().ip(),
        IpAddress::parse(b"2001:db8::7").unwrap()
    );

    let silent = UdpSocket::bind("127.0.0.1:0").expect("bind silent DNS fixture");
    let port = silent.local_addr().expect("silent fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let _ = silent.recv_from(&mut request).expect("receive timed-out query");
    });
    let mut config = query_config(port);
    config.set_timeout_ms(45).unwrap();
    let started = Instant::now();
    let result = Resolver::new(config).lookup(
        Some("timeout.example.test"),
        None,
        LookupOptions {
            family: AddressFamily::INET,
            ..LookupOptions::default()
        },
    );
    let elapsed = started.elapsed();
    worker.join().expect("silent DNS fixture completed");
    assert_eq!(result, Err(ResolveError::Temporary));
    assert!(
        elapsed < Duration::from_secs(1),
        "resolver exceeded bounded failure budget: {elapsed:?}"
    );
}

#[test]
fn x86_64_resolver_system_snapshot_uses_direct_bounded_file_reads() {
    let expected_hosts = HostDatabase::from_bytes(
        &std::fs::read("/etc/hosts").expect("read fixture hosts snapshot"),
    )
    .expect("parse fixture hosts snapshot");
    let config = ResolverConfig::from_system().expect("load direct resolver snapshots");
    assert_eq!(config.hosts(), Some(&expected_hosts));
    assert!(config.nameserver_count() <= 3);
    assert!(config.search_domains().len() <= 6);
    assert!(config.timeout_ms() > 0);
    assert!(config.attempts() > 0);
}
