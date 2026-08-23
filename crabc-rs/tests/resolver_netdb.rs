use crabc_rs::net::{AddressFamily, SocketType};
use crabc_rs::netdb::{HostDatabase, ProtocolDatabase, ServiceDatabase, ServiceProtocol};
use crabc_rs::resolver::{
    IpAddress, LookupFlags, LookupOptions, NameInfoOptions, Resolver, ResolverConfig,
};

#[test]
fn native_resolver_keeps_numeric_results_owned_and_typed() {
    let resolver = Resolver::new(ResolverConfig::default());
    let results = resolver
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
        .expect("numeric lookup does not need a nameserver");

    assert_eq!(results.as_slice().len(), 1);
    assert_eq!(
        results.as_slice()[0].address().ip(),
        IpAddress::parse(b"2001:db8::42").unwrap()
    );
    assert_eq!(results.as_slice()[0].address().port(), 443);
    assert_eq!(results.as_slice()[0].socket_type(), SocketType::STREAM);
    assert_eq!(results.as_slice()[0].protocol(), 6);
    assert_eq!(results.canonical_name(), Some("2001:db8::42"));
}

#[test]
fn native_reverse_numeric_fallback_has_no_global_state() {
    let resolver = Resolver::new(ResolverConfig::default());
    let address =
        crabc_rs::resolver::SocketAddress::new(IpAddress::parse(b"192.0.2.7").unwrap(), 53);
    let result = resolver
        .reverse_lookup(
            address,
            Some(53),
            NameInfoOptions {
                numeric_host: true,
                ..NameInfoOptions::default()
            },
        )
        .expect("numeric reverse lookup does not need a nameserver");
    assert_eq!(result.host(), "192.0.2.7");
    assert_eq!(result.service(), Some("53"));
}

#[test]
fn ipv6_presentation_preserves_leading_and_interior_compression() {
    assert_eq!(IpAddress::parse(b"::1").unwrap().to_string(), "::1");
    assert_eq!(IpAddress::parse(b"1::2").unwrap().to_string(), "1::2");
    assert_eq!(IpAddress::parse(b"::").unwrap().to_string(), "::");
}

#[test]
fn native_dns_uses_the_caller_configured_direct_fixture() {
    use std::net::UdpSocket;
    use std::thread;

    let server = UdpSocket::bind("127.0.0.1:0").expect("bind isolated DNS fixture");
    let port = server.local_addr().expect("fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).expect("receive DNS query");
        assert!(length >= 16);
        let record_type = u16::from_be_bytes([request[length - 4], request[length - 3]]);
        assert_eq!(record_type, 1, "fixture is serving the A query only");

        let mut response = Vec::with_capacity(length + 16);
        response.extend_from_slice(&request[..2]);
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&request[12..length]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 7]);
        server
            .send_to(&response, peer)
            .expect("send deterministic DNS answer");
    });

    let mut config = ResolverConfig::new();
    config
        .add_nameserver_on_port(IpAddress::parse(b"127.0.0.1").unwrap(), port)
        .unwrap();
    config.set_attempts(1).unwrap();
    config.set_timeout_ms(500).unwrap();
    let resolver = Resolver::new(config);
    let result = resolver
        .lookup(
            Some("native.test"),
            None,
            LookupOptions {
                family: AddressFamily::INET,
                flags: LookupFlags::CANONNAME,
                ..LookupOptions::default()
            },
        )
        .expect("direct DNS fixture resolves through native API");
    worker.join().expect("DNS fixture completed");
    assert_eq!(result.canonical_name(), Some("native.test"));
    assert_eq!(
        result.as_slice()[0].address().ip(),
        IpAddress::parse(b"198.51.100.7").unwrap()
    );
}

#[test]
fn caller_owned_netdb_parsers_return_typed_copies() {
    let hosts = HostDatabase::from_bytes(
        b"# fixture\n192.0.2.7 example.test alias.test\n2001:db8::7 example.test\n",
    )
    .expect("valid hosts fixture");
    let host = hosts
        .lookup("ALIAS.TEST", None)
        .expect("alias resolves in caller-owned database");
    assert_eq!(host.name(), "example.test");
    assert_eq!(host.aliases(), &["alias.test"]);
    assert_eq!(host.addresses().len(), 2);
    assert_eq!(
        hosts
            .lookup("example.test", Some(AddressFamily::INET6))
            .unwrap()
            .addresses(),
        &[IpAddress::parse(b"2001:db8::7").unwrap()]
    );

    let services = ServiceDatabase::from_bytes(b"https 443/tcp www\ndomain 53/udp\n")
        .expect("valid services fixture");
    let https = services
        .lookup("www", Some(ServiceProtocol::Tcp))
        .expect("service alias resolves");
    assert_eq!(https.port(), 443);
    assert_eq!(https.protocol(), ServiceProtocol::Tcp);
    assert_eq!(
        services
            .lookup_port(53, Some(ServiceProtocol::Udp))
            .unwrap()
            .name(),
        "domain"
    );

    let protocols =
        ProtocolDatabase::from_bytes(b"tcp 6\nudp 17\n").expect("valid protocols fixture");
    assert_eq!(protocols.lookup_name("TCP").unwrap().number(), 6);
    assert_eq!(protocols.lookup_number(17).unwrap().name(), "udp");
}

#[test]
fn netdb_snapshots_own_input_and_enumerate_source_order() {
    let mut input = b"192.0.2.7 example.test alias.test\n2001:db8::7 example.test\n".to_vec();
    let hosts = HostDatabase::from_bytes(&input).expect("valid hosts fixture");
    input.fill(b'x');
    assert_eq!(hosts.entries().len(), 1);
    assert_eq!(hosts.iter().count(), hosts.len());
    assert_eq!((&hosts).into_iter().next().unwrap().name(), "example.test");
    let copied_host = hosts.lookup("alias.test", None).expect("owned host lookup");
    drop(hosts);
    assert_eq!(copied_host.name(), "example.test");
    assert_eq!(copied_host.addresses().len(), 2);

    let services = ServiceDatabase::from_bytes(b"custom 4242/custom-proto alias\n")
        .expect("valid service fixture");
    assert_eq!(services.entries().len(), 1);
    assert_eq!(
        services.iter().next().unwrap().protocol_name(),
        "custom-proto"
    );
    assert_eq!(services.lookup("ALIAS", None).unwrap().port(), 4242);

    let protocols =
        ProtocolDatabase::from_bytes(b"custom 253 alias\n").expect("valid protocol fixture");
    assert_eq!(protocols.entries().len(), 1);
    assert_eq!(protocols.iter().count(), protocols.len());
    assert_eq!(protocols.lookup_name("ALIAS").unwrap().number(), 253);
}

#[test]
fn malformed_netdb_records_reject_the_complete_snapshot() {
    use crabc_rs::netdb::NetDbError;

    assert_eq!(
        HostDatabase::from_bytes(b"not-an-address only-name"),
        Err(NetDbError::InvalidInput)
    );
    assert_eq!(
        ServiceDatabase::from_bytes(b"broken 80/tcp/extra"),
        Err(NetDbError::InvalidInput)
    );
    assert_eq!(
        ProtocolDatabase::from_bytes(b"broken 65536"),
        Err(NetDbError::Overflow)
    );
    assert_eq!(
        ProtocolDatabase::from_bytes(b"bad\xff 1"),
        Err(NetDbError::InvalidInput)
    );
}

#[test]
fn system_netdb_loaders_match_their_direct_file_snapshots() {
    let hosts_bytes = std::fs::read("/etc/hosts").expect("system hosts file");
    let hosts_expected = HostDatabase::from_bytes(&hosts_bytes).expect("parse system hosts bytes");
    let hosts = HostDatabase::from_system().expect("direct hosts loader");
    assert_eq!(hosts, hosts_expected);
    assert_eq!(hosts.iter().count(), hosts.len());

    let services_bytes = std::fs::read("/etc/services").expect("system services file");
    let services_expected =
        ServiceDatabase::from_bytes(&services_bytes).expect("parse system services bytes");
    let services = ServiceDatabase::from_system().expect("direct services loader");
    assert_eq!(services, services_expected);
    assert_eq!(services.iter().count(), services.len());

    let protocols_bytes = std::fs::read("/etc/protocols").expect("system protocols file");
    let protocols_expected =
        ProtocolDatabase::from_bytes(&protocols_bytes).expect("parse system protocols bytes");
    let protocols = ProtocolDatabase::from_system().expect("direct protocols loader");
    assert_eq!(protocols, protocols_expected);
    assert_eq!(protocols.iter().count(), protocols.len());
}

#[test]
fn unsupported_addrconfig_is_explicit() {
    let resolver = Resolver::new(ResolverConfig::default());
    let result = resolver.lookup(
        Some("127.0.0.1"),
        None,
        LookupOptions {
            flags: LookupFlags::ADDRCONFIG,
            ..LookupOptions::default()
        },
    );
    assert_eq!(result, Err(crabc_rs::resolver::ResolveError::InvalidInput));
}
