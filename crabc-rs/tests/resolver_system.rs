use std::net::UdpSocket;
use std::thread;

use crabc_rs::net::{AddressFamily, SocketType};
use crabc_rs::resolver::{IpAddress, LookupFlags, LookupOptions, Resolver, ResolverConfig};

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

fn dns_a_answer(request: &[u8], address: [u8; 4]) -> Vec<u8> {
    let identifier = u16::from_be_bytes([request[0], request[1]]);
    let mut response = Vec::new();
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
    let mut response = Vec::new();
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16]);
    response.extend_from_slice(&address);
    response
}

fn dns_cname_answer(request: &[u8], target: &str) -> Vec<u8> {
    let identifier = u16::from_be_bytes([request[0], request[1]]);
    let target = wire_name(target);
    let mut response = Vec::new();
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8180u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30]);
    response.extend_from_slice(&(target.len() as u16).to_be_bytes());
    response.extend_from_slice(&target);
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
fn caller_owned_system_snapshots_parse_and_hosts_precede_dns() {
    let config = ResolverConfig::from_bytes(
        b"# isolated fixture\nnameserver 192.0.2.53\nsearch example.test local.test\noptions ndots:2 timeout:3 attempts:4\n",
        b"192.0.2.17 canonical.example.test alias.example.test\n",
    )
    .expect("parse caller-owned resolver snapshots");

    assert_eq!(config.search_domains(), &["example.test", "local.test"]);
    assert_eq!(config.ndots(), 2);
    assert_eq!(config.nameserver_count(), 1);
    assert_eq!(config.timeout_ms(), 3000);
    assert_eq!(config.attempts(), 4);

    let result = Resolver::new(config)
        .lookup(
            Some("alias.example.test"),
            None,
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                ..LookupOptions::default()
            },
        )
        .expect("hosts entry must resolve without DNS");
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"192.0.2.17").unwrap());
}

#[test]
fn caller_owned_resolver_snapshot_rejects_invalid_configuration() {
    assert!(ResolverConfig::from_bytes(b"nameserver not-an-address\n", b"").is_err());
    assert!(ResolverConfig::from_bytes(b"options ndots:16\n", b"").is_err());
    assert!(ResolverConfig::from_bytes(b"search\n", b"").is_err());
}

#[test]
fn resolver_search_candidates_follow_ndots_order() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        assert_eq!(question_name(&request[..length]), "service.example.test");
        server.send_to(&dns_a_answer(&request[..length], [192, 0, 2, 44]), peer).unwrap();
    });

    let mut config = query_config(port);
    config.add_search_domain("example.test").unwrap();
    config.set_ndots(1).unwrap();
    let result = Resolver::new(config)
        .lookup(
            Some("service"),
            None,
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME,
            },
        )
        .unwrap();
    worker.join().unwrap();
    assert_eq!(result.canonical_name(), Some("service.example.test"));
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"192.0.2.44").unwrap());
}

#[test]
fn resolver_completes_cname_chain_and_keeps_target_canonical_name() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        assert_eq!(question_name(&request[..length]), "alias.example.test");
        server
            .send_to(&dns_cname_answer(&request[..length], "target.example.test"), peer)
            .unwrap();
        let (length, peer) = server.recv_from(&mut request).unwrap();
        assert_eq!(question_name(&request[..length]), "target.example.test");
        server.send_to(&dns_a_answer(&request[..length], [192, 0, 2, 45]), peer).unwrap();
    });

    let result = Resolver::new(query_config(port))
        .lookup(
            Some("alias.example.test"),
            None,
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME,
            },
        )
        .unwrap();
    worker.join().unwrap();
    assert_eq!(result.canonical_name(), Some("target.example.test"));
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"192.0.2.45").unwrap());
}

#[test]
fn resolver_completes_aaaa_answers_for_inet6() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        assert_eq!(&request[length - 4..length - 2], &[0, 28]);
        server
            .send_to(&dns_aaaa_answer(&request[..length], [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ]), peer)
            .unwrap();
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
        .unwrap();
    worker.join().unwrap();
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"2001:db8::7").unwrap());
}

#[test]
fn resolver_system_snapshot_reads_direct_files_without_global_state() {
    let config = ResolverConfig::from_system().expect("Linux resolver files should be readable");
    assert!(config.hosts().is_some());
    assert!(config.nameserver_count() <= 3);
    assert!(config.search_domains().len() <= 6);
}
