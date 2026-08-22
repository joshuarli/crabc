use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use crabc_rs::net::{AddressFamily, SocketType};
use crabc_rs::resolver::{IpAddress, LookupFlags, LookupOptions, ResolveError, Resolver, ResolverConfig};

fn dns_answer(request: &[u8], identifier: u16, flags: u16, address: [u8; 4]) -> Vec<u8> {
    let mut response = Vec::with_capacity(request.len() + 16);
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
    response.extend_from_slice(&address);
    response
}

fn dns_truncated(request: &[u8], identifier: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(request.len());
    response.extend_from_slice(&identifier.to_be_bytes());
    response.extend_from_slice(&0x8380u16.to_be_bytes());
    response.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    response.extend_from_slice(&request[12..]);
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

fn lookup_a(config: ResolverConfig, name: &str) -> crabc_rs::resolver::AddressResults {
    Resolver::new(config)
        .lookup(
            Some(name),
            None,
            LookupOptions {
                family: AddressFamily::INET,
                socket_type: Some(SocketType::STREAM),
                protocol: Some(6),
                flags: LookupFlags::CANONNAME,
            },
        )
        .unwrap()
}

#[test]
fn udp_ignores_short_and_wrong_transaction_packets_before_valid_answer() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).unwrap();
        let request = &request[..length];
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        server.send_to(&[0, 1, 0], peer).unwrap();
        server
            .send_to(
                &dns_answer(request, identifier.wrapping_add(1), 0x8180, [198, 51, 100, 10]),
                peer,
            )
            .unwrap();
        server
            .send_to(&dns_answer(request, identifier, 0x8180, [198, 51, 100, 42]), peer)
            .unwrap();
    });

    let result = lookup_a(query_config(port), "malformed.example.test");
    worker.join().unwrap();
    assert_eq!(result.canonical_name(), Some("malformed.example.test"));
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"198.51.100.42").unwrap());
}

#[test]
fn udp_truncation_retries_same_query_over_length_prefixed_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = udp.recv_from(&mut request).unwrap();
        let request = request[..length].to_vec();
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        udp.send_to(&dns_truncated(&request, identifier), peer).unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let mut frame_length = [0u8; 2];
        stream.read_exact(&mut frame_length).unwrap();
        let query_length = u16::from_be_bytes(frame_length) as usize;
        let mut tcp_query = vec![0u8; query_length];
        stream.read_exact(&mut tcp_query).unwrap();
        assert_eq!(tcp_query, request, "TCP must retry the exact DNS query");

        let response = dns_answer(&tcp_query, identifier, 0x8180, [198, 51, 100, 43]);
        let frame_length = (response.len() as u16).to_be_bytes();
        stream.write_all(&frame_length[..1]).unwrap();
        thread::sleep(Duration::from_millis(5));
        stream.write_all(&frame_length[1..]).unwrap();
        stream.write_all(&response[..3]).unwrap();
        thread::sleep(Duration::from_millis(5));
        stream.write_all(&response[3..]).unwrap();
    });

    let result = lookup_a(query_config(port), "truncated.example.test");
    worker.join().unwrap();
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"198.51.100.43").unwrap());
}

#[test]
fn failed_first_nameserver_advances_to_the_next_configured_server() {
    let dropped = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dropped_port = dropped.local_addr().unwrap().port();
    let answering = UdpSocket::bind("127.0.0.1:0").unwrap();
    let answering_port = answering.local_addr().unwrap().port();
    let drop_worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let _ = dropped.recv_from(&mut request).unwrap();
    });
    let answer_worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = answering.recv_from(&mut request).unwrap();
        let request = &request[..length];
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        answering
            .send_to(&dns_answer(request, identifier, 0x8180, [198, 51, 100, 44]), peer)
            .unwrap();
    });

    let mut config = ResolverConfig::new();
    config
        .add_nameserver_on_port(IpAddress::parse(b"127.0.0.1").unwrap(), dropped_port)
        .unwrap();
    config
        .add_nameserver_on_port(IpAddress::parse(b"127.0.0.1").unwrap(), answering_port)
        .unwrap();
    config.set_attempts(1).unwrap();
    config.set_timeout_ms(60).unwrap();

    let result = lookup_a(config, "fallback.example.test");
    drop_worker.join().unwrap();
    answer_worker.join().unwrap();
    assert_eq!(result.as_slice()[0].address().ip(), IpAddress::parse(b"198.51.100.44").unwrap());
}

#[test]
fn all_nameserver_failures_are_bounded_and_report_temporary_failure() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let _ = server.recv_from(&mut request).unwrap();
    });

    let mut config = query_config(port);
    config.set_timeout_ms(45).unwrap();
    let started = Instant::now();
    let result = Resolver::new(config).lookup(
        Some("timeout.example.test"),
        None,
        LookupOptions { family: AddressFamily::INET, ..LookupOptions::default() },
    );
    let elapsed = started.elapsed();
    worker.join().unwrap();

    assert_eq!(result, Err(ResolveError::Temporary));
    assert!(elapsed < Duration::from_secs(1), "resolver exceeded bounded failure budget: {elapsed:?}");
}
