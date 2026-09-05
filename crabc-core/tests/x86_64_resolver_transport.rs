//! Native x86-64 regression for the bounded caller-owned DNS exchange seam.
//!
//! Every server is a local UDP or TCP fixture. The test deliberately proves
//! transport behavior only: it does not admit resolver policy, hosts parsing,
//! netdb state, a C resolver ABI, or any external-network fallback.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use crabc_core::resolver::{
    encode_query, exchange, DnsResponse, ExchangeConfig, NameServer, TYPE_A,
};
use crabc_core::Errno;

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

fn loopback_server(port: u16) -> NameServer {
    let mut server = NameServer::ipv4([127, 0, 0, 1]);
    server.port = port;
    server
}

fn one_server_config(port: u16) -> ExchangeConfig {
    ExchangeConfig::single(loopback_server(port), 250)
}

fn exchange_a(config: ExchangeConfig, name: &[u8], identifier: u16) -> [u8; 4] {
    let mut query = [0u8; 512];
    let query_len = encode_query(name, TYPE_A, identifier, &mut query).expect("encode A query");
    let mut answer = [0u8; 512];
    let answer_len = exchange(&config, &query[..query_len], identifier, &mut answer)
        .expect("complete DNS exchange");
    let response = DnsResponse::parse(&answer[..answer_len], name, TYPE_A, identifier)
        .expect("validate DNS response");
    let mut address = [0u8; 4];
    assert_eq!(
        response
            .rdata_at(TYPE_A, 0, &mut address)
            .expect("read A response"),
        Some(address.len())
    );
    address
}

#[test]
fn x86_64_udp_ignores_short_wrong_id_malformed_and_oversized_packets_before_an_answer() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind local DNS fixture");
    let port = server.local_addr().expect("fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = server.recv_from(&mut request).expect("receive DNS query");
        let request = &request[..length];
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        server.send_to(&[0, 1, 0], peer).expect("send short packet");
        server
            .send_to(
                &dns_answer(
                    request,
                    identifier.wrapping_add(1),
                    0x8180,
                    [198, 51, 100, 10],
                ),
                peer,
            )
            .expect("send wrong-ID packet");
        let mut question_mismatch =
            dns_answer(request, identifier, 0x8180, [198, 51, 100, 10]);
        assert!(question_mismatch[12] > 0, "fixture query has a first label");
        question_mismatch[13] ^= 0x20;
        server
            .send_to(&question_mismatch, peer)
            .expect("send question-mismatched packet");
        let malformed = [
            (identifier >> 8) as u8,
            identifier as u8,
            0x81,
            0x80,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
        ];
        server
            .send_to(&malformed, peer)
            .expect("send malformed matching-ID packet");
        let mut malformed_records = dns_answer(request, identifier, 0x8180, [198, 51, 100, 12]);
        malformed_records.pop();
        server
            .send_to(&malformed_records, peer)
            .expect("send record-framing-malformed packet");
        let mut oversized = dns_answer(request, identifier, 0x8180, [198, 51, 100, 11]);
        oversized.resize(600, 0);
        server
            .send_to(&oversized, peer)
            .expect("send oversized matching-ID packet");
        server
            .send_to(
                &dns_answer(request, identifier, 0x8180, [198, 51, 100, 42]),
                peer,
            )
            .expect("send matching packet");
    });

    assert_eq!(
        exchange_a(one_server_config(port), b"wrong-id.example.test", 0x4101),
        [198, 51, 100, 42]
    );
    worker.join().expect("DNS fixture completed");
}

#[test]
fn x86_64_dns_response_rejects_an_out_of_bounds_compressed_record_owner() {
    let mut query = [0u8; 512];
    let query_len = encode_query(
        b"compressed-owner.example.test",
        TYPE_A,
        0x4105,
        &mut query,
    )
    .expect("encode A query");
    let mut response = dns_answer(
        &query[..query_len],
        0x4105,
        0x8180,
        [198, 51, 100, 45],
    );
    response[query_len] = 0xff;
    response[query_len + 1] = 0xff;

    let parsed = DnsResponse::parse(
        &response,
        b"compressed-owner.example.test",
        TYPE_A,
        0x4105,
    )
    .expect("the response header and question remain valid");
    let mut address = [0u8; 4];
    assert_eq!(
        parsed.rdata_at(TYPE_A, 0, &mut address),
        Err(Errno::BADMSG),
        "an owner compression pointer must name a prior packet position"
    );
}

#[test]
fn x86_64_dns_response_rejects_a_compressed_record_owner_in_the_header() {
    let mut query = [0u8; 512];
    let query_len = encode_query(
        b"header-owner.example.test",
        TYPE_A,
        0x4106,
        &mut query,
    )
    .expect("encode A query");
    let mut response = dns_answer(
        &query[..query_len],
        0x4106,
        0x8180,
        [198, 51, 100, 46],
    );
    response[query_len] = 0xc0;
    response[query_len + 1] = 4;

    let parsed = DnsResponse::parse(
        &response,
        b"header-owner.example.test",
        TYPE_A,
        0x4106,
    )
    .expect("the response header and question remain valid");
    let mut address = [0u8; 4];
    assert_eq!(
        parsed.rdata_at(TYPE_A, 0, &mut address),
        Err(Errno::BADMSG),
        "a compression pointer cannot name DNS header bytes"
    );
}

#[test]
fn x86_64_exchange_rejects_a_header_compression_pointer_in_the_caller_query() {
    let mut config = ExchangeConfig::single(NameServer::ipv4([127, 0, 0, 1]), 1);
    // A deliberately invalid family keeps the pre-fix path entirely local: if
    // caller-query validation incorrectly accepts this header pointer, the
    // transport exhausts the unusable server and returns TIMEDOUT instead.
    config.nameservers[0].family = 0;
    let mut query = [0u8; 18];
    query[0..2].copy_from_slice(&0x4106u16.to_be_bytes());
    query[5] = 1;
    query[12] = 0xc0;
    query[13] = 4;
    query[14..16].copy_from_slice(&TYPE_A.to_be_bytes());
    query[16..18].copy_from_slice(&1u16.to_be_bytes());
    let mut answer = [0u8; 512];

    assert_eq!(
        exchange(&config, &query, 0x4106, &mut answer),
        Err(Errno::INVAL),
        "a caller query must contain one complete DNS question"
    );
}

#[test]
fn x86_64_udp_truncation_retries_the_exact_query_over_partial_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TCP DNS fixture");
    let port = listener.local_addr().expect("TCP fixture address").port();
    let udp = UdpSocket::bind(("127.0.0.1", port)).expect("bind UDP DNS fixture");
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = udp.recv_from(&mut request).expect("receive UDP DNS query");
        let request = request[..length].to_vec();
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        udp.send_to(&dns_truncated(&request, identifier), peer)
            .expect("send truncated UDP answer");

        let (mut stream, _) = listener.accept().expect("accept TCP retry");
        let mut frame_length = [0u8; 2];
        stream
            .read_exact(&mut frame_length)
            .expect("read TCP query length");
        let query_length = u16::from_be_bytes(frame_length) as usize;
        let mut tcp_query = vec![0u8; query_length];
        stream
            .read_exact(&mut tcp_query)
            .expect("read exact TCP query");
        assert_eq!(tcp_query, request, "TCP must retry the exact UDP query");

        let response = dns_answer(&tcp_query, identifier, 0x8180, [198, 51, 100, 43]);
        let frame_length = (response.len() as u16).to_be_bytes();
        stream
            .write_all(&frame_length[..1])
            .expect("write partial TCP length");
        thread::sleep(Duration::from_millis(5));
        stream
            .write_all(&frame_length[1..])
            .expect("write remaining TCP length");
        stream
            .write_all(&response[..3])
            .expect("write partial TCP response");
        thread::sleep(Duration::from_millis(5));
        stream
            .write_all(&response[3..])
            .expect("write remaining TCP response");
    });

    assert_eq!(
        exchange_a(one_server_config(port), b"truncated.example.test", 0x4102),
        [198, 51, 100, 43]
    );
    worker.join().expect("DNS fixture completed");
}

#[test]
fn x86_64_failed_first_nameserver_advances_in_configured_order() {
    let dropped = UdpSocket::bind("127.0.0.1:0").expect("bind silent DNS fixture");
    let dropped_port = dropped.local_addr().expect("silent fixture address").port();
    let answering = UdpSocket::bind("127.0.0.1:0").expect("bind answering DNS fixture");
    let answering_port = answering
        .local_addr()
        .expect("answering fixture address")
        .port();
    let dropped_worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let _ = dropped.recv_from(&mut request).expect("receive silent query");
    });
    let answering_worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let (length, peer) = answering
            .recv_from(&mut request)
            .expect("receive fallback query");
        let request = &request[..length];
        let identifier = u16::from_be_bytes([request[0], request[1]]);
        answering
            .send_to(
                &dns_answer(request, identifier, 0x8180, [198, 51, 100, 44]),
                peer,
            )
            .expect("send fallback answer");
    });

    let mut config = ExchangeConfig::single(loopback_server(dropped_port), 60);
    config.nameservers[1] = loopback_server(answering_port);
    config.nameserver_count = 2;
    assert_eq!(
        exchange_a(config, b"fallback.example.test", 0x4103),
        [198, 51, 100, 44]
    );
    dropped_worker.join().expect("silent fixture completed");
    answering_worker.join().expect("answering fixture completed");
}

#[test]
fn x86_64_all_nameserver_failures_are_bounded() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind silent DNS fixture");
    let port = server.local_addr().expect("silent fixture address").port();
    let worker = thread::spawn(move || {
        let mut request = [0u8; 512];
        let _ = server.recv_from(&mut request).expect("receive silent query");
    });

    let mut config = one_server_config(port);
    config.timeout_ms = 45;
    let mut query = [0u8; 512];
    let query_len = encode_query(b"timeout.example.test", TYPE_A, 0x4104, &mut query)
        .expect("encode timeout query");
    let mut answer = [0u8; 512];
    let started = Instant::now();
    assert_eq!(
        exchange(&config, &query[..query_len], 0x4104, &mut answer),
        Err(Errno::TIMEDOUT)
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "resolver exceeded its bounded failure budget"
    );
    worker.join().expect("silent fixture completed");
}

#[test]
fn x86_64_socket_setup_failure_is_distinct_from_exhausted_dns_attempts() {
    const CHILD: &str = "CRABC_RESOLVER_SETUP_FAILURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "x86_64_socket_setup_failure_is_distinct_from_exhausted_dns_attempts"])
            .env(CHILD, "1")
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let mut query = [0u8; 128];
    let length = encode_query(b"setup.test", TYPE_A, 19, &mut query).unwrap();
    let mut answer = [0u8; 128];
    let config = one_server_config(53);
    let mut limit = crabc_core::process::getrlimit_raw(7).unwrap();
    limit.rlim_cur = 0;
    crabc_core::process::setrlimit_raw(7, &limit).unwrap();
    assert_eq!(
        crabc_core::resolver::exchange_with_setup_error(&config, &query[..length], 19, &mut answer),
        Err(crabc_core::resolver::ExchangeError::Setup(Errno::MFILE))
    );
    assert_eq!(exchange(&config, &query[..length], 19, &mut answer), Err(Errno::TIMEDOUT));
}
