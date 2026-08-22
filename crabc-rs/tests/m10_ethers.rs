use crabc_rs::net::ethers::{
    parse_line, EthernetDatabase, EthernetLine, Ipv6Constants, IN6ADDR_ANY, IN6ADDR_LOOPBACK,
};
use crabc_rs::net::{EthernetAddress, Ipv6Addr};

#[test]
fn line_parser_borrows_valid_records_and_classifies_non_records() {
    let line = b"00:1:2A:03:4:ff Router # comment";
    let parsed = parse_line(line);
    let EthernetLine::Record(record) = parsed else {
        panic!("valid ethers line must produce a record: {parsed:?}");
    };
    assert_eq!(record.address(), EthernetAddress::new([0, 1, 0x2a, 3, 4, 0xff]));
    assert_eq!(record.hostname(), b"Router");

    assert_eq!(parse_line(b" \t\r\n"), EthernetLine::Blank);
    assert_eq!(parse_line(b"  # ignored"), EthernetLine::Comment);
    assert_eq!(parse_line(b"00:11:22:33:44 host"), EthernetLine::Invalid);
    assert_eq!(parse_line(b"00:11:22:33:44:55"), EthernetLine::Invalid);

    let non_utf8 = b"0:01:02:03:04:5 \xffhost trailing-token";
    let EthernetLine::Record(record) = parse_line(non_utf8) else {
        panic!("non-UTF-8 hostname bytes are part of the C grammar");
    };
    assert_eq!(record.address().octets(), [0, 1, 2, 3, 4, 5]);
    assert_eq!(record.hostname(), b"\xffhost");
}

#[test]
fn database_skips_invalid_lines_retains_source_order_and_matches_first_case_insensitively() {
    let bytes = b"# comment\n\n00:00:00:00:00:01 Router\ninvalid\n00:00:00:00:00:02 router\n00:00:00:00:00:03 Other\n";
    let database = EthernetDatabase::from_bytes(bytes).expect("small database allocation");

    assert_eq!(database.len(), 3);
    assert_eq!(database.entries()[0].hostname(), b"Router");
    assert_eq!(database.entries()[1].hostname(), b"router");
    assert_eq!(database.entries()[2].hostname(), b"Other");
    assert_eq!(
        database.lookup_hostname(b"ROUTER"),
        Some(EthernetAddress::new([0, 0, 0, 0, 0, 1]))
    );
    assert_eq!(
        database.lookup_hostname_entry(b"other").map(|entry| entry.hostname()),
        Some(b"Other".as_slice())
    );
    assert!(database.lookup_hostname(b"missing").is_none());
}

#[test]
fn ipv6_constants_are_native_values_with_documented_contents() {
    assert_eq!(IN6ADDR_ANY, Ipv6Addr::UNSPECIFIED);
    assert_eq!(IN6ADDR_LOOPBACK, Ipv6Addr::LOCALHOST);
    assert_eq!(Ipv6Constants::ANY, Ipv6Addr::UNSPECIFIED);
    assert_eq!(Ipv6Constants::LOOPBACK, Ipv6Addr::LOCALHOST);
    assert_eq!(IN6ADDR_ANY.octets(), [0; 16]);
    assert_eq!(IN6ADDR_LOOPBACK.octets()[15], 1);
}
