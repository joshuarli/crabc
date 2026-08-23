use crabc_rs::net::EthernetAddress;

#[test]
fn ethernet_parser_accepts_canonical_and_musl_noncanonical_components() {
    let canonical = EthernetAddress::parse(b"00:1a:2B:03:04:ff").expect("canonical address");
    assert_eq!(canonical.octets(), [0x00, 0x1a, 0x2b, 0x03, 0x04, 0xff]);

    let noncanonical = EthernetAddress::parse(b"0x0:1:02:0X3:4:05").expect("noncanonical address");
    assert_eq!(noncanonical, EthernetAddress::new([0, 1, 2, 3, 4, 5]));
}

#[test]
fn ethernet_parser_rejects_malformed_incomplete_and_trailing_input() {
    for input in [
        b"".as_slice(),
        b"00:11:22:33:44".as_slice(),
        b"00:11:22:33:44:".as_slice(),
        b"00:11:22:33:44:55:66".as_slice(),
        b":11:22:33:44:55".as_slice(),
        b"00::22:33:44:55".as_slice(),
        b"00:11:22:33:44:gg".as_slice(),
        b"00:11:22:33:44:100".as_slice(),
        b"00:11:22:33:44:0x".as_slice(),
        b"00:11:22:33:44:55\0".as_slice(),
        b"00:11:22:33:44:55 ".as_slice(),
        b" 00:11:22:33:44:55".as_slice(),
        b"+00:11:22:33:44:55".as_slice(),
    ] {
        assert_eq!(EthernetAddress::parse(input), None, "input: {input:?}");
    }
}

#[test]
fn ethernet_formatter_is_fixed_width_uppercase_and_bounded() {
    let address = EthernetAddress::new([0x00, 0x01, 0x0a, 0x10, 0xab, 0xff]);
    assert_eq!(address.to_ascii_bytes(), *b"00:01:0A:10:AB:FF");
    assert_eq!(address.to_string(), "00:01:0A:10:AB:FF");

    let mut output = [0xa5; 18];
    assert_eq!(address.write_to(&mut output), Some(17));
    assert_eq!(&output[..17], b"00:01:0A:10:AB:FF");
    assert_eq!(output[17], 0xa5);

    let mut short = [0xa5; 16];
    assert_eq!(address.write_to(&mut short), None);
    assert_eq!(short, [0xa5; 16]);
}

#[test]
fn ethernet_parser_and_formatter_round_trip_every_octet_shape() {
    for octets in [
        [0, 0, 0, 0, 0, 0],
        [1, 2, 3, 4, 5, 6],
        [0x0f, 0xf0, 0x10, 0xa0, 0xb0, 0xc0],
        [u8::MAX; 6],
    ] {
        let address = EthernetAddress::new(octets);
        let text = address.to_ascii_bytes();
        assert_eq!(EthernetAddress::parse(&text), Some(address));
    }
}
