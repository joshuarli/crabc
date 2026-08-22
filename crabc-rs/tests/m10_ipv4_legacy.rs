use crabc_rs::net::{
    ipv4_local_number, ipv4_network_number, make_ipv4_address,
    parse_ipv4_legacy, parse_ipv4_network_number, Ipv4Addr,
};

#[test]
fn legacy_ipv4_forms_preserve_musl_component_widths() {
    assert_eq!(
        parse_ipv4_legacy(b"127.1"),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"10.0.128.31"),
        Some(Ipv4Addr::new(10, 0, 128, 31)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"10.20.30"),
        Some(Ipv4Addr::new(10, 20, 0, 30)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"0x7f000001"),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"2130706433"),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
    );
}

#[test]
fn legacy_ipv4_accepts_base_zero_octal_hex_and_maximum() {
    assert_eq!(
        parse_ipv4_legacy(b"0177.1"),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"0XFF.0.0.1"),
        Some(Ipv4Addr::new(255, 0, 0, 1)),
    );
    assert_eq!(
        parse_ipv4_legacy(b"0xffffffff"),
        Some(Ipv4Addr::new(255, 255, 255, 255)),
    );
}

#[test]
fn legacy_ipv4_values_expose_network_octets_and_canonical_output() {
    let address = parse_ipv4_legacy(b"192.0.2.7").expect("parse address");
    assert_eq!(address.octets(), [192, 0, 2, 7]);
    assert_eq!(address.to_string(), "192.0.2.7");
}

#[test]
fn legacy_ipv4_rejects_non_c_number_forms() {
    for input in [
        b"".as_slice(),
        b" 127.0.0.1".as_slice(),
        b"+127.0.0.1".as_slice(),
        b"-127.0.0.1".as_slice(),
        b"127.0.0.1 ".as_slice(),
        b"127.0.0.1\0".as_slice(),
        b"127.0.0.1.2".as_slice(),
        b"127..1".as_slice(),
        b"127.0.0.".as_slice(),
        b"0x".as_slice(),
        b"08.0.0.1".as_slice(),
        &[0xff, b'.', 0, 0, 1],
    ] {
        assert_eq!(parse_ipv4_legacy(input), None, "input: {input:?}");
    }
}

#[test]
fn legacy_ipv4_rejects_component_overflow_and_too_many_parts() {
    for input in [
        b"256.0.0.1".as_slice(),
        b"1.2.65536".as_slice(),
        b"4294967296".as_slice(),
        b"1.2.3.4.5".as_slice(),
        b"0x100.0.0.1".as_slice(),
    ] {
        assert_eq!(parse_ipv4_legacy(input), None, "input: {input:?}");
    }
}

#[test]
fn legacy_ipv4_network_number_distinguishes_invalid_from_all_ones() {
    assert_eq!(
        parse_ipv4_network_number(b"127.0.0.1"),
        Some(0x7f00_0001),
    );
    assert_eq!(
        parse_ipv4_network_number(b"0xffffffff"),
        Some(u32::MAX),
    );
    assert_eq!(parse_ipv4_network_number(b"256.0.0.1"), None);
}

#[test]
fn classful_helpers_follow_logical_network_word_boundaries() {
    let class_a = Ipv4Addr::new(127, 0, 0, 1);
    assert_eq!(ipv4_local_number(class_a), 0x0000_0001);
    assert_eq!(ipv4_network_number(class_a), 0x0000_007f);

    let class_b = Ipv4Addr::new(128, 0, 0, 1);
    assert_eq!(ipv4_local_number(class_b), 0x0000_0001);
    assert_eq!(ipv4_network_number(class_b), 0x0000_8000);

    let class_c = Ipv4Addr::new(192, 0, 0, 1);
    assert_eq!(ipv4_local_number(class_c), 0x0000_0001);
    assert_eq!(ipv4_network_number(class_c), 0x00c0_0000);

    let class_d_or_later = Ipv4Addr::new(224, 0, 0, 1);
    assert_eq!(ipv4_local_number(class_d_or_later), 0x0000_0001);
    assert_eq!(ipv4_network_number(class_d_or_later), 0x00e0_0000);
}

#[test]
fn classful_make_address_adds_missing_class_markers() {
    assert_eq!(
        make_ipv4_address(0x7f, 1),
        Ipv4Addr::new(127, 0, 0, 1),
    );
    assert_eq!(
        make_ipv4_address(0x8001, 2),
        Ipv4Addr::new(128, 1, 0, 2),
    );
    assert_eq!(
        make_ipv4_address(0xc00102, 3),
        Ipv4Addr::new(192, 1, 2, 3),
    );
    assert_eq!(
        make_ipv4_address(128, 1),
        Ipv4Addr::new(128, 128, 0, 1),
    );
    assert_eq!(
        make_ipv4_address(0x400000, 1),
        Ipv4Addr::new(192, 0, 0, 1),
    );
    assert_eq!(
        make_ipv4_address(0xe0000001, 0),
        Ipv4Addr::new(224, 0, 0, 1),
    );
}
