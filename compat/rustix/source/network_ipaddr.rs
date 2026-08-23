use api::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() {
    let ipv4 = Ipv4Addr::new(192, 0, 2, 7);
    assert_eq!(ipv4.octets(), [192, 0, 2, 7]);
    assert_eq!(Ipv4Addr::from_bits(ipv4.to_bits()), ipv4);

    let ipv6 = Ipv6Addr::new(
        0x2001,
        0x0db8,
        0,
        0,
        0,
        0,
        0x0042,
        0x0007,
    );
    assert_eq!(
        ipv6.octets(),
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42, 0, 0x07,
        ]
    );
    assert_eq!(Ipv6Addr::from_bits(ipv6.to_bits()), ipv6);

    let v4 = IpAddr::V4(ipv4);
    let v6 = IpAddr::V6(ipv6);
    assert!(v4.is_ipv4() && !v4.is_ipv6());
    assert!(v6.is_ipv6() && !v6.is_ipv4());
    assert!(matches!(v4, IpAddr::V4(value) if value == ipv4));
    assert!(matches!(v6, IpAddr::V6(value) if value == ipv6));

    println!("native-network-ipaddr ok");
}
