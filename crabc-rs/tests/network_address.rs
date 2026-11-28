use crabc_rs::net::{NetworkU16, NetworkU32};

#[test]
fn network_values_keep_host_and_wire_order_explicit() {
    let port = NetworkU16::from_host(0x1234);
    assert_eq!(port.to_bytes(), [0x12, 0x34]);
    assert_eq!(port.to_host(), 0x1234);
    assert_eq!(NetworkU16::from_bytes([0xab, 0xcd]).to_host(), 0xabcd);

    let address = NetworkU32::from_host(0x0102_0304);
    assert_eq!(address.to_bytes(), [1, 2, 3, 4]);
    assert_eq!(address.to_host(), 0x0102_0304);
    assert_eq!(
        NetworkU32::from_bytes([0xc0, 0x00, 0x02, 0x07]).to_host(),
        0xc000_0207
    );
}

#[test]
fn network_values_are_copyable_and_compare_by_wire_value() {
    let first = NetworkU16::from_bytes([0, 53]);
    let second = first;
    assert_eq!(first, second);
    assert_eq!(first.to_host(), 53);
}
