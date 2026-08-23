use crabc_rs::net::{netdevice, IpAddress};

#[test]
fn snapshot_contains_loopback_link_and_ip_without_external_interfaces() {
    let snapshot = netdevice::InterfaceAddresses::new().expect("collect interface addresses");

    let loopback = snapshot
        .entries()
        .iter()
        .find_map(|entry| match entry {
            netdevice::InterfaceAddress::Link(link) if link.name().as_bytes() == b"lo" => {
                Some(link)
            }
            _ => None,
        })
        .expect("kernel must expose loopback");
    assert!(loopback.index().get() > 0);
    assert!(loopback.flags() != u32::MAX);

    let loopback_ip = snapshot.entries().iter().find_map(|entry| match entry {
        netdevice::InterfaceAddress::Ip(address)
            if address.index() == loopback.index()
                && address.name().as_bytes() == b"lo"
                && address.address().address() == IpAddress::V4([127, 0, 0, 1]) =>
        {
            Some(address)
        }
        _ => None,
    });
    let loopback_ip = loopback_ip.expect("loopback must have IPv4 127.0.0.1");
    assert_eq!(loopback_ip.netmask(), IpAddress::V4([255, 0, 0, 0]));
    assert_eq!(loopback_ip.address().scope_id(), 0);
}

#[test]
fn snapshot_keeps_link_records_before_address_records() {
    let snapshot = netdevice::InterfaceAddresses::collect().expect("collect interface addresses");
    let first_ip = snapshot
        .entries()
        .iter()
        .position(|entry| matches!(entry, netdevice::InterfaceAddress::Ip(_)));
    let last_link = snapshot
        .entries()
        .iter()
        .rposition(|entry| matches!(entry, netdevice::InterfaceAddress::Link(_)));

    if let (Some(first_ip), Some(last_link)) = (first_ip, last_link) {
        assert!(
            last_link < first_ip,
            "the RTM_GETLINK dump must precede RTM_GETADDR"
        );
    }
}
