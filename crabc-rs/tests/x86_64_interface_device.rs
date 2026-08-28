//! Native x86-64 regression for the bounded Linux interface-device facade.
//!
//! The assertions intentionally use loopback and cross-operation consistency
//! only. Interface counts and kernel dump order within a phase are host state,
//! not part of this facade's contract.

use crabc_rs::net::{self, netdevice, IpAddress};
use crabc_rs::Errno;

fn ioctl_socket() -> crabc_rs::OwnedFd {
    net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 ioctl socket")
}

#[test]
fn x86_64_interface_names_are_owned_and_self_consistent() {
    let socket = ioctl_socket();
    let loopback_index = netdevice::name_to_index(&socket, "lo")
        .expect("query the loopback interface index");
    assert!(loopback_index > 0, "Linux interface indexes are nonzero");

    let loopback_name = netdevice::index_to_name_inlined(&socket, loopback_index)
        .expect("round-trip the loopback interface index");
    assert_eq!(loopback_name.as_bytes(), b"lo");
    assert_eq!(loopback_name.as_str(), "lo");

    assert_eq!(
        netdevice::name_to_index(&socket, "0123456789abcdef"),
        Err(Errno::NODEV),
        "a name that occupies IFNAMSIZ has no representable NUL terminator"
    );
    assert_eq!(
        netdevice::index_to_name_inlined(&socket, 0),
        Err(Errno::NODEV),
        "the kernel preserves the invalid-index error directly"
    );

    let mut links = std::vec::Vec::new();
    netdevice::for_each_link_name(|entry| {
        assert!(entry.index().get() > 0);
        assert!(!entry.name().as_bytes().is_empty());
        assert!(
            !links.iter().any(|known| known == &entry),
            "the one RTM_GETLINK dump must not duplicate an index/name pair"
        );
        links.push(entry);
        Ok(())
    })
    .expect("enumerate the RTM_GETLINK dump");

    let loopback_link = links
        .iter()
        .find(|entry| entry.as_str() == "lo")
        .expect("the link dump includes loopback");
    assert_eq!(loopback_link.index().get(), loopback_index);

    let names = netdevice::if_nameindex().expect("collect owned interface names");
    assert!(names.iter().any(|entry| entry == loopback_link));
    assert!(names.iter().enumerate().all(|(position, entry)| {
        names[..position].iter().all(|previous| previous != entry)
    }));
    netdevice::if_freenameindex(names);
}

#[test]
fn x86_64_interface_address_snapshot_keeps_the_two_netlink_phases_owned() {
    let snapshot = netdevice::InterfaceAddresses::new().expect("collect interface snapshot");
    let loopback_link = snapshot
        .entries()
        .iter()
        .find_map(|entry| match entry {
            netdevice::InterfaceAddress::Link(link) if link.name().as_bytes() == b"lo" => {
                Some(link)
            }
            _ => None,
        })
        .expect("the snapshot includes a loopback link record");
    assert!(loopback_link.index().get() > 0);

    assert!(snapshot.entries().iter().any(|entry| matches!(
        entry,
        netdevice::InterfaceAddress::Ip(address)
            if address.index() == loopback_link.index()
                && address.name().as_bytes() == b"lo"
                && address.address().address() == IpAddress::V4([127, 0, 0, 1])
                && address.netmask() == IpAddress::V4([255, 0, 0, 0])
                && address.address().scope_id() == 0
    )));
    assert!(snapshot.entries().iter().any(|entry| matches!(
        entry,
        netdevice::InterfaceAddress::Ip(address)
            if address.index() == loopback_link.index()
                && address.name().as_bytes() == b"lo"
                && address.address().address()
                    == IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                && address.netmask()
                    == IpAddress::V6([
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    ])
                && address.address().scope_id() == 0
    )));

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
            "RTM_GETLINK records precede RTM_GETADDR records in one owned snapshot"
        );
    }
}
