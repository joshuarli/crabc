use crabc_rs::net::netdevice;
use crabc_rs::Errno;

fn ioctl_socket() -> std::net::UdpSocket {
    std::net::UdpSocket::bind("127.0.0.1:0").expect("create an IPv4 datagram socket")
}

#[test]
fn if_nameindex_includes_links_and_deduplicates_records() {
    let socket = ioctl_socket();
    let entries = netdevice::if_nameindex().expect("enumerate interface names");

    assert!(
        !entries.is_empty(),
        "the kernel must expose at least loopback"
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.as_str() == "lo" && entry.index().get() > 0),
        "if_nameindex must include loopback"
    );

    assert!(
        entries.iter().enumerate().all(|(position, entry)| {
            entries[..position].iter().all(|previous| previous != entry)
        }),
        "musl-shaped enumeration must suppress duplicate index/name pairs"
    );

    let mut links = std::vec::Vec::new();
    netdevice::for_each_link_name(|entry| {
        links.push(entry);
        Ok(())
    })
    .expect("stream the RTM_GETLINK dump");

    for entry in &links {
        assert!(
            entries.contains(entry),
            "full enumeration must retain every RTM_GETLINK record"
        );

        // The link-only stream consists of kernel interface names, which
        // must round-trip through the existing ioctl boundary. The full
        // musl-shaped list can additionally contain IPv4 address labels;
        // those are deliberately not assumed to be ioctl interface names.
        let index = entry.index().get();
        let name = netdevice::index_to_name_inlined(&socket, index)
            .expect("every link index must resolve through SIOCGIFNAME");
        assert_eq!(name.as_str(), entry.as_str());
        assert_eq!(
            netdevice::name_to_index(&socket, entry.as_str())
                .expect("every link name must resolve through SIOCGIFINDEX"),
            index
        );
    }
}

#[test]
fn link_stream_is_owned_and_reports_loopback_without_duplicates() {
    let mut entries = std::vec::Vec::new();
    netdevice::for_each_link_name(|entry| {
        assert!(entry.index().get() > 0);
        assert!(!entry.name().as_bytes().is_empty());
        assert!(!entries
            .iter()
            .any(|seen: &netdevice::InterfaceNameIndex| seen == &entry));
        entries.push(entry);
        Ok(())
    })
    .expect("stream the RTM_GETLINK dump");

    assert!(
        entries.iter().any(|entry| entry.as_str() == "lo"),
        "the link stream must include loopback"
    );
}

#[test]
fn explicit_free_counterpart_consumes_owned_result() {
    let entries = netdevice::if_nameindex().expect("enumerate interface names");
    netdevice::if_freenameindex(entries);
}

#[test]
fn invalid_index_still_reports_kernel_error() {
    let socket = ioctl_socket();
    assert_eq!(
        netdevice::index_to_name_inlined(&socket, 0),
        Err(Errno::NODEV)
    );
}
