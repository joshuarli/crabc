use crabc_rs::net::{self, netdevice};

#[test]
fn network_device_name_to_index_queries_loopback() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create ioctl socket");

    let index = netdevice::name_to_index(&socket, "lo").expect("query loopback interface");
    assert!(index > 0, "Linux interface indexes are positive");
}

#[test]
fn network_device_name_to_index_rejects_unrepresentable_names() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::DGRAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create ioctl socket");

    assert_eq!(
        netdevice::name_to_index(&socket, "0123456789abcdef"),
        Err(crabc_rs::Errno::NODEV),
    );
    assert_eq!(
        netdevice::name_to_index(&socket, "lo\0suffix"),
        Err(crabc_rs::Errno::NODEV),
    );
}
