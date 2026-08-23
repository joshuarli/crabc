use core::num::NonZeroU32;

use crabc_rs::{io, net};

#[test]
fn socket_returns_an_owned_descriptor_with_typed_creation_flags() {
    let socket = net::socket(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create a Unix stream socket through the direct kernel seam");

    assert!(socket.as_raw_fd() >= 0);
    assert!(
        io::fcntl_getfd(&socket)
            .expect("read socket descriptor flags")
            .contains(io::FdFlags::CLOEXEC),
        "SOCK_CLOEXEC must become FD_CLOEXEC on the returned owner",
    );
}

#[test]
fn socket_flags_reject_unknown_bits_and_shutdown_uses_a_typed_mode() {
    assert!(
        net::SocketFlags::from_bits(0x4).is_none(),
        "unknown socket creation flags must not be silently forwarded",
    );

    let (left, right) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::empty(),
        None,
    )
    .expect("create a connected Unix socket pair");
    net::shutdown(&left, net::Shutdown::Both)
        .expect("shut down both directions through the direct kernel seam");
    drop(right);
}

#[test]
fn protocol_preserves_the_linux_raw_word_contract() {
    let protocol = net::Protocol::from_raw(NonZeroU32::new(u32::MAX).expect("all-one word is nonzero"));
    assert_eq!(protocol.as_raw().get(), u32::MAX);
}
