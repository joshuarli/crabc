use crabc_rs::{net, Errno};

#[test]
fn socket_acceptconn_tracks_stream_listening_state() {
    let socket = net::socket(
        net::AddressFamily::INET,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("create an IPv4 stream socket");

    assert!(!net::sockopt::socket_acceptconn(&socket).expect("read initial SO_ACCEPTCONN"));
    net::listen(&socket, 1).expect("listen on stream socket");
    assert!(net::sockopt::socket_acceptconn(&socket).expect("read listening SO_ACCEPTCONN"));
}

#[test]
fn socket_acceptconn_rejects_a_non_socket_descriptor() {
    let file = std::fs::File::open("Cargo.toml").expect("open a regular file");

    assert_eq!(net::sockopt::socket_acceptconn(&file), Err(Errno::NOTSOCK));
}
