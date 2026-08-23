use api::net::sockopt;

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("create an IPv4 stream socket");

    assert!(!sockopt::socket_oobinline(&listener).expect("read default OOBINLINE"));
    sockopt::set_socket_oobinline(&listener, true).expect("enable OOBINLINE");
    assert!(sockopt::socket_oobinline(&listener).expect("read enabled OOBINLINE"));
    sockopt::set_socket_oobinline(&listener, false).expect("disable OOBINLINE");
    assert!(!sockopt::socket_oobinline(&listener).expect("read disabled OOBINLINE"));
    println!("native-socket-oobinline ok");
}
