use api::net::sockopt;

fn main() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("create a listening IPv4 stream socket");

    assert!(sockopt::socket_acceptconn(&listener).expect("read listener state"));
    println!("native-socket-acceptconn ok");
}
