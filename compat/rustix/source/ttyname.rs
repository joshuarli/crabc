use api::{pty, termios};

fn main() {
    let master = pty::openpt(
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");
    let slave = pty::ioctl_tiocgptpeer(
        &master,
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open PTY slave");

    let expected = pty::ptsname(&master, Vec::new()).expect("name PTY slave");
    let actual = termios::ttyname(&slave, expected.as_bytes().to_vec())
        .expect("name PTY slave descriptor");
    assert_eq!(actual.as_bytes(), expected.as_bytes());
    assert!(actual.as_bytes().starts_with(b"/dev/pts/"));
    println!("native-ttyname ok");
}
