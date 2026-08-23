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

    termios::ioctl_tiocexcl(&slave).expect("enable PTY exclusive mode");
    termios::ioctl_tiocnxcl(&slave).expect("disable PTY exclusive mode");
    println!("native-termios-exclusive ok");
}
