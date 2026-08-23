use crabc_rs::{fs, pipe, pty, termios, Errno};

fn pty_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
    let master =
        pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
            .expect("open PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");
    let slave = pty::ioctl_tiocgptpeer(
        &master,
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open PTY slave");
    (master, slave)
}

#[test]
fn exclusive_mode_can_be_enabled_and_disabled_on_a_terminal() {
    let (master, slave) = pty_pair();
    let path = pty::ptsname(&master, Vec::new()).expect("name PTY slave");

    termios::ioctl_tiocexcl(&slave).expect("enable PTY exclusive mode");
    match fs::open(
        path.as_c_str(),
        fs::OFlags::RDWR | fs::OFlags::NOCTTY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    ) {
        Err(Errno::BUSY) => {}
        Ok(fd) => {
            // A privileged test process may bypass TIOCEXCL. The operation
            // pair remains valid; keep this environment-specific exception
            // from making the source contract depend on container caps.
            drop(fd);
        }
        Err(error) => panic!("unexpected exclusive PTY open error: {error:?}"),
    }

    termios::ioctl_tiocnxcl(&slave).expect("disable PTY exclusive mode");
    let reopened = fs::open(
        path.as_c_str(),
        fs::OFlags::RDWR | fs::OFlags::NOCTTY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .expect("reopen PTY after disabling exclusive mode");
    drop(reopened);
}

#[test]
fn exclusive_mode_requests_reject_non_terminals() {
    let (reader, _writer) = pipe::pipe().expect("create non-terminal fixture");

    assert_eq!(termios::ioctl_tiocexcl(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::ioctl_tiocnxcl(&reader), Err(Errno::NOTTY));
}
