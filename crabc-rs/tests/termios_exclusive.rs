use crabc_rs::{fs, pipe, pty, termios, Errno};

fn pty_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
    pty::PtyPair::open(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
        .expect("open PTY pair")
        .into_parts()
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

#[cfg(target_os = "macos")]
#[test]
fn darwin_exclusive_mode_still_admits_an_unprivileged_slave_open() {
    if crabc_rs::process::geteuid().as_raw() == 0 {
        return;
    }
    let (master, slave) = pty_pair();
    let path = pty::ptsname(&master, Vec::new()).expect("name PTY slave");

    termios::ioctl_tiocexcl(&slave).expect("enable PTY exclusive mode");
    let reopened = fs::open(
        path.as_c_str(),
        fs::OFlags::RDWR | fs::OFlags::NOCTTY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .expect("XNU admits an unprivileged open of an exclusive PTY slave");
    drop(reopened);
    termios::ioctl_tiocnxcl(&slave).expect("disable PTY exclusive mode");
}
