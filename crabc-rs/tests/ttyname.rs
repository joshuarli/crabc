use core::mem::MaybeUninit;

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
fn ttyname_returns_the_validated_slave_path_and_reuses_storage() {
    let (master, slave) = pty_pair();
    let expected = pty::ptsname(&master, Vec::new()).expect("name PTY slave");

    let first = termios::ttyname(&slave, b"stale-name".to_vec()).expect("name PTY slave fd");
    assert_eq!(first.as_bytes(), expected.as_bytes());
    assert!(first.as_bytes().starts_with(b"/dev/pts/"));

    // A second call with the first result's allocation exercises the exact
    // Rustix reuse contract rather than relying on a fresh vector each time.
    let reused = termios::ttyname(&slave, first.into_bytes()).expect("reuse ttyname storage");
    assert_eq!(reused.as_bytes(), expected.as_bytes());

    let descriptor_stat = fs::fstat(&slave).expect("stat PTY slave fd");
    let path_stat = fs::stat(reused.as_c_str()).expect("stat validated PTY path");
    assert_eq!(path_stat.st_dev, descriptor_stat.st_dev);
    assert_eq!(path_stat.st_ino, descriptor_stat.st_ino);
}

#[test]
fn ttyname_into_reports_small_caller_storage_without_truncation() {
    let (_master, slave) = pty_pair();
    let mut storage = [MaybeUninit::uninit(); 4];

    assert_eq!(
        termios::ttyname_into(&slave, &mut storage).unwrap_err(),
        Errno::RANGE,
    );
}

#[test]
fn ttyname_rejects_a_non_terminal_descriptor() {
    let (reader, _writer) = pipe::pipe().expect("create non-terminal descriptor fixture");

    assert_eq!(
        termios::ttyname(&reader, Vec::new()).unwrap_err(),
        Errno::NOTTY,
    );
}
