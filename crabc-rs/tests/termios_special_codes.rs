use crabc_rs::{pty, termios};

fn pty_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
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
    (master, slave)
}

#[test]
fn special_codes_round_trip_through_linux_termios() {
    let (_master, slave) = pty_pair();
    let original = termios::tcgetattr(&slave).expect("read PTY terminal attributes");

    // Linux PTY defaults use ETX for VINTR and leave VEOL undefined. These
    // named indices are the bounded Rustix-compatible surface under test.
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VINTR], 3);
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VEOL], 0);

    let mut changed = original.clone();
    changed.special_codes[termios::SpecialCodeIndex::VINTR] = 47;
    changed.special_codes[termios::SpecialCodeIndex::VEOL] = 99;
    termios::tcsetattr(&slave, termios::OptionalActions::Now, &changed)
        .expect("write PTY terminal attributes");

    let observed = termios::tcgetattr(&slave).expect("re-read PTY terminal attributes");
    assert_eq!(observed.special_codes[termios::SpecialCodeIndex::VINTR], 47);
    assert_eq!(observed.special_codes[termios::SpecialCodeIndex::VEOL], 99);

    // The PTY is disposable, but restoring the original state also makes the
    // test safe if its descriptor lifetime is changed by a future harness.
    termios::tcsetattr(&slave, termios::OptionalActions::Now, &original)
        .expect("restore PTY terminal attributes");
}

#[test]
fn special_code_indices_cover_the_linux_nccs_prefix() {
    let (_master, slave) = pty_pair();
    let mut attributes = termios::tcgetattr(&slave).expect("read PTY terminal attributes");

    let indices = [
        termios::SpecialCodeIndex::VINTR,
        termios::SpecialCodeIndex::VQUIT,
        termios::SpecialCodeIndex::VERASE,
        termios::SpecialCodeIndex::VKILL,
        termios::SpecialCodeIndex::VEOF,
        termios::SpecialCodeIndex::VTIME,
        termios::SpecialCodeIndex::VMIN,
        termios::SpecialCodeIndex::VSWTC,
        termios::SpecialCodeIndex::VSTART,
        termios::SpecialCodeIndex::VSTOP,
        termios::SpecialCodeIndex::VSUSP,
        termios::SpecialCodeIndex::VEOL,
        termios::SpecialCodeIndex::VREPRINT,
        termios::SpecialCodeIndex::VDISCARD,
        termios::SpecialCodeIndex::VWERASE,
        termios::SpecialCodeIndex::VLNEXT,
        termios::SpecialCodeIndex::VEOL2,
    ];
    for (value, index) in indices.into_iter().enumerate() {
        attributes.special_codes[index] = value as u8;
        assert_eq!(attributes.special_codes[index], value as u8);
    }
}
