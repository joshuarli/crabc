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

    let original = termios::tcgetattr(&slave).expect("read PTY terminal attributes");
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

    termios::tcsetattr(&slave, termios::OptionalActions::Now, &original)
        .expect("restore PTY terminal attributes");
    println!("m10-termios-special-codes ok");
}
