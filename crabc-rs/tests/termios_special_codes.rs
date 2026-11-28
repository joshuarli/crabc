use crabc_rs::{pty, termios};

fn pty_pair() -> (crabc_rs::OwnedFd, crabc_rs::OwnedFd) {
    pty::PtyPair::open(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
        .expect("open PTY pair")
        .into_parts()
}

#[test]
fn special_codes_round_trip_through_linux_termios() {
    let (_master, slave) = pty_pair();
    let original = termios::tcgetattr(&slave).expect("read PTY terminal attributes");

    // Linux PTY defaults use ETX for VINTR and leave VEOL undefined. These
    // named indices are the bounded Rustix-compatible surface under test.
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VINTR], 3);
    #[cfg(target_os = "linux")]
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VEOL], 0);
    // Darwin marks an undefined code with _POSIX_VDISABLE.
    #[cfg(target_os = "macos")]
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VEOL], 0xff);

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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "macos")]
#[test]
fn special_code_indices_address_distinct_darwin_slots_that_round_trip() {
    let (_master, slave) = pty_pair();
    let original = termios::tcgetattr(&slave).expect("read PTY terminal attributes");

    let indices = [
        termios::SpecialCodeIndex::VEOF,
        termios::SpecialCodeIndex::VEOL,
        termios::SpecialCodeIndex::VEOL2,
        termios::SpecialCodeIndex::VERASE,
        termios::SpecialCodeIndex::VWERASE,
        termios::SpecialCodeIndex::VKILL,
        termios::SpecialCodeIndex::VREPRINT,
        termios::SpecialCodeIndex::VINTR,
        termios::SpecialCodeIndex::VQUIT,
        termios::SpecialCodeIndex::VSUSP,
        termios::SpecialCodeIndex::VDSUSP,
        termios::SpecialCodeIndex::VSTART,
        termios::SpecialCodeIndex::VSTOP,
        termios::SpecialCodeIndex::VLNEXT,
        termios::SpecialCodeIndex::VDISCARD,
        termios::SpecialCodeIndex::VMIN,
        termios::SpecialCodeIndex::VTIME,
        termios::SpecialCodeIndex::VSTATUS,
    ];
    let mut changed = original.clone();
    for (value, index) in indices.into_iter().enumerate() {
        changed.special_codes[index] = 0x40 + value as u8;
    }
    for (value, index) in indices.into_iter().enumerate() {
        assert_eq!(changed.special_codes[index], 0x40 + value as u8, "{index:?} aliases another slot");
    }

    // XNU stores every named slot, so each distinct value survives the
    // kernel round trip in its own position.
    termios::tcsetattr(&slave, termios::OptionalActions::Now, &changed)
        .expect("write every Darwin special code");
    let observed = termios::tcgetattr(&slave).expect("re-read Darwin special codes");
    for (value, index) in indices.into_iter().enumerate() {
        assert_eq!(observed.special_codes[index], 0x40 + value as u8, "{index:?} round trip");
    }
    let debug = format!("{:?}", observed.special_codes);
    assert!(debug.contains("VSTATUS: Q"), "named Darwin index in debug output: {debug}");

    termios::tcsetattr(&slave, termios::OptionalActions::Now, &original)
        .expect("restore PTY terminal attributes");
}
