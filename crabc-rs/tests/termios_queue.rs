use crabc_rs::{fs, pty, termios, Errno};

// Darwin's null device answers terminal requests with ENODEV.
#[cfg(target_os = "linux")]
const NULL_DEVICE_TERMINAL_ERROR: Errno = Errno::NOTTY;
#[cfg(target_os = "macos")]
const NULL_DEVICE_TERMINAL_ERROR: Errno = Errno::NODEV;

#[cfg(target_os = "linux")]
fn pty_master() -> crabc_rs::OwnedFd {
    let master =
        pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
            .expect("open disposable PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");
    master
}

#[test]
fn terminal_queue_operations_use_typed_actions_on_a_pty() {
    #[cfg(target_os = "linux")]
    let master = pty_master();
    // A Darwin master rejects terminal requests until its slave is opened.
    #[cfg(target_os = "macos")]
    let (master, _slave) = pty::PtyPair::open(
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open disposable PTY pair")
    .into_parts();

    for queue in [
        termios::QueueSelector::IFlush,
        termios::QueueSelector::OFlush,
        termios::QueueSelector::IOFlush,
    ] {
        termios::tcflush(&master, queue).expect("flush PTY queue");
    }

    termios::tcdrain(&master).expect("drain PTY output");
    termios::tcsendbreak(&master).expect("send PTY break");

    // Exercise both stop/start directions while leaving the disposable PTY
    // in its normal flowing state before teardown.
    termios::tcflow(&master, termios::Action::OOff).expect("stop PTY output");
    termios::tcflow(&master, termios::Action::OOn).expect("resume PTY output");
    termios::tcflow(&master, termios::Action::IOff).expect("stop PTY input");
    termios::tcflow(&master, termios::Action::IOn).expect("resume PTY input");
}

#[test]
fn terminal_queue_operations_report_notty_for_non_terminals() {
    let null = fs::open(
        "/dev/null",
        fs::OFlags::RDONLY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .expect("open deterministic non-terminal");

    for queue in [
        termios::QueueSelector::IFlush,
        termios::QueueSelector::OFlush,
        termios::QueueSelector::IOFlush,
    ] {
        assert_eq!(termios::tcflush(&null, queue), Err(NULL_DEVICE_TERMINAL_ERROR));
    }
    for action in [
        termios::Action::OOff,
        termios::Action::OOn,
        termios::Action::IOff,
        termios::Action::IOn,
    ] {
        assert_eq!(termios::tcflow(&null, action), Err(NULL_DEVICE_TERMINAL_ERROR));
    }
    assert_eq!(termios::tcdrain(&null), Err(NULL_DEVICE_TERMINAL_ERROR));
    assert_eq!(termios::tcsendbreak(&null), Err(NULL_DEVICE_TERMINAL_ERROR));
}
