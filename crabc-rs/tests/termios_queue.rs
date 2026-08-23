use crabc_rs::{fs, pty, termios, Errno};

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
    let master = pty_master();

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
        assert_eq!(termios::tcflush(&null, queue), Err(Errno::NOTTY));
    }
    for action in [
        termios::Action::OOff,
        termios::Action::OOn,
        termios::Action::IOff,
        termios::Action::IOn,
    ] {
        assert_eq!(termios::tcflow(&null, action), Err(Errno::NOTTY));
    }
    assert_eq!(termios::tcdrain(&null), Err(Errno::NOTTY));
    assert_eq!(termios::tcsendbreak(&null), Err(Errno::NOTTY));
}
