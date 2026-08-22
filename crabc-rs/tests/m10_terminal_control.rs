use crabc_rs::{pipe, process, pty, termios, Errno, OwnedFd};

fn pty_master() -> OwnedFd {
    let master = pty::openpt(
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open disposable PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");
    master
}

fn terminal_control_child(master: &OwnedFd) -> ! {
    let pid = process::getpid();
    if process::setsid().is_err() {
        process::exit_immediately(10);
    }

    // Opening the slave without O_NOCTTY from this new session makes this
    // child the controlling-terminal/session owner. The parent never changes
    // its own session or foreground process group.
    let slave = match pty::ioctl_tiocgptpeer(master, pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC) {
        Ok(slave) => slave,
        Err(_) => process::exit_immediately(11),
    };
    let original = match termios::tcgetattr(&slave) {
        Ok(attributes) => attributes,
        Err(_) => process::exit_immediately(12),
    };
    for action in [
        termios::OptionalActions::Now,
        termios::OptionalActions::Drain,
        termios::OptionalActions::Flush,
    ] {
        if termios::tcsetattr(&slave, action, &original).is_err() {
            process::exit_immediately(13);
        }
    }

    let session = match termios::tcgetsid(&slave) {
        Ok(session) => session,
        Err(_) => process::exit_immediately(14),
    };
    if session != pid {
        process::exit_immediately(15);
    }

    let foreground = match termios::tcgetpgrp(&slave) {
        Ok(foreground) => foreground,
        Err(_) => process::exit_immediately(16),
    };
    if foreground != pid {
        process::exit_immediately(17);
    }
    if termios::tcsetpgrp(&slave, pid).is_err() {
        process::exit_immediately(18);
    }
    if termios::tcgetpgrp(&slave) != Ok(pid) {
        process::exit_immediately(19);
    }

    process::exit_immediately(0)
}

#[test]
fn terminal_control_round_trips_attributes_and_session_state_in_isolated_child() {
    let master = pty_master();
    let child = match unsafe { process::fork_raw() }.expect("fork isolated terminal-control child") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => terminal_control_child(&master),
    };

    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("reap terminal-control child")
        .expect("terminal-control child status");
    assert_eq!(status.exit_status(), Some(0), "terminal-control child status: {status:?}");
}

#[test]
fn terminal_control_ioctls_report_notty_for_a_non_terminal() {
    let (reader, _writer) = pipe::pipe().expect("create deterministic non-terminal");
    let master = pty_master();
    let attributes = termios::tcgetattr(&master).expect("read disposable PTY attributes");
    let pid = process::getpid();

    assert!(matches!(termios::tcgetattr(&reader), Err(Errno::NOTTY)));
    assert_eq!(termios::tcsetattr(&reader, termios::OptionalActions::Now, &attributes), Err(Errno::NOTTY));
    assert_eq!(termios::tcgetpgrp(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::tcsetpgrp(&reader, pid), Err(Errno::NOTTY));
    assert_eq!(termios::tcgetsid(&reader), Err(Errno::NOTTY));
}
