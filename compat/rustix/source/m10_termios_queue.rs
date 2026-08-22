use api::{fs, pty, termios};
use api::io::Errno;

fn main() {
    let master = pty::openpt(
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open disposable PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");

    for queue in [
        termios::QueueSelector::IFlush,
        termios::QueueSelector::OFlush,
        termios::QueueSelector::IOFlush,
    ] {
        termios::tcflush(&master, queue).expect("flush PTY queue");
    }
    termios::tcdrain(&master).expect("drain PTY output");
    termios::tcsendbreak(&master).expect("send PTY break");
    for action in [
        termios::Action::OOff,
        termios::Action::OOn,
        termios::Action::IOff,
        termios::Action::IOn,
    ] {
        termios::tcflow(&master, action).expect("change PTY flow state");
    }

    let null = fs::open(
        "/dev/null",
        fs::OFlags::RDONLY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    )
    .expect("open deterministic non-terminal");
    assert_eq!(termios::tcdrain(&null), Err(Errno::NOTTY));
    assert_eq!(termios::tcsendbreak(&null), Err(Errno::NOTTY));
    assert_eq!(
        termios::tcflush(&null, termios::QueueSelector::IOFlush),
        Err(Errno::NOTTY),
    );
    assert_eq!(
        termios::tcflow(&null, termios::Action::OOn),
        Err(Errno::NOTTY),
    );

    println!("m10-termios-queue ok");
}
