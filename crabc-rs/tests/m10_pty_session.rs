use core::mem::MaybeUninit;

use crabc_rs::{process, pty, termios, Errno};

fn flags() -> pty::OpenptFlags {
    pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC
}

#[test]
fn pair_owns_both_descriptors_and_supports_borrowed_and_owned_names() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");

    let mut storage = [MaybeUninit::uninit(); 32];
    let borrowed = pty::ptsname_into(pair.master(), &mut storage)
        .expect("resolve PTY name into caller storage");
    assert!(borrowed.to_bytes().starts_with(b"/dev/pts/"));

    let owned = pty::ptsname(pair.master(), b"stale-name".to_vec())
        .expect("resolve owned PTY name");
    assert_eq!(borrowed.to_bytes(), owned.as_bytes());

    let (master, slave) = pair.into_parts();
    assert!(master.as_raw_fd() >= 0);
    assert!(slave.as_raw_fd() >= 0);
}

#[test]
fn ptsname_into_rejects_short_caller_storage() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");
    let mut storage = [MaybeUninit::uninit(); 4];

    assert_eq!(pty::ptsname_into(pair.master(), &mut storage), Err(Errno::RANGE));
}

fn controlling_terminal_child(pair: &pty::PtyPair) -> ! {
    // The pair was opened with O_NOCTTY. The explicit API performs both the
    // Linux session transition and the TIOCSCTTY handoff in this child only.
    if unsafe { pair.establish_session_and_controlling_terminal(false) }.is_err() {
        process::exit_immediately(10);
    }
    let pid = process::getpid();
    if termios::tcgetsid(pair.slave()) != Ok(pid) {
        process::exit_immediately(11);
    }
    if termios::tcgetpgrp(pair.slave()) != Ok(pid) {
        process::exit_immediately(12);
    }
    process::exit_immediately(0)
}

#[test]
fn explicit_session_handoff_isolated_in_child() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");
    let child = match unsafe { process::fork_raw() }.expect("fork session child") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => controlling_terminal_child(&pair),
    };

    let (_, status) = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("reap session child")
        .expect("session child status");
    assert_eq!(status.exit_status(), Some(0), "session child status: {status:?}");
}
