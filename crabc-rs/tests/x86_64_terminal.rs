//! Linux/x86-64 regression coverage for the complete native terminal slice.
//!
//! The session-changing check runs only in a raw-fork child.  The parent test
//! process therefore never acquires a controlling terminal or changes its
//! foreground process group.

#![cfg(target_arch = "x86_64")]

use core::mem::MaybeUninit;

use crabc_core::process as raw_process;
use crabc_rs::{fs, pipe, pty, termios, Errno};

fn flags() -> pty::OpenptFlags {
    pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC
}

fn pair() -> pty::PtyPair {
    pty::PtyPair::open(flags()).expect("open owned PTY pair")
}

#[test]
fn x86_64_terminal_attributes_queue_special_codes_and_window_size_round_trip() {
    let pair = pair();
    let original = termios::tcgetattr(pair.slave()).expect("read PTY attributes");
    assert!(termios::isatty(pair.slave()));
    assert_eq!(original.special_codes[termios::SpecialCodeIndex::VINTR], 3);

    let mut raw = original.clone();
    raw.make_raw();
    assert_eq!(raw.special_codes[termios::SpecialCodeIndex::VMIN], 1);
    assert_eq!(raw.special_codes[termios::SpecialCodeIndex::VTIME], 0);
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Now, &raw)
        .expect("apply typed raw mode");
    let observed_raw = termios::tcgetattr(pair.slave()).expect("re-read typed raw mode");
    assert_eq!(observed_raw.special_codes[termios::SpecialCodeIndex::VMIN], 1);
    assert_eq!(observed_raw.special_codes[termios::SpecialCodeIndex::VTIME], 0);

    let mut changed = original.clone();
    changed.special_codes[termios::SpecialCodeIndex::VINTR] = b'/';
    changed.special_codes[termios::SpecialCodeIndex::VEOL] = b'c';
    changed.set_speed(9_600).expect("select standard baud rate");
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Now, &changed)
        .expect("apply PTY attributes immediately");
    let observed = termios::tcgetattr(pair.slave()).expect("re-read PTY attributes");
    assert_eq!(observed.special_codes[termios::SpecialCodeIndex::VINTR], b'/');
    assert_eq!(observed.special_codes[termios::SpecialCodeIndex::VEOL], b'c');
    assert_eq!(observed.input_speed(), 9_600);
    assert_eq!(observed.output_speed(), 9_600);

    // On Linux/x86-64, a zero CIBAUD selector is the distinct B0 input
    // setting. It must not be reported as a copy of the output selector.
    changed.set_input_speed(0).expect("select B0 input baud rate");
    assert_eq!(changed.input_speed(), 0);
    assert_eq!(changed.output_speed(), 9_600);
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Now, &changed)
        .expect("apply independent B0 input speed");
    let observed = termios::tcgetattr(pair.slave()).expect("re-read B0 input speed");
    assert_eq!(observed.input_speed(), 0);
    assert_eq!(observed.output_speed(), 9_600);

    // The remaining update actions have distinct Linux ioctl request words.
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Drain, &original)
        .expect("drain then restore PTY attributes");
    termios::tcsetattr(pair.slave(), termios::OptionalActions::Flush, &original)
        .expect("flush then restore PTY attributes");

    for queue in [
        termios::QueueSelector::IFlush,
        termios::QueueSelector::OFlush,
        termios::QueueSelector::IOFlush,
    ] {
        termios::tcflush(pair.master(), queue).expect("flush PTY queue");
    }
    termios::tcdrain(pair.master()).expect("drain PTY output");
    termios::tcsendbreak(pair.master()).expect("send PTY break");
    for action in [
        termios::Action::OOff,
        termios::Action::OOn,
        termios::Action::IOff,
        termios::Action::IOn,
    ] {
        termios::tcflow(pair.master(), action).expect("apply PTY flow action");
    }

    let original_size = termios::tcgetwinsize(pair.slave()).expect("read PTY window size");
    let changed_size = termios::Winsize {
        ws_row: original_size.ws_row.saturating_add(1),
        ws_col: original_size.ws_col.saturating_add(1),
        ws_xpixel: original_size.ws_xpixel,
        ws_ypixel: original_size.ws_ypixel,
    };
    termios::tcsetwinsize(pair.slave(), changed_size).expect("write PTY window size");
    assert_eq!(
        termios::tcgetwinsize(pair.slave()).expect("re-read PTY window size"),
        changed_size
    );
    termios::tcsetwinsize(pair.slave(), original_size).expect("restore PTY window size");
}

#[test]
fn x86_64_terminal_name_and_exclusive_mode_are_typed_and_bounded() {
    let pair = pair();
    let mut storage = [MaybeUninit::uninit(); 128];
    let name = termios::ttyname_into(pair.slave(), &mut storage).expect("name PTY slave");
    assert!(name.to_bytes().starts_with(b"/dev/pts/"));

    termios::ioctl_tiocexcl(pair.slave()).expect("enable PTY exclusive mode");
    match fs::open(
        name,
        fs::OFlags::RDWR | fs::OFlags::NOCTTY | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    ) {
        Err(Errno::BUSY) => {}
        Ok(fd) => drop(fd), // privileged test hosts can bypass `TIOCEXCL`.
        Err(error) => panic!("unexpected exclusive PTY open error: {error:?}"),
    }
    termios::ioctl_tiocnxcl(pair.slave()).expect("disable PTY exclusive mode");

    let mut short = [MaybeUninit::uninit(); 4];
    assert_eq!(termios::ttyname_into(pair.slave(), &mut short), Err(Errno::RANGE));
}

#[cfg(feature = "alloc")]
#[test]
fn x86_64_terminal_name_reuses_owned_storage() {
    let pair = pair();
    let expected = pty::ptsname(pair.master(), Vec::new()).expect("name PTY master peer");
    let first = termios::ttyname(pair.slave(), b"stale-name".to_vec())
        .expect("name PTY slave with owned storage");
    assert_eq!(first.as_bytes(), expected.as_bytes());
    let reused = termios::ttyname(pair.slave(), first.into_bytes())
        .expect("reuse prior tty-name allocation");
    assert_eq!(reused.as_bytes(), expected.as_bytes());
}

#[test]
fn x86_64_terminal_operations_reject_non_tty_descriptors() {
    let (reader, _writer) = pipe::pipe().expect("create non-terminal fixture");
    let attributes = termios::tcgetattr(pair().slave()).expect("read disposable attributes");

    assert!(!termios::isatty(&reader));
    assert!(matches!(termios::tcgetattr(&reader), Err(Errno::NOTTY)));
    assert_eq!(
        termios::tcsetattr(&reader, termios::OptionalActions::Now, &attributes),
        Err(Errno::NOTTY)
    );
    assert_eq!(termios::tcgetpgrp(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::tcgetsid(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::ioctl_tiocexcl(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::ioctl_tiocnxcl(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::tcdrain(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::tcsendbreak(&reader), Err(Errno::NOTTY));
}

fn session_child(pair: &pty::PtyPair) -> ! {
    // SAFETY: this raw-fork child is the isolated, single-threaded session
    // owner documented by `PtyPair`'s terminal-handoff contract.
    if unsafe { pair.establish_session_and_controlling_terminal(false) }.is_err() {
        raw_process::exit_immediately(10);
    }
    let pid = match crabc_rs::process::Pid::from_raw(raw_process::getpid()) {
        Some(pid) => pid,
        None => raw_process::exit_immediately(11),
    };
    if termios::tcgetsid(pair.slave()) != Ok(pid) {
        raw_process::exit_immediately(12);
    }
    if termios::tcgetpgrp(pair.slave()) != Ok(pid) {
        raw_process::exit_immediately(13);
    }
    if termios::tcsetpgrp(pair.slave(), pid).is_err() {
        raw_process::exit_immediately(14);
    }
    raw_process::exit_immediately(0)
}

#[test]
fn x86_64_explicit_session_handoff_is_confined_to_a_child() {
    let pair = pair();
    let child = raw_process::fork_raw().expect("fork isolated terminal child");
    if child == 0 {
        session_child(&pair);
    }

    let mut status = 0_i32;
    let observed = unsafe { raw_process::wait4_raw(child, &mut status, 0) }
        .expect("reap isolated terminal child");
    assert_eq!(observed, child);
    assert_eq!(status, 0, "terminal child status: {status:#x}");
}
