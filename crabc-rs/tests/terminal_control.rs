#![cfg(not(target_arch = "x86_64"))]
// x86 coverage: x86_64_terminal.rs:x86_64_explicit_session_handoff_is_confined_to_a_child covers explicit handoff; x86_64_terminal_operations_reject_non_tty_descriptors covers errors.

use crabc_rs::{fs, pipe, process, pty, termios, Errno, OwnedFd};
#[cfg(target_os = "linux")]
use crabc_core::process as raw_process;

/// The raw fork, wait and session calls the Linux tests take from
/// `crabc-core`, declared from libSystem with the same shapes.
#[cfg(target_os = "macos")]
mod raw_process {
    use crabc_rs::Errno;

    mod sys {
        unsafe extern "C" {
            pub(super) fn fork() -> i32;
            pub(super) fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            pub(super) fn setsid() -> i32;
        }
    }

    fn checked(result: i32) -> Result<i32, Errno> {
        if result == -1 {
            let raw = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            Err(Errno::from_raw(raw).unwrap_or(Errno::IO))
        } else {
            Ok(result)
        }
    }

    pub fn fork_raw() -> Result<i32, Errno> {
        // SAFETY: every forked child in these tests makes only
        // allocation-free calls before `_exit`.
        checked(unsafe { sys::fork() })
    }

    pub unsafe fn wait4_raw(pid: i32, status: *mut i32, options: i32) -> Result<i32, Errno> {
        // SAFETY: the caller supplies writable status storage.
        checked(unsafe { sys::waitpid(pid, status, options) })
    }

    #[allow(dead_code)]
    pub fn setsid() -> Result<i32, Errno> {
        // SAFETY: `setsid` has no memory arguments.
        checked(unsafe { sys::setsid() })
    }

    #[allow(dead_code)]
    pub fn getpid() -> i32 {
        crabc_rs::process::getpid().as_raw_pid()
    }

    #[allow(dead_code)]
    pub fn exit_immediately(status: i32) -> ! {
        crabc_rs::process::exit_immediately(status)
    }
}

fn pty_master() -> OwnedFd {
    let master =
        pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)
            .expect("open disposable PTY master");
    pty::grantpt(&master).expect("grant PTY");
    pty::unlockpt(&master).expect("unlock PTY");
    master
}

fn terminal_control_child(master: &OwnedFd) -> ! {
    let pid = process::getpid();
    if raw_process::setsid().is_err() {
        process::exit_immediately(10);
    }

    // Opening the slave without O_NOCTTY from this new session makes this
    // child the controlling-terminal/session owner. The parent never changes
    // its own session or foreground process group.
    let mut name_buffer = [core::mem::MaybeUninit::uninit(); 128];
    let name = match pty::ptsname_into(master, &mut name_buffer) {
        Ok(name) => name,
        Err(_) => process::exit_immediately(11),
    };
    let slave = match fs::open(name, fs::OFlags::RDWR | fs::OFlags::CLOEXEC, fs::Mode::empty()) {
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
    let child = match raw_process::fork_raw().map(crabc_rs::Pid::from_raw).expect("fork isolated terminal-control child")
    {
        Some(child) => child,
        None => terminal_control_child(&master),
    };

    let mut status = 0;
    // SAFETY: The status word is writable and the child is owned by this test.
    unsafe { raw_process::wait4_raw(child.as_raw_pid(), &mut status, 0) }.expect("reap child");
    assert_eq!(
        status,
        0,
        "terminal-control child status: {status:?}"
    );
}

#[test]
fn terminal_control_ioctls_report_notty_for_a_non_terminal() {
    let (reader, _writer) = pipe::pipe().expect("create deterministic non-terminal");
    #[cfg(target_os = "linux")]
    let master = pty_master();
    // A Darwin master rejects terminal requests until its slave is opened.
    #[cfg(target_os = "macos")]
    let (master, _slave) = pty::PtyPair::open(
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )
    .expect("open disposable PTY pair")
    .into_parts();
    let attributes = termios::tcgetattr(&master).expect("read disposable PTY attributes");
    let pid = process::getpid();

    assert!(matches!(termios::tcgetattr(&reader), Err(Errno::NOTTY)));
    assert_eq!(
        termios::tcsetattr(&reader, termios::OptionalActions::Now, &attributes),
        Err(Errno::NOTTY)
    );
    assert_eq!(termios::tcgetpgrp(&reader), Err(Errno::NOTTY));
    assert_eq!(termios::tcsetpgrp(&reader, pid), Err(Errno::NOTTY));
    assert_eq!(termios::tcgetsid(&reader), Err(Errno::NOTTY));
}
