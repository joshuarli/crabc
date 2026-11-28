#![cfg(not(target_arch = "x86_64"))]
// x86 coverage: x86_64_pty_basic.rs:x86_64_pair_owns_both_descriptors_and_resolves_slave_name, x86_64_ptsname_into_rejects_short_caller_storage and x86_64_terminal.rs:x86_64_explicit_session_handoff_is_confined_to_a_child.

use core::mem::MaybeUninit;

use crabc_rs::{process, pty, termios, Errno};
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

fn flags() -> pty::OpenptFlags {
    pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC
}

#[test]
fn pair_owns_both_descriptors_and_supports_borrowed_and_owned_names() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");

    let mut storage = [MaybeUninit::uninit(); 32];
    let borrowed = pty::ptsname_into(pair.master(), &mut storage)
        .expect("resolve PTY name into caller storage");
    #[cfg(target_os = "linux")]
    assert!(borrowed.to_bytes().starts_with(b"/dev/pts/"));
    #[cfg(target_os = "macos")]
    assert!(borrowed.to_bytes().starts_with(b"/dev/ttys"));

    let owned =
        pty::ptsname(pair.master(), b"stale-name".to_vec()).expect("resolve owned PTY name");
    assert_eq!(borrowed.to_bytes(), owned.as_bytes());

    let (master, slave) = pair.into_parts();
    assert!(master.as_raw_fd() >= 0);
    assert!(slave.as_raw_fd() >= 0);
}

#[test]
fn ptsname_into_rejects_short_caller_storage() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");
    let mut storage = [MaybeUninit::uninit(); 4];

    assert_eq!(
        pty::ptsname_into(pair.master(), &mut storage),
        Err(Errno::RANGE)
    );
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
    let child = match raw_process::fork_raw().map(crabc_rs::Pid::from_raw).expect("fork session child") {
        Some(child) => child,
        None => controlling_terminal_child(&pair),
    };

    let mut status = 0;
    // SAFETY: The status word is writable and the child is owned by this test.
    unsafe { raw_process::wait4_raw(child.as_raw_pid(), &mut status, 0) }.expect("reap child");
    assert_eq!(
        status,
        0,
        "session child status: {status:?}"
    );
}

/// Takes the pair's slave as this child's controlling terminal, then has a
/// grandchild in a second session try to take it with `steal`.
#[cfg(target_os = "macos")]
fn steal_attempt_child(pair: &pty::PtyPair) -> ! {
    // SAFETY: this raw-fork child is the isolated, single-threaded session
    // owner the handoff contract requires.
    if unsafe { pair.establish_session_and_controlling_terminal(false) }.is_err() {
        process::exit_immediately(20);
    }
    let grandchild = match raw_process::fork_raw() {
        Ok(0) => {
            if raw_process::setsid().is_err() {
                process::exit_immediately(21);
            }
            // SAFETY: the grandchild is an isolated, single-threaded session
            // leader without a controlling terminal.
            let stolen = unsafe { pair.set_controlling_terminal(true) };
            process::exit_immediately(if stolen == Err(Errno::PERM) { 0 } else { 22 })
        }
        Ok(grandchild) => grandchild,
        Err(_) => process::exit_immediately(23),
    };
    let mut status = 0;
    // SAFETY: the status word is writable and the grandchild is owned here.
    if unsafe { raw_process::wait4_raw(grandchild, &mut status, 0) } != Ok(grandchild) {
        process::exit_immediately(24);
    }
    if termios::tcgetsid(pair.slave()) != Ok(process::getpid()) {
        process::exit_immediately(25);
    }
    process::exit_immediately(if status == 0 { 0 } else { 26 })
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_steal_cannot_take_another_sessions_controlling_terminal() {
    let pair = pty::PtyPair::open(flags()).expect("open owned PTY pair");
    let child = match raw_process::fork_raw().map(crabc_rs::Pid::from_raw).expect("fork session child") {
        Some(child) => child,
        None => steal_attempt_child(&pair),
    };

    let mut status = 0;
    // SAFETY: The status word is writable and the child is owned by this test.
    unsafe { raw_process::wait4_raw(child.as_raw_pid(), &mut status, 0) }.expect("reap child");
    assert_eq!(status, 0, "steal child status: {:#x}", status);
}
