#![cfg(feature = "alloc")]

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use crabc_rs::{io, pipe, process, signal};

static SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn interruption_handler(_: signal::Signal) {
    SIGNAL_SEEN.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
#[test]
fn x86_64_consuming_child_wait_keeps_ownership_across_interruption() {
    let selected = signal::Signal::USR2;
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interruption_handler),
        #[cfg(target_arch = "aarch64")]
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The static handler only writes a lock-free atomic and is valid
    // for this binary's sole test. The saved disposition is restored below.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }.unwrap();
    let mut unblocked = signal::current_mask().unwrap();
    unblocked.remove(selected);
    let old_mask = signal::set_mask(&unblocked).unwrap();
    let (release_reader, release_writer) = pipe::pipe().unwrap();
    let cstr = |bytes| CStr::from_bytes_with_nul(bytes).unwrap();
    let prepared = process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[cstr(b"sh\0"), cstr(b"-c\0"), cstr(b"IFS= read -r _ <&21; exit 29\0")],
        &[],
    ).unwrap().with_actions(&[
        process::FdAction::close(&release_writer),
        process::FdAction::dup2(&release_reader, 21),
    ]);
    let child = prepared.spawn().unwrap();
    drop(prepared);
    drop(release_reader);
    let tid = crabc_core::thread::gettid();
    let sender = std::thread::spawn(move || {
        let syscall_path = format!("/proc/self/task/{tid}/syscall");
        let deadline = Instant::now() + Duration::from_secs(5);
        // Observe the actual wait4 syscall before delivering the signal,
        // rather than relying on a sleep to place the interruption.
        while !std::fs::read_to_string(&syscall_path).unwrap().starts_with(if cfg!(target_arch = "aarch64") { "260 " } else { "61 " }) {
            assert!(Instant::now() < deadline, "waiter did not enter wait4");
            std::thread::yield_now();
        }
        crabc_core::process::tgkill(crabc_core::process::getpid(), tid, selected.as_raw()).unwrap();
        while !SIGNAL_SEEN.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "signal handler did not run");
            std::thread::yield_now();
        }
        io::write(&release_writer, b"release\n").unwrap();
    });
    let result = child.wait(process::WaitOptions::empty());
    sender.join().unwrap();
    signal::set_mask(&old_mask).unwrap();
    // SAFETY: The sender has joined and the static handler has returned.
    unsafe { signal::sigaction(selected, Some(&old_action)) }.unwrap();
    assert!(SIGNAL_SEEN.load(Ordering::SeqCst));
    assert_eq!(result.expect("interruption must retain the consuming wait operation")
        .reaped().unwrap().exit_status(), Some(29));
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_self() -> usize;
    fn pthread_kill(thread: usize, signal: i32) -> i32;
}

// Darwin exposes no view of a thread's current system call, so the sender
// waits for the waiter to block and then resends until the handler has run.
#[cfg(target_os = "macos")]
#[test]
fn x86_64_consuming_child_wait_keeps_ownership_across_interruption() {
    let selected = signal::Signal::USR2;
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interruption_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The static handler only writes a lock-free atomic and is valid
    // for this binary's sole test. The saved disposition is restored below.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }.unwrap();
    let mut unblocked = signal::current_mask().unwrap();
    unblocked.remove(selected);
    let old_mask = signal::set_mask(&unblocked).unwrap();
    let (release_reader, release_writer) = pipe::pipe().unwrap();
    let cstr = |bytes| CStr::from_bytes_with_nul(bytes).unwrap();
    let prepared = process::PreparedExec::new(
        cstr(b"/bin/sh\0"),
        &[cstr(b"sh\0"), cstr(b"-c\0"), cstr(b"IFS= read -r _ <&9; exit 29\0")],
        &[],
    ).unwrap().with_actions(&[
        process::FdAction::close(&release_writer),
        process::FdAction::dup2(&release_reader, 9),
    ]);
    let child = prepared.spawn().unwrap();
    drop(prepared);
    drop(release_reader);
    // SAFETY: `pthread_self` has no preconditions; this thread outlives the
    // sender, which joins before the test returns.
    let waiter = unsafe { pthread_self() };
    let sender = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        std::thread::sleep(Duration::from_millis(50));
        while !SIGNAL_SEEN.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "signal handler did not run");
            // SAFETY: `waiter` names the live waiting thread.
            assert_eq!(unsafe { pthread_kill(waiter, selected.as_raw()) }, 0);
            std::thread::sleep(Duration::from_millis(20));
        }
        io::write(&release_writer, b"release\n").unwrap();
    });
    let result = child.wait(process::WaitOptions::empty());
    sender.join().unwrap();
    signal::set_mask(&old_mask).unwrap();
    // SAFETY: The sender has joined and the static handler has returned.
    unsafe { signal::sigaction(selected, Some(&old_action)) }.unwrap();
    assert!(SIGNAL_SEEN.load(Ordering::SeqCst));
    assert_eq!(result.expect("interruption must retain the consuming wait operation")
        .reaped().unwrap().exit_status(), Some(29));
}
