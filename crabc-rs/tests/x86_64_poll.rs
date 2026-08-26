#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{event, io, pipe, signal, time::Timespec, Errno};

static PPOLL_SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn ppoll_signal_handler(_: signal::Signal) {
    PPOLL_SIGNAL_SEEN.store(true, Ordering::SeqCst);
}

#[test]
fn x86_64_poll_observes_pipe_readiness_and_preserves_requested_events() {
    let (reader, writer) = pipe::pipe().expect("create poll fixture pipe");
    let mut fds = [event::PollFd::new(&reader, event::PollFlags::IN)];
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };

    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(0));
    assert!(fds[0].revents().is_empty());

    io::write(&writer, b"x").expect("seed readable pipe");
    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(1));
    assert!(fds[0].revents().contains(event::PollFlags::IN));

    let mut byte = [0_u8; 1];
    assert_eq!(io::read(&reader, &mut byte), Ok(1));
    drop(writer);
    fds[0].clear_revents();
    assert_eq!(event::poll(&mut fds, Some(&zero)), Ok(1));
    assert!(fds[0].revents().contains(event::PollFlags::HUP));
}

#[test]
fn x86_64_poll_rejects_timeout_that_cannot_fit_linux_milliseconds() {
    let (_, writer) = pipe::pipe().expect("create timeout fixture pipe");
    let mut fds = [event::PollFd::new(&writer, event::PollFlags::OUT)];
    let too_large = Timespec { tv_sec: i64::from(i32::MAX), tv_nsec: 0 };
    assert_eq!(
        event::poll(&mut fds, Some(&too_large)),
        Err(Errno::INVAL)
    );

    let invalid_nanoseconds = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    assert_eq!(
        event::poll(&mut fds, Some(&invalid_nanoseconds)),
        Err(Errno::INVAL)
    );
}

#[test]
fn x86_64_poll_flags_match_musl_x86_values() {
    assert_eq!(event::PollFlags::IN.bits(), 0x0001);
    assert_eq!(event::PollFlags::PRI.bits(), 0x0002);
    assert_eq!(event::PollFlags::OUT.bits(), 0x0004);
    assert_eq!(event::PollFlags::ERR.bits(), 0x0008);
    assert_eq!(event::PollFlags::HUP.bits(), 0x0010);
    assert_eq!(event::PollFlags::NVAL.bits(), 0x0020);
    assert_eq!(event::PollFlags::RDHUP.bits(), 0x2000);
}

#[test]
fn x86_64_signal_set_matches_kernel_mask_and_musl_reserved_bits() {
    let mut set = signal::SignalSet::EMPTY;
    assert!(set.is_empty());
    set.insert(signal::Signal::USR1);
    assert!(set.contains(signal::Signal::USR1));
    set.remove(signal::Signal::USR1);
    assert!(!set.contains(signal::Signal::USR1));

    let full = signal::SignalSet::full();
    assert!(full.contains(signal::Signal::HUP));
    assert!(full.contains(signal::Signal::SYS));
    assert!(full.contains(signal::Signal::RTMIN));
    assert!(full.contains(signal::Signal::RTMAX));
    assert!(!full.contains(unsafe { signal::Signal::from_raw_unchecked(32) }));
    assert!(!full.contains(unsafe { signal::Signal::from_raw_unchecked(33) }));
    assert!(!full.contains(unsafe { signal::Signal::from_raw_unchecked(34) }));
}

#[test]
fn x86_64_ppoll_temporarily_installs_mask_and_restores_previous_mask() {
    const SIG_SETMASK: i32 = 2;
    let selected_signal = signal::Signal::USR1;
    let signal_bit = 1_u64 << (selected_signal.as_raw() - 1);

    let old_action = unsafe { signal::sigaction(selected_signal, None) }.expect("query SIGUSR1 action");
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(ppoll_signal_handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is a static function with an x86-64 restorer owned
    // by crabc-rs and remains installed only for this test.
    unsafe { signal::sigaction(selected_signal, Some(&action)) }.expect("install SIGUSR1 handler");

    let mut old_mask = 0_u64;
    // SAFETY: A null input queries this thread's one-word kernel mask.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut old_mask,
        )
        .expect("query signal mask");
    }
    let blocked_mask = old_mask | signal_bit;
    // SAFETY: `blocked_mask` is one initialized x86-64 kernel mask word.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            &blocked_mask,
            core::ptr::null_mut(),
        )
        .expect("block SIGUSR1");
    }

    PPOLL_SIGNAL_SEEN.store(false, Ordering::SeqCst);
    signal::raise(selected_signal).expect("queue blocked SIGUSR1");
    let (reader, writer) = pipe::pipe().expect("create ppoll fixture pipe");
    let timeout = Timespec { tv_sec: 0, tv_nsec: 0 };
    let empty = signal::SignalSet::EMPTY;
    let mut fds = [event::PollFd::new(&reader, event::PollFlags::IN)];
    assert_eq!(event::ppoll(&mut fds, Some(&timeout), Some(&empty)), Err(Errno::INTR));
    assert!(PPOLL_SIGNAL_SEEN.load(Ordering::SeqCst));

    let mut observed_mask = 0_u64;
    // SAFETY: A null input queries the mask restored by `ppoll`.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            core::ptr::null(),
            &mut observed_mask,
        )
        .expect("query restored signal mask");
    }
    assert_ne!(observed_mask & signal_bit, 0);

    // SAFETY: Restore the caller's signal state and the prior disposition.
    unsafe {
        crabc_core::signal::rt_sigprocmask_raw(
            SIG_SETMASK,
            &old_mask,
            core::ptr::null_mut(),
        )
        .expect("restore signal mask");
        signal::sigaction(selected_signal, Some(&old_action)).expect("restore SIGUSR1 action");
    }
    drop(writer);
}

#[test]
fn x86_64_pause_waits_for_a_signal_on_the_ppoll_seam() {
    static PAUSE_SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn pause_signal_handler(_: signal::Signal) {
        PAUSE_SIGNAL_SEEN.store(true, Ordering::SeqCst);
    }

    let signal = signal::Signal::USR2;
    let old_action = unsafe { signal::sigaction(signal, None) }.expect("query SIGUSR2 action");
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(pause_signal_handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is a static function with a valid x86-64 restorer.
    unsafe { signal::sigaction(signal, Some(&action)) }.expect("install SIGUSR2 handler");
    PAUSE_SIGNAL_SEEN.store(false, Ordering::SeqCst);

    let tid = crabc_core::thread::gettid();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(10));
        crabc_core::process::tgkill(
            crabc_core::process::getpid(),
            tid,
            signal.as_raw(),
        )
        .expect("send SIGUSR2 to paused thread");
    });
    event::pause();
    sender.join().expect("join signal sender");
    assert!(PAUSE_SIGNAL_SEEN.load(Ordering::SeqCst));

    // SAFETY: Restore the prior disposition after the handler has returned.
    unsafe { signal::sigaction(signal, Some(&old_action)) }.expect("restore SIGUSR2 action");
}
