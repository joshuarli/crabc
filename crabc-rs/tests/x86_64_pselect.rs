#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{event, io, pipe, signal, time, Errno};

static PSELECT_SIGNAL_SEEN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn pselect_signal_handler(_: signal::Signal) {
    PSELECT_SIGNAL_SEEN.store(true, Ordering::SeqCst);
}

#[test]
fn x86_64_fd_set_helpers_use_native_words_and_sorted_bits() {
    assert_eq!(size_of::<event::FdSetElement>(), 8);
    assert_eq!(align_of::<event::FdSetElement>(), 8);
    assert_eq!(event::fd_set_num_elements(0, 0), 0);
    assert_eq!(event::fd_set_num_elements(0, 1), 1);
    assert_eq!(event::fd_set_num_elements(0, 64), 1);
    assert_eq!(event::fd_set_num_elements(0, 65), 2);

    let mut set = [event::FdSetElement::default(); 2];
    event::fd_set_insert(&mut set, 1);
    event::fd_set_insert(&mut set, 63);
    event::fd_set_insert(&mut set, 64);
    assert_eq!(event::fd_set_bound(&set), 65);
    assert_eq!(
        event::FdSetIter::new(&set).collect::<std::vec::Vec<_>>(),
        vec![1, 63, 64]
    );

    event::fd_set_remove(&mut set, 63);
    assert_eq!(
        event::FdSetIter::new(&set).collect::<std::vec::Vec<_>>(),
        vec![1, 64]
    );
}

#[test]
fn x86_64_select_rejects_negative_nfds_and_short_sets_without_panicking() {
    let timeout = time::Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut one = [event::FdSetElement::default(); 1];

    // SAFETY: This deliberately exercises the public validation boundary; no
    // descriptor-set pointer may be formed for an invalid negative `nfds`.
    assert_eq!(
        unsafe { event::select(-1, Some(&mut one), None, None, Some(&timeout)) },
        Err(Errno::INVAL)
    );

    // 65 bits require two eight-byte x86-64 kernel words. Each supplied set
    // is checked before the direct syscall is entered.
    // SAFETY: The invalid slice lengths are intentional; validation must
    // return `EINVAL` without dereferencing or passing these sets to Linux.
    assert_eq!(
        unsafe { event::pselect(65, Some(&mut one), None, None, Some(&timeout), None) },
        Err(Errno::INVAL)
    );

    let mut one = [event::FdSetElement::default(); 1];
    // SAFETY: See the preceding call; this covers the write set boundary.
    assert_eq!(
        unsafe { event::pselect(65, None, Some(&mut one), None, Some(&timeout), None) },
        Err(Errno::INVAL)
    );

    let mut one = [event::FdSetElement::default(); 1];
    // SAFETY: See the preceding call; this covers the exception set boundary.
    assert_eq!(
        unsafe { event::pselect(65, None, None, Some(&mut one), Some(&timeout), None) },
        Err(Errno::INVAL)
    );
}

#[test]
fn x86_64_select_and_masked_pselect_report_pipe_readiness_without_mutating_timeout() {
    let (reader, writer) = pipe::pipe().expect("create select pipe");
    let nfds = reader.as_raw_fd() + 1;
    let elements = event::fd_set_num_elements(0, nfds);
    let mut readfds = std::vec![event::FdSetElement::default(); elements];
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());

    let timeout = time::Timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: The reader remains open and `readfds` has enough storage for all
    // descriptors below `nfds`; Linux may rewrite the set in place.
    let ready = unsafe { event::select(nfds, Some(&mut readfds), None, None, Some(&timeout)) }
        .expect("empty select");
    assert_eq!(ready, 0);
    assert_eq!(event::fd_set_bound(&readfds), 0);
    assert_eq!(timeout, time::Timespec { tv_sec: 0, tv_nsec: 0 });

    assert_eq!(io::write(&writer, b"p").expect("write select byte"), 1);
    event::fd_set_insert(&mut readfds, reader.as_raw_fd());
    let timeout = time::Timespec {
        tv_sec: 1,
        tv_nsec: 234_567_890,
    };
    let original_timeout = timeout;
    let mask = signal::SignalSet::EMPTY;
    // SAFETY: The pipe and set remain valid for the call. `mask` is a live
    // x86-64 kernel signal-set word and the supplied timeout is copied by the
    // facade before Linux receives its mutable pointer.
    let ready = unsafe {
        event::pselect(
            nfds,
            Some(&mut readfds),
            None,
            None,
            Some(&timeout),
            Some(&mask),
        )
    }
    .expect("masked pselect for readable pipe");
    assert_eq!(ready, 1);
    assert_eq!(timeout, original_timeout);
    assert_eq!(
        event::FdSetIter::new(&readfds).collect::<std::vec::Vec<_>>(),
        vec![reader.as_raw_fd()]
    );
}

#[test]
fn x86_64_pselect_temporarily_installs_and_restores_the_signal_mask() {
    const SIG_SETMASK: i32 = 2;
    let selected_signal = signal::Signal::USR1;
    let signal_bit = 1_u64 << (selected_signal.as_raw() - 1);

    let old_action =
        unsafe { signal::sigaction(selected_signal, None) }.expect("query SIGUSR1 action");
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(pselect_signal_handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is a static function with the x86-64 restorer owned
    // by crabc-rs and remains installed only for this test.
    unsafe { signal::sigaction(selected_signal, Some(&action)) }
        .expect("install SIGUSR1 handler");

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

    PSELECT_SIGNAL_SEEN.store(false, Ordering::SeqCst);
    signal::raise(selected_signal).expect("queue blocked SIGUSR1");
    let timeout = time::Timespec { tv_sec: 0, tv_nsec: 0 };
    let empty = signal::SignalSet::EMPTY;
    // SAFETY: There are no descriptor sets, the timeout and mask remain live
    // for this direct syscall, and the queued signal exercises the atomic
    // temporary-mask transition.
    assert_eq!(
        unsafe { event::pselect(0, None, None, None, Some(&timeout), Some(&empty)) },
        Err(Errno::INTR),
    );
    assert!(PSELECT_SIGNAL_SEEN.load(Ordering::SeqCst));

    let mut observed_mask = 0_u64;
    // SAFETY: A null input queries the mask restored by pselect.
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
        signal::sigaction(selected_signal, Some(&old_action))
            .expect("restore SIGUSR1 action");
    }
}
