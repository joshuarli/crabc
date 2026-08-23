use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use crabc_rs::thread::futex::{self, Flags, Timespec};
use crabc_rs::Errno;

#[test]
fn wait_reports_value_mismatch_as_eagain() {
    let word = AtomicU32::new(7);
    assert_eq!(
        futex::wait(&word, Flags::PRIVATE, 8, None),
        Err(Errno::AGAIN)
    );
}

#[test]
fn wake_without_waiters_reports_zero() {
    let word = AtomicU32::new(0);
    assert_eq!(futex::wake(&word, Flags::PRIVATE, 1), Ok(0));
}

#[test]
fn wait_timeout_is_relative_and_reports_timeout() {
    let word = AtomicU32::new(0);
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    assert_eq!(
        futex::wait(&word, Flags::PRIVATE, 0, Some(&timeout)),
        Err(Errno::TIMEDOUT)
    );
}

#[test]
fn wait_and_wake_exchange_an_atomic_state() {
    let word = Arc::new(AtomicU32::new(0));
    let entered = Arc::new(AtomicBool::new(false));
    let worker_word = Arc::clone(&word);
    let worker_entered = Arc::clone(&entered);
    let worker = std::thread::spawn(move || {
        worker_entered.store(true, Ordering::Release);
        loop {
            match futex::wait(&worker_word, Flags::PRIVATE, 0, None) {
                Ok(()) | Err(Errno::AGAIN) => return,
                Err(Errno::INTR) => continue,
                Err(error) => panic!("futex wait: {error:?}"),
            }
        }
    });

    while !entered.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    // Give the worker a scheduling opportunity to enter the kernel. If it has
    // not queued yet, the value change makes its wait return EAGAIN instead;
    // either result is the Linux futex lost-wakeup contract.
    std::thread::sleep(std::time::Duration::from_millis(2));
    word.store(1, Ordering::Release);
    let wake_result = futex::wake(&word, Flags::PRIVATE, 1).expect("wake worker");
    assert!(wake_result <= 1);
    worker.join().expect("join futex worker");
    assert_eq!(word.load(Ordering::Acquire), 1);
}
