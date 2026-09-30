#![cfg(target_arch = "x86_64")]

use crabc_rs::{signal, time::Timespec, Errno};

unsafe extern "C" { fn __errno_location() -> *mut i32; }

fn selected() -> signal::SignalSet {
    let mut set = signal::SignalSet::EMPTY;
    set.insert(signal::Signal::USR1);
    set.insert(signal::Signal::RTMIN);
    set
}

fn queue(tid: signal::Pid, member: signal::Signal, value: i32) {
    // SAFETY: The test runtime owns writable calling-thread errno storage.
    unsafe { *__errno_location() = 1234; }
    signal::queue_thread(tid, member, value).unwrap();
    // SAFETY: The same thread retains its live errno storage.
    assert_eq!(unsafe { *__errno_location() }, 1234);
}

fn check(info: signal::SigInfo, member: signal::Signal, value: i32) {
    assert_eq!(info.signal(), Some(member));
    assert_eq!(info.raw_errno(), 0);
    assert_eq!(info.raw_code(), -1);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), crabc_core::process::getpid());
    assert_eq!(info.queued_i32(), value);
}

#[test]
fn x86_64_signal_thread_queue_targets_only_the_known_worker_pending_queue() {
    let mask = selected();
    let original = signal::block(&mask).unwrap();
    if std::env::var_os("CRABC_SIGNAL_THREAD_QUEUE_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "x86_64_signal_thread_queue_targets_only_the_known_worker_pending_queue", "--test-threads=1"])
            .env("CRABC_SIGNAL_THREAD_QUEUE_CHILD", "1").output().unwrap();
        signal::set_mask(&original).unwrap();
        assert!(output.status.success(), "isolated thread-queue child: {:?}\n{}\n{}",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }

    let caller_mask = signal::current_mask().unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let tid = crabc_core::thread::gettid();
        assert_ne!(tid, crabc_core::process::getpid());
        assert_eq!(signal::current_mask().unwrap(), caller_mask);
        ready_tx.send(tid).unwrap();
        release_rx.recv().unwrap();
        let pending = signal::pending().unwrap();
        assert!(pending.contains(signal::Signal::RTMIN));
        assert!(pending.contains(signal::Signal::USR1));
        let mut realtime = signal::SignalSet::EMPTY;
        realtime.insert(signal::Signal::RTMIN);
        for expected in [i32::MIN, i32::MAX, -1234567] {
            let (received, info) = signal::timed_wait(&realtime, Some(&zero)).unwrap();
            assert_eq!(received, signal::Signal::RTMIN);
            check(info, received, expected);
        }
        let mut ordinary = signal::SignalSet::EMPTY;
        ordinary.insert(signal::Signal::USR1);
        let (received, info) = signal::wait_info(&ordinary).unwrap();
        assert_eq!(received, signal::Signal::USR1);
        check(info, received, 11);
        assert_eq!(signal::timed_wait(&ordinary, Some(&zero)).unwrap_err(), Errno::AGAIN);
        assert!(!signal::pending().unwrap().contains(signal::Signal::RTMIN));
        assert!(!signal::pending().unwrap().contains(signal::Signal::USR1));
        assert_eq!(signal::current_mask().unwrap(), caller_mask);
        assert_eq!(crabc_core::thread::gettid(), tid);
    });
    let worker_tid = signal::Pid::from_raw(ready_rx.recv().unwrap()).unwrap();
    for value in [i32::MIN, i32::MAX, -1234567] {
        queue(worker_tid, signal::Signal::RTMIN, value);
    }
    queue(worker_tid, signal::Signal::USR1, 11);
    queue(worker_tid, signal::Signal::USR1, 22);
    let pending = signal::pending().unwrap();
    assert!(!pending.contains(signal::Signal::RTMIN));
    assert!(!pending.contains(signal::Signal::USR1));
    assert_eq!(signal::timed_wait(&mask, Some(&zero)).unwrap_err(), Errno::AGAIN);
    release_tx.send(()).unwrap();
    worker.join().unwrap();

    // A userspace join can finish before Linux removes the exiting task's
    // TID. Observe kernel retirement before requiring its missing-thread error.
    let task = std::path::PathBuf::from(format!("/proc/self/task/{}", worker_tid.as_raw_pid()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while task.try_exists().unwrap() {
        assert!(std::time::Instant::now() < deadline, "joined worker TID remains in the kernel");
        std::thread::yield_now();
    }

    // SAFETY: The test thread owns its errno storage. No thread is created
    // between kernel retirement and this stale-TID observation.
    unsafe { *__errno_location() = 1234; }
    assert_eq!(signal::queue_thread(worker_tid, signal::Signal::RTMIN, 0).unwrap_err(), Errno::SRCH);
    assert_eq!(signal::queue_thread(signal::Pid::from_raw(i32::MAX).unwrap(), signal::Signal::RTMIN, 0).unwrap_err(), Errno::SRCH);
    // SAFETY: The same calling-thread errno storage remains live.
    assert_eq!(unsafe { *__errno_location() }, 1234);

    let self_tid = signal::Pid::from_raw(crabc_core::thread::gettid()).unwrap();
    queue(self_tid, signal::Signal::RTMIN, 7654321);
    let (received, info) = signal::timed_wait(&mask, Some(&zero)).unwrap();
    assert_eq!(received, signal::Signal::RTMIN);
    check(info, received, 7654321);
    assert_eq!(signal::current_mask().unwrap(), caller_mask);
    signal::set_mask(&original).unwrap();
}
