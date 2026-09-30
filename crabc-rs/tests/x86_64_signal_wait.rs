#![cfg(target_arch = "x86_64")]

use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicBool, Ordering};
use crabc_rs::{signal, time::Timespec, Errno};

unsafe extern "C" {
    fn __errno_location() -> *mut i32;
}

fn seed_errno() {
    // SAFETY: The musl test runtime owns writable calling-thread errno storage.
    unsafe { *__errno_location() = 1234; }
}

fn assert_errno_unchanged() {
    // SAFETY: The same test thread retains its live errno storage.
    assert_eq!(unsafe { *__errno_location() }, 1234);
}

#[test]
fn x86_64_signal_wait_layout_and_timeout_errors() {
    assert_eq!(size_of::<signal::SigInfo>(), 128);
    assert_eq!(align_of::<signal::SigInfo>(), 8);
    assert_eq!(size_of::<Timespec>(), 16);
    assert_eq!(offset_of!(Timespec, tv_nsec), 8);
    let mask = signal::current_mask().unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    seed_errno();
    assert_eq!(signal::timed_wait(&signal::SignalSet::EMPTY, Some(&zero)).unwrap_err(), Errno::AGAIN);
    assert_errno_unchanged();
    for invalid in [Timespec { tv_sec: -1, tv_nsec: 0 },
                    Timespec { tv_sec: 0, tv_nsec: -1 },
                    Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 }] {
        seed_errno();
        assert_eq!(signal::timed_wait(&signal::SignalSet::EMPTY, Some(&invalid)).unwrap_err(), Errno::INVAL);
        assert_errno_unchanged();
    }
    assert_eq!(signal::current_mask().unwrap(), mask);
}

fn isolated_child(name: &str, selected: &signal::SignalSet) -> bool {
    let previous = signal::block(selected).unwrap();
    if std::env::var_os("CRABC_SIGNAL_WAIT_CHILD").is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact").arg(name).arg("--test-threads=1")
        .env("CRABC_SIGNAL_WAIT_CHILD", "1").status().unwrap();
    signal::set_mask(&previous).unwrap();
    assert!(status.success(), "isolated signal wait child: {status}");
    false
}

fn queue_self(selected: signal::Signal, value: i32) {
    queue_record(selected, value, crabc_core::process::getpid());
}

fn queue_record(selected: signal::Signal, value: i32, sender_pid: i32) {
    let mut info = crabc_core::signal::SigInfo::zeroed();
    info.bytes[0..4].copy_from_slice(&selected.as_raw().to_ne_bytes());
    info.bytes[8..12].copy_from_slice(&(-1_i32).to_ne_bytes());
    info.bytes[16..20].copy_from_slice(&sender_pid.to_ne_bytes());
    info.bytes[20..24].copy_from_slice(&crabc_core::process::getuid().to_ne_bytes());
    info.bytes[24..28].copy_from_slice(&value.to_ne_bytes());
    // SAFETY: This zero-initialized x86 siginfo record carries SI_QUEUE,
    // the test-supplied sender identity, and its payload at fixed ABI offsets.
    // Linux permits a self-queued SI_QUEUE record to retain a non-positive PID.
    unsafe {
        crabc_core::signal::rt_sigqueueinfo_raw(
            crabc_core::process::getpid(), selected.as_raw(), &info,
        ).unwrap();
    }
}

#[test]
fn x86_64_signal_wait_consumes_selected_pending_and_realtime_queue_records() {
    let mut selected = signal::SignalSet::EMPTY;
    for member in [signal::Signal::USR1, signal::Signal::RTMIN,
                   signal::Signal::RTMAX, signal::Signal::CHILD] {
        selected.insert(member);
    }
    if !isolated_child("x86_64_signal_wait_consumes_selected_pending_and_realtime_queue_records", &selected) {
        return;
    }
    let mask = signal::current_mask().unwrap();
    let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut usr1 = signal::SignalSet::EMPTY;
    usr1.insert(signal::Signal::USR1);
    crabc_core::process::kill(crabc_core::process::getpid(), signal::Signal::USR1.as_raw()).unwrap();
    assert!(signal::pending().unwrap().contains(signal::Signal::USR1));
    let invalid = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
    assert_eq!(signal::timed_wait(&usr1, Some(&invalid)).unwrap_err(), Errno::INVAL);
    assert!(signal::pending().unwrap().contains(signal::Signal::USR1));
    seed_errno();
    let (received, info) = signal::timed_wait(&usr1, Some(&zero)).unwrap();
    assert_errno_unchanged();
    assert_eq!(received, signal::Signal::USR1);
    assert_eq!(info.signal(), Some(received));
    assert_eq!(info.raw_signal(), received.as_raw());
    assert_eq!(info.raw_errno(), 0);
    assert_eq!(info.raw_code(), 0);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), crabc_core::process::getpid());
    assert!(!signal::pending().unwrap().contains(received));
    queue_self(signal::Signal::RTMIN, 1234567);
    queue_self(signal::Signal::RTMIN, -1234567);
    queue_self(signal::Signal::RTMAX, i32::MIN);
    let mut realtime = signal::SignalSet::EMPTY;
    realtime.insert(signal::Signal::RTMIN);
    realtime.insert(signal::Signal::RTMAX);
    for (expected, value) in [(signal::Signal::RTMIN, 1234567),
                              (signal::Signal::RTMIN, -1234567),
                              (signal::Signal::RTMAX, i32::MIN)] {
        seed_errno();
        let (received, info) = signal::wait_info(&realtime).unwrap();
        assert_errno_unchanged();
        assert_eq!(received, expected);
        assert_eq!(info.signal(), Some(expected));
        assert_eq!(info.raw_errno(), 0);
        assert_eq!(info.raw_code(), -1);
        assert_eq!(info.sender_pid().unwrap().as_raw_pid(), crabc_core::process::getpid());
        assert_eq!(info.queued_i32(), value);
    }
    queue_record(signal::Signal::RTMIN, 7, -7);
    let (_, info) = signal::wait_info(&realtime).unwrap();
    assert_eq!(info.sender_pid(), None);
    assert_eq!(info.queued_i32(), 7);
    assert!(signal::pending().unwrap().is_empty());
    let tid = crabc_core::thread::gettid();
    let sender = std::thread::spawn(move || {
        wait_until_blocked(tid);
        queue_self(signal::Signal::RTMAX, 7654321);
    });
    let mut maximum = signal::SignalSet::EMPTY;
    maximum.insert(signal::Signal::RTMAX);
    let timeout = Timespec { tv_sec: 5, tv_nsec: 0 };
    let outcome = signal::timed_wait(&maximum, Some(&timeout));
    sender.join().unwrap();
    let (received, info) = outcome.unwrap();
    assert_eq!(received, signal::Signal::RTMAX);
    assert_eq!(info.raw_code(), -1);
    assert_eq!(info.queued_i32(), 7654321);
    let mut child = std::process::Command::new("/bin/sh").args(["-c", "exit 42"]).spawn().unwrap();
    let child_pid = child.id() as i32;
    assert_eq!(child.wait().unwrap().code(), Some(42));
    let mut child_set = signal::SignalSet::EMPTY;
    child_set.insert(signal::Signal::CHILD);
    let (received, info) = signal::timed_wait(&child_set, Some(&zero)).unwrap();
    assert_eq!(received, signal::Signal::CHILD);
    assert_eq!(info.raw_code(), 1);
    assert_eq!(info.sender_pid().unwrap().as_raw_pid(), child_pid);
    assert_eq!(info.status(), 42);
    assert_eq!(signal::current_mask().unwrap(), mask);
    assert_eq!(zero, Timespec { tv_sec: 0, tv_nsec: 0 });
}

fn wait_until_blocked(tid: i32) {
    let path = format!("/proc/self/task/{tid}/syscall");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if std::fs::read_to_string(&path).unwrap().starts_with("128 ") {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "waiter never entered rt_sigtimedwait");
        std::thread::yield_now();
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" fn wait_interrupt(_: signal::Signal) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[test]
fn x86_64_signal_wait_preserves_kernel_eintr_and_errno() {
    let mut selected = signal::SignalSet::EMPTY;
    selected.insert(signal::Signal::RTMIN);
    if !isolated_child("x86_64_signal_wait_preserves_kernel_eintr_and_errno", &selected) {
        return;
    }
    let mut interrupt = signal::SignalSet::EMPTY;
    interrupt.insert(signal::Signal::USR2);
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(wait_interrupt), signal::SigActionFlags::empty(),
    );
    // SAFETY: The static handler only stores a lock-free atomic flag and stays
    // executable until the original disposition is reinstated after delivery.
    let old_action = unsafe { signal::sigaction(signal::Signal::USR2, Some(&action)) }.unwrap();
    let old_mask = signal::unblock(&interrupt).unwrap();
    let waiting_mask = signal::current_mask().unwrap();
    let tid = crabc_core::thread::gettid();
    let sender = std::thread::spawn(move || {
        wait_until_blocked(tid);
        crabc_core::process::tgkill(
            crabc_core::process::getpid(), tid, signal::Signal::USR2.as_raw(),
        ).unwrap();
    });
    let timeout = Timespec { tv_sec: 5, tv_nsec: 0 };
    seed_errno();
    let outcome = signal::timed_wait(&selected, Some(&timeout));
    assert_errno_unchanged();
    sender.join().unwrap();
    assert_eq!(outcome.unwrap_err(), Errno::INTR);
    assert!(INTERRUPTED.load(Ordering::SeqCst));
    assert_eq!(signal::current_mask().unwrap(), waiting_mask);
    assert_eq!(timeout, Timespec { tv_sec: 5, tv_nsec: 0 });
    signal::set_mask(&old_mask).unwrap();
    // SAFETY: The handler has completed and its sender thread is joined.
    unsafe { signal::sigaction(signal::Signal::USR2, Some(&old_action)) }.unwrap();
}
