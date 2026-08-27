#![cfg(target_arch = "x86_64")]

use core::time::Duration;
use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{process, signal, thread};
use crabc_rs::time::{self, ClockId, SleepError, SleepOutcome, Timespec};

static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn interrupt_handler(_: signal::Signal) {
    SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}

fn wait_until_clock_nanosleep_is_blocked(pid: i32, tid: i32, initial_switches: u64) {
    let status_path = format!("/proc/{pid}/task/{tid}/status");
    loop {
        let status = std::fs::read_to_string(&status_path)
            .expect("read sleeping test thread status");
        let sleeping = status
            .lines()
            .find_map(|line| line.strip_prefix("State:")?.split_whitespace().next())
            == Some("S");
        let switched = status
            .lines()
            .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:")?.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|count| count > initial_switches);
        if sleeping && switched {
            return;
        }
        std::thread::yield_now();
    }
}

#[test]
fn x86_64_clock_nanosleep_relative_zero_completes_on_monotonic_clock() {
    assert_eq!(
        time::clock_nanosleep_relative(ClockId::Monotonic, Duration::ZERO),
        Ok(SleepOutcome::Completed),
    );
}

#[test]
fn x86_64_clock_nanosleep_rejects_duration_outside_linux_timespec_range() {
    let too_large = Duration::from_secs(i64::MAX as u64 + 1);
    assert_eq!(
        time::clock_nanosleep_relative(ClockId::Monotonic, too_large),
        Err(SleepError::DurationOutOfRange),
    );
}

#[test]
fn x86_64_clock_nanosleep_relative_preserves_eintr_and_remaining_duration() {
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let selected = signal::Signal::USR1;
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interrupt_handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is static and remains installed until restored
    // below; it performs only an atomic signal-safe store.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }
        .expect("install direct interruption handler");

    let pid = process::getpid().as_raw_pid();
    let tid = thread::gettid().as_raw_pid();
    let status_path = format!("/proc/{pid}/task/{tid}/status");
    let initial_switches = std::fs::read_to_string(status_path)
        .expect("read test thread context-switch count")
        .lines()
        .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:")?.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("task status must expose voluntary context switches");
    let sender = std::thread::spawn(move || {
        wait_until_clock_nanosleep_is_blocked(pid, tid, initial_switches);
        crabc_core::process::tgkill(pid, tid, selected.as_raw())
            .expect("send signal to sleeping thread");
    });

    let outcome = time::clock_nanosleep_relative(ClockId::Monotonic, Duration::from_secs(2))
        .expect("clock_nanosleep syscall");
    sender.join().expect("join signal sender");

    // SAFETY: Restore the caller's previous action after the handler has
    // returned and the sender has stopped targeting this thread.
    unsafe { signal::sigaction(selected, Some(&old_action)) }
        .expect("restore interruption handler");

    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    match outcome {
        SleepOutcome::Interrupted { remaining } => assert!(remaining > Duration::ZERO),
        SleepOutcome::Completed => panic!("signal must preserve EINTR as interrupted"),
    }
}

#[test]
fn x86_64_clock_nanosleep_absolute_has_no_remaining_and_validates_request() {
    // The monotonic epoch is in the past, so an absolute deadline of zero
    // completes immediately. The unit result carries no invented remainder.
    assert_eq!(
        time::clock_nanosleep_absolute(
            ClockId::Monotonic,
            Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        ),
        Ok(()),
    );
    assert_eq!(
        time::clock_nanosleep_absolute(
            ClockId::Monotonic,
            Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
        ),
        Err(SleepError::InvalidRequest),
    );
}
