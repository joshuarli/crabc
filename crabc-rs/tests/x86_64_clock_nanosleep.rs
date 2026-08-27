#![cfg(target_arch = "x86_64")]

use core::time::Duration;
use core::sync::atomic::{AtomicBool, Ordering};

use crabc_rs::{process, signal, thread};
use crabc_rs::time::{self, ClockId, SleepError, SleepOutcome, Timespec};

static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);
static ABSOLUTE_SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);

// Test-only direct-mask handling makes the chosen delivery signal independent
// of the harness's inherited mask. It does not expand the narrow x86 signal
// facade with public general mask mutation.
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;

unsafe extern "C" fn interrupt_handler(_: signal::Signal) {
    SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn absolute_interrupt_handler(_: signal::Signal) {
    ABSOLUTE_SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}

struct RestoreInterruptionSignal {
    selected: signal::Signal,
    old_action: signal::SigAction,
    old_mask: u64,
}

impl Drop for RestoreInterruptionSignal {
    fn drop(&mut self) {
        // SAFETY: `old_mask` is the exact initialized x86 kernel signal-mask
        // word observed before this test unblocked only `selected`.
        unsafe {
            let _ = crabc_core::signal::rt_sigprocmask_raw(
                SIG_SETMASK,
                &self.old_mask,
                core::ptr::null_mut(),
            );
        }
        // SAFETY: `old_action` was returned by Linux before this test replaced
        // the selected process-global signal disposition.
        unsafe {
            let _ = signal::sigaction(self.selected, Some(&self.old_action));
        }
    }
}

fn install_interruption_handler(
    selected: signal::Signal,
    handler: unsafe extern "C" fn(signal::Signal),
) -> RestoreInterruptionSignal {
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(handler),
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is static and remains installed through the returned
    // restoration guard; it performs only an atomic signal-safe store.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }
        .expect("install direct interruption handler");
    let signal_bit = 1_u64 << (selected.as_raw() - 1);
    let mut old_mask = 0_u64;
    // SAFETY: `signal_bit` and `old_mask` are one readable/writable x86
    // kernel-sized mask word. The exact former mask is restored by the guard.
    let unblocked = unsafe {
        crabc_core::signal::rt_sigprocmask_raw(SIG_UNBLOCK, &signal_bit, &mut old_mask)
    };
    if let Err(error) = unblocked {
        // SAFETY: The temporary handler was just installed from `old_action`.
        unsafe {
            let _ = signal::sigaction(selected, Some(&old_action));
        }
        panic!("unblock direct interruption signal: {error:?}");
    }
    RestoreInterruptionSignal {
        selected,
        old_action,
        old_mask,
    }
}

fn wait_until_clock_nanosleep_is_blocked(pid: i32, tid: i32, initial_switches: u64) -> bool {
    let status_path = format!("/proc/{pid}/task/{tid}/status");
    let timeout = std::time::Instant::now() + Duration::from_secs(3);
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
            return true;
        }
        if std::time::Instant::now() >= timeout {
            return false;
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
    let selected = signal::Signal::USR1;
    let restore_signal = install_interruption_handler(selected, interrupt_handler);
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);

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
        let observed_blocked = wait_until_clock_nanosleep_is_blocked(pid, tid, initial_switches);
        crabc_core::process::tgkill(pid, tid, selected.as_raw())
            .expect("send signal to sleeping thread");
        observed_blocked
    });

    let outcome = time::clock_nanosleep_relative(ClockId::Monotonic, Duration::from_secs(2));
    let observed_blocked = sender.join().expect("join signal sender");
    drop(restore_signal);

    assert!(observed_blocked, "clock_nanosleep must block before its signal");
    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    match outcome {
        Ok(SleepOutcome::Interrupted { remaining }) => assert!(remaining > Duration::ZERO),
        Ok(SleepOutcome::Completed) => panic!("signal must preserve EINTR as interrupted"),
        Err(error) => panic!("clock_nanosleep must preserve EINTR, got {error:?}"),
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

#[test]
fn x86_64_clock_nanosleep_absolute_preserves_eintr_without_a_remaining_duration() {
    // Use a distinct process-global signal from the relative-sleep test so
    // libtest may run both interruption regressions concurrently.
    let selected = signal::Signal::USR2;
    let restore_signal = install_interruption_handler(selected, absolute_interrupt_handler);
    ABSOLUTE_SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let pid = process::getpid().as_raw_pid();
    let tid = thread::gettid().as_raw_pid();
    let status_path = format!("/proc/{pid}/task/{tid}/status");
    let initial_switches = std::fs::read_to_string(status_path)
        .expect("read test thread context-switch count")
        .lines()
        .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:")?.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("task status must expose voluntary context switches");

    // Complete the fallible deadline setup before starting a helper that
    // waits on the rendezvous channel. That keeps setup panics from leaving a
    // detached helper whose channel has no sender.
    let deadline = time::clock_gettime(ClockId::Monotonic)
        .expect("read monotonic deadline for interrupted absolute sleep");
    let deadline = Timespec {
        tv_sec: deadline
            .tv_sec
            .checked_add(10)
            .expect("monotonic clock must leave room for test deadline"),
        tv_nsec: deadline.tv_nsec,
    };

    let (start_sender, sender_start) = std::sync::mpsc::sync_channel::<()>(0);
    let sender = std::thread::spawn(move || {
        sender_start
            .recv()
            .expect("start absolute-sleep signal sender");
        let observed_blocked = wait_until_clock_nanosleep_is_blocked(pid, tid, initial_switches);
        crabc_core::process::tgkill(pid, tid, selected.as_raw())
            .expect("send signal to absolute-sleeping thread");
        observed_blocked
    });
    start_sender
        .send(())
        .expect("start absolute-sleep signal sender");

    let result = time::clock_nanosleep_absolute(ClockId::Monotonic, deadline);
    let observed_blocked = sender.join().expect("join absolute signal sender");
    drop(restore_signal);

    assert!(observed_blocked, "clock_nanosleep must block before its signal");
    assert!(ABSOLUTE_SIGNAL_DELIVERED.load(Ordering::SeqCst));
    assert_eq!(result, Err(SleepError::Kernel(crabc_rs::Errno::INTR)));
}
