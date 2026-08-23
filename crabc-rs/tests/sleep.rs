use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crabc_rs::{process, signal, thread};
use crabc_rs::time::{self, ClockId, SleepError, SleepOutcome, Timespec};

static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn interrupt_handler(_: process::Signal) {
    SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}

#[test]
fn native_nanosleep_completes_a_zero_duration_without_c_state() {
    assert_eq!(
        time::nanosleep(Duration::ZERO),
        Ok(SleepOutcome::Completed),
    );
}

#[test]
fn native_nanosleep_rejects_seconds_outside_the_linux_timespec_range() {
    let too_large = Duration::from_secs(i64::MAX as u64 + 1);

    assert_eq!(
        time::nanosleep(too_large),
        Err(SleepError::DurationOutOfRange),
    );
    assert_eq!(
        SleepError::Kernel(crabc_rs::Errno::INVAL).kernel_errno(),
        Some(crabc_rs::Errno::INVAL),
    );
}

#[test]
fn native_nanosleep_preserves_eintr_and_remaining_duration() {
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interrupt_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    let old_action = unsafe { signal::sigaction(process::Signal::USR1, Some(&action)) }
        .expect("install direct interruption handler");
    let parent = process::getpid();
    let sleeper = thread::gettid();
    let child = match unsafe { process::fork_raw() }.expect("fork interrupter") {
        process::ForkResult::Parent { child } => child,
        process::ForkResult::Child => {
            let start = time::clock_gettime(ClockId::Monotonic);
            let target = after_delay(start, 100_000_000);
            loop {
                let now = time::clock_gettime(ClockId::Monotonic);
                if (now.tv_sec, now.tv_nsec) >= (target.tv_sec, target.tv_nsec) {
                    break;
                }
            }
            if crabc_core::process::tgkill(
                parent.as_raw_pid(),
                sleeper.as_raw_pid(),
                process::Signal::USR1.as_raw(),
            )
            .is_err()
            {
                process::exit_immediately(127);
            }
            process::exit_immediately(0);
        }
    };

    let requested = Duration::from_secs(2);
    let outcome = time::nanosleep(requested).expect("nanosleep syscall");
    let status = process::waitpid(Some(child), process::WaitOptions::empty())
        .expect("wait for interrupter")
        .expect("interrupter status")
        .1;
    unsafe { signal::sigaction(process::Signal::USR1, Some(&old_action)) }
        .expect("restore interruption handler");

    assert_eq!(status.exit_status(), Some(0));
    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    match outcome {
        SleepOutcome::Interrupted { remaining } => {
            assert!(remaining > Duration::ZERO);
            assert!(remaining < requested);
        }
        SleepOutcome::Completed => panic!("signal must preserve EINTR as an interrupted result"),
    }
}

fn after_delay(start: Timespec, delay_nanoseconds: i64) -> Timespec {
    let nanoseconds = start.tv_nsec + delay_nanoseconds;
    if nanoseconds < 1_000_000_000 {
        Timespec {
            tv_sec: start.tv_sec,
            tv_nsec: nanoseconds,
        }
    } else {
        Timespec {
            tv_sec: start.tv_sec + 1,
            tv_nsec: nanoseconds - 1_000_000_000,
        }
    }
}
