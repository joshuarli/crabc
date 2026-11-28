use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

#[cfg(target_os = "linux")]
use crabc_rs::{process, thread};
use crabc_rs::{signal, time, Errno};
use crabc_rs::time::{SleepError, SleepOutcome};

static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn interrupt_handler(_: signal::Signal) {
    SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn voluntary_context_switches(pid: i32, tid: i32) -> u64 {
    let status_path = format!("/proc/{pid}/task/{tid}/status");
    let status = std::fs::read_to_string(status_path)
        .expect("read test thread context-switch count");
    status
        .lines()
        .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:")?.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .expect("task status must expose voluntary context switches")
}

#[cfg(target_os = "linux")]
fn wait_until_nanosleep_is_blocked(pid: i32, tid: i32, initial_switches: u64) {
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
fn x86_64_nanosleep_completes_zero_duration_without_c_state() {
    assert_eq!(time::nanosleep(Duration::ZERO), Ok(SleepOutcome::Completed));
}

#[test]
fn x86_64_nanosleep_rejects_seconds_outside_linux_timespec_range() {
    let too_large = Duration::from_secs(i64::MAX as u64 + 1);
    assert_eq!(
        time::nanosleep(too_large),
        Err(SleepError::DurationOutOfRange),
    );
    assert_eq!(
        SleepError::Kernel(Errno::INVAL).kernel_errno(),
        Some(Errno::INVAL),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn x86_64_nanosleep_preserves_eintr_and_remaining_duration() {
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let selected = signal::Signal::USR1;
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interrupt_handler),
        #[cfg(target_arch = "aarch64")]
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is static and remains installed until restored
    // below; it performs only an atomic signal-safe store.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }
        .expect("install direct interruption handler");

    let pid = process::getpid().as_raw_pid();
    let tid = thread::gettid().as_raw_pid();
    let initial_switches = voluntary_context_switches(pid, tid);
    let sender = std::thread::spawn(move || {
        // `/proc/<pid>/task/<tid>/status` exposes the kernel task state.
        // Between the baseline capture and the direct sleep call, this test
        // performs no other blocking operation on the target thread. A
        // sleeping state after a voluntary context switch therefore proves it
        // has yielded in `nanosleep`; a timing delay alone could signal too
        // early. Do not depend on a kernel-specific `wchan` symbol here.
        wait_until_nanosleep_is_blocked(pid, tid, initial_switches);
        crabc_core::process::tgkill(pid, tid, selected.as_raw())
            .expect("send signal to sleeping thread");
    });

    let outcome = time::nanosleep(Duration::from_secs(2)).expect("nanosleep syscall");
    sender.join().expect("join signal sender");

    // SAFETY: Restore the caller's previous action after the handler has
    // returned and the sender has stopped targeting this thread.
    unsafe { signal::sigaction(selected, Some(&old_action)) }
        .expect("restore interruption handler");

    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    match outcome {
        SleepOutcome::Interrupted { remaining } => {
            assert!(remaining > Duration::ZERO);
            // The facade has already checked the kernel timespec's canonical
            // representation. Linux may round an interrupted remainder, so
            // this direct boundary deliberately preserves its positive value
            // rather than imposing a lossy comparison with `requested`.
        }
        SleepOutcome::Completed => panic!("signal must preserve EINTR as interrupted"),
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn pthread_self() -> usize;
    fn pthread_kill(thread: usize, signal: i32) -> i32;
}

// Darwin exposes no task state for a sleeping thread, so the sender signals
// after a delay long enough for the sleeper to have blocked, and the elapsed
// monotonic time shows that the sleep did block before it was interrupted.
#[cfg(target_os = "macos")]
#[test]
fn x86_64_nanosleep_preserves_eintr_and_remaining_duration() {
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let selected = signal::Signal::USR1;
    let action = signal::SigAction::new(
        signal::SigHandler::Simple(interrupt_handler),
        signal::SignalSet::EMPTY,
        signal::SigActionFlags::empty(),
    );
    // SAFETY: The handler is static and remains installed until restored
    // below; it performs only an atomic signal-safe store.
    let old_action = unsafe { signal::sigaction(selected, Some(&action)) }
        .expect("install interruption handler");

    // SAFETY: `pthread_self` has no preconditions; this thread outlives the
    // sender, which joins before the handler is removed.
    let sleeper = unsafe { pthread_self() };
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: `sleeper` names the live sleeping thread.
        assert_eq!(unsafe { pthread_kill(sleeper, selected.as_raw()) }, 0);
    });

    let requested = Duration::from_secs(2);
    let before = time::clock_gettime(time::ClockId::Monotonic).expect("monotonic before");
    let outcome = time::nanosleep(requested).expect("nanosleep call");
    let after = time::clock_gettime(time::ClockId::Monotonic).expect("monotonic after");
    sender.join().expect("join signal sender");

    // SAFETY: Restore the caller's previous action after the handler has
    // returned and the sender has stopped targeting this thread.
    unsafe { signal::sigaction(selected, Some(&old_action)) }
        .expect("restore interruption handler");

    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    let elapsed = Duration::new(
        (after.tv_sec - before.tv_sec) as u64,
        0,
    ) + Duration::from_nanos(after.tv_nsec as u64) - Duration::from_nanos(before.tv_nsec as u64);
    assert!(elapsed >= Duration::from_millis(100), "slept only {elapsed:?}");
    match outcome {
        SleepOutcome::Interrupted { remaining } => {
            assert!(remaining > Duration::ZERO);
            assert!(remaining < requested);
        }
        SleepOutcome::Completed => panic!("signal must preserve EINTR as interrupted"),
    }
}
