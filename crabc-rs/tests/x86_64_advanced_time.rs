//! Native x86-64 regression for advanced clock IDs and owned POSIX timers.
//!
//! This selects direct typed Linux records only. It deliberately never sets
//! realtime, installs a signal handler, or requests `SIGEV_THREAD` callbacks.

use core::time::Duration;

use crabc_rs::pipe;
use crabc_rs::time::{
    self, clock_gettime_dynamic, ClockId, DynamicClockId, PosixTimer, TimerNotification,
    TimerSetFlags, TimerSpec, Timespec, NANOS_PER_SECOND,
};
use crabc_rs::{AsFd, Errno};

#[test]
fn x86_64_advanced_clock_ids_are_validated_and_direct() {
    assert_eq!(ClockId::try_from(3), Ok(ClockId::ThreadCPUTime));
    assert_eq!(ClockId::try_from(11), Ok(ClockId::Tai));
    assert_eq!(ClockId::try_from(10), Err(Errno::INVAL));

    let resolution = time::clock_getres(ClockId::Monotonic).expect("monotonic resolution");
    assert!(resolution.tv_sec >= 0);
    assert!((0..NANOS_PER_SECOND as i64).contains(&resolution.tv_nsec));

    let before = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .expect("known monotonic clock");
    let after = clock_gettime_dynamic(DynamicClockId::Known(ClockId::Monotonic))
        .expect("known monotonic clock");
    assert!((0..NANOS_PER_SECOND as i64).contains(&before.tv_nsec));
    assert!((0..NANOS_PER_SECOND as i64).contains(&after.tv_nsec));
    assert!((after.tv_sec, after.tv_nsec) >= (before.tv_sec, before.tv_nsec));

    let current = time::clock_getcpuclockid(None).expect("calling process CPU clock");
    let by_pid = time::clock_getcpuclockid(Some(crabc_rs::process::getpid()))
        .expect("calling process CPU clock by PID");
    assert_eq!(current.as_raw(), -6);
    assert_eq!(
        by_pid.as_raw(),
        ((-(crabc_rs::process::getpid().as_raw_pid() as i64) - 1) * 8 + 2) as i32,
    );
    let process_time = clock_gettime_dynamic(DynamicClockId::Process(current))
        .expect("encoded current-process CPU clock");
    assert!(process_time.tv_sec >= 0);
    assert!((0..NANOS_PER_SECOND as i64).contains(&process_time.tv_nsec));

    let unencodable = crabc_rs::process::Pid::from_raw(i32::MAX).expect("positive test PID");
    assert_eq!(time::clock_getcpuclockid(Some(unencodable)), Err(Errno::SRCH));

    let (reader, _writer) = pipe::pipe().expect("pipe for invalid dynamic clock");
    assert_eq!(
        clock_gettime_dynamic(DynamicClockId::Dynamic(reader.as_fd())),
        Err(Errno::INVAL),
    );
}

#[test]
fn x86_64_clock_settime_preflights_and_never_mutates_realtime() {
    assert_eq!(
        time::clock_settime(
            ClockId::Monotonic,
            Timespec {
                tv_sec: 0,
                tv_nsec: NANOS_PER_SECOND as i64,
            },
        ),
        Err(Errno::INVAL),
    );

    let result = time::clock_settime(
        ClockId::Monotonic,
        Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    );
    assert!(matches!(result, Err(Errno::INVAL | Errno::PERM)));
}

#[test]
fn x86_64_posix_timer_owns_a_sigev_none_lifecycle() {
    let zero = TimerSpec::new(Duration::ZERO, Duration::ZERO).expect("zero timer specification");
    assert!(TimerSpec::new(Duration::from_secs(i64::MAX as u64 + 1), Duration::ZERO).is_none());

    let mut timer = PosixTimer::new(ClockId::Monotonic, TimerNotification::None)
        .expect("create SIGEV_NONE timer");
    assert_eq!(timer.gettime().expect("initial timer setting"), zero);

    let one_shot = TimerSpec::new(Duration::ZERO, Duration::from_millis(50))
        .expect("one-shot timer specification");
    assert_eq!(
        timer
            .settime(TimerSetFlags::empty(), one_shot)
            .expect("arm one-shot timer"),
        zero,
    );
    let current = timer.gettime().expect("current timer setting");
    assert_eq!(current.interval(), Duration::ZERO);
    assert!(current.value() <= one_shot.value());
    assert!(timer.getoverrun().expect("timer overrun count") >= 0);

    // Linux 5.10 forwards this extra bit to the POSIX timer path, which masks
    // it to TIMER_ABSTIME rather than rejecting it. The typed flag keeps that
    // direct behavior instead of inventing an EINVAL preflight.
    let previous = timer
        .settime(TimerSetFlags::from_bits_retain(2), zero)
        .expect("extra timer_settime flag is forwarded and ignored by Linux");
    assert_eq!(previous.interval(), Duration::ZERO);
    assert!(previous.value() <= one_shot.value());
    let disarmed = timer.gettime().expect("read SIGEV_NONE after disarm");
    assert_eq!(disarmed.interval(), Duration::ZERO);
    assert!(disarmed.value() <= one_shot.value());

    let signal_timer = PosixTimer::new(
        ClockId::Monotonic,
        TimerNotification::Signal {
            signal: crabc_rs::signal::Signal::USR1,
            value: 7,
        },
    )
    .expect("create unarmed signal timer");
    let thread_timer = PosixTimer::new(
        ClockId::Monotonic,
        TimerNotification::ThreadId {
            thread: crabc_rs::thread::gettid(),
            signal: crabc_rs::signal::Signal::USR1,
            value: 8,
        },
    )
    .expect("create unarmed thread-directed timer");
    drop(signal_timer);
    drop(thread_timer);

    timer.delete().expect("explicitly delete timer");
    assert_eq!(timer.delete(), Err(Errno::INVAL));
}
