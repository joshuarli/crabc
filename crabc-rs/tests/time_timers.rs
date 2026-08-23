use core::time::Duration;

use crabc_rs::time::{
    self, ClockId, IntervalTimerKind, IntervalTimerValue, PosixTimer, TimerNotification,
    TimerSetFlags, TimerSpec,
};

#[test]
fn native_setitimer_and_legacy_aliases_control_the_real_timer() {
    let disarmed = IntervalTimerValue::new(Duration::ZERO, Duration::ZERO).unwrap();
    let old = time::setitimer(IntervalTimerKind::Real, disarmed).expect("disarm real timer");
    assert!(old.value() >= Duration::ZERO);

    let armed = IntervalTimerValue::new(Duration::ZERO, Duration::from_millis(50)).unwrap();
    let previous = time::setitimer(IntervalTimerKind::Real, armed).expect("arm real timer");
    assert_eq!(previous.value(), Duration::ZERO);

    let remaining = time::alarm(0).expect("alarm disarms real timer");
    assert!(remaining <= 1);
    assert_eq!(time::ualarm(0, 0).expect("ualarm disarms real timer"), 0);
}

#[test]
fn interval_timer_rejects_submicrosecond_values_before_the_kernel() {
    assert!(IntervalTimerValue::new(Duration::from_nanos(1), Duration::ZERO).is_none());
    assert!(IntervalTimerValue::new(Duration::ZERO, Duration::from_nanos(999)).is_none());
}

#[test]
fn native_posix_timer_owns_and_deletes_a_kernel_timer() {
    let mut timer = PosixTimer::new(ClockId::Monotonic, TimerNotification::None)
        .expect("create a SIGEV_NONE timer");
    let spec = TimerSpec::new(Duration::from_millis(20), Duration::from_millis(50)).unwrap();
    let old = timer
        .settime(TimerSetFlags::empty(), spec)
        .expect("arm POSIX timer");
    assert_eq!(old, TimerSpec::new(Duration::ZERO, Duration::ZERO).unwrap());

    let current = timer.gettime().expect("read POSIX timer");
    assert!(current.value() <= spec.value());
    assert!(timer.getoverrun().expect("read timer overrun") >= 0);

    timer.delete().expect("explicitly delete POSIX timer");
    assert_eq!(timer.delete(), Err(crabc_rs::Errno::INVAL));
}

#[test]
fn timer_notification_vocabulary_excludes_thread_callbacks() {
    let signal = crabc_rs::process::Signal::USR1;
    let thread = crabc_rs::thread::gettid();
    let notification = TimerNotification::ThreadId {
        thread,
        signal,
        value: 7,
    };
    let timer = PosixTimer::new(ClockId::Monotonic, notification)
        .expect("create a thread-directed timer");
    drop(timer);
}
