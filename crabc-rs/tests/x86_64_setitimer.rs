#![cfg(target_arch = "x86_64")]

use core::time::Duration;
use std::process::Command;

use crabc_rs::{
    signal::{self, SigAction, SigActionFlags, SigHandler, Signal},
    time::{self, IntervalTimerKind, IntervalTimerValue},
};

const ISOLATED_CASE: &str = "CRABC_RS_X86_64_SETITIMER_CASE";

#[test]
fn x86_64_setitimer_exchange_and_disarm_are_isolated() {
    if std::env::var_os(ISOLATED_CASE).is_some() {
        isolated_setitimer_case();
        return;
    }

    let output = Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            "x86_64_setitimer_exchange_and_disarm_are_isolated",
            "--nocapture",
        ])
        .env(ISOLATED_CASE, "1")
        .output()
        .expect("run isolated setitimer child");
    assert!(
        output.status.success(),
        "isolated setitimer child failed with {:?}, stdout: {}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn isolated_setitimer_case() {
    // IntervalTimerValue is the validation boundary: finer-than-microsecond
    // values are rejected before a setting can reach the raw syscall.
    assert!(IntervalTimerValue::new(Duration::from_nanos(1), Duration::ZERO).is_none());
    assert!(IntervalTimerValue::new(Duration::ZERO, Duration::from_nanos(999)).is_none());
    assert!(
        IntervalTimerValue::new(
            Duration::from_secs(i64::MAX as u64 + 1),
            Duration::ZERO,
        )
        .is_none()
    );

    let ignore_alarm = SigAction::new(SigHandler::Ignore, SigActionFlags::empty());
    // SAFETY: This short-lived child owns the temporary ignored disposition;
    // `SIGALRM` has no Rust handler pointer or lifetime to uphold.
    let old_alarm = unsafe { signal::sigaction(Signal::ALARM, Some(&ignore_alarm)) }
        .expect("ignore SIGALRM in isolated timer child");
    // SAFETY: This short-lived child owns these temporary ignored dispositions
    // while exercising the two CPU-accounted interval-timer selectors.
    let old_virtual_alarm = unsafe { signal::sigaction(Signal::VTALARM, Some(&ignore_alarm)) }
        .expect("ignore SIGVTALRM in isolated timer child");
    // SAFETY: This short-lived child owns this temporary ignored disposition
    // while exercising the profiler interval-timer selector.
    let old_prof_alarm = unsafe { signal::sigaction(Signal::PROF, Some(&ignore_alarm)) }
        .expect("ignore SIGPROF in isolated timer child");

    let disarmed = IntervalTimerValue::new(Duration::ZERO, Duration::ZERO).unwrap();
    // Clear any inherited process state before exercising exchange semantics.
    let _ = time::setitimer(IntervalTimerKind::Real, disarmed).expect("initial disarm");

    let first = IntervalTimerValue::new(Duration::from_millis(10), Duration::from_secs(2)).unwrap();
    let old = time::setitimer(IntervalTimerKind::Real, first).expect("arm real timer");
    assert_eq!(old, disarmed);

    let current = time::getitimer(IntervalTimerKind::Real).expect("read newly armed timer");
    assert_eq!(current.interval(), first.interval());
    assert!(current.value() > Duration::ZERO);
    assert!(current.value() <= first.value());

    let replacement =
        IntervalTimerValue::new(Duration::from_millis(20), Duration::from_secs(2)).unwrap();
    let old = time::setitimer(IntervalTimerKind::Real, replacement).expect("replace timer");
    assert_eq!(old.interval(), first.interval());
    assert!(old.value() > Duration::ZERO);
    assert!(old.value() <= first.value());

    let old = time::setitimer(IntervalTimerKind::Real, disarmed).expect("disarm real timer");
    assert_eq!(old.interval(), replacement.interval());
    assert!(old.value() > Duration::ZERO);
    assert!(old.value() <= replacement.value());
    assert_eq!(time::getitimer(IntervalTimerKind::Real).unwrap(), disarmed);

    // Virtual and profiler timers use CPU-accounted clocks instead of elapsed
    // time. A deliberately long one-shot setting lets this child prove the
    // same complete exchange without comparing naturally decrementing values
    // or risking signal delivery.
    let cpu_accounted = IntervalTimerValue::new(Duration::ZERO, Duration::from_secs(3_600))
        .expect("representable CPU-accounted timer setting");
    for kind in [IntervalTimerKind::Virtual, IntervalTimerKind::Profiler] {
        let _ = time::setitimer(kind, disarmed).expect("clear inherited selector state");
        assert_eq!(
            time::setitimer(kind, cpu_accounted).expect("arm CPU-accounted timer"),
            disarmed
        );
        let current = time::getitimer(kind).expect("read CPU-accounted timer");
        assert_eq!(current.interval(), Duration::ZERO);
        // Linux may round CPU-accounted timers up to its accounting tick, so
        // this transient read need not be numerically below the requested
        // duration as an elapsed real timer would be.
        assert!(current.value() > Duration::ZERO);
        let old = time::setitimer(kind, disarmed).expect("disarm CPU-accounted timer");
        assert_eq!(old.interval(), Duration::ZERO);
        assert!(old.value() > Duration::ZERO);
        assert_eq!(time::getitimer(kind).unwrap(), disarmed);
    }

    // The aliases exchange the same process-global real timer. Keeping them
    // in this short-lived child makes even a long-lived alias setting unable
    // to leak into the test harness. `alarm` must ceiling a positive
    // fractional remainder rather than truncating it to zero seconds.
    assert_eq!(
        time::ualarm(3_600_999_000, 0).expect("arm fractional alias timer"),
        0
    );
    assert_eq!(
        time::alarm(0).expect("alarm disarms and ceilings remainder"),
        3_601
    );
    assert_eq!(time::getitimer(IntervalTimerKind::Real).unwrap(), disarmed);

    // `ualarm` keeps its integral-microsecond vocabulary, including its
    // periodic interval, and its bounded Rust return value saturates rather
    // than exposing C unsigned-integer wrapping for a large prior setting.
    assert_eq!(
        time::ualarm(600_000_000, 750_000).expect("arm periodic microsecond alias"),
        0
    );
    let current = time::getitimer(IntervalTimerKind::Real).expect("read alias timer");
    assert_eq!(current.interval(), Duration::from_micros(750_000));
    assert!(current.value() > Duration::from_secs(599));
    assert!(current.value() <= Duration::from_secs(600));
    let old_micros = time::ualarm(0, 0).expect("ualarm disarms periodic timer");
    assert!(old_micros > 599_000_000);
    assert!(old_micros <= 600_000_000);
    assert_eq!(time::getitimer(IntervalTimerKind::Real).unwrap(), disarmed);

    assert_eq!(time::alarm(u32::MAX).expect("arm largest alias second setting"), 0);
    assert_eq!(
        time::ualarm(0, 0).expect("saturating microsecond alias return"),
        u32::MAX
    );
    assert_eq!(time::getitimer(IntervalTimerKind::Real).unwrap(), disarmed);

    // SAFETY: The action was returned by the successful installation above and
    // remains valid until it is restored after the timer is disarmed.
    unsafe { signal::sigaction(Signal::PROF, Some(&old_prof_alarm)) }
        .expect("restore SIGPROF in isolated timer child");
    // SAFETY: The action was returned by the successful installation above and
    // remains valid until it is restored after the timer is disarmed.
    unsafe { signal::sigaction(Signal::VTALARM, Some(&old_virtual_alarm)) }
        .expect("restore SIGVTALRM in isolated timer child");
    // SAFETY: The action was returned by the successful installation above and
    // remains valid until it is restored after the timer is disarmed.
    unsafe { signal::sigaction(Signal::ALARM, Some(&old_alarm)) }
        .expect("restore SIGALRM in isolated timer child");
}
