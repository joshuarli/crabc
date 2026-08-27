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

    // SAFETY: The action was returned by the successful installation above and
    // remains valid until it is restored after the timer is disarmed.
    unsafe { signal::sigaction(Signal::ALARM, Some(&old_alarm)) }
        .expect("restore SIGALRM in isolated timer child");
}
