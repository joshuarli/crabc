//! Link-free no-std proof for the native process/POSIX timer seam.

#![no_std]
#![crate_type = "staticlib"]

use core::time::Duration;

use crabc_rs::time::{
    self, ClockId, IntervalTimerKind, IntervalTimerValue, PosixTimer, TimerNotification,
    TimerSetFlags, TimerSpec,
};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_time_timers_direct_probe() -> i32 {
    let disarmed = match IntervalTimerValue::new(Duration::ZERO, Duration::ZERO) {
        Some(value) => value,
        None => return 1,
    };
    if time::setitimer(IntervalTimerKind::Real, disarmed).is_err() {
        return 2;
    }

    let mut timer = match PosixTimer::new(ClockId::Monotonic, TimerNotification::None) {
        Ok(timer) => timer,
        Err(error) => return -error.raw(),
    };
    let spec = match TimerSpec::new(Duration::ZERO, Duration::from_millis(10)) {
        Some(spec) => spec,
        None => return 3,
    };
    if timer.settime(TimerSetFlags::empty(), spec).is_err() {
        return 4;
    }
    if timer.gettime().is_err() || timer.getoverrun().is_err() {
        return 5;
    }
    if timer.delete().is_err() {
        return 6;
    }
    0
}
