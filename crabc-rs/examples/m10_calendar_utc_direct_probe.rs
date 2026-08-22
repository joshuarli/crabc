//! Link-free no-std proof for the M10 UTC calendar conversion seam.

#![no_std]

use crabc_rs::time::{self, CalendarTime};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_calendar_utc_direct_probe() -> i32 {
    let value = match time::gmtime(0) {
        Ok(value) => value,
        Err(error) => return -error.raw(),
    };
    if (value.year(), value.month(), value.day()) != (1970, 1, 1) {
        return 1;
    }
    match time::timegm(&value) {
        Ok(0) => {}
        Ok(_) => return 2,
        Err(error) => return -error.raw(),
    }

    let leap = match CalendarTime::from_ymdhms(2000, 2, 29, 23, 59, 59) {
        Ok(value) => value,
        Err(error) => return -error.raw(),
    };
    match time::timegm(&leap) {
        Ok(951_868_799) => {}
        Ok(_) => return 3,
        Err(error) => return -error.raw(),
    }
    if !time::difftime(i64::MAX, i64::MIN).is_finite() {
        return 4;
    }
    if let Err(error) = time::time() {
        return -error.raw();
    }
    0
}
