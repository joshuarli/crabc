//! Link-free no-std probe for the M8 direct floating-point environment seam.

#![no_std]

use crabc_rs::fenv::{self, Environment, ExceptionFlags, RoundingMode};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m8_fenv_direct_probe() -> i32 {
    let original = fenv::get_environment();
    let result = (|| {
        fenv::set_environment(Environment::default());
        if fenv::get_rounding() != RoundingMode::Nearest {
            return 1;
        }
        fenv::set_rounding(RoundingMode::TowardZero);
        if fenv::get_rounding() != RoundingMode::TowardZero {
            return 2;
        }

        let raised = ExceptionFlags::INVALID | ExceptionFlags::INEXACT;
        fenv::raise_exceptions(raised);
        if fenv::test_exceptions(ExceptionFlags::ALL) != raised {
            return 3;
        }
        let held = fenv::hold_exceptions();
        if held.exceptions() != raised
            || !fenv::test_exceptions(ExceptionFlags::ALL).is_empty()
        {
            return 4;
        }

        fenv::raise_exceptions(ExceptionFlags::OVERFLOW);
        fenv::update_environment(held);
        if fenv::test_exceptions(ExceptionFlags::ALL)
            != (raised | ExceptionFlags::OVERFLOW)
        {
            return 5;
        }
        0
    })();
    fenv::set_environment(original);
    result
}
