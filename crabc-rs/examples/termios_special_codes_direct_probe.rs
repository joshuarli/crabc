#![cfg(target_os = "linux")]
//! Link-free no-std proof for the bounded Linux `termios` special-code slice.
//!
//! This source is intentionally self-contained until the architecture
//! harness registers its static probe. It checks the native layout and
//! round-trips named control bytes through a disposable PTY.

#![no_std]
#![crate_type = "staticlib"]

use core::mem::size_of;

use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios::{self, SpecialCodeIndex};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_termios_special_codes_direct_probe() -> i32 {
    if size_of::<termios::SpecialCodes>() != 19 || size_of::<termios::Termios>() != 44 {
        return 1;
    }

    let (master, slave) = match pty::PtyPair::open(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(pair) => pair.into_parts(),
        Err(error) => return -error.raw(),
    };

    let original = match termios::tcgetattr(&slave) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    if original.special_codes[SpecialCodeIndex::VINTR] != 3
        || original.special_codes[SpecialCodeIndex::VEOL] != 0
    {
        return 2;
    }

    let mut changed = original.clone();
    changed.special_codes[SpecialCodeIndex::VINTR] = 47;
    changed.special_codes[SpecialCodeIndex::VEOL] = 99;
    if let Err(error) = termios::tcsetattr(&slave, termios::OptionalActions::Now, &changed) {
        return -error.raw();
    }
    let observed = match termios::tcgetattr(&slave) {
        Ok(attributes) => attributes,
        Err(error) => return -error.raw(),
    };
    let result = if observed.special_codes[SpecialCodeIndex::VINTR] == 47
        && observed.special_codes[SpecialCodeIndex::VEOL] == 99
    {
        0
    } else {
        3
    };

    // Restore before returning; descriptor drop also closes this disposable
    // PTY if restoration fails.
    let _ = termios::tcsetattr(&slave, termios::OptionalActions::Now, &original);
    result
}
