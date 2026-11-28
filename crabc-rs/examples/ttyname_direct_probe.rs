#![cfg(target_os = "linux")]
//! Link-free no-std proof for the direct `termios::ttyname` seam.
//!
//! The probe creates a PTY using direct Linux operations, then resolves the
//! slave through caller-owned storage. It deliberately uses the no-alloc form
//! so the static AArch64 probe does not depend on a runtime allocator.

#![no_std]

use core::mem::MaybeUninit;

use crabc_rs::pty::{self, OpenptFlags};
use crabc_rs::termios;

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_ttyname_direct_probe() -> i32 {
    let (master, slave) = match pty::PtyPair::open(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC) {
        Ok(pair) => pair.into_parts(),
        Err(error) => return -error.raw(),
    };

    let mut storage = [MaybeUninit::uninit(); 128];
    let name = match termios::ttyname_into(&slave, &mut storage) {
        Ok(name) => name,
        Err(error) => return -error.raw(),
    };
    if !name.to_bytes().starts_with(b"/dev/pts/") {
        return 1;
    }
    0
}
