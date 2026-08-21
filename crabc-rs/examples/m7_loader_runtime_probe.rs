//! Runtime proof for M7's native dynamic-loader boundary.
//!
//! This archive is linked into a C fixture that runs under crabc's `libldso`.
//! It reaches the private singleton table, not public dlfcn or errno APIs.

#![cfg_attr(not(feature = "std"), no_std)]

use core::ffi::CStr;

use crabc_rs::dl::{Library, OpenFlags};

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m7_loader_runtime_probe() -> i32 {
    let libc = unsafe { CStr::from_bytes_with_nul_unchecked(b"libc.so\0") };
    let strlen = unsafe { CStr::from_bytes_with_nul_unchecked(b"strlen\0") };
    let missing = unsafe { CStr::from_bytes_with_nul_unchecked(b"crabc_rs_missing_symbol\0") };

    let library = match Library::open(libc, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(library) => library,
        Err(_) => return 1,
    };
    let symbol = match unsafe { library.symbol::<unsafe extern "C" fn(*const u8) -> usize>(strlen) } {
        Ok(symbol) => symbol,
        Err(_) => return 2,
    };
    let length = unsafe { symbol.get()(b"m7\0".as_ptr()) };
    if length != 2 {
        return 3;
    }
    if Library::address_of(symbol.address()).is_err() {
        return 4;
    }
    if unsafe { library.symbol::<unsafe extern "C" fn()>(missing) }.is_ok() {
        return 5;
    }
    if library.close().is_err() {
        return 6;
    }

    let main = match Library::open_main(OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(main) => main,
        Err(_) => return 7,
    };
    // The global process handle is permanent. Its successful construction is
    // the native representation of `dlopen(NULL, ...)`; it has no mandatory
    // global symbol-export promise for this fixture's executable.
    drop(main);
    0
}
