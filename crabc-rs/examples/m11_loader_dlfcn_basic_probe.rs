//! Runtime proof for the bounded M11 native dynamic-loader slice.
//!
//! The archive is linked into a C fixture and runs under crabc's `libldso`.
//! It reaches only the versioned private runtime table; public dlfcn and
//! `errno` symbols are rejected by the companion ELF verifier.

#![no_std]

use core::ffi::CStr;

use crabc_rs::dl::{Library, OpenFlags};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

const CLOSE_DSO: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"libm11_loader_close.so\0") };
const DROP_DSO: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"libm11_loader_drop.so\0") };
const VALUE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"m11_loader_value\0") };
const CLOSE_STATE: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"m11_loader_close_state\0") };
const DROP_STATE: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"m11_loader_drop_state\0") };
const MISSING_SYMBOL: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"m11_loader_missing_symbol\0") };
const MISSING_DSO: &CStr =
    unsafe { CStr::from_bytes_with_nul_unchecked(b"libm11_loader_missing.so\0") };

type StateFn = unsafe extern "C" fn() -> i32;

fn is_owned_error(error: &crabc_rs::dl::LoaderError) -> bool {
    !error.as_bytes().is_empty() && !error.is_truncated()
}

#[no_mangle]
pub extern "C" fn crabc_rs_m11_loader_dlfcn_basic_probe() -> i32 {
    let main = match Library::open_main(OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(main) => main,
        Err(_) => return 1,
    };

    let missing_open_error = match Library::open(MISSING_DSO, OpenFlags::NOW | OpenFlags::LOCAL) {
        Ok(_) => return 2,
        Err(error) if is_owned_error(&error) => error,
        Err(_) => return 2,
    };

    let first = match Library::open(CLOSE_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) {
        Ok(library) => library,
        Err(_) => return 3,
    };
    let second = match Library::open(CLOSE_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) {
        Ok(library) => library,
        Err(_) => return 4,
    };

    {
        let state = match unsafe { first.symbol::<StateFn>(CLOSE_STATE) } {
            Ok(symbol) => symbol,
            Err(_) => return 5,
        };
        if unsafe { (state.get())() } != 1 {
            return 6;
        }
    }
    {
        let value = match unsafe { second.symbol::<StateFn>(VALUE) } {
            Ok(symbol) => symbol,
            Err(_) => return 7,
        };
        if unsafe { (value.get())() } != 73 {
            return 8;
        }
        let address = match Library::address_of(value.address()) {
            Ok(address) => address,
            Err(_) => return 9,
        };
        if address.image_base().is_none() || address.symbol_address().is_none() {
            return 10;
        }
        let Some(image_name) = address.image_name() else {
            return 11;
        };
        if image_name.as_bytes() != CLOSE_DSO.to_bytes() {
            return 12;
        }
        let Some(symbol_name) = address.symbol_name() else {
            return 13;
        };
        if symbol_name.as_bytes() != VALUE.to_bytes() {
            return 14;
        }
    }

    let missing_symbol_error = match unsafe { second.symbol::<StateFn>(MISSING_SYMBOL) } {
        Ok(_) => return 15,
        Err(error) if is_owned_error(&error) => error,
        Err(_) => return 15,
    };

    if first.close().is_err() {
        return 16;
    }
    {
        let state = match unsafe { second.symbol::<StateFn>(CLOSE_STATE) } {
            Ok(symbol) => symbol,
            Err(_) => return 17,
        };
        if unsafe { (state.get())() } != 1 {
            return 18;
        }
    }
    if second.close().is_err() {
        return 19;
    }
    {
        let state = match unsafe { main.symbol::<StateFn>(CLOSE_STATE) } {
            Ok(symbol) => symbol,
            Err(_) => return 20,
        };
        if unsafe { (state.get())() } != 2 {
            return 21;
        }
    }

    let drop_library = match Library::open(DROP_DSO, OpenFlags::NOW | OpenFlags::GLOBAL) {
        Ok(library) => library,
        Err(_) => return 22,
    };
    {
        let state = match unsafe { drop_library.symbol::<StateFn>(DROP_STATE) } {
            Ok(symbol) => symbol,
            Err(_) => return 23,
        };
        if unsafe { (state.get())() } != 1 {
            return 24;
        }
    }
    drop(drop_library);
    {
        let state = match unsafe { main.symbol::<StateFn>(DROP_STATE) } {
            Ok(symbol) => symbol,
            Err(_) => return 25,
        };
        if unsafe { (state.get())() } != 2 {
            return 26;
        }
    }

    if !is_owned_error(&missing_open_error) || !is_owned_error(&missing_symbol_error) {
        return 27;
    }

    drop(main);
    0
}
