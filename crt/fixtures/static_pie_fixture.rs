#![no_std]

//! Minimal Rust application used only to link and execute `rcrt1.o`.

use core::ffi::c_void;

type ApplicationMain = unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type LifecycleHook = unsafe extern "C" fn();

#[no_mangle]
pub unsafe extern "C" fn main(
    _argc: i32,
    _argv: *const *const u8,
    _envp: *const *const u8,
) -> i32 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    application: ApplicationMain,
    argc: i32,
    argv: *const *const u8,
    init: *const c_void,
    fini: *const c_void,
    _rtld_fini: *const c_void,
) -> ! {
    if !init.is_null() {
        // SAFETY: the CRT passed its own no-argument lifecycle callback.
        let callback: LifecycleHook = unsafe { core::mem::transmute(init) };
        // SAFETY: the callback has the declared C ABI and no arguments.
        unsafe { callback() };
    }
    let status = unsafe { application(argc, argv, argv.wrapping_add(argc as usize + 1)) };
    if !fini.is_null() {
        // SAFETY: the CRT passed its own no-argument lifecycle callback.
        let callback: LifecycleHook = unsafe { core::mem::transmute(fini) };
        // SAFETY: the callback has the declared C ABI and no arguments.
        unsafe { callback() };
    }
    exit(status)
}

#[no_mangle]
pub extern "C" fn exit(status: i32) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 93usize,
            in("x0") status as usize,
            options(noreturn, nostack),
        );
    }
}
