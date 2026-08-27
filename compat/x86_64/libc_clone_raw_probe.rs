#![no_std]

#[path = "../../libc/src/c_abi/x86_64/clone.rs"]
mod clone;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
pub unsafe extern "C" fn crabc_clone_raw_probe_entry(
    func: unsafe extern "C" fn(*mut core::ffi::c_void) -> i32,
    stack: *mut u8,
    flags: i32,
    arg: *mut core::ffi::c_void,
) -> i64 {
    unsafe { clone::clone_raw(func, stack, flags, arg) }
}
