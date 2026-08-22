//! Link-free no-std proof for logical current-directory naming.
//!
//! The probe supplies an explicit absolute `PWD` snapshot. The implementation
//! validates it with AArch64 `newfstatat` and falls back to direct `getcwd` if
//! it does not name the current directory; no environment, C wrapper, errno,
//! or allocator dependency is part of this proof.

#![no_std]

use core::ffi::CStr;
use core::mem::MaybeUninit;

use crabc_rs::process;

const PROBE_PATH_CAPACITY: usize = 4096;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn crabc_rs_m10_current_dir_name_direct_probe() -> i32 {
    // `/tmp` is a stable absolute pathname in the dev image. Whether it is
    // the current directory is immaterial: both the validation stat pair and
    // the direct getcwd fallback remain on the native syscall path.
    let pwd = unsafe { CStr::from_bytes_with_nul_unchecked(b"/tmp\0") };
    let mut storage = [MaybeUninit::<u8>::uninit(); PROBE_PATH_CAPACITY];
    let (initialized, untouched) = match process::get_current_dir_name(Some(pwd), &mut storage) {
        Ok(result) => result,
        Err(error) => return -error.raw(),
    };
    if initialized.is_empty() || initialized.last() != Some(&0) {
        return 1;
    }
    if untouched.len() != PROBE_PATH_CAPACITY - initialized.len() {
        return 2;
    }
    0
}
