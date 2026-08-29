// generic ioctl boundary.
//
// Linux ioctl requests are 32-bit command words on every supported LP64 ABI,
// and musl exposes the public request as signed `int`. Converting it to u32
// preserves the Linux command bits. The third argument is passed without
// interpretation: ioctl commands legitimately use both a pointer and an
// immediate integer value.

use super::{c_int, sys_ioctl, syscall_result};

#[no_mangle]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_int, mut args: ...) -> c_int {
    let argument = args.next_arg::<usize>();
    syscall_result(sys_ioctl(fd, request as u32, argument as *mut u8)) as c_int
}
