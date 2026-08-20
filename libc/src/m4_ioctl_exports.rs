// M4 generic ioctl boundary.
//
// Linux ioctl requests are 32-bit command words on every supported LP64 ABI,
// even though the public argument is an unsigned long.  The third argument is
// passed without interpretation: ioctl commands legitimately use both a
// pointer and an immediate integer value.

#[no_mangle]
pub unsafe extern "C" fn ioctl(fd: c_int, request: c_ulong, mut args: ...) -> c_int {
    let argument = args.next_arg::<usize>();
    syscall_result(sys_ioctl(fd, request as u32, argument as *mut u8)) as c_int
}
