// Timed SysV semaphore operations are a distinct kernel ABI from semop: the
// timeout is relative, and the kernel both validates and leaves it unchanged.
// Keep the wrapper direct so errno retains the syscall's IPC-specific error.

#[inline]
unsafe fn m4_sys_semtimedop(
    semid: c_int,
    operations: *mut c_void,
    operation_count: usize,
    timeout: *const timespec,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        SYS_SEMTIMEDOP,
        semid as i64,
        operations as i64,
        operation_count as i64,
        timeout as i64,
    )
}

#[no_mangle]
pub unsafe extern "C" fn semtimedop(
    semid: c_int,
    operations: *mut c_void,
    operation_count: usize,
    timeout: *const timespec,
) -> c_int {
    syscall_result(m4_sys_semtimedop(semid, operations, operation_count, timeout)) as c_int
}
