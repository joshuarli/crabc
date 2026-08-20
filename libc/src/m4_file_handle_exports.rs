// Linux file-handle ABI.  The variable-sized `struct file_handle` is owned by
// the C caller, so the libc boundary intentionally forwards it as opaque
// storage and lets the kernel report both required size and filesystem support.

#[cfg(target_arch = "x86_64")]
const M4_SYS_NAME_TO_HANDLE_AT: i64 = 303;
#[cfg(target_arch = "x86_64")]
const M4_SYS_OPEN_BY_HANDLE_AT: i64 = 304;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_NAME_TO_HANDLE_AT: i64 = 264;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_OPEN_BY_HANDLE_AT: i64 = 265;

#[no_mangle]
pub unsafe extern "C" fn name_to_handle_at(
    dirfd: c_int,
    path: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall5(
        M4_SYS_NAME_TO_HANDLE_AT,
        dirfd as i64,
        path as i64,
        handle as i64,
        mount_id as i64,
        flags as i64,
    )) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn open_by_handle_at(
    mount_fd: c_int,
    handle: *mut c_void,
    flags: c_int,
) -> c_int {
    syscall_result(<Arch as Syscalls>::syscall3(
        M4_SYS_OPEN_BY_HANDLE_AT,
        mount_fd as i64,
        handle as i64,
        flags as i64,
    )) as c_int
}
