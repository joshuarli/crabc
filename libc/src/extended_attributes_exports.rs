// Linux extended-attribute exports.
//
// Linux exposes the path, no-follow-path, and file-descriptor variants as
// separate syscalls.  Keep these wrappers thin so the kernel remains the
// authority for attribute names, value sizes, flags, and filesystem errors;
// syscall_result translates its negative errno convention at the C ABI.

#[inline]
fn cabi_core_result(result: crabc_core::Result<usize>) -> i64 {
    match result {
        Ok(value) => value as i64,
        Err(errno) => -(errno.raw() as i64),
    }
}

#[inline]
unsafe fn cabi_setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe {
        crabc_core::fs::setxattr_raw(path.cast(), name.cast(), value.cast(), size, flags as u32)
        .map(|_| 0)
    })
}

#[inline]
unsafe fn cabi_lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe {
        crabc_core::fs::lsetxattr_raw(path.cast(), name.cast(), value.cast(), size, flags as u32)
        .map(|_| 0)
    })
}

#[inline]
unsafe fn cabi_fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe {
        crabc_core::fs::fsetxattr_raw(fd, name.cast(), value.cast(), size, flags as u32)
        .map(|_| 0)
    })
}

#[inline]
unsafe fn cabi_getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::getxattr_raw(path.cast(), name.cast(), value.cast(), size) })
}

#[inline]
unsafe fn cabi_lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::lgetxattr_raw(path.cast(), name.cast(), value.cast(), size) })
}

#[inline]
unsafe fn cabi_fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::fgetxattr_raw(fd, name.cast(), value.cast(), size) })
}

#[inline]
unsafe fn cabi_listxattr(path: *const c_char, list: *mut c_char, size: SizeT) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::listxattr_raw(path.cast(), list.cast(), size) })
}

#[inline]
unsafe fn cabi_llistxattr(path: *const c_char, list: *mut c_char, size: SizeT) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::llistxattr_raw(path.cast(), list.cast(), size) })
}

#[inline]
unsafe fn cabi_flistxattr(fd: c_int, list: *mut c_char, size: SizeT) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::flistxattr_raw(fd, list.cast(), size) })
}

#[inline]
unsafe fn cabi_removexattr(path: *const c_char, name: *const c_char) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::removexattr_raw(path.cast(), name.cast()).map(|_| 0) })
}

#[inline]
unsafe fn cabi_lremovexattr(path: *const c_char, name: *const c_char) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::lremovexattr_raw(path.cast(), name.cast()).map(|_| 0) })
}

#[inline]
unsafe fn cabi_fremovexattr(fd: c_int, name: *const c_char) -> i64 {
    // SAFETY: The public C wrapper inherits C's xattr pointer contracts.
    cabi_core_result(unsafe { crabc_core::fs::fremovexattr_raw(fd, name.cast()).map(|_| 0) })
}

#[no_mangle]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_setxattr(path, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_lsetxattr(path, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(cabi_fsetxattr(fd, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(cabi_getxattr(path, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(cabi_lgetxattr(path, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(cabi_fgetxattr(fd, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn listxattr(
    path: *const c_char,
    list: *mut c_char,
    size: SizeT,
) -> SSizeT {
    syscall_result(cabi_listxattr(path, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn llistxattr(
    path: *const c_char,
    list: *mut c_char,
    size: SizeT,
) -> SSizeT {
    syscall_result(cabi_llistxattr(path, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: SizeT) -> SSizeT {
    syscall_result(cabi_flistxattr(fd, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    syscall_result(cabi_removexattr(path, name)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    syscall_result(cabi_lremovexattr(path, name)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    syscall_result(cabi_fremovexattr(fd, name)) as c_int
}
