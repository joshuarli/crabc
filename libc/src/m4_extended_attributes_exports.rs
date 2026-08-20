// M4 Linux extended-attribute exports.
//
// Linux exposes the path, no-follow-path, and file-descriptor variants as
// separate syscalls.  Keep these wrappers thin so the kernel remains the
// authority for attribute names, value sizes, flags, and filesystem errors;
// syscall_result translates its negative errno convention at the C ABI.

#[cfg(target_arch = "x86_64")]
const M4_SYS_SETXATTR: i64 = 188;
#[cfg(target_arch = "x86_64")]
const M4_SYS_LSETXATTR: i64 = 189;
#[cfg(target_arch = "x86_64")]
const M4_SYS_FSETXATTR: i64 = 190;
#[cfg(target_arch = "x86_64")]
const M4_SYS_GETXATTR: i64 = 191;
#[cfg(target_arch = "x86_64")]
const M4_SYS_LGETXATTR: i64 = 192;
#[cfg(target_arch = "x86_64")]
const M4_SYS_FGETXATTR: i64 = 193;
#[cfg(target_arch = "x86_64")]
const M4_SYS_LISTXATTR: i64 = 194;
#[cfg(target_arch = "x86_64")]
const M4_SYS_LLISTXATTR: i64 = 195;
#[cfg(target_arch = "x86_64")]
const M4_SYS_FLISTXATTR: i64 = 196;
#[cfg(target_arch = "x86_64")]
const M4_SYS_REMOVEXATTR: i64 = 197;
#[cfg(target_arch = "x86_64")]
const M4_SYS_LREMOVEXATTR: i64 = 198;
#[cfg(target_arch = "x86_64")]
const M4_SYS_FREMOVEXATTR: i64 = 199;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_SETXATTR: i64 = 5;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_LSETXATTR: i64 = 6;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FSETXATTR: i64 = 7;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_GETXATTR: i64 = 8;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_LGETXATTR: i64 = 9;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FGETXATTR: i64 = 10;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_LISTXATTR: i64 = 11;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_LLISTXATTR: i64 = 12;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FLISTXATTR: i64 = 13;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_REMOVEXATTR: i64 = 14;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_LREMOVEXATTR: i64 = 15;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
const M4_SYS_FREMOVEXATTR: i64 = 16;

#[inline]
unsafe fn m4_setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_SETXATTR,
        path as i64,
        name as i64,
        value as i64,
        size as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn m4_lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_LSETXATTR,
        path as i64,
        name as i64,
        value as i64,
        size as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn m4_fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> i64 {
    <Arch as Syscalls>::syscall5(
        M4_SYS_FSETXATTR,
        fd as i64,
        name as i64,
        value as i64,
        size as i64,
        flags as i64,
    )
}

#[inline]
unsafe fn m4_getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_GETXATTR,
        path as i64,
        name as i64,
        value as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_LGETXATTR,
        path as i64,
        name as i64,
        value as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> i64 {
    <Arch as Syscalls>::syscall4(
        M4_SYS_FGETXATTR,
        fd as i64,
        name as i64,
        value as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_listxattr(path: *const c_char, list: *mut c_char, size: SizeT) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_LISTXATTR,
        path as i64,
        list as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_llistxattr(path: *const c_char, list: *mut c_char, size: SizeT) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_LLISTXATTR,
        path as i64,
        list as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_flistxattr(fd: c_int, list: *mut c_char, size: SizeT) -> i64 {
    <Arch as Syscalls>::syscall3(
        M4_SYS_FLISTXATTR,
        fd as i64,
        list as i64,
        size as i64,
    )
}

#[inline]
unsafe fn m4_removexattr(path: *const c_char, name: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_REMOVEXATTR, path as i64, name as i64)
}

#[inline]
unsafe fn m4_lremovexattr(path: *const c_char, name: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_LREMOVEXATTR, path as i64, name as i64)
}

#[inline]
unsafe fn m4_fremovexattr(fd: c_int, name: *const c_char) -> i64 {
    <Arch as Syscalls>::syscall2(M4_SYS_FREMOVEXATTR, fd as i64, name as i64)
}

#[no_mangle]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(m4_setxattr(path, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(m4_lsetxattr(path, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: SizeT,
    flags: c_int,
) -> c_int {
    syscall_result(m4_fsetxattr(fd, name, value, size, flags)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(m4_getxattr(path, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(m4_lgetxattr(path, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: SizeT,
) -> SSizeT {
    syscall_result(m4_fgetxattr(fd, name, value, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn listxattr(
    path: *const c_char,
    list: *mut c_char,
    size: SizeT,
) -> SSizeT {
    syscall_result(m4_listxattr(path, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn llistxattr(
    path: *const c_char,
    list: *mut c_char,
    size: SizeT,
) -> SSizeT {
    syscall_result(m4_llistxattr(path, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: SizeT) -> SSizeT {
    syscall_result(m4_flistxattr(fd, list, size)) as SSizeT
}

#[no_mangle]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    syscall_result(m4_removexattr(path, name)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    syscall_result(m4_lremovexattr(path, name)) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    syscall_result(m4_fremovexattr(fd, name)) as c_int
}
